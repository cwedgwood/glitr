package appliance

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"slices"

	"github.com/cwedgwood/glitr/lio"
	"github.com/cwedgwood/glitr/storage"
)

// maxLUN bounds a caller-supplied mapped LUN so an absurd value can't be
// persisted and then rejected by the kernel at startup replay.
const maxLUN = 16383

// StatusError carries an HTTP status for the REST layer. Ops return it for
// client errors (bad request, not found, conflict); any other
// error is treated as internal (http.StatusInternalServerError).
type StatusError struct {
	Code int
	Msg  string
}

func (e *StatusError) Error() string { return e.Msg }

func statusErr(code int, format string, a ...any) error {
	return &StatusError{Code: code, Msg: fmt.Sprintf(format, a...)}
}

func validIQN(s string) bool { return lio.ValidInitiatorIQN(s) }

// copyHost returns a Host whose IQNs slice is independent of any stored
// record, so a caller cannot mutate the coordinator's state through it.
func copyHost(h Host) Host {
	h.IQNs = append([]string(nil), h.IQNs...)
	return h
}

// ConnInfo is what a client needs to connect to a mapped volume.
type ConnInfo struct {
	TargetIQN string `json:"target_iqn"`
	// Portals carry their own ports -- see Config.Portals. A client needs the
	// endpoint, not an address plus a guess.
	Portals []lio.Portal `json:"portals"`
	LUN     int          `json:"lun"`
	Wwid    string       `json:"wwid"`
}

// --- volume operations (storage + reconcile) ---

// CreateVolume allocates a new volume (size bytes). Not exported until mapped.
// MinVolumeSize is the smallest volume the appliance will create.
//
// Not a kernel or storage limit -- the layers below accept any whole number of
// blocks. It is a policy floor, because volumes below roughly this size are
// not useful and are actively troublesome:
//
//   - A GPT costs 34 sectors at each end, and the conventional 1 MiB first
//     partition offset (which every partitioner and this project's own
//     alignment checks assume) does not fit at all below 1 MiB.
//   - Filesystems have their own minima well above it -- mkfs.xfs refuses
//     anything under 16 MiB, and ext4 needs hundreds of KiB before it will
//     produce something mountable.
//   - The smaller the volume, the larger the share consumed by metadata and
//     alignment, so what the initiator can actually use diverges sharply from
//     what was asked for.
//   - Tiny volumes concentrate exactly the edge cases that have cost this
//     project the most: partial trailing blocks, capacities that round to
//     nothing, and geometry arithmetic where the block size is a significant
//     fraction of the whole device.
//
// 1 MiB is a whole number of both 512-byte and 4096-byte blocks, so the floor
// does not interact with the block-size policy.
//
// Worth revisiting if a real use case for smaller volumes appears; raising a
// floor is easy, and nothing below this line is load-bearing elsewhere.
const MinVolumeSize = 1 << 20

// CreateVolume makes a volume of the given size and logical block size.
//
// blockSize 0 means the default (512). The appliance deliberately offers only
// 512 and 4096 -- 512n and 4Kn, the two geometries real disks have -- even
// though the kernel would also take 1024 and 2048; those have no hardware
// analogue and only add ways for a consumer to be surprised.
//
// It is fixed for the life of the volume. The kernel refuses to change it
// while the device is exported, and changing it under a mounted filesystem
// would redefine the geometry beneath it.
func (c *Coordinator) CreateVolume(size int64, blockSize int) (storage.Volume, error) {
	if size < MinVolumeSize {
		return storage.Volume{}, statusErr(http.StatusBadRequest,
			"volume size %d is below the %d-byte minimum", size, MinVolumeSize)
	}
	if blockSize == 0 {
		blockSize = storage.DefaultBlockSize
	}
	if !storage.ValidBlockSize(blockSize) {
		return storage.Volume{}, statusErr(http.StatusBadRequest,
			"block_size must be %d or %d", storage.DefaultBlockSize, storage.MaxBlockSize)
	}
	if size%int64(blockSize) != 0 {
		return storage.Volume{}, statusErr(http.StatusBadRequest,
			"size %d must be a multiple of block_size %d", size, blockSize)
	}
	return volumeResult(c.store.Create(size, blockSize))
}

// volumeResult normalises the (*storage.Volume, error) pair the store returns
// for the operations that mint a new identity.
//
// It exists because a non-nil volume and a non-nil error are not mutually
// exclusive: storage returns BOTH for ErrPersistedNotDurable, where persist
// renamed the db into place and only then failed to fsync the directory. By
// the time the caller sees that error the db already NAMES the volume, and
// the volume's directory and backing file are on disk.
//
// Both call sites used to `return storage.Volume{}, err` here, which threw the
// UUID away. The volume was real -- it appears in GET /volumes and survives a
// reopen -- but the caller that created it never learned its name, so it could
// neither retry against it, resize it, nor delete it. That is the same class
// of bug storage/store_test.go's TestSnapshotDoesNotDestroyDataOnANonDurablePersist
// pins one layer down; storage honours the contract, the appliance did not.
//
// The error is still returned, and still maps to 500: durability was not
// proven, so the caller must not assume the record survives a power cut.
func volumeResult(v *storage.Volume, err error) (storage.Volume, error) {
	if v == nil {
		return storage.Volume{}, err
	}
	return *v, err
}

// ListVolumes returns all volumes.
func (c *Coordinator) ListVolumes() []storage.Volume { return c.store.List() }

// GetVolume returns a volume record.
func (c *Coordinator) GetVolume(uuid string) (storage.Volume, bool) { return c.store.Get(uuid) }

// SnapshotVolume creates a reflink snapshot (new identity).
func (c *Coordinator) SnapshotVolume(uuid string) (storage.Volume, error) {
	if _, ok := c.store.Get(uuid); !ok {
		return storage.Volume{}, statusErr(http.StatusNotFound, "volume %s not found", uuid)
	}
	return volumeResult(c.store.Snapshot(uuid))
}

// DeleteVolume removes a volume; rejected while it has attachments.
func (c *Coordinator) DeleteVolume(uuid string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.store.Get(uuid); !ok {
		return statusErr(http.StatusNotFound, "volume %s not found", uuid)
	}
	if len(c.attachmentsOf(uuid)) > 0 {
		return statusErr(http.StatusConflict, "volume %s is attached; detach first", uuid)
	}
	// The db says this volume is unattached — but if a previous reconcile
	// failed, the kernel may still hold a live LUN with an open fd on the
	// backing file. Converge first; never unlink storage the kernel is serving.
	if err := c.healIfDegraded(); err != nil {
		return err
	}
	v, _ := c.store.Get(uuid)
	if err := c.store.Delete(uuid); err != nil {
		return err
	}
	c.discardSavedPR(v.WWN)
	return nil
}

// discardSavedPR removes the kernel's saved SCSI-3 PR metadata for a deleted
// volume. The kernel writes db_root/pr/aptpl_<wwn> but never removes it, so
// without this the files accumulate for the life of the appliance.
//
// Only ever called for a volume that has just been deleted while unattached,
// which is the one moment the saved reservations are certainly dead: the
// backstore has been pruned by the preceding reconcile, so nothing can
// rewrite the file, and no future volume can inherit it (a WWN is the first 8
// bytes of a CSPRNG UUID -- 60 random bits, since one nibble is the UUID
// version -- and is enforced unique across live volumes).
//
// Best-effort by design. The volume is already gone, and failing the delete
// because a metadata file could not be unlinked would turn a tidiness
// problem into an API error. A leftover file is inert: it is only ever read
// back for a backstore with that exact WWN.
func (c *Coordinator) discardSavedPR(wwn string) {
	if c.cfg.DBRoot == "" || wwn == "" {
		return
	}
	path := APTPLPath(c.cfg.DBRoot, wwn)
	// A failure here leaves an orphan. It is not retried and not fatal: the
	// volume is already deleted, so there is nothing to roll back and no
	// correctness consequence (the file is only ever read back for a
	// backstore with this exact WWN, which no longer exists and cannot recur
	// -- see OrphanPRState). It is logged, and the leftover is reported at
	// the next startup and by `applianced inspect`.
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Printf("warning: could not remove saved SCSI-3 PR state %s: %v "+
			"(harmless leftover; `applianced inspect` will list it)", path, err)
	}
}

// ResizeVolume grows a volume and refreshes any live export. Returns
// whether the volume was exported (i.e. the client must rescan).
func (c *Coordinator) ResizeVolume(uuid string, newSize int64) (rescanRequired bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.store.Get(uuid)
	if !ok {
		return false, statusErr(http.StatusNotFound, "volume %s not found", uuid)
	}
	if newSize <= 0 {
		return false, statusErr(http.StatusBadRequest, "volume size must be > 0")
	}
	if newSize < v.Capacity {
		return false, statusErr(http.StatusConflict, "shrink unsupported (%d < %d)", newSize, v.Capacity)
	}
	// Growing has to stay on a block boundary for the same reason creating
	// does: the kernel floors the block count, so an unaligned grow would
	// hand back fewer bytes than asked for.
	if bs := int64(v.BlockSizeOrDefault()); newSize%bs != 0 {
		return false, statusErr(http.StatusBadRequest,
			"size %d must be a multiple of this volume's block_size %d", newSize, bs)
	}
	if err := c.healIfDegraded(); err != nil {
		return false, err
	}
	if _, err := c.store.Resize(uuid, newSize); err != nil {
		return false, err
	}
	exported := len(c.attachmentsOf(uuid)) > 0
	if _, err := c.reconcile(); err != nil { // grows fd_dev_size on the live backstore
		return exported, err
	}
	return exported, nil
}

// --- host operations ---

// CreateHost creates a host with the given initiator IQNs.
func (c *Coordinator) CreateHost(iqns []string) (Host, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(iqns) == 0 {
		return Host{}, statusErr(http.StatusBadRequest, "host needs at least one initiator IQN")
	}
	seen := map[string]bool{}
	for _, q := range iqns {
		if !validIQN(q) {
			return Host{}, statusErr(http.StatusBadRequest, "invalid initiator IQN %q (must start with iqn.)", q)
		}
		if seen[q] {
			return Host{}, statusErr(http.StatusBadRequest, "duplicate initiator IQN %q in request", q)
		}
		seen[q] = true
		if owner := c.iqnOwner(q, ""); owner != "" {
			return Host{}, statusErr(http.StatusConflict, "iqn %s already owned by host %s", q, owner)
		}
	}
	uuid, err := newHostUUID()
	if err != nil {
		return Host{}, err
	}
	var created Host
	if err := c.commit(func() error {
		h := &Host{UUID: uuid, IQNs: append([]string(nil), iqns...)}
		c.st.Hosts = append(c.st.Hosts, h)
		created = *h
		return nil
	}); err != nil {
		return Host{}, err
	}
	return copyHost(created), nil
}

// ListHosts returns all hosts.
func (c *Coordinator) ListHosts() []Host {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Host, 0, len(c.st.Hosts))
	for _, h := range c.st.Hosts {
		out = append(out, copyHost(*h))
	}
	return out
}

// DeleteHost removes a host; rejected while it has attachments.
func (c *Coordinator) DeleteHost(uuid string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.host(uuid) == nil {
		return statusErr(http.StatusNotFound, "host %s not found", uuid)
	}
	for _, a := range c.st.Attachments {
		if a.HostUUID == uuid && a.Desired == "attached" {
			return statusErr(http.StatusConflict, "host %s has attachments; detach first", uuid)
		}
	}
	return c.commit(func() error {
		kept := c.st.Hosts[:0]
		for _, h := range c.st.Hosts {
			if h.UUID != uuid {
				kept = append(kept, h)
			}
		}
		c.st.Hosts = kept
		return nil
	})
}

// --- attachment operations (LUN is a caller input) ---

// Lunmap attaches a volume to a host at the caller-supplied mapped LUN.
func (c *Coordinator) Lunmap(volumeUUID, hostUUID string, lun int) (ConnInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	v, ok := c.store.Get(volumeUUID)
	if !ok {
		return ConnInfo{}, statusErr(http.StatusNotFound, "volume %s not found", volumeUUID)
	}
	if v.State != storage.Ready {
		return ConnInfo{}, statusErr(http.StatusConflict, "volume %s is %s", volumeUUID, v.State)
	}
	if c.host(hostUUID) == nil {
		return ConnInfo{}, statusErr(http.StatusNotFound, "host %s not found", hostUUID)
	}
	if lun < 0 || lun > maxLUN {
		return ConnInfo{}, statusErr(http.StatusBadRequest, "invalid lun %d (must be 0..%d)", lun, maxLUN)
	}
	for _, a := range c.st.Attachments {
		if a.Desired != "attached" {
			continue
		}
		if a.VolumeUUID == volumeUUID && a.HostUUID == hostUUID {
			return ConnInfo{}, statusErr(http.StatusConflict, "volume already mapped to this host")
		}
		if a.HostUUID == hostUUID && a.LUN == lun {
			return ConnInfo{}, statusErr(http.StatusConflict, "lun %d already in use on this host", lun)
		}
	}

	if err := c.commit(func() error {
		c.exportIndex(volumeUUID)
		c.st.Attachments = append(c.st.Attachments, &Attachment{
			VolumeUUID: volumeUUID, HostUUID: hostUUID, LUN: lun,
			Desired: "attached",
		})
		return nil
	}); err != nil {
		return ConnInfo{}, err
	}
	return ConnInfo{
		TargetIQN: c.cfg.TargetIQN,
		Portals:   c.portals(),
		LUN:       lun, Wwid: Wwid(v.WWN),
	}, nil
}

// Lununmap detaches a volume from a host.
//
// Returns a warning when the detach RELEASED A RESERVATION this host held.
// The detach still happens: an operator must always be able to unmap, not
// least because the holder may be dead and unable to release anything itself.
//
// The release is the kernel's deliberate choice. Removing a mapped LUN runs
// core_disable_device_list_for_node, which calls
// core_scsi3_free_pr_reg_from_nacl (linux v6.6
// drivers/target/target_core_device.c, target_core_pr.c), and that function is
// commented "If the passed se_node_acl matches the reservation holder, release
// the reservation" immediately above the code doing it.
//
// It is a CHOICE because the standard does not cover this case: SPC models I_T
// nexus loss, logical unit reset and power loss, while an administrative unmap
// is an array feature SCSI has no concept of. LIO chose release; other
// implementations are reported to retain the registration and require an
// explicit clear. Where a choice has to be made, ours is to let the operation
// proceed and to say plainly what it cost.
//
// MEASURED on the lab: with A holding a reservation and B fenced (write
// refused, errno 52), detaching A let B write immediately, and re-attaching A
// did NOT restore the reservation -- saved records are only replayed when a
// backstore is CREATED, and the backstore survived because B was still
// attached. So the effect is permanent, not a window.
//
// This project's rule is that it may over-fence but never under-fence, and
// this path under-fences. It cannot be refused and the kernel cannot be
// talked out of it, so the guarantee that remains is weaker than the rule:
// the operator is TOLD, immediately and by name, rather than discovering it
// when two nodes write to one filesystem.
func (c *Coordinator) Lununmap(volumeUUID, hostUUID string) (warning string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	found := false
	for _, a := range c.st.Attachments {
		if a.VolumeUUID == volumeUUID && a.HostUUID == hostUUID {
			found = true
			break
		}
	}
	if !found {
		return "", statusErr(http.StatusNotFound, "attachment not found")
	}
	// Read the holder BEFORE the detach, because afterwards there is nothing
	// left to read: the registration is gone and the reservation with it.
	warning = c.fenceLossWarning(volumeUUID, hostUUID)
	// Log it here rather than after commit. A reconcile failure inside commit
	// arrives AFTER the mutation is durable -- commit's own contract is that a
	// reconcile failure "is reported but not rolled back (the db is the source
	// of truth; startup replay re-reconciles)". So on that path the detach
	// still happens, the reservation is still released, and returning early
	// with only the error would drop the one signal this whole function
	// exists to produce, on the path where an operator is least likely to go
	// looking because something else already went wrong.
	if warning != "" {
		log.Printf("WARNING: %s", warning)
	}
	if err := c.commit(func() error {
		kept := c.st.Attachments[:0]
		for _, a := range c.st.Attachments {
			if a.VolumeUUID == volumeUUID && a.HostUUID == hostUUID {
				continue
			}
			kept = append(kept, a)
		}
		c.st.Attachments = kept
		c.pruneExports()
		return nil
	}); err != nil {
		// Return the warning WITH the error. The caller renders both.
		return warning, err
	}
	return warning, nil
}

// fenceLossWarning reports whether detaching this host will release a
// reservation it holds, and returns the text to hand back to the caller.
//
// Best-effort and never fatal: this is a report channel, and failing an unmap
// because the reservation state could not be read would trade a real operation
// for a diagnostic. An unreadable holder simply yields no warning, which is
// the same outcome as no reservation -- an acceptable loss for a signal, and
// the reason this is not the only place the condition is reported.
func (c *Coordinator) fenceLossWarning(volumeUUID, hostUUID string) string {
	v, ok := c.store.Get(volumeUUID)
	if !ok {
		return ""
	}
	// Find the backstore through desiredLIO rather than reconstructing one.
	//
	// An earlier version built lio.Backstore{Type: FileIO, Name: ..., HBA: 0}
	// by hand, and HBA is an allocated INDEX, not a constant -- so on any
	// volume that did not happen to land on fileio_0 it read a different
	// object's reservation state, or none, and warned about nothing. The unit
	// test did not catch it because the fixture staged the volume at fileio_0
	// too: the test agreed with the bug. Only the live run exposed it.
	//
	// Asking desiredLIO means the lookup is by construction the same object
	// the reconcile manages.
	name := backstoreName(v.UUID)
	var bs *lio.Backstore
	desired := c.desiredLIO()
	for i := range desired.Backstores {
		if desired.Backstores[i].Name == name {
			bs = &desired.Backstores[i]
			break
		}
	}
	if bs == nil {
		return ""
	}
	res, err := c.lio.ReservationHolder(*bs)
	if err != nil {
		// Not silence. This used to return "" on any error, so an
		// uninterpretable res_holder produced the same outcome as "no
		// reservation is held": the operator unmapped and was told nothing,
		// in the one moment where they most needed to know that fencing might
		// be dropping. Say that we cannot tell instead -- a warning that
		// turns out to be unnecessary costs an operator a second look, and
		// the silence costs them the fence.
		return fmt.Sprintf(
			"whether a SCSI-3 reservation protects this volume could NOT be determined (%v), "+
				"so it is unknown whether this unmap released one; verify fencing before "+
				"relying on it", err)
	}
	if res.Holder == "" {
		return ""
	}
	// An SPC-2 reservation lives in dev->reservation_holder, which
	// core_scsi3_free_pr_reg_from_nacl never touches (linux v6.6
	// drivers/target/target_core_pr.c:1342-1377). res_holder renders it
	// through the same " Initiator: " shape as a SCSI-3 one
	// (target_core_configfs.c:1804), so without this check the warning would
	// name a persistent reservation that is not one and claim a release that
	// does not happen.
	if res.SPC2 {
		return ""
	}
	var host *Host
	for _, h := range c.st.Hosts {
		if h.UUID == hostUUID {
			host = h
			break
		}
	}
	if host == nil || !slices.Contains(host.IQNs, res.Holder) {
		// Detaching a NON-holder is safe: it removes that host's access,
		// which over-fences rather than under-fencing, and leaves the
		// reservation protecting whoever remains.
		return ""
	}
	// ALL REGISTRANTS types TRANSFER rather than release: removing the holder
	// enters __core_scsi3_complete_pro_release with unreg=1, which promotes
	// the next registration (linux v6.6
	// drivers/target/target_core_pr.c:2463-2478). The fence survives, so
	// warning here would be a false alarm -- and a warning that fires when
	// nothing was lost trains an operator to ignore the one that matters.
	// lio/aptpl_test.go's TestAPTPLLapsedHolderSilentWhenReservationTransferred
	// is the same reasoning applied to the sibling APTPL report.
	if res.AllRegistrants() {
		return ""
	}
	// Whether the release is permanent depends on whether the backstore
	// survives the detach, which it does only if some OTHER host is still
	// attached. If this is the last attachment, pruneExports drops the export,
	// reconcile removes the backstore, and creating it again replays the saved
	// APTPL records (loadAPTPL, before enable) -- so the reservation can come
	// back on a later attach. Both are fence loss NOW; they differ in whether
	// re-attaching undoes it, and saying the wrong one is a claim the code did
	// not establish.
	others := 0
	for _, a := range c.st.Attachments {
		if a.VolumeUUID == volumeUUID && a.HostUUID != hostUUID {
			others++
		}
	}
	restores := "re-attaching does not restore it, because saved records are " +
		"replayed only when a backstore is CREATED and this one survives the detach"
	if others == 0 {
		restores = "this was the last attachment, so the backstore is removed and a " +
			"later attach will recreate it and replay the saved records -- the " +
			"reservation may return, which is its own surprise"
	}
	return fmt.Sprintf("detaching host %s from volume %s RELEASED the SCSI-3 "+
		"reservation it held (%s, type: %s). Initiators this reservation was fencing "+
		"can write to the volume NOW, and %s. The kernel releases a reservation whose "+
		"holder loses its mapped LUN (core_scsi3_free_pr_reg_from_nacl, linux v6.6 "+
		"drivers/target/target_core_device.c:454); the unmap was not refused because "+
		"an operator must be able to detach a host that may itself be dead. Detaching "+
		"also frees every OTHER registration this host held on the volume, so a "+
		"preempt-based recovery may have lost the registration it needed. If the "+
		"volume is still in use by a cluster, re-establish fencing before allowing "+
		"writes",
		hostUUID, volumeUUID, res.Holder, resTypeOrUnknown(res.Type), restores)
}

func resTypeOrUnknown(t string) string {
	if t == "" {
		return "could not be read"
	}
	return t
}

// Target returns the appliance's target IQN and its portals.
//
// Portals carry their own ports. There is deliberately no separate port
// return value: one existed, and it asserted that every portal shared it.
func (c *Coordinator) Target() (string, []lio.Portal) {
	// portals() reads c.st.Portals and its contract says the caller must hold
	// c.mu. This did not, while SetPortals writes that same field under the
	// lock -- and net/http serves every request on its own goroutine, so a GET
	// racing a PUT read a slice header being replaced. Every sibling accessor
	// (ListHosts, Lunmap) locks; this was the outlier, and -race stayed green
	// only because no test drove the two concurrently.
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg.TargetIQN, c.portals()
}

// SetPortals replaces the target's portal list.
//
// Portals are the fabric's shape, and changing them is exactly what an
// orchestrator needs to do without editing a systemd unit and restarting. The
// new list becomes the durable record; the -portals flag is only a bootstrap
// default (see adoptPortals).
//
// Ordering is deliberately NOT this function's business. Everything else in
// this package adds before it removes so there is never a window with the
// object missing, but portals cannot work that way: a wildcard will not bind
// while any other address holds its port, so the wildcard cases are strictly
// prune-then-add. lio.Sync already encodes that, and re-implementing any of it
// here would give two orderings that can disagree.
func (c *Coordinator) SetPortals(portals []lio.Portal) ([]lio.Portal, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// An empty list is the one change that cannot be undone through this API:
	// it takes away every address the target answers on, and this endpoint is
	// reached over a DIFFERENT socket, so the caller would keep its connection
	// and still have bricked the fabric.
	if len(portals) == 0 {
		return nil, statusErr(http.StatusBadRequest,
			"refusing to remove every portal: the target would answer on no "+
				"address and could not be reached to fix it")
	}

	// Validate against the same rules startup uses, so a set that would fail
	// replay can never be persisted. Config.Validate rejects duplicates by
	// address+port and malformed entries.
	next := Config{TargetIQN: c.cfg.TargetIQN, Portals: portals}
	if err := next.Validate(); err != nil {
		return nil, statusErr(http.StatusBadRequest, "%v", err)
	}

	prev := slices.Clone(c.st.Portals)
	if samePortalSet(prev, portals) {
		// Nothing to do. Returning early keeps a no-op request from bouncing
		// the fabric: the reconciler would prune and re-add nothing, but a
		// caller polling this endpoint should not be able to cause churn.
		return c.portals(), nil
	}

	if err := c.commit(func() error {
		c.st.Portals = slices.Clone(portals)
		return nil
	}); err != nil {
		// commit rolls the db back for anything up to and including persist.
		// A reconcile failure is NOT rolled back -- the record is the source
		// of truth and startup replay re-reconciles -- so say which happened,
		// because the two need different operator responses.
		if samePortalSet(c.st.Portals, prev) {
			return nil, statusErr(http.StatusConflict,
				"portal change rejected, portals unchanged (%s): %v",
				portalsText(prev), err)
		}
		return nil, statusErr(http.StatusConflict,
			"portals are now recorded as %s but the kernel did not accept them "+
				"(%v). The record is authoritative and will be retried on "+
				"restart; set a working list to recover", portalsText(portals), err)
	}
	// Adopting a new list makes any disagreement with the boot flag moot: the
	// operator has just said what they want through the API.
	//
	// healthMu, not mu (which this already holds): the field is published to
	// /health and read under healthMu. Lock order is mu -> healthMu
	// throughout, so taking it here is consistent with publishReconcile.
	c.healthMu.Lock()
	c.portalFlagIgnored = ""
	c.healthMu.Unlock()
	log.Printf("appliance: portals set to %s (were %s)",
		portalsText(portals), portalsText(prev))
	return c.portals(), nil
}
