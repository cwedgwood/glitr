package appliance

import (
	"errors"
	"log"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/cwedgwood/glitr/lio"
)

// slowReconcile is the threshold above which a reconcile logs its phase
// breakdown. Chosen to be quiet in normal operation on a small tree while
// still surfacing the O(n) growth that shows up with a few dozen exports.
const slowReconcile = 100 * time.Millisecond

// slowCommit is the threshold for logging the persist/reconcile split of a
// mutation. This is the window that serialises concurrent callers, so when it
// is unusually long it is worth knowing which half is responsible. Set well
// above normal operation (measured: persist 2-4ms, reconcile 45-60ms) so it
// reports outliers rather than narrating every request; lower it temporarily
// when profiling.
const slowCommit = 250 * time.Millisecond

// backstoreName is the LIO backstore name for a volume: "vol_" + the
// volume UUID's 32 hex digits (dashes stripped). The FULL uuid is used —
// truncating it risks two volumes colliding on a duplicate backstore name,
// which lio.Validate rejects and would fail the reconcile.
func backstoreName(volumeUUID string) string {
	return "vol_" + strings.ReplaceAll(volumeUUID, "-", "")
}

// Wwid returns the initiator-visible device wwid derived from a volume's
// wwn (LIO NAA: 0x6001405 + <16-hex wwn> + zero-pad to 32 hex), or "" if wwn
// is not a 16-hex-digit value.
//
// The guard matters because the result is what an initiator matches a device
// by. Without it Wwid("") returned "0x6001405000000000" -- a structurally
// invalid designator that still LOOKS like one, so a caller comparing against
// it would silently never match, or worse, match a different volume built the
// same way.
func Wwid(wwn string) string {
	if len(wwn) != 16 {
		return ""
	}
	for _, r := range wwn {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return ""
		}
	}
	return "0x6001405" + wwn + "000000000"
}

// desiredLIO translates the whole appliance desired state into an
// lio.Config (one target, one TPG). Caller must hold c.mu.
func (c *Coordinator) desiredLIO() lio.Config {
	// Volumes that are exported (have ≥1 attached attachment) AND ready.
	exported := map[string]bool{}
	for _, cn := range c.st.Connections {
		if o := c.object(cn.ObjectUUID); o != nil && o.State == stateReady {
			exported[cn.ObjectUUID] = true
		}
	}

	tpg := lio.TPG{
		Tag:    1,
		Enable: true,
		Attributes: map[string]string{
			"generate_node_acls":      "0",
			"authentication":          "0",
			"demo_mode_write_protect": "0",
		},
	}
	tpg.Portals = c.portals()

	var cfg lio.Config
	for vol := range exported {
		v := c.object(vol)
		// Allocate through exportIndex, never a bare map read: a missing entry
		// would otherwise silently become TPG LUN 0 and collide with whichever
		// volume legitimately holds index 0. Safe to allocate here — desiredLIO
		// is only called with c.mu held.
		idx := c.exportIndex(vol)
		name := backstoreName(vol)
		// Floor the size to a whole number of blocks.
		//
		// The kernel derives the last LBA as (size - block_size)/block_size
		// (linux v6.6 drivers/target/target_core_file.c:804-822), so it serves
		// the floored figure whatever it is told. Volumes created through the
		// current API are already aligned (Store.Create and Store.Resize both
		// refuse otherwise); this is for LEGACY records written before any
		// alignment rule existed, whose capacity can be a partial block.
		//
		// Flooring HERE rather than rewriting the durable record is
		// deliberate -- see the note in storage.Store.repair, where doing it
		// the other way produced two separate crash loops.
		//
		// The result is always at least one block: Store.load refuses a
		// record whose capacity is smaller than its block size, because that
		// is not a volume the kernel could present at all.
		bs := int64(v.BlockSize)
		size := v.Capacity - v.Capacity%bs
		cfg.Backstores = append(cfg.Backstores, lio.Backstore{
			Type: lio.FileIO, HBA: idx, Name: name,
			Dev: c.store.DiskPath(vol), WWN: v.WWN, Size: size,
			BufferedIO: c.cfg.WriteBack,
			// Always emitted, never omitted-when-default: lio writes managed
			// attributes and re-enforces them on reconcile, so stating 512
			// explicitly is what keeps a pre-existing volume pinned to the
			// geometry its initiator already has, rather than leaving it
			// unmanaged and open to drift.
			Attributes: map[string]string{
				"block_size": strconv.Itoa(v.BlockSize),
				// 0 means "no optimal transfer size advertised".
				//
				// We set it not because 0 is a measured optimum, but because
				// the value LIO would otherwise leave is provably wrong at
				// 4Kn and we have no concrete, validated figure to put in its
				// place. Choosing 0 buys CONSISTENCY between geometries
				// instead of round-tripping a number that is wrong in one of
				// them.
				//
				// What LIO does by default: optimal_sectors is copied from
				// hw_max_sectors at device configure (linux v6.6
				// drivers/target/target_core_device.c:948), and for fileio
				// hw_max_sectors is FD_MAX_BYTES/fd_block_size = 8MiB/512 =
				// 16384 (target_core_file.c:196) -- fd_block_size being 512
				// for any regular file. That 8MiB is a VFS ceiling (2048
				// iovecs x PAGE_SIZE), not a storage optimum.
				//
				// The Block Limits VPD then rescales MAXIMUM but not OPTIMAL
				// (target_core_spc.c:552-563): maximum is
				// mult_frac(hw_max_sectors, hw_block_size, block_size) while
				// optimal is emitted raw. At block_size=4096 that advertises
				// an optimal transfer of 16384 blocks (64MiB) against a
				// maximum of 2048 blocks (8MiB) -- an optimum larger than the
				// maximum. Linux rejects it and logs a warning on every
				// attach, leaving io_opt=0; at 512n the same number happens to
				// be self-consistent and is accepted as 8MiB, so parted then
				// calls a conventional 1MiB partition "not aligned".
				//
				// So the default is not merely arbitrary, it is inconsistent
				// BETWEEN the two geometries we support. Save-and-restore of
				// the raw attribute cannot fix it either -- it preserves the
				// wrong value rather than correcting it, which is why this is
				// decided here. With 0, both geometries advertise nothing,
				// consumers fall back to their own 1MiB convention, and the
				// kernel warning goes away.
				//
				// Revisit if a real optimal transfer size is ever measured.
				//
				// On UPGRADE: a volume created before this was managed carries
				// the kernel default (16384) and is exported, so the kernel
				// refuses to change it and the reconcile reports drift rather
				// than failing. That is not permanent. configfs is kernel
				// memory, so the backstore is recreated from the db on the
				// next boot and takes 0 then -- an upgraded fleet converges on
				// its next reboot, not never. Measured; see lio.Report.Drift.
				"optimal_sectors": "0",
				// Advertised write cache, welded to the backing mode above.
				//
				// These two MUST move together. The kernel lets them diverge:
				// measured on Azure Linux 3.0 (kernel 6.6.144.1),
				// fd_buffered_io=1 sets this to 1 and it can then be forced
				// back to 0 on the live object -- acknowledging writes from
				// volatile page cache while telling the initiator there is
				// nothing to flush. That loses acknowledged data on power
				// loss and leaves the consumer no way to defend itself.
				//
				// Deriving both from one appliance-level setting makes that
				// combination unrepresentable at create time; because the
				// backing mode is create-time only while this attribute is
				// mutable, lio additionally holds this to the live mode on
				// reconcile (see lio's constrainWriteCache) so a restart with
				// a changed setting cannot construct it either. Managed
				// explicitly rather than left at the kernel default so the
				// value is enforced on every reconcile and any divergence
				// shows up as drift.
				"emulate_write_cache": boolAttr(c.cfg.WriteBack),
				// Thin provisioning. The backing file is sparse either way;
				// these two decide whether the initiator is TOLD, and so
				// whether it can hand space back. Managed rather than left at
				// the kernel default (which is off) for the same reason as
				// emulate_write_cache: enforced on every reconcile, and any
				// divergence shows up as drift.
				//
				// emulate_tpws is WRITE SAME with the UNMAP bit -- how a guest
				// zeroes a large range without writing zeroes. Paired with tpu
				// deliberately: advertising one without the other gives a
				// device that can discard but not zero efficiently, or the
				// reverse, and no guest expects that combination.
				//
				// unmap_zeroes_data (LBPRZ) is deliberately NOT set here. It
				// promises that a discarded region reads back as zeros, which
				// is true of a hole in a sparse file -- MEASURED -- but it is
				// a promise about every future backing store, and the safe
				// direction for a promise is to under-claim.
				"emulate_tpu":  boolAttr(!c.cfg.NoUnmap),
				"emulate_tpws": boolAttr(!c.cfg.NoUnmap),
			},
		})
		tpg.LUNs = append(tpg.LUNs, lio.LUN{Index: idx, Backstore: name})
	}

	// One NodeACL per host IQN (host lifecycle), carrying that host's
	// mapped LUNs — so a host with zero attachments still gets an ACL and
	// can log in.
	for _, h := range c.st.Hosts {
		var mls []lio.MappedLUN
		for _, cn := range c.st.Connections {
			if cn.HostUUID == h.UUID && exported[cn.ObjectUUID] {
				mls = append(mls, lio.MappedLUN{Index: cn.LUN, TPGLUN: c.st.Exports[cn.ObjectUUID]})
			}
		}
		for _, iqn := range h.Bindings.IQNs {
			tpg.ACLs = append(tpg.ACLs, lio.ACL{InitiatorIQN: iqn, MappedLUNs: mls})
		}
	}

	cfg.Targets = []lio.Target{{IQN: c.cfg.TargetIQN, TPGs: []lio.TPG{tpg}}}
	return cfg
}

// reconcile drives the kernel to the current desired state.
//
// It reconciles INCREMENTALLY where it can: the appliance already knows what
// the desired state was and what it is now, so it can apply just the
// difference instead of re-walking every object. That matters because a full
// reconcile is O(objects in the tree) and runs on every mutation, so without
// this a single-volume operation gets steadily slower as unrelated volumes
// are added — measured at ~0.75ms per exported volume, so 165ms for a lunmap
// on a 200-volume tree, almost all of it spent on volumes the request did not
// touch.
//
// The full reconcile remains the authority and still runs whenever the
// incremental path cannot be trusted:
//
//   - at startup, when nothing is known about the live tree;
//   - when the change is not expressible as a delta (Diff reports !ok);
//   - after any failure, because a partially applied delta leaves the tree in
//     a state the cached view no longer describes;
//   - when healing a degraded appliance.
//
// The cached view is only ever a belief about what was applied. It is
// discarded on error rather than repaired, so the next reconcile rediscovers
// reality rather than compounding a wrong assumption.
//
// Caller must hold c.mu.
func (c *Coordinator) reconcile() (lio.Report, error) {
	desired := c.desiredLIO()

	if c.applied == nil {
		return c.reconcileFull(desired)
	}
	delta, ok := lio.Diff(*c.applied, desired)
	if !ok {
		return c.reconcileFull(desired)
	}

	rep, err := c.lio.ApplyDelta(desired, delta)
	if err != nil {
		if errors.Is(err, lio.ErrStaleScope) {
			// The live tree is not what we believed, so there is nothing to
			// retry incrementally: fall back to the authority rather than
			// reporting a failure the full path would have handled. This is
			// what preserves self-healing if the kernel tree is lost from
			// under a running daemon.
			log.Printf("incremental reconcile refused (%v); falling back to a full reconcile", err)
			c.applied = nil
			return c.reconcileFull(desired)
		}
		// The tree no longer matches the cached view; force a full reconcile
		// next time rather than diffing against a belief we know is wrong.
		c.applied = nil
		c.setReconcileErr(err)
		return rep, err
	}
	// Establish every fact BEFORE publishing any of it. Both of these walk
	// configfs, which blocks in the kernel with no timeout, and publishing
	// success first would leave /health pairing a fresh "ok" with the
	// previous generation's warnings for the duration -- see
	// publishReconcile.
	//
	// Sync verifies APTPL itself; the incremental path must do it explicitly
	// or the pr_unbound signal goes stale.
	unbound := c.lio.VerifyAPTPL(desired)
	// Same traversal, same moment: a stranded reservation is only meaningful
	// against the tree that was just reconciled.
	stranded := strandedText(c.lio.StrandedReservations(desired))
	// Drift is re-derived, NOT taken from rep: ApplyDelta only visits
	// backstores whose desired config changed, so rep.Drift covers that
	// subset while drift is a standing condition covering the whole tree.
	// Publishing the delta's view would erase the standing one -- see
	// lio.VerifyDrift. Exactly the staleness the line above guards against
	// for pr_unbound.
	drift := c.lio.VerifyDrift(desired)

	c.lastReconcileErr = nil
	c.applied = appliedView(desired, drift)
	c.publishReconcile(nil, unbound, stranded, drift)
	c.logSlow(rep, "incremental")
	return rep, nil
}

// reconcileFull runs the authoritative full-tree reconcile and refreshes the
// cached view of what is applied. Caller must hold c.mu.
func (c *Coordinator) reconcileFull(desired lio.Config) (lio.Report, error) {
	rep, err := c.lio.Sync(desired)
	c.lastReconcileErr = err
	if err != nil {
		c.applied = nil
		// A failed Sync established nothing about fencing or drift, so the
		// previous generation's warnings stand rather than being replaced
		// with a partial report. Degraded is the loud direction anyway.
		c.publishReconcileFailure(err)
		c.logSlow(rep, "full")
		return rep, err
	}
	c.applied = appliedView(desired, rep.Drift)
	// Sync visits every desired backstore, so its report IS the whole-tree
	// view here; only the incremental path needs re-derivation. Published as
	// one generation under a single lock -- see publishReconcile.
	c.publishReconcile(nil, rep.APTPLUnbound, strandedText(c.lio.StrandedReservations(desired)), rep.Drift)
	c.logSlow(rep, "full")
	return rep, err
}

func (c *Coordinator) logSlow(rep lio.Report, kind string) {
	if rep.Timings.Total() > slowReconcile {
		log.Printf("slow %s reconcile: %s (%d exported volume(s))",
			kind, rep.Timings, len(c.st.Exports))
	}
}

// appliedView is the desired config with every drifted attribute set back to
// the value the kernel actually holds -- what was APPLIED, as opposed to what
// was asked for.
//
// c.applied is the delta engine's picture of the live tree: Diff compares the
// next desired config against it and visits only what changed. Caching the
// desired config after a reconcile that SKIPPED an immutable attribute records
// a convergence that did not happen, and the consequence is not merely
// cosmetic -- the backstore then matches the cache on every subsequent Diff,
// so it is never revisited, and if the attribute later becomes writable the
// engine has no reason to try again.
//
// With the live value cached instead, the drifted backstore differs from
// desired on every pass, so each reconcile retries exactly that one object.
// While the kernel keeps refusing, the retry costs one attribute write that
// fails; the moment the volume is unexported and the attribute becomes
// mutable, it converges on its own.
//
// This state is currently unreachable through the appliance -- desiredLIO
// emits a backstore only together with its TPG LUN, so "desired but
// unexported" does not arise (see TestBackstorePresenceImpliesExport). The fix
// is here anyway because the engine should record what it did rather than what
// it intended, and because that invariant is a property of one caller, not of
// the cache.
func appliedView(desired lio.Config, drift []lio.AttrDrift) *lio.Config {
	if len(drift) == 0 {
		return &desired
	}
	live := map[string]map[string]string{}
	for _, d := range drift {
		if d.Err != nil {
			// The live value is UNKNOWN, not observed. Caching the empty
			// string as if it were applied would make the appliance report a
			// value the kernel never confirmed -- the opposite of what this
			// cache exists to do.
			continue
		}
		if live[d.Backstore] == nil {
			live[d.Backstore] = map[string]string{}
		}
		live[d.Backstore][d.Attr] = d.Live
	}
	out := desired
	out.Backstores = make([]lio.Backstore, len(desired.Backstores))
	copy(out.Backstores, desired.Backstores)
	for i, b := range out.Backstores {
		patch, ok := live[b.Name]
		if !ok {
			continue
		}
		// Copy the map before writing: the caller's desired config must not
		// be mutated, and these two values are about to be compared.
		attrs := make(map[string]string, len(b.Attributes))
		maps.Copy(attrs, b.Attributes)
		maps.Copy(attrs, patch)
		out.Backstores[i].Attributes = attrs
	}
	return &out
}

// boolAttr renders a configfs boolean attribute.
func boolAttr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
