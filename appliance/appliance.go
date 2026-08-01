// Package appliance is a control plane: it exposes stored volumes over iSCSI
// and serves a REST API. It owns hosts, attachments and the target/portal
// configuration, and reaches the kernel only through the lio library and the
// bytes only through the storage package.
//
// It is a worked example of building on those libraries rather than a product,
// and is deliberately small enough to read end to end. The parts worth
// borrowing are the reconcile discipline below and the fencing behaviour, not
// the particular REST shape or object model.
//
// The appliance is the single writer of the LIO tree. Every mutation
// takes the coordinator lock, updates the durable db, then reconciles the
// kernel by translating the whole desired state into an lio.Config and
// calling into lio (an incremental delta where possible, a full Sync
// otherwise) — so the kernel always matches
// the db, and startup replay is the same reconcile.
package appliance

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cwedgwood/glitr/lio"
	"github.com/cwedgwood/glitr/storage"
)

// newHostUUID returns a fresh canonical v4 UUID string, or an error if the
// system CSPRNG fails (never fall back to a zero/duplicate UUID).
func newHostUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

// Config is the appliance-wide configuration (one target, one TPG).
type Config struct {
	TargetIQN string `json:"target_iqn"`
	// Portals are the addresses the target listens on, EACH WITH ITS OWN
	// PORT.
	//
	// This used to be []string beside a single Port, which quietly asserted
	// that every portal shares one port. It does not: iSCSI defines a portal
	// as an endpoint, not an address. RFC 3720 renders a TargetAddress as
	// <address>[:<port>],<portal-group-tag> -- the port belongs to the
	// portal and the TAG is what groups them -- SendTargets returns
	// "10.0.0.1:3260,1" per portal, and the kernel names each one
	// np/<ip>:<port>. lio.Portal modelled this correctly all along; the
	// flattening was introduced here, one layer up, and lost information the
	// layer below had right.
	Portals []lio.Portal `json:"portals"`
	// DBRoot is the kernel target database root (configfs "dbroot",
	// normally /var/target), where LIO persists SCSI-3 PR APTPL metadata as
	// pr/aptpl_<wwn>. Used to discard a volume's saved reservations when the
	// volume itself is deleted. Empty disables that cleanup.
	DBRoot string `json:"db_root"`

	// WriteBack makes volumes use the fileio backend's buffered mode: writes
	// are acknowledged from the page cache instead of going straight to
	// stable storage, and the device advertises a volatile write cache
	// (WCE=1) so consumers know they must flush.
	//
	// OFF by default, and that default is the product position rather than a
	// tuning preference. A hardware array that advertises a write cache backs
	// it with battery or NVRAM, so the write survives power loss; ours would
	// be plain page cache in volatile host RAM. SCSI has one bit for both
	// cases, so an initiator cannot tell them apart -- which makes WCE=1 here
	// technically honest and practically misleading. Most vendors do not
	// offer the choice at all, for exactly that reason.
	//
	// It exists because this appliance is also a development and test target,
	// where losing a scratch volume to a power cut costs nothing. Anything
	// that must be trusted should leave it off.
	//
	// OFF BY DEFAULT, WHICH MAY BE A SURPRISE: buffered write-back is a
	// common default for fileio backstores elsewhere, so an operator can
	// easily have been running with WCE=1 without ever choosing it. This
	// defaults the other way, because a device that acknowledges writes it
	// has not stored is not something a consumer can build a cluster on, and
	// the choice is invisible from the initiator side -- the write simply
	// succeeds either way, and only a power cut tells you which you had.
	// -write-back is there when buffered really is what is wanted.
	//
	// Measured, and the result is not the obvious one: write-back was
	// substantially faster for small writes that never ask for durability,
	// and substantially SLOWER for small writes that do. With WCE=0 the write
	// IS the durability, one operation; with WCE=1 it becomes a write plus a
	// SYNCHRONIZE CACHE that has to push out the data the write just
	// deferred. Sequential throughput, mkfs and mount showed no difference
	// that survived the noise.
	//
	// So write-back is not simply "the fast option". It is faster only for
	// consumers that never flush -- and filesystems and databases flush.
	//
	// Deliberately no figures here: they were taken on one lab whose backing
	// store is a copy-on-write pool tuned to trade durability for throughput,
	// so O_DSYNC at this layer never reached stable media in the sense the
	// test implied. They would not transfer to anyone else's hardware and
	// quoting them would lend them an authority they have not earned. Measure
	// on the storage you actually have, with the durability flags you intend
	// to use, before believing any number in this area.
	//
	// Appliance-wide, not per-volume: the mode is fixed when a backstore is
	// created, so a per-volume knob would produce a fleet whose durability
	// varies by creation order.
	WriteBack bool `json:"write_back"`
}

// Host is a first-class client object carrying one or more initiator IQNs
// (its NodeACL lifecycle == host lifecycle).
type Host struct {
	UUID string   `json:"uuid"`
	IQNs []string `json:"iqns"`
}

// Attachment maps a volume to a host at a caller-supplied LUN.
type Attachment struct {
	VolumeUUID string `json:"volume_uuid"`
	HostUUID   string `json:"host_uuid"`
	LUN        int    `json:"lun"`     // caller-supplied mapped LUN
	Desired    string `json:"desired"` // "attached" | "detached"
}

// There is deliberately no observed-State field here.
//
// One existed, declared as "pending | applying | ready | failed", persisted in
// appliance.json, and written exactly once -- as the literal "ready", at
// creation. Nothing ever read it and nothing ever advanced it. A field that
// advertises a four-state machine while only ever holding one value is worse
// than an absent one: it tells a reader, and any API that exposes the record,
// that reconcile progress is tracked per attachment when it is not.
//
// The appliance does not work that way. Desired state is declarative and the
// whole configuration is reconciled to the kernel at once, so "has this
// attachment been applied" is not a per-record property -- it is answered by
// the reconcile's own result and by /health. Removing the field is
// backward-compatible: encoding/json ignores the key in already-written
// records, so old appliance.json files load unchanged and simply stop carrying
// it forward.

// dbState is the appliance's persisted record set (hosts/attachments/
// export indexes). Storage volumes live in the storage package's store.
type dbState struct {
	Hosts       []*Host        `json:"hosts"`
	Attachments []*Attachment  `json:"attachments"`
	Exports     map[string]int `json:"exports"` // volume uuid -> TPG LUN index
	// Portals is the DURABLE record of what the target listens on.
	//
	// It used to live only in Config, i.e. only in the -portals flag, which
	// made the systemd unit the record and put the fabric's shape outside the
	// control plane: an orchestrator could not change a multipath topology
	// without editing a unit file and restarting.
	//
	// Empty means "not recorded", and is read as "adopt the flag" rather than
	// as "no portals" -- same shape as storage.Volume.BlockSize, where zero
	// means the historical default rather than "unmanaged". Open() backfills
	// it once so that unrecorded stops existing rather than being
	// reinterpreted at every call site.
	//
	// NOT omitempty: a reader has to be able to tell "recorded, and this is
	// the list" from "never recorded", and omitting it for exactly the
	// pre-existing appliances being adopted would erase that distinction.
	Portals []lio.Portal `json:"portals"`
}

// Coordinator is the single-writer control plane.
type Coordinator struct {
	mu     sync.Mutex
	store  *storage.Store
	lio    *lio.Manager
	cfg    Config
	dbPath string
	st     dbState
	// applied is the desired config the kernel was last successfully
	// reconciled to, and is what an incremental reconcile diffs against. nil
	// means "unknown" -- at startup, or after any failure -- which forces the
	// next reconcile to be a full one. Guarded by mu.
	applied *lio.Config
	// portalFlagIgnored is set when the -portals flag disagrees with the
	// durable record, so /health can say so.
	//
	// Guarded by healthMu, NOT mu, because /health is its only reader and
	// health must stay answerable while mu is held across an uncancellable
	// configfs reconcile. It was declared "Guarded by mu" while
	// HealthSnapshot read it under healthMu -- a write and a read under
	// different locks, which is a race whether or not it is observed.
	portalFlagIgnored string
	// prStranded holds reservations that are in effect but unaddressable by
	// their holder. Published alongside prUnbound so a reader cannot see one
	// without the other, and stored as text because it is a report.
	// Guarded by healthMu.
	prStranded []string
	// prUnbound holds restored SCSI-3 PR registrations that did not bind.
	// Guarded by healthMu.
	prUnbound []string
	// drift holds managed attributes that could not be converged because the
	// kernel makes them immutable while the volume is exported. Guarded by
	// healthMu. Kept out of Changes-style logging on purpose: this is a
	// standing condition, not an event, and the daemon is the only place it
	// can be observed -- lio reports it, and before this nothing consumed it.
	drift []string
	// lastReconcileErr records the outcome of the most recent reconcile. A
	// non-nil value means the kernel LIO tree may not match the durable db
	// (a post-commit reconcile failed); the appliance is "degraded" until a
	// reconcile succeeds. Written under mu; read either under mu or — for
	// /health — under healthMu alone, because mu is held across an
	// uncancellable configfs reconcile and health must stay answerable
	// exactly when a reconcile is wedged in the kernel.
	lastReconcileErr error
	healthMu         sync.Mutex
	healthErr        error
	// prCheckedAt is when prUnbound was last recomputed. Guarded by
	// healthMu. Reported so an operator can tell "no PR problem" from "no
	// PR check has succeeded recently".
	prCheckedAt time.Time
}

// Health is a single consistent view of the appliance's health.
//
// It exists because /health used to take two separate lock acquisitions --
// Healthy() then PRUnbound() -- and a reconcile landing between them could
// pair an older healthy verdict with a newer warning, or the reverse.
type Health struct {
	// Degraded means the kernel tree may not match the durable db.
	Degraded bool
	// Detail explains Degraded.
	Detail string
	// PRUnbound names saved SCSI-3 PR state that is not in effect.
	PRUnbound []string

	// PRStranded names reservations that ARE in effect but whose holder can
	// no longer address them, because its session identifier rotated.
	//
	// Deliberately separate from PRUnbound, and deliberately not "degraded".
	// Those signals mean a reservation someone relies on is NOT protecting
	// them; this one means the opposite -- the reservation is protecting them
	// and will not stop. It over-fences rather than failing open, so the
	// appliance is not unhealthy. What an operator needs to know is that the
	// holder cannot lift it and that waiting is futile. The recovery is in
	// each report's own text, because preemption is NOT always available: on
	// the lab both registrations were stranded at once, so nothing could
	// locate a registration to preempt with.
	PRStranded []string
	// Drift names managed attributes the kernel refused to change because
	// the volume is exported. See lio.Report.Drift.
	Drift []string
	// BackupErr reports that the record-db backups are not being maintained,
	// which turns the documented lost-db recovery into no recovery.
	BackupErr string
	// RejectedRecords names db records that failed validation and were
	// excluded from the live volume set. DEGRADED: those volumes are not
	// exported, so an initiator that expects one finds nothing.
	//
	// This is the channel the old behaviour did not have. A malformed record
	// used to fail Open, which exited applianced, which systemd restarted
	// every 2s -- so the one interface that could have explained the problem
	// was the one guaranteed to be down. Serving the healthy volumes is only
	// half the fix; being able to say what was dropped is the other half.
	RejectedRecords []storage.RejectedRecord

	// Quarantined names volume dirs startup repair set aside because the db
	// had no record of them. Their data is intact; reclaiming or re-recording
	// them is an operator decision. See storage.Store.Quarantined.
	Quarantined []string
	// CheckedAt is when PRUnbound was last recomputed; zero if never.
	CheckedAt time.Time
	// PortalFlagIgnored is set when the -portals flag disagrees with the
	// durable record. Not an error -- the record wins by design -- but an
	// operator who edited the unit file and restarted needs to be told that
	// nothing happened, rather than left to discover it.
	PortalFlagIgnored string
}

// Open initialises the coordinator: opens the storage store, loads the
// appliance db, and reconciles the kernel to the loaded desired state
// (startup replay).
//
// A nil store or manager is refused rather than dereferenced. Open returns an
// error already, so there is no reason for a caller's mistake to arrive as a
// panic from somewhere deeper -- the startup replay below reconciles, which
// calls straight into the manager, so nil surfaced as a SIGSEGV in lio.Sync
// with nothing in the trace naming the actual error.
func Open(root string, store *storage.Store, m *lio.Manager, cfg Config) (*Coordinator, error) {
	if store == nil {
		return nil, errors.New("appliance: nil storage store")
	}
	if m == nil {
		return nil, errors.New("appliance: nil lio manager")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	c := &Coordinator{
		store:  store,
		lio:    m,
		cfg:    cfg,
		dbPath: filepath.Join(root, "appliance.json"),
		st:     dbState{Exports: map[string]int{}},
	}
	if err := c.load(); err != nil {
		return nil, err
	}
	if c.st.Exports == nil {
		c.st.Exports = map[string]int{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.adoptPortals(); err != nil {
		return nil, err
	}
	if _, err := c.reconcile(); err != nil {
		return nil, err
	}
	c.logOrphanPRState()
	return c, nil
}

// adoptPortals settles the flag-vs-record question once, at startup.
//
// The rule, and the reason for each half:
//
//   - No portals recorded -> the -portals flag IS the record. Persist it and
//     stop calling it unrecorded. This is what adopts an appliance that
//     predates portals being durable, and it is the same backfill shape
//     storage.Store.repair uses for an unrecorded block size.
//   - Portals recorded -> the RECORD WINS. It has to: a portal set changed
//     over REST would otherwise be silently undone by the next restart, which
//     makes the API a lie.
//
// The second half has an obvious trap -- an operator edits the unit file,
// restarts, and nothing happens -- so a flag that DISAGREES with the record is
// reported rather than silently ignored. It is not an error: the flag is a
// bootstrap default and disagreeing with it is the normal state of any
// appliance whose portals have ever been changed through the API.
//
// Caller must hold c.mu.
func (c *Coordinator) adoptPortals() error {
	if len(c.st.Portals) == 0 {
		c.st.Portals = slices.Clone(c.cfg.Portals)
		if err := c.persist(); err != nil {
			return fmt.Errorf("recording the initial portal list: %w", err)
		}
		return nil
	}
	if !samePortalSet(c.st.Portals, c.cfg.Portals) {
		c.healthMu.Lock()
		c.portalFlagIgnored = fmt.Sprintf(
			"the -portals flag says %s but the recorded portals are %s; "+
				"the record wins. Change portals through the API, or clear "+
				"the portals field in appliance.json to re-adopt the flag",
			portalsText(c.cfg.Portals), portalsText(c.st.Portals))
		msg := c.portalFlagIgnored
		c.healthMu.Unlock()
		log.Printf("appliance: %s", msg)
	}
	return nil
}

// samePortalSet compares two portal lists as SETS -- order is not identity,
// and the reconciler reorders them anyway (lio.portalApplyOrder puts wildcards
// first because the kernel will not bind them otherwise).
func samePortalSet(a, b []lio.Portal) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[netip.AddrPort]int{}
	for _, p := range a {
		seen[netip.AddrPortFrom(p.IP, uint16(p.Port))]++
	}
	for _, p := range b {
		k := netip.AddrPortFrom(p.IP, uint16(p.Port))
		seen[k]--
		if seen[k] < 0 {
			return false
		}
	}
	return true
}

func portalsText(ps []lio.Portal) string {
	if len(ps) == 0 {
		return "(none)"
	}
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return strings.Join(out, ",")
}

// portals returns the EFFECTIVE portal list.
//
// The durable record, falling back to the boot flag while the record is
// unrecorded -- the same two-part shape as storage.Volume.BlockSize, where
// BlockSizeOrDefault interprets an unrecorded value and Store.repair backfills
// it so unrecorded stops existing. adoptPortals is the backfill here.
//
// The fallback is not redundant with the backfill. Open() always backfills, but
// a Coordinator assembled without it -- a test, or some future construction
// path -- would otherwise report NO portals rather than the configured ones,
// and "no portals" is the one portal answer that is never harmless.
//
// Caller must hold c.mu.
func (c *Coordinator) portals() []lio.Portal {
	if len(c.st.Portals) == 0 {
		return slices.Clone(c.cfg.Portals)
	}
	return slices.Clone(c.st.Portals)
}

// logOrphanPRState reports saved SCSI-3 PR metadata belonging to no live
// volume. See OrphanPRState for why these are never reaped automatically.
//
// Logged once at startup rather than per reconcile: the condition is
// operator-actionable and changes only when volumes do, so repeating it on
// every mutation would be noise that trains people to ignore it. Without
// this it was visible only if someone happened to run `applianced inspect`,
// which is not a thing anyone does unprompted.
//
// Caller must hold c.mu.
func (c *Coordinator) logOrphanPRState() {
	if c.cfg.DBRoot == "" {
		return
	}
	var live []string
	for _, v := range c.store.List() {
		live = append(live, v.WWN)
	}
	orphans, err := OrphanPRState(c.cfg.DBRoot, live)
	if err != nil {
		log.Printf("warning: cannot check for orphaned SCSI-3 PR state: %v", err)
		return
	}
	if len(orphans) == 0 {
		return
	}
	log.Printf("NOTICE: %d saved SCSI-3 PR reservation file(s) belong to no existing volume. "+
		"They are inert (only read back for a backstore with the same WWN) and are NOT removed "+
		"automatically, because a volume can be absent temporarily (a partially restored db, a "+
		"backstore not yet replayed) and reaping would destroy live fencing state. "+
		"Run `applianced inspect` for the list, and remove them if the volumes are really gone.",
		len(orphans))
	for i, o := range orphans {
		if i == 5 {
			log.Printf("  ... and %d more", len(orphans)-5)
			break
		}
		log.Printf("  %s", o)
	}
}

func (c *Coordinator) load() error {
	data, err := os.ReadFile(c.dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := json.Unmarshal(data, &c.st); err != nil {
		return err
	}
	return c.validateLoaded()
}

// validateLoaded fails closed on a structurally invalid appliance db so a
// corrupt/foreign appliance.json produces a clear error at startup rather
// than a nil-pointer panic or an unreconcilable "poison" record that would
// fail every startup replay. It mirrors the invariants the API enforces on
// mutation: well-formed and unique host UUIDs, unique initiator IQNs across
// hosts, in-range LUNs, attachments that reference a real host and are unique
// per (host,volume) and (host,LUN), and a sane export map.
func (c *Coordinator) validateLoaded() error {
	hosts := map[string]bool{}
	iqnOwner := map[string]string{}
	for _, h := range c.st.Hosts {
		if h == nil {
			return fmt.Errorf("appliance: %s contains a null host record", c.dbPath)
		}
		if !validUUID(h.UUID) {
			return fmt.Errorf("appliance: %s contains ill-formed host uuid %q", c.dbPath, h.UUID)
		}
		if hosts[h.UUID] {
			return fmt.Errorf("appliance: %s contains duplicate host uuid %q", c.dbPath, h.UUID)
		}
		hosts[h.UUID] = true
		if len(h.IQNs) == 0 {
			return fmt.Errorf("appliance: %s host %s has no initiator IQNs", c.dbPath, h.UUID)
		}
		for _, q := range h.IQNs {
			if !lio.ValidInitiatorIQN(q) {
				return fmt.Errorf("appliance: %s host %s has invalid initiator IQN %q", c.dbPath, h.UUID, q)
			}
			if prev, dup := iqnOwner[q]; dup {
				return fmt.Errorf("appliance: %s initiator IQN %q is claimed by both host %s and %s",
					c.dbPath, q, prev, h.UUID)
			}
			iqnOwner[q] = h.UUID
		}
	}
	seenPair := map[string]bool{}
	seenHostLUN := map[string]bool{}
	for _, a := range c.st.Attachments {
		if a == nil {
			return fmt.Errorf("appliance: %s contains a null attachment record", c.dbPath)
		}
		if a.LUN < 0 || a.LUN > maxLUN {
			return fmt.Errorf("appliance: %s attachment (vol %s) has out-of-range lun %d", c.dbPath, a.VolumeUUID, a.LUN)
		}
		if !validUUID(a.VolumeUUID) {
			return fmt.Errorf("appliance: %s attachment has ill-formed volume uuid %q", c.dbPath, a.VolumeUUID)
		}
		if !hosts[a.HostUUID] {
			return fmt.Errorf("appliance: %s attachment (vol %s) references unknown host %q", c.dbPath, a.VolumeUUID, a.HostUUID)
		}
		pair := a.HostUUID + "/" + a.VolumeUUID
		if seenPair[pair] {
			return fmt.Errorf("appliance: %s has duplicate attachment (host %s, vol %s)", c.dbPath, a.HostUUID, a.VolumeUUID)
		}
		seenPair[pair] = true
		if a.Desired == "attached" {
			hl := fmt.Sprintf("%s/%d", a.HostUUID, a.LUN)
			if seenHostLUN[hl] {
				return fmt.Errorf("appliance: %s has two attachments at lun %d on host %s", c.dbPath, a.LUN, a.HostUUID)
			}
			seenHostLUN[hl] = true
		}
	}
	usedIdx := map[int]string{}
	for vol, idx := range c.st.Exports {
		if !validUUID(vol) {
			return fmt.Errorf("appliance: %s export map has ill-formed volume uuid %q", c.dbPath, vol)
		}
		if idx < 0 || idx > maxLUN {
			return fmt.Errorf("appliance: %s export map has out-of-range index %d for volume %s", c.dbPath, idx, vol)
		}
		if prev, dup := usedIdx[idx]; dup {
			return fmt.Errorf("appliance: %s export index %d is claimed by both volume %s and %s",
				c.dbPath, idx, prev, vol)
		}
		usedIdx[idx] = vol
	}
	return nil
}

// validUUID reports whether s is a canonical dashed UUID (8-4-4-4-12 lower hex).
func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
	}
	return true
}

func (c *Coordinator) persist() error {
	// Refuse rather than write relative to the process's working directory.
	// The temp file is c.dbPath+".tmp", so an empty dbPath makes that ".tmp"
	// in whatever directory the process happens to be in; the rename to ""
	// then fails, leaving the file behind. A daemon should not scatter state
	// into its CWD because it was constructed wrong -- it should say so.
	// (One such file was committed to this repo before this guard existed.)
	if c.dbPath == "" {
		return errors.New("appliance: no database path configured")
	}
	data, err := json.MarshalIndent(c.st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := c.dbPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil { // durable: flush the temp file
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, c.dbPath); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(c.dbPath)); err != nil {
		// The rename already made the new db visible, so the ON-DISK state is
		// the NEW state; the caller must not roll memory back to the old one.
		return fmt.Errorf("%w: %v", errPersistedNotDurable, err)
	}
	return nil
}

// errPersistedNotDurable reports that the db was renamed into place but the
// containing directory could not be fsynced. The new state IS on disk; only
// its survival across a power loss is unproven. commit() must not roll back.
var errPersistedNotDurable = errors.New("appliance: db written but not proven durable")

// syncDir fsyncs a directory so a preceding rename is durable.
func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// snapshotState returns a deep copy of the db sufficient to roll back any
// mutation the coordinator performs (slice append/filter, map edits, and
// in-place field writes). It clones the pointed-to Host/Attachment structs —
// not just the slice headers — so commit()'s rollback is correct even if a
// mutation edits a record in place (e.g. an attachment's Desired).
func (c *Coordinator) snapshotState() dbState {
	exports := make(map[string]int, len(c.st.Exports))
	maps.Copy(exports, c.st.Exports)
	hosts := make([]*Host, len(c.st.Hosts))
	for i, h := range c.st.Hosts {
		cp := *h
		cp.IQNs = append([]string(nil), h.IQNs...)
		hosts[i] = &cp
	}
	atts := make([]*Attachment, len(c.st.Attachments))
	for i, a := range c.st.Attachments {
		cp := *a
		atts[i] = &cp
	}
	return dbState{Hosts: hosts, Attachments: atts, Exports: exports,
		Portals: slices.Clone(c.st.Portals)}
}

// healIfDegraded re-reconciles when a previous reconcile failed, so a caller
// about to take an irreversible action (deleting a backing file, resizing a live
// device) knows the kernel actually matches the durable db. Returns a
// service-unavailable status
// error if the kernel still cannot be reconciled. Caller must hold c.mu.
//
// This gate must cover EVERY mutation that can act on kernel-backed state, not
// just commit(): if a detach persisted but its reconcile failed, the db shows no
// attachment while the kernel still holds a live LUN with an open fd on the
// backing file — deleting that file would destroy data still being served.
func (c *Coordinator) healIfDegraded() error {
	if c.lastReconcileErr == nil {
		return nil
	}
	// This is necessarily a FULL reconcile, not an incremental one: whatever
	// failed last time also cleared the cached view of what is applied, so
	// reconcile() has nothing to diff against and falls back to Sync. Healing
	// must rediscover the tree rather than trust a belief formed before the
	// failure.
	if _, err := c.reconcile(); err != nil {
		return statusErr(http.StatusServiceUnavailable, "appliance degraded: previous reconcile failed (%v); "+
			"retry once the kernel LIO state is reachable", err)
	}
	return nil
}

// commit applies a db mutation crash-safely: snapshot -> mutate -> validate
// the resulting desired LIO state -> persist -> reconcile. If the mutation
// errors, the desired state is invalid, or persist fails, the in-memory db
// is rolled back so an invalid request is NEVER persisted — a persisted
// invalid record would fail startup replay and brick the daemon. A
// reconcile failure AFTER a valid, durable commit is reported but not rolled
// back (the db is the source of truth; startup replay re-reconciles).
// Caller must hold c.mu.
func (c *Coordinator) commit(mutate func() error) error {
	tCommit := time.Now()
	// If the previous reconcile left the kernel out of sync with the db, heal
	// it before accepting a new mutation. Otherwise a mutation computed against
	// a stale kernel — e.g. an export index freed by a failed detach and then
	// reused for a different volume — could apply a disruptive in-place change.
	// Refuse the mutation if the kernel still can't be reconciled.
	if err := c.healIfDegraded(); err != nil {
		return err
	}
	backup := c.snapshotState()
	if err := mutate(); err != nil {
		c.restoreState(backup)
		return err
	}
	if err := c.desiredLIO().Validate(); err != nil {
		c.restoreState(backup)
		return err
	}
	tPersist := time.Now()
	if err := c.persist(); err != nil {
		if errors.Is(err, errPersistedNotDurable) {
			// Already on disk — reconcile it rather than diverging from it.
			_, _ = c.reconcile()
			return err
		}
		c.restoreState(backup)
		return err
	}
	persistFor := time.Since(tPersist)
	tRec := time.Now()
	_, err := c.reconcile()
	reconcileFor := time.Since(tRec)

	// This spans the whole of commit, which is held under c.mu and is
	// therefore the window that serialises concurrent mutations -- minus the
	// time a caller spent WAITING for the lock, which is not observable from
	// in here. "other" is the remainder: heal-if-degraded, the state
	// snapshot, the mutation itself, and validating the desired config.
	//
	// The split matters because it bounds what finer-grained locking could
	// buy. Configfs work has to be serialised regardless, so only the
	// non-configfs remainder is even a candidate for overlapping.
	if total := time.Since(tCommit); total > slowCommit {
		log.Printf("slow commit: persist=%s reconcile=%s other=%s total=%s",
			persistFor.Round(time.Millisecond), reconcileFor.Round(time.Millisecond),
			(total - persistFor - reconcileFor).Round(time.Millisecond),
			total.Round(time.Millisecond))
	}
	return err
}

func (c *Coordinator) restoreState(b dbState) { c.st = b }

// The two warning signals published below are deliberately NOT degraded
// states, and for the same reason in both cases: the db and the kernel tree
// agree about which objects exist, so mutations remain safe. Blocking every
// mutation over either would be worse than the thing being reported.
//
// pr_unbound: a restored SCSI-3 registration that did not take effect. The
// volumes are already exported by that point, and it is recoverable -- the
// saved record is not consumed, so it binds again if its coordinates return.
// But it must be loud, because a reservation someone believes is fencing a
// node is not actually in effect.
//
// attribute_drift: a managed attribute the kernel would not change while the
// volume is exported. Loud because the live device does not match what this
// appliance reports about it, and no reconcile can fix that -- only
// unexporting can. It is NOT a permanent condition requiring migration
// tooling: configfs is kernel memory, so the object is recreated from the db
// on the next boot and takes the desired value then (see lio.Report.Drift,
// where this is measured rather than assumed). Read an entry as "this host
// has not been rebooted since the change", not "this volume is stuck".

// publishReconcile publishes ONE generation of health facts under a SINGLE
// lock acquisition: the reconcile verdict, the fencing warnings, the attribute
// drift, and when the fencing state was last checked.
//
// Atomicity here is the point, and it is not what a snapshot on the read side
// can provide. Publishing these separately meant a successful reconcile
// announced "healthy" first, then walked configfs to verify APTPL, then walked
// it again for drift, publishing each result as it arrived. In that window
// /health paired a FRESH success with the PREVIOUS generation's warnings -- so
// a reconcile that had just produced a fencing warning reported clean until
// the walk finished. That is the fail-open direction in the one signal whose
// job is to say a reservation someone relies on is not in effect.
//
// The window was not short by construction either: those walks are configfs
// reads, which block in the kernel with no timeout or cancellation, and
// /health exists precisely to stay answerable while a reconcile is wedged
// there. The wedged case was the one it got wrong.
//
// prCheckedAt is advanced because both reconcile paths genuinely verify the
// fencing state -- the full path through Sync, the incremental path through
// VerifyAPTPL -- so leaving it to the periodic checker alone under-reported
// the freshness of a fact that had just been established.
func (c *Coordinator) publishReconcile(err error, unbound, stranded []string, drift []lio.AttrDrift) {
	rendered := make([]string, 0, len(drift))
	for _, d := range drift {
		rendered = append(rendered, d.String())
	}
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	c.healthErr = err
	c.storePRUnboundLocked(unbound)
	c.storePRStrandedLocked(stranded)
	c.storeDriftLocked(rendered)
	c.prCheckedAt = time.Now()
}

// publishReconcileFailure records a failed reconcile without touching the
// warnings, in one acquisition.
//
// The warnings are left at the last generation that actually established
// them: a reconcile that failed produced no new information about fencing or
// drift, and inventing "none" would be the fail-open direction. Pairing a
// fresh degraded verdict with older warnings is honest and is the loud
// direction -- degraded already tells the operator not to trust the rest.
func (c *Coordinator) publishReconcileFailure(err error) {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	c.healthErr = err
}

// publishPRCheck publishes a periodic fencing re-verification: the warnings
// and their timestamp together, so a reader cannot see one without the other.
func (c *Coordinator) publishPRCheck(unbound, stranded []string) {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	c.storePRUnboundLocked(unbound)
	c.storePRStrandedLocked(stranded)
	c.prCheckedAt = time.Now()
}

// storePRStrandedLocked logs each newly-seen stranded reservation once.
// Caller holds healthMu.
//
// Logged as a NOTICE, not a WARNING: the reservation is doing its job. What
// makes it worth saying is that its holder cannot lift it, so an operator
// waiting for the holder to release would wait forever.
func (c *Coordinator) storePRStrandedLocked(stranded []string) {
	for _, s := range stranded {
		if !slices.Contains(c.prStranded, s) {
			log.Printf("NOTICE: SCSI-3 PR reservation is in effect but its holder "+
				"cannot release it: %s", s)
		}
	}
	c.prStranded = stranded
}

// storePRUnboundLocked and storeDriftLocked hold the newly-seen logging so it
// happens inside whichever critical section is publishing. Caller holds
// healthMu.
func (c *Coordinator) storePRUnboundLocked(unbound []string) {
	for _, u := range unbound {
		if !slices.Contains(c.prUnbound, u) {
			log.Printf("WARNING: SCSI-3 PR reservation NOT in effect after replay: %s", u)
		}
	}
	c.prUnbound = unbound
}

func (c *Coordinator) storeDriftLocked(rendered []string) {
	for _, d := range rendered {
		if !slices.Contains(c.drift, d) {
			log.Printf("WARNING: desired attribute could not be applied: %s", d)
		}
	}
	c.drift = rendered
}

// PRUnbound returns restored PR registrations that never became live.
func (c *Coordinator) PRUnbound() []string {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	return slices.Clone(c.prUnbound)
}

// HealthSnapshot returns the reconcile verdict and the PR warnings as ONE
// consistent view, taken under a single lock acquisition.
//
// Like Healthy it deliberately does not take c.mu: that lock is held across
// reconcile, whose configfs operations can block uncancellably in the kernel,
// and health must stay answerable exactly then.
func (c *Coordinator) HealthSnapshot() Health {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	h := Health{PRUnbound: slices.Clone(c.prUnbound), PRStranded: slices.Clone(c.prStranded),
		Drift: slices.Clone(c.drift), CheckedAt: c.prCheckedAt}
	h.PortalFlagIgnored = c.portalFlagIgnored
	// Read from the store rather than mirrored into a coordinator field: it is
	// sticky and rare, so there is nothing to keep in step and no generation
	// to tear against. The store guards it with a dedicated mutex, so this
	// cannot block behind volume I/O.
	if c.store != nil {
		if err := c.store.BackupErr(); err != nil {
			h.BackupErr = err.Error()
		}
		// Fixed at Open and read-only after, so it needs no lock and cannot
		// tear against the reconcile generation above.
		h.Quarantined = c.store.Quarantined()
		// Same lifetime as Quarantined: fixed at Open, read-only after.
		h.RejectedRecords = c.store.RejectedRecords()
	}
	if c.healthErr != nil {
		h.Degraded, h.Detail = true, c.healthErr.Error()
	}
	// A rejected record means a volume an operator believes exists is not
	// exported, which is degraded by any reading. Appended rather than
	// assigned so it cannot mask a reconcile error that is already set: both
	// conditions can hold at once and the reconcile error is the more urgent.
	if len(h.RejectedRecords) > 0 {
		h.Degraded = true
		detail := fmt.Sprintf("%d db record(s) rejected and not exported: %s",
			len(h.RejectedRecords), h.RejectedRecords[0].Reason)
		if h.Detail == "" {
			h.Detail = detail
		} else {
			h.Detail += "; " + detail
		}
	}
	return h
}

// RecheckPR recomputes the SCSI-3 PR warnings against the live kernel tree.
//
// It exists because the warnings are otherwise a cache refreshed only by
// reconcile, and reconcile only runs on LIO-affecting mutations: CreateVolume
// never reconciles and DeleteVolume only does so when degraded. So a condition
// that RESOLVES stays reported, and -- more seriously now that a lapsed
// reservation holder is reported -- a condition that ARISES without a
// topology change stays invisible, on an idle appliance, indefinitely. The
// live counter-test had to synthesise a spare volume and map it just to make
// the assertion observable, which is the clearest possible evidence that the
// signal was not observable in production.
//
// Deliberately NOT done on the /health read path, which was the obvious
// suggestion: VerifyAPTPL reads configfs, and those reads can block
// uncancellably in the same kernel situations that make a reconcile hang.
// Putting them behind /health would reintroduce exactly the unanswerable-health
// failure Healthy() is written to avoid. A periodic caller bounds staleness
// without putting configfs on the latency path.
//
// Skips the tick rather than waiting when a mutation holds c.mu: that
// reconcile publishes its own fresher result on the way out, so blocking here
// would only queue goroutines behind a lock that may be wedged in the kernel.
func (c *Coordinator) RecheckPR() {
	if !c.mu.TryLock() {
		return
	}
	defer c.mu.Unlock()
	desired := c.desiredLIO()
	c.publishPRCheck(c.lio.VerifyAPTPL(desired), strandedText(c.lio.StrandedReservations(desired)))
}

// Healthy reports whether the kernel LIO tree is in sync with the db. It is
// false ("degraded") when the last reconcile failed — surfaced on /health so
// a failed post-commit reconcile is observable rather than silently green.
//
// It deliberately does NOT take c.mu: that lock is held across reconcile, whose
// configfs operations can block uncancellably in the kernel, and /health must
// answer precisely in that situation rather than hang.
func (c *Coordinator) Healthy() (bool, string) {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	if c.healthErr != nil {
		return false, c.healthErr.Error()
	}
	return true, ""
}

// setReconcileErr records the reconcile outcome for both the mutation gate
// (under mu) and /health (under healthMu).
func (c *Coordinator) setReconcileErr(err error) {
	c.lastReconcileErr = err
	c.publishReconcileFailure(err)
}

// --- helpers (caller must hold c.mu) ---

func (c *Coordinator) host(uuid string) *Host {
	for _, h := range c.st.Hosts {
		if h.UUID == uuid {
			return h
		}
	}
	return nil
}

// iqnOwner returns the host UUID that owns iqn (excluding exceptHost), or "".
func (c *Coordinator) iqnOwner(iqn, exceptHost string) string {
	for _, h := range c.st.Hosts {
		if h.UUID == exceptHost {
			continue
		}
		if slices.Contains(h.IQNs, iqn) {
			return h.UUID
		}
	}
	return ""
}

// attachmentsOf returns a volume's attached (desired) attachments.
func (c *Coordinator) attachmentsOf(volumeUUID string) []*Attachment {
	var out []*Attachment
	for _, a := range c.st.Attachments {
		if a.VolumeUUID == volumeUUID && a.Desired == "attached" {
			out = append(out, a)
		}
	}
	return out
}

// exportIndex returns the TPG LUN index for a volume, allocating the
// lowest free one if needed.
func (c *Coordinator) exportIndex(volumeUUID string) int {
	if idx, ok := c.st.Exports[volumeUUID]; ok {
		return idx
	}
	used := map[int]bool{}
	for _, idx := range c.st.Exports {
		used[idx] = true
	}
	idx := 0
	for used[idx] {
		idx++
	}
	c.st.Exports[volumeUUID] = idx
	return idx
}

// pruneExports drops export indexes for volumes with no attachments.
func (c *Coordinator) pruneExports() {
	for vol := range c.st.Exports {
		if len(c.attachmentsOf(vol)) == 0 {
			delete(c.st.Exports, vol)
		}
	}
}

// Validate checks the appliance configuration before anything is opened or
// reconciled.
//
// These values come from flags or an environment file and are otherwise not
// examined until they reach configfs, where a typo surfaces as a reconcile
// error naming a kernel path. Under Restart=on-failure that is a crash loop
// whose log says nothing about the setting that caused it, and the daemon
// never gets far enough to serve /health and explain itself. A mistyped IQN is
// an ordinary mistake and should produce an ordinary message.
//
// Checked here rather than only in cmd/applianced so that any embedder gets
// the same guarantee, and so the rules live next to the type they constrain.
func (c Config) Validate() error {
	if !lio.ValidTargetIQN(c.TargetIQN) {
		return fmt.Errorf("appliance: target IQN %q is not usable: it must start with "+
			"iqn. or naa. and contain no '/', spaces or control characters (-iqn)",
			c.TargetIQN)
	}
	if len(c.Portals) == 0 {
		return errors.New("appliance: at least one portal address is required (-portals)")
	}
	// netip.AddrPort is comparable and canonical, so it is the key directly.
	// One IPv6 address has many spellings -- fd00::1, fd00:0:0:0:0:0:0:1,
	// FD00::0001 -- and a string key let them all through as distinct
	// portals. The kernel then made two np directories for one endpoint and
	// refused the second bind with EADDRINUSE, surfaced through configfs as a
	// bare EINVAL: the startup crash loop this validation exists to prevent,
	// reached through the one door it left open.
	//
	// Parsing happens in ParsePortals, so the whitespace, hostname and
	// character checks that used to live here are gone: an invalid address
	// cannot reach a netip.Addr at all, and an unset one is !IsValid().
	seen := map[netip.AddrPort]bool{}
	for _, p := range c.Portals {
		if !p.IP.IsValid() {
			return errors.New("appliance: a portal has no address -- check for a stray " +
				"comma in -portals")
		}
		// Only zero needs rejecting here: the upper bound is the uint16
		// itself. The appliance requires an explicit port rather than
		// defaulting, so that a portal record always says what it means.
		if p.Port == 0 {
			return fmt.Errorf("appliance: portal %s has no port (-portals)", p.IP)
		}
		// The kernel names a portal np/<ip>:<port>, so a repeat is the same
		// directory twice. Harmless to the reconcile, which is idempotent,
		// but it means the operator wrote something they did not mean.
		key := netip.AddrPortFrom(p.IP, uint16(p.Port))
		if seen[key] {
			return fmt.Errorf("appliance: portal %s is listed twice, possibly written two "+
				"different ways -- one address has many spellings and the kernel binds "+
				"it once (-portals)", key)
		}
		seen[key] = true
	}
	if err := checkPortalOverlap(c.Portals); err != nil {
		return err
	}
	// DBRoot is optional -- empty disables the saved-PR cleanup -- but a
	// relative path would be resolved against the daemon's working directory,
	// which is not something the operator chose.
	if c.DBRoot != "" && !filepath.IsAbs(c.DBRoot) {
		return fmt.Errorf("appliance: db root %q must be an absolute path", c.DBRoot)
	}
	return nil
}

// ParsePortals turns a comma-separated portal specification into portals,
// applying defaultPort to any entry that does not name one.
//
// Each entry is "<ip>" or "<ip>:<port>", with IPv6 addresses bracketed when a
// port is given: "10.0.0.1", "10.0.0.1:3261", "fd00::1", "[fd00::1]:3261".
// The brackets are not decoration -- an IPv6 address contains colons, so
// "fd00::1:3261" cannot be split unambiguously, which is the same reason the
// kernel insists on them in configfs names.
//
// Both forms are handed to net/netip rather than split by hand:
// ParseAddrPort accepts exactly the bracketed syntax above, and ParseAddr the
// bare address, so neither this function nor anything downstream has to know
// which family it is looking at. The address is Unmap()ed so ::ffff:10.0.0.1
// and 10.0.0.1 are one portal rather than two.
//
// Parsing lives here rather than in the command so it can be tested without a
// process, and so any embedder gets the same syntax.
func ParsePortals(spec string, defaultPort uint16) ([]lio.Portal, error) {
	var out []lio.Portal
	for entry := range strings.SplitSeq(spec, ",") {
		p, ok := lio.ParsePortal(entry)
		if !ok {
			return nil, fmt.Errorf("appliance: portal %q is not an address or address:port "+
				"(-portals). Hostnames are not accepted -- the kernel wants a literal "+
				"address, and resolving one here would bind to whatever DNS said at "+
				"startup", entry)
		}
		if p.Port == 0 {
			p.Port = defaultPort
		}
		out = append(out, p)
	}
	return out, nil
}

// checkPortalOverlap rejects a portal list the kernel could never bind.
//
// A wildcard and a specific address cannot share a port. The socket is opened
// with SO_REUSEADDR but NOT SO_REUSEPORT (linux v6.6
// drivers/target/iscsi/iscsi_target_login.c, iscsit_setup_np: sock_set_reuseaddr
// then ip_sock_set_freebind then kernel_bind), so the second bind returns
// EADDRINUSE. MEASURED on Azure Linux 3.0, kernel 6.6.144.1 -- the failing
// bind is reported as "kernel_bind() failed: -98" in dmesg, while configfs
// surfaces a bare EINVAL that names nothing.
//
// This is worth catching HERE because it is decidable from the list alone. The
// alternative is what it did before: the daemon starts, takes the host lock,
// opens storage, reaches configfs, gets "mkdir ... invalid argument", exits,
// and repeats under Restart=on-failure -- a crash loop whose log never
// mentions portals.
//
// Note the asymmetry, which is measured rather than assumed:
//
//	0.0.0.0 + 10.0.0.1   conflict      (v4 wildcard covers v4)
//	0.0.0.0 + fd00::1    BOTH FINE     (v4 wildcard does NOT cover v6)
//	::      + fd00::1    conflict
//	::      + 10.0.0.1   conflict      (v6 wildcard covers v4 as well)
//	::      + 0.0.0.0    conflict
//
// "::" covering IPv4 is Linux's default dual-stack behaviour
// (net.ipv6.bindv6only=0). A host set to bindv6only=1 would accept "::" beside
// an IPv4 address, and this rejects it anyway: reading a sysctl would make
// validation depend on mutable global state, and naming explicit addresses
// works under either setting.
func checkPortalOverlap(portals []lio.Portal) error {
	// Grouped by port, because two portals on different ports never contend.
	byPort := map[uint16][]lio.Portal{}
	for _, p := range portals {
		byPort[p.Port] = append(byPort[p.Port], p)
	}
	for port, group := range byPort {
		for _, w := range group {
			if !w.IP.IsUnspecified() {
				continue
			}
			for _, o := range group {
				if o.IP == w.IP || !wildcardCovers(w.IP, o.IP) {
					continue
				}
				return fmt.Errorf("appliance: portals %s and %s cannot both be bound on port "+
					"%d -- %s is a wildcard that already covers %s, and the kernel refuses "+
					"the second with EADDRINUSE. Use the wildcard alone, or list only "+
					"specific addresses (-portals)",
					w.IP, o.IP, port, w.IP, o.IP)
			}
		}
	}
	return nil
}

// wildcardCovers reports whether binding wildcard w precludes binding other.
// 0.0.0.0 covers IPv4 only; :: covers both families on a default Linux.
//
// The family test is Addr.Is4(), asked of the address itself, rather than a
// re-parse and a To4() nil-check per side.
func wildcardCovers(w, other netip.Addr) bool {
	if !w.IsValid() || !other.IsValid() || !w.IsUnspecified() {
		return false
	}
	if w.Is4() {
		return other.Is4() // 0.0.0.0: IPv4 only
	}
	return true // ::: dual-stack, so everything
}

// strandedText renders stranded reservations for the report channel.
func strandedText(in []lio.StrandedReservation) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, s.String())
	}
	return out
}
