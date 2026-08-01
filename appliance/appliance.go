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
//
// What it does NOT do is span its two durable files transactionally. Volume
// records live in storage's volumes.json under that package's mutex; hosts,
// attachments and portals live in the appliance's own db under the coordinator
// lock. Each file is replaced atomically; the pair is not, and a crash between
// the two writes can leave a volume the appliance's db does not describe.
//
// That is deliberate, and it is why there is no durable caller-supplied
// identity here. An external controller wanting to name volumes and retry
// safely needs the name and the volume to commit together, and neither order
// gives it: recording the name first cannot work, because storage mints the
// UUID inside Create, so an intent record written beforehand cannot say what
// it is about to make. The arrangement that WOULD be atomic is to carry the
// name on the storage record itself — one file, one mutex — at the cost of
// teaching storage about callers it has no business knowing about.
//
// Neither is attempted. Callers retry using the volume UUID the appliance
// already returned. Anything needing crash-safe external identity wants a
// transactional store underneath it, which this is not.
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
// newIdentity mints an object's UUID and the WWN derived from it.
//
// Derived, not independent: the WWN is what an initiator identifies the device
// by, and two identifiers that can drift apart are two things to keep in step.
// Deriving one from the other makes that impossible by construction.
//
// The WWN is 16 lowercase hex characters, which is what LIO's vpd_unit_serial
// takes and what becomes the SCSI WWID an initiator sees.
func newIdentity() (uuid, wwn string, err error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	// RFC 4122 version 4, variant 1: not because anything parses it, but
	// because a uuid that does not say what it is invites something
	// downstream to guess.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	uuid = fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	wwn = hex.EncodeToString(b[0:8])
	return uuid, wwn, nil
}

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

// Config is the appliance-wide configuration.
//
// One target with one TPG, deliberately: a second target means a second
// appliance, on its own machine, with its own identity, portals and volumes
// sharing nothing. That keeps this file describing a machine rather than a
// fleet, and keeps the fencing question -- which is per target -- answerable.
type Config struct {
	// TargetIQN is what the operator ASKED for, which is not necessarily what
	// this appliance is called: at startup the recorded identity wins and this
	// field is replaced by it. Empty means "derive one", which is the normal
	// case -- see [Coordinator.adoptIdentity].
	TargetIQN string `json:"target_iqn"`
	// MachineIDPath overrides where the machine ID is read from. For tests;
	// empty means [DefaultMachineIDPath].
	MachineIDPath string `json:"-"`
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

	// NoUnmap disables thin provisioning: the volume stops advertising UNMAP,
	// so a guest cannot return space it has freed.
	//
	// Inverted -- default OFF, meaning UNMAP is ON -- because the backing
	// files are sparse whether or not this is set. Without UNMAP the device is
	// thin on disk and claims to be fully provisioned on the wire, which is
	// the incoherent combination: the pool can still be overcommitted and can
	// still fill up, and the guest has no way to help. Advertising it makes
	// the wire match the disk.
	//
	// The escape hatch exists for a backing filesystem that cannot punch holes
	// (the kernel would then fail each UNMAP rather than silently ignoring
	// it), and for anyone who wants volumes to only ever grow.
	//
	// Appliance-wide, like WriteBack. The kernel does allow this per backstore
	// -- it is settable while exported -- but a fleet where some volumes
	// return space and others do not is a fleet whose free-space arithmetic
	// nobody can do.
	NoUnmap bool `json:"no_unmap"`
}

// Coordinator is the single-writer control plane.
type Coordinator struct {
	mu     sync.Mutex
	store  *storage.Store
	lio    *lio.Manager
	cfg    Config
	dbPath string
	st     db
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
	// iqnFlagIgnored is set when -iqn disagrees with the recorded identity.
	// Reported for the same reason as portalFlagIgnored: the appliance is not
	// running the configuration its operator believes it is.
	iqnFlagIgnored string
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
	// backupErr remembers a failure to keep a db backup. Guarded by healthMu.
	backupErr error
	healthErr error
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
	// IQNFlagIgnored is the same report for -iqn. Separate from the portal
	// one because the remedy differs: portals can be changed through the API,
	// while the IQN is set when the appliance is initialised and changing it
	// is a re-initialisation.
	IQNFlagIgnored string
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
		st:     db{Version: dbVersion, Exports: map[string]int{}},
	}
	existed, err := c.load()
	if err != nil {
		return nil, err
	}
	if c.st.Exports == nil {
		c.st.Exports = map[string]int{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.adoptStorage(existed); err != nil {
		return nil, err
	}
	// Identity BEFORE portals and before any reconcile: everything below
	// builds a target, and this is what decides which target that is.
	if err := c.adoptIdentity(); err != nil {
		return nil, err
	}
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
	for _, o := range c.st.Objects {
		live = append(live, o.WWN)
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

func (c *Coordinator) load() (existed bool, err error) {
	data, err := os.ReadFile(c.dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	// Decoded into a FRESH value, never into c.st.
	//
	// Open initialises c.st with the current Version so a first boot writes a
	// stamped db. Decoding on top of that would leave the field at its default
	// when the file has no version key, making an unversioned file
	// indistinguishable from a current one. Absent must stay distinguishable
	// from current; decoding into a zero value is what keeps it so.
	var loaded db
	if err := json.Unmarshal(data, &loaded); err != nil {
		return true, err
	}
	c.st = loaded
	if err := c.checkVersion(); err != nil {
		return true, err
	}
	if c.st.Exports == nil {
		c.st.Exports = map[string]int{}
	}
	return true, c.validateLoaded()
}

// checkVersion refuses a database this build does not understand.
//
// Both directions matter, and neither used to be checked at all -- the version
// was simply overwritten with the current one after loading.
//
// Older: a version 0 file is the pre-name layout, which nothing has produced
// since names arrived and whose conversion has been removed. Without this it
// reached validateLoaded and failed with "name is required", which describes
// the symptom rather than the cause.
//
// NEWER is the dangerous one. A file written by a later build decodes here
// with its unknown fields silently dropped, and snapshot() serialises only the
// fields THIS build knows -- so the next write would persist a truncated copy
// of somebody's database. Refusing to start is the only safe answer: a
// downgrade must not quietly destroy what it cannot represent.
//
// Caller must hold c.mu, or be in Open before the coordinator is shared.
func (c *Coordinator) checkVersion() error {
	switch {
	case c.st.Version == dbVersion:
		return nil
	case c.st.Version < dbVersion:
		return fmt.Errorf("appliance: %s is a version %d database and this build reads "+
			"version %d. Conversion from the pre-name layout was removed; restore a "+
			"newer backup, or start from an empty data root",
			c.dbPath, c.st.Version, dbVersion)
	default:
		return fmt.Errorf("appliance: %s is a version %d database and this build reads "+
			"version %d. It was written by a NEWER build: running this one would rewrite "+
			"it without the fields that build added. Run the newer build, or restore a "+
			"version %d backup",
			c.dbPath, c.st.Version, dbVersion, dbVersion)
	}
}

// adoptStorage reconciles the object records against what is actually on disk.
//
// Two directions, and they are not symmetric:
//
//   - A directory with no record is set ASIDE, never deleted. It is somebody's
//     data, and the case where this fires is exactly the case where it matters
//     -- a restored db is always at least one object behind the disk.
//
//   - A record with no directory is left alone and marked, because the record
//     is the only evidence the object ever existed and deleting it would erase
//     the one clue an operator has.
//
// If the db is absent entirely while directories are present, this REFUSES.
// That is the lost-records case, and quarantining every object because the
// file that names them went missing would turn a recoverable problem into a
// pile of timestamped directories. Caller must hold c.mu.
func (c *Coordinator) adoptStorage(dbExisted bool) error {
	dirs, err := c.store.ObjectDirs()
	if err != nil {
		return err
	}
	if !dbExisted && len(dirs) > 0 {
		// Name the backup explicitly. The recovery is "restore the db", and an
		// operator meeting this for the first time -- at the worst possible
		// moment -- should not have to discover where a backup might be, or
		// guess whether one exists.
		hint := "no backups were found beside " + c.dbPath + ", so the records must be rebuilt by hand"
		if bak, err := latestBackup(c.dbPath); err == nil && bak != "" {
			hint = "the most recent backup is " + bak + " -- copy it to " + c.dbPath +
				" to recover. Objects created after that backup was taken have no record " +
				"in it; they will be set aside with their data intact, not deleted"
		}
		return fmt.Errorf("appliance: %s is missing but %d object director(ies) are present "+
			"in %s; refusing to start rather than set aside live data. %s",
			c.dbPath, len(dirs), c.store.Root(), hint)
	}
	known := map[string]bool{}
	for _, o := range c.st.Objects {
		known[o.UUID] = true
	}
	for _, d := range dirs {
		if known[d] {
			continue
		}
		q, err := c.store.Quarantine(d)
		if err != nil {
			return err
		}
		log.Printf("warning: object directory %s has no record; set aside as %s with its data intact", d, q)
	}
	for _, o := range c.st.Objects {
		if !c.store.Exists(o.UUID) {
			// Reported, not removed: the record is the only evidence this
			// object existed, and an operator who deletes it loses the ability
			// to tell what was lost.
			o.State = stateMissing
			log.Printf("warning: %s %q (%s) has a record but no backing file; marked %s",
				o.Kind, o.Name, o.UUID, stateMissing)
		}
	}
	return nil
}

// validateLoaded fails closed on a structurally invalid db, so a corrupt or
// foreign file produces a clear error at startup rather than a nil-pointer
// panic or a record that fails every reconcile from then on.
//
// It mirrors the invariants the API enforces on mutation. Enforcing them in
// both places is deliberate: the API is not the only way bytes reach this
// file -- a restored backup, a hand edit, or an older build all bypass it.
func (c *Coordinator) validateLoaded() error {
	seenObj := map[string]bool{}
	seenName := map[string]bool{} // kind + "/" + name
	for _, o := range c.st.Objects {
		if o == nil {
			return fmt.Errorf("appliance: %s contains a null object record", c.dbPath)
		}
		if !validUUID(o.UUID) {
			return fmt.Errorf("appliance: %s contains ill-formed object uuid %q", c.dbPath, o.UUID)
		}
		if seenObj[o.UUID] {
			return fmt.Errorf("appliance: %s contains duplicate object uuid %q", c.dbPath, o.UUID)
		}
		seenObj[o.UUID] = true
		if o.Kind != KindVolume && o.Kind != KindSnapshot {
			return fmt.Errorf("appliance: %s object %s has unknown kind %q", c.dbPath, o.UUID, o.Kind)
		}
		if err := validName(o.Name); err != nil {
			return fmt.Errorf("appliance: %s object %s: %w", c.dbPath, o.UUID, err)
		}
		key := string(o.Kind) + "/" + o.Name
		if seenName[key] {
			return fmt.Errorf("appliance: %s has two %ss named %q", c.dbPath, o.Kind, o.Name)
		}
		seenName[key] = true
	}
	// A source that names nothing is NOT rejected. Deleting the thing a
	// snapshot came from is allowed -- the snapshot's bytes are its own -- so
	// a dangling source is provenance that has outlived its subject, not
	// corruption.

	hosts := map[string]bool{}
	hostNames := map[string]bool{}
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
		if err := validName(h.Name); err != nil {
			return fmt.Errorf("appliance: %s host %s: %w", c.dbPath, h.UUID, err)
		}
		if hostNames[h.Name] {
			return fmt.Errorf("appliance: %s has two hosts named %q", c.dbPath, h.Name)
		}
		hostNames[h.Name] = true
		// No check that a host HAS bindings: zero is legitimate. A host is
		// its UUID, and its bindings are how an initiator proves it is that
		// host, so one registered before its initiator is known has none yet.
		// This used to reject that, which meant the API would create such a
		// host, persist it, and the daemon would refuse to start on the next
		// boot -- accepting a mutation that cannot be loaded back is worse
		// than refusing it outright.
		for _, q := range h.Bindings.IQNs {
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
	for _, cn := range c.st.Connections {
		if cn == nil {
			return fmt.Errorf("appliance: %s contains a null connection record", c.dbPath)
		}
		if cn.LUN < 0 || cn.LUN > maxLUN {
			return fmt.Errorf("appliance: %s connection (object %s) has out-of-range lun %d",
				c.dbPath, cn.ObjectUUID, cn.LUN)
		}
		if !seenObj[cn.ObjectUUID] {
			return fmt.Errorf("appliance: %s connection references unknown object %q", c.dbPath, cn.ObjectUUID)
		}
		if !hosts[cn.HostUUID] {
			return fmt.Errorf("appliance: %s connection (object %s) references unknown host %q",
				c.dbPath, cn.ObjectUUID, cn.HostUUID)
		}
		pair := cn.HostUUID + "/" + cn.ObjectUUID
		if seenPair[pair] {
			return fmt.Errorf("appliance: %s has duplicate connection (host %s, object %s)",
				c.dbPath, cn.HostUUID, cn.ObjectUUID)
		}
		seenPair[pair] = true
		hl := fmt.Sprintf("%s/%d", cn.HostUUID, cn.LUN)
		if seenHostLUN[hl] {
			return fmt.Errorf("appliance: %s has two connections at lun %d on host %s",
				c.dbPath, cn.LUN, cn.HostUUID)
		}
		seenHostLUN[hl] = true
	}

	usedIdx := map[int]string{}
	for objUUID, idx := range c.st.Exports {
		if !validUUID(objUUID) {
			return fmt.Errorf("appliance: %s export map has ill-formed object uuid %q", c.dbPath, objUUID)
		}
		if idx < 0 || idx > maxLUN {
			return fmt.Errorf("appliance: %s export map has out-of-range index %d for object %s",
				c.dbPath, idx, objUUID)
		}
		if prev, dup := usedIdx[idx]; dup {
			return fmt.Errorf("appliance: %s export index %d is claimed by both object %s and %s",
				c.dbPath, idx, prev, objUUID)
		}
		usedIdx[idx] = objUUID
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
	// Hard-link a backup of what is there BEFORE replacing it.
	//
	// A link, not a copy: the rename below swaps the directory entry and
	// leaves the inode alone, so the link keeps pointing at the old bytes for
	// free and with no window in which either file is incomplete. Copying
	// would read a file that is about to be overwritten and could tear.
	//
	// Best-effort, and deliberately not fatal: this is a recovery convenience,
	// and refusing a mutation because a backup could not be made would turn a
	// tidy-up problem into an outage. The failure is remembered for /health.
	backupErr := func() error {
		if _, err := linkBackup(c.dbPath, time.Now()); err != nil {
			return err
		}
		return pruneBackups(c.dbPath, dbBackupsKept)
	}()

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
	if backupErr != nil {
		c.healthMu.Lock()
		c.backupErr = backupErr
		c.healthMu.Unlock()
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
func (c *Coordinator) snapshotState() db {
	exports := make(map[string]int, len(c.st.Exports))
	maps.Copy(exports, c.st.Exports)
	objs := make([]*Object, len(c.st.Objects))
	for i, o := range c.st.Objects {
		cp := *o
		objs[i] = &cp
	}
	hosts := make([]*Host, len(c.st.Hosts))
	for i, h := range c.st.Hosts {
		cp := *h
		cp.Bindings.IQNs = append([]string(nil), h.Bindings.IQNs...)
		hosts[i] = &cp
	}
	conns := make([]*Connection, len(c.st.Connections))
	for i, cn := range c.st.Connections {
		cp := *cn
		conns[i] = &cp
	}
	return db{Version: c.st.Version, Objects: objs, Hosts: hosts,
		Connections: conns, Exports: exports, Portals: slices.Clone(c.st.Portals)}
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
// persistOnly applies a mutation that provably cannot change the desired LIO
// configuration, and so needs no reconcile.
//
// Binding a caller's name to a volume is the case this exists for: external
// ids appear nowhere in desiredLIO, and a newly created volume is unexported,
// which desiredLIO ignores -- it emits a backstore only for volumes with an
// attached attachment. Routing these through commit() instead would make
// creating a volume acquire reconcile latency and, worse, share a failure
// domain with every LUN map on the appliance: healIfDegraded would refuse a
// create because something unrelated was wedged. Creating a volume touches no
// kernel state and should not care.
//
// Still serialised under c.mu and still rolled back on failure. Caller must
// hold c.mu.
func (c *Coordinator) persistOnly(mutate func() error) error {
	backup := c.snapshotState()
	if err := mutate(); err != nil {
		c.restoreState(backup)
		return err
	}
	if err := c.persist(); err != nil {
		if errors.Is(err, errPersistedNotDurable) {
			// Already on disk; keep memory in step with it rather than
			// diverging, exactly as commit does.
			return err
		}
		c.restoreState(backup)
		return err
	}
	return nil
}

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

func (c *Coordinator) restoreState(b db) { c.st = b }

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
	h.IQNFlagIgnored = c.iqnFlagIgnored
	// Read from the store rather than mirrored into a coordinator field: it is
	// sticky and rare, so there is nothing to keep in step and no generation
	// to tear against. The store guards it with a dedicated mutex, so this
	// cannot block behind volume I/O.
	if c.store != nil {
		// Fixed at Open and read-only after, so it needs no lock and cannot
		// tear against the reconcile generation above.
		h.Quarantined = c.store.Quarantined()
		// Same lifetime as Quarantined: fixed at Open, read-only after.
	}
	if c.backupErr != nil {
		h.BackupErr = c.backupErr.Error()
	}
	if c.healthErr != nil {
		h.Degraded, h.Detail = true, c.healthErr.Error()
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
		if slices.Contains(h.Bindings.IQNs, iqn) {
			return h.UUID
		}
	}
	return ""
}

// exportIndex returns the TPG LUN index for a volume, allocating the
// lowest free one if needed.
func (c *Coordinator) exportIndex(objectUUID string) int {
	if idx, ok := c.st.Exports[objectUUID]; ok {
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
	c.st.Exports[objectUUID] = idx
	return idx
}

// pruneExports drops export indexes for volumes with no attachments.
func (c *Coordinator) pruneExports() {
	for obj := range c.st.Exports {
		if len(c.connectionsOf(obj)) == 0 {
			delete(c.st.Exports, obj)
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
	// Empty is allowed and means "derive one from this machine". Only a
	// stated IQN is checked, because an unusable one must fail here rather
	// than at configfs, where it arrives as a bare EINVAL about a kernel path.
	if c.TargetIQN != "" && !lio.ValidTargetIQN(c.TargetIQN) {
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
