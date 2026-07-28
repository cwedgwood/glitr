package lio

import (
	"fmt"
	"strings"
	"time"

	"github.com/cwedgwood/glitr/lio/configfs"
)

// Manager is the entry point for declarative LIO management. It is
// stateless: every call reads/writes configfs directly.
type Manager struct {
	fs *configfs.FS

	// APTPLRecords, if non-nil, supplies saved SCSI-3 Persistent
	// Reservation registrations to restore onto a backstore at the moment
	// it is created. See SetAPTPLRecords for the full contract.
	aptplRecords func(Backstore) ([]string, error)
}

// New returns a Manager backed by the given configfs FS. Pass
// configfs.Default() for the standard kernel mount point.
func New(fs *configfs.FS) *Manager { return &Manager{fs: fs} }

// SetAPTPLRecords installs a provider for saved SCSI-3 Persistent
// Reservation state (APTPL — Activate Persist Through Power Loss).
//
// Why this is a hook and not a Config field: APTPL state is write-once and
// non-discoverable, so it cannot participate in the declarative model.
//
//   - Non-discoverable: pr/res_aptpl_metadata is write-only. Reading it
//     returns the fixed string "Ready to process PR APTPL metadata..", not
//     the stored records, so Discover can never report it. A Config field
//     would therefore always read back empty and desired/actual would
//     disagree forever.
//   - Write-once: the kernel rejects the write with EINVAL once the device
//     is exported (dev->export_count > 0), so it cannot be re-applied on a
//     steady-state reconcile.
//
// The provider is called for each backstore at the instant it is created,
// BEFORE the object is enabled and therefore before anything can reference
// it. It returns the records to load, or nil for none. It is NOT called for
// a backstore that is already ENABLED, because the kernel would reject the
// write once the device is exported.
//
// "Already enabled" is the precise condition, not "already exists": an
// object that exists but was never enabled — the residue of an earlier
// failed create — falls through to the create path and the provider IS
// called again. That is deliberate. It is what makes a failed restore
// recoverable instead of silently converging on an exported-but-unreserved
// backstore.
//
// It returns data rather than performing the write so that record format,
// configfs paths, ordering and error wrapping stay inside this package;
// callers only answer "what was saved for this backstore?".
//
// A provider error is fail-stop, like any other apply error.
//
// Ordering note: loading records does not activate them. The kernel holds
// them dormant and binds them when the matching ACL mapped LUN is created,
// which is also the moment the initiator first gains an I/O path to the
// device. Reservations are therefore live strictly before any I/O is
// possible against that LUN.
func (m *Manager) SetAPTPLRecords(fn func(Backstore) ([]string, error)) { m.aptplRecords = fn }

// Report describes what an Apply pass changed.
type Report struct {
	Changes []string

	// Drift names managed attributes whose desired value could NOT be
	// written because the kernel makes them immutable while the backstore is
	// exported, and which were therefore skipped rather than treated as a
	// reconcile failure. Each entry is human-readable and names the
	// backstore, the attribute, the live value and the desired one.
	//
	// This is a DEGRADED condition, not a change note, and it is separate
	// from Changes for that reason: Changes is a log of what happened, which
	// a caller may reasonably ignore, while an entry here means the live
	// device does not match what this stack believes about it and cannot be
	// made to without unexporting -- an operator decision about a device an
	// initiator may have mounted. A daemon must surface this rather than
	// converge silently.
	//
	// The severity is not uniform. optimal_sectors drift costs an alignment
	// hint. block_size drift means the API reports one geometry while the
	// initiator sees another, so those entries say so explicitly.
	//
	// Structured rather than pre-rendered because a caller needs the LIVE
	// value, not just a sentence about it: the reconcile engine has to record
	// what was actually applied, and "desired, except these attributes are
	// really still X" is only expressible with X in hand. See AttrDrift.
	//
	// DRIFT IS TRANSIENT, NOT PERMANENT. "Immutable while exported" is a
	// property of the LIVE OBJECT, not of the volume: configfs is
	// kernel-memory state (see package configfs), so the object ceases to
	// exist on reboot and is recreated from the caller's durable records on
	// the create path -- where export_count is 0 and the kernel accepts the
	// desired value. Drift therefore survives a DAEMON restart (the tree
	// stays up underneath the process) and does NOT survive a host reboot,
	// a tree purge, or a prune-and-recreate of the object.
	//
	// Spelled out because the opposite is a natural and wrong reading:
	// "the kernel will not let this be changed" invites "so it is stuck
	// forever", which would imply an upgraded fleet permanently split
	// between old and new values. MEASURED otherwise (Azure Linux 3.0,
	// kernel 6.6.144.1, 2026-07): a volume created carrying
	// optimal_sectors=16384 still read 16384 after the upgrade and a daemon
	// restart, and read 0 after a host reboot while staying exported. An
	// upgraded fleet converges on its next reboot; until then the
	// divergence is visible here instead of being silent, which is the
	// whole reason this field exists.
	Drift []AttrDrift

	// APTPLUnbound names backstores where the saved SCSI-3 PR state and the
	// live state disagree in a way that affects fencing. Three conditions:
	// a saved registration that is still exported but not live; a saved
	// reservation HOLDER that is still exported but is not the live holder;
	// and a saved holder whose own export was removed while the backstore is
	// still exported to others, which leaves those survivors un-fenced. Each
	// entry is human-readable and names the initiator concerned.
	//
	// Sync and Apply populate this. ApplyDelta always leaves it nil, which is
	// indistinguishable from "all bound" -- see VerifyAPTPL.
	//
	// This exists because a restored record is position-bound. It carries
	// the target IQN, TPG tag, target LUN, mapped LUN and initiator IQN it
	// was saved under, and the kernel binds it only when a matching ACL
	// mapped LUN appears. A record still exported at those coordinates but
	// with no live registration — or one whose key does not match, or whose
	// saved reservation holder is not the live holder — stays DORMANT
	// forever, and that is what this reports.
	//
	// REGISTRATIONS whose export no longer exists are deliberately NOT
	// reported: a volume re-mapped at a different LUN, a changed target IQN,
	// a host recreated under a new IQN, or simply a detached host. That is
	// what a deliberate topology change leaves behind, the kernel never
	// rewrites the saved file to match, so reporting it produced a permanent
	// alarm for a routine operator action. Matching is by identity rather
	// than by count for the same reason — see lio/aptplcheck.go.
	//
	// A lapsed HOLDER is the exception, because a registration is the
	// registering initiator's own claim while a reservation restricts
	// everyone else. It is bounded three ways: the backstore must still be
	// exported to someone OTHER than the lapsed holder, NO reservation may
	// be live (the kernel promotes a surviving registrant instead of
	// releasing, for the all-registrants types), and it clears as soon as a
	// survivor reserves, because RESERVE is a PR OUT and PR OUT is what
	// makes the kernel rewrite the saved file. See reportLapsedHolder.
	//
	// Dormant is otherwise indistinguishable from success, because
	// pr/res_aptpl_metadata is write-only: nothing can read back what was
	// loaded. That makes the failure silent, and silence here means a
	// reservation someone is relying on for fencing is simply not in
	// effect. The bound registrations ARE readable, so this compares them.
	//
	// It is reported rather than fatal on purpose. A record naming an
	// initiator whose ACL no longer exists legitimately never binds, and
	// failing the reconcile would refuse to serve every other volume over
	// it. The state is also recoverable: the saved file is not consumed, so
	// a record rebinds if its coordinates return.
	APTPLUnbound []string

	// Timings records how long each phase took. Zero for a bare Apply.
	// ApplyDelta fills only Apply and Prune, since an incremental reconcile
	// neither discovers the tree nor verifies PR state. Reconcile cost is dominated by configfs syscalls and grows with
	// the number of objects in the tree, so a caller that reconciles on every
	// mutation needs to be able to see which phase is responsible rather than
	// guess.
	Timings SyncTimings
}

// SyncTimings breaks a Sync down by phase.
type SyncTimings struct {
	Apply    time.Duration // create/update every object in the desired config
	Discover time.Duration // read the entire live tree back
	Prune    time.Duration // remove live objects absent from desired
	Verify   time.Duration // check restored SCSI-3 PR registrations bound
}

// Total is the sum of the phases.
func (t SyncTimings) Total() time.Duration { return t.Apply + t.Discover + t.Prune + t.Verify }

// String renders the breakdown for logs.
func (t SyncTimings) String() string {
	return fmt.Sprintf("apply=%s discover=%s prune=%s verify=%s total=%s",
		t.Apply.Round(time.Millisecond), t.Discover.Round(time.Millisecond),
		t.Prune.Round(time.Millisecond), t.Verify.Round(time.Millisecond),
		t.Total().Round(time.Millisecond))
}

// Changed reports whether Apply made any modification.
func (r Report) Changed() bool { return len(r.Changes) > 0 }

// applyCtx extension: desired backstores, for LUN→backstore wiring.
func (a *applyCtx) backstoreByName(name string) (Backstore, bool) {
	b, ok := a.stateBackstores[name]
	return b, ok
}

// Apply reconciles the live configfs state with the desired Config.
// Objects are created/updated in dependency order:
//
//	backstore → target → TPG → portal → LUN → ACL(+mapped LUN)
//
// The operation is idempotent: reapplying an already-satisfied Config
// makes no changes.
func (m *Manager) Apply(cfg Config) (Report, error) {
	if err := cfg.Validate(); err != nil {
		return Report{}, err
	}
	a := &applyCtx{fs: m.fs, stateBackstores: map[string]Backstore{}, aptplRecords: m.aptplRecords}
	for _, b := range cfg.Backstores {
		a.stateBackstores[b.Name] = b
	}

	for _, b := range cfg.Backstores {
		if err := a.ensureBackstore(b); err != nil {
			return Report{Changes: a.changes, Drift: a.drift}, err
		}
	}
	for _, t := range cfg.Targets {
		if err := a.ensureTarget(t); err != nil {
			return Report{Changes: a.changes, Drift: a.drift}, err
		}
	}
	// Restored PR registrations activate when their ACL mapped LUN is
	// created, so this can only be checked once the targets exist.
	return Report{Changes: a.changes, Drift: a.drift, APTPLUnbound: a.verifyAPTPL(cfg)}, nil
}

// Remove deletes the objects described by cfg in reverse dependency
// order. It is best-effort per object but stops on the first hard error.
func (m *Manager) Remove(cfg Config) (Report, error) {
	a := &applyCtx{fs: m.fs}
	for _, t := range cfg.Targets {
		if err := a.removeTarget(t.IQN); err != nil {
			return Report{Changes: a.changes, Drift: a.drift}, err
		}
	}
	for _, b := range cfg.Backstores {
		if err := a.removeBackstore(b); err != nil {
			return Report{Changes: a.changes, Drift: a.drift}, err
		}
	}
	return Report{Changes: a.changes, Drift: a.drift}, nil
}

// Discover reconstructs the current Config from live configfs.
//
// It first checks that the LIO tree itself is present, and fails if it is
// not. This matters more than it looks. Both discoverBackstores and
// discoverTargets treat an absent subdirectory as "none configured", which is
// right inside a live tree -- a target with no backstores really does have no
// core/ directory. But if configfs is not mounted, or target_core_mod is not
// loaded, every subdirectory is absent and that same rule reports an empty
// configuration: indistinguishable from a host that is genuinely idle.
//
// An empty answer is not harmless, because callers persist it. A save on a
// host whose modules had not loaded yet discovered {}, wrote it over the
// existing saved configuration, and reported success -- destroying the only
// record that survives a reboot, with a restore afterwards silently restoring
// nothing. "I cannot tell" and "nothing is configured" have to be different
// answers, and only Discover is in a position to tell them apart.
//
// An empty tree that IS present remains a valid, non-error empty Config.
func (m *Manager) Discover() (Config, error) {
	if ok, err := m.fs.IsDir(); err != nil {
		return Config{}, errf(KindConfigfs, "discover", m.fs.Root, err)
	} else if !ok {
		return Config{}, errf(KindConfigfs, "discover", m.fs.Root, ErrNoLIOTree)
	}
	bs, err := discoverBackstores(m.fs)
	if err != nil {
		return Config{}, err
	}
	ts, err := discoverTargets(m.fs)
	if err != nil {
		return Config{}, err
	}
	return Config{Backstores: bs, Targets: ts}, nil
}

// --- discovery path parsing helpers ----------------------------------

// parseTPGT and parseLUN reject a NEGATIVE index rather than returning it.
//
// The kernel does not create tpgt_-1 or lun_-1, but this library is
// deliberately safe against a tree it did not create, and "the kernel would
// never" is the assumption that ages worst. Accepting one produced a Config
// that Validate then REFUSES -- so Discover could hand back a configuration
// that Apply will not take, breaking the save/restore round trip on a
// directory nobody here made. Treating it as "not an index directory", which
// is what any other unrecognised name gets, keeps discovery total.
//
// Found by a fuzz seed, not by reasoning: parseLUN("lun_-1") = (-1, true).
func parseTPGT(name string) (int, bool) {
	if !strings.HasPrefix(name, "tpgt_") {
		return 0, false
	}
	n, ok := atoi(strings.TrimPrefix(name, "tpgt_"))
	return n, ok && n >= 0
}

func parseLUN(name string) (int, bool) {
	if !strings.HasPrefix(name, "lun_") {
		return 0, false
	}
	n, ok := atoi(strings.TrimPrefix(name, "lun_"))
	return n, ok && n >= 0
}

// backstoreNameFromPath extracts the object name from a resolved
// symlink target like ".../core/fileio_0/test0".
func backstoreNameFromPath(p string) string {
	return lastPathSegment(p)
}

// lunIndexFromPath extracts N from ".../lun/lun_N".
func lunIndexFromPath(p string) int {
	if idx, ok := parseLUN(lastPathSegment(p)); ok {
		return idx
	}
	return 0
}

func lastPathSegment(p string) string {
	p = strings.TrimRight(p, "/")
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// DBRoot reports the kernel's target database root (configfs "dbroot",
// default /var/target). It is where LIO itself persists SCSI-3 Persistent
// Reservation APTPL metadata, as db_root/pr/aptpl_<wwn>.
//
// The kernel writes those files but never reads them back: restoring is a
// userspace responsibility (see SetAPTPLRecords). This accessor exists so
// callers can locate them without hardcoding the path; reading and parsing
// the files is deliberately left outside this package, which stays a pure
// configfs projection.
//
// Note db_root/pr must exist or the kernel cannot persist APTPL metadata:
// it logs a filp_open failure and answers PR OUT with NOT READY / "Logical
// unit communication failure" while still applying the change in memory.
func (m *Manager) DBRoot() (string, error) {
	v, err := m.fs.ReadAttr("dbroot")
	if err != nil {
		return "", errf(KindConfigfs, "read", "dbroot", err)
	}
	v = strings.TrimSpace(v)
	// An empty or relative value would silently resolve against the caller's
	// working directory, so every saved-state lookup would miss and restore
	// nothing — the failure mode this whole path exists to avoid.
	if !strings.HasPrefix(v, "/") {
		return "", errf(KindKernelRejected, "read", "dbroot",
			wrapf("kernel reported a non-absolute db_root %q", v))
	}
	return v, nil
}
