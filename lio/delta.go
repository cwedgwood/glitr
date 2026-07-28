package lio

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Incremental reconcile.
//
// Sync is a full-tree reconcile: it applies every object in the desired
// config, reads the entire live tree back, and prunes whatever is absent.
// That is the right primitive for startup replay and for recovering from
// drift, but it makes a single-object change cost O(total objects) — and a
// caller that reconciles on every mutation therefore gets slower as unrelated
// objects accumulate.
//
// Diff + ApplyDelta are the scoped counterpart, for a caller that already
// knows what changed because it holds the desired state itself. The saving is
// not a micro-optimisation: on a 200-volume tree a full Sync spends ~85ms
// reading the tree back purely so prune can discover that it has nothing to
// do, plus ~60-80ms re-walking objects that did not change.
//
// This does NOT replace Sync. A delta is only as good as the caller's belief
// about what is live, so the full reconcile remains the authority and must
// still run at startup and whenever that belief may be wrong.

// ErrStaleScope reports that a delta refers to objects that are no longer
// present, so the caller's view of the live tree is out of date. The correct
// response is a full Sync, not a retry: only Sync can rediscover what is
// actually there.
var ErrStaleScope = errors.New("lio: delta scope is stale")

// Delta is an incremental change to a live tree, as computed by Diff and
// applied by ApplyDelta.
//
// It exists so the two halves travel together and cannot be confused with the
// desired config: ApplyDelta previously took two adjacent Config parameters,
// which transpose silently — and transposing them reproduced exactly the
// fail-open this guard was added to close, because the narrower value passed
// as `desired` weakens the staleness check.
type Delta struct {
	Add    Config    // objects to create or update, applied like Apply
	Remove RemoveSet // objects to remove, in reverse dependency order
}

// Empty reports whether the delta would change nothing.
func (d Delta) Empty() bool {
	return len(d.Add.Backstores) == 0 && len(d.Add.Targets) == 0 && d.Remove.Empty()
}

// LUNRef identifies a TPG LUN.
type LUNRef struct {
	IQN   string
	Tag   int
	Index int
}

// MappedLUNRef identifies an ACL's mapped LUN.
type MappedLUNRef struct {
	IQN       string
	Tag       int
	Initiator string
	Index     int
}

// ACLRef identifies a NodeACL.
type ACLRef struct {
	IQN       string
	Tag       int
	Initiator string
}

// RemoveSet names individual objects to remove. Order within the set does
// not matter; ApplyDelta removes them in the same reverse dependency order
// prune uses (mapped LUNs → ACLs → LUNs → backstores), because an incoming
// mapped-LUN symlink holds a configfs reference on the TPG LUN it points at
// and a LUN holds one on its backstore — removing them out of order fails
// EBUSY.
type RemoveSet struct {
	MappedLUNs []MappedLUNRef
	ACLs       []ACLRef
	LUNs       []LUNRef
	Backstores []Backstore
}

// Empty reports whether there is nothing to remove.
func (r RemoveSet) Empty() bool {
	return len(r.MappedLUNs) == 0 && len(r.ACLs) == 0 && len(r.LUNs) == 0 && len(r.Backstores) == 0
}

func (r RemoveSet) count() int {
	return len(r.MappedLUNs) + len(r.ACLs) + len(r.LUNs) + len(r.Backstores)
}

// Diff computes the incremental change from prev to next.
//
// It returns a Delta -- the objects to create-or-update (d.Add) and the
// objects to remove (d.Remove) -- and whether the change is expressible as a
// delta at all.
//
// d.Add is applied with the same ensure* primitives as Apply -- additive and
// idempotent, never removing anything -- but ApplyDelta is NOT Apply: it does
// not call Config.Validate (a partial config cannot satisfy it, since
// Validate requires every LUN's backstore to be present in the same config)
// and it does not verify restored SCSI-3 PR registrations. See ApplyDelta.
//
// ok is false when the difference touches structure this deliberately does
// not attempt incrementally: targets appearing or disappearing, TPGs
// appearing or disappearing, portal or TPG-attribute changes. Those are rare,
// cheap relative to a whole reconcile, and each has ordering subtleties that
// are not worth duplicating outside Sync. A caller MUST fall back to a full
// Sync when ok is false — treating it as "nothing to do" would silently
// diverge from the desired state.
func Diff(prev, next Config) (d Delta, ok bool) {
	var add Config
	var rm RemoveSet
	// --- backstores: keyed by full configfs identity ---
	prevBS := map[string]Backstore{}
	for _, b := range prev.Backstores {
		prevBS[backstoreKey(b)] = b
	}
	nextBS := map[string]bool{}
	for _, b := range next.Backstores {
		k := backstoreKey(b)
		nextBS[k] = true
		if old, had := prevBS[k]; !had || !backstoreEqual(old, b) {
			// New, or changed (a resize alters Size). Apply handles both:
			// create, or reconcile the mutable attributes of a live object.
			add.Backstores = append(add.Backstores, b)
		}
	}
	for k, b := range prevBS {
		if !nextBS[k] {
			rm.Backstores = append(rm.Backstores, b)
		}
	}
	// A backstore identity is Type+HBA+Name, but a LUN references it by NAME
	// alone. So a backstore that keeps its name while moving Type or HBA is
	// added under the new key and removed under the old one, while its LUN
	// record is unchanged and therefore never re-emitted -- leaving the LUN
	// still pointing at the object being removed, which fails EBUSY.
	// Refuse rather than emit a delta that cannot be applied.
	for _, b := range next.Backstores {
		if movedIdentity(prevBS, b) {
			return Delta{}, false
		}
	}

	// --- targets and TPGs must match structurally ---
	if len(prev.Targets) != len(next.Targets) {
		return Delta{}, false
	}
	prevT := map[string]Target{}
	for _, t := range prev.Targets {
		prevT[t.IQN] = t
	}
	for _, nt := range next.Targets {
		pt, had := prevT[nt.IQN]
		if !had || len(pt.TPGs) != len(nt.TPGs) {
			return Delta{}, false
		}
		prevG := map[int]TPG{}
		for _, g := range pt.TPGs {
			prevG[g.Tag] = g
		}
		var addTPGs []TPG
		for _, ng := range nt.TPGs {
			pg, had := prevG[ng.Tag]
			if !had || pg.Enable != ng.Enable ||
				!sameStringMap(pg.Attributes, ng.Attributes) ||
				!samePortals(pg.Portals, ng.Portals) {
				return Delta{}, false
			}
			ag, changed := diffTPG(nt.IQN, pg, ng, &rm)
			if changed {
				addTPGs = append(addTPGs, ag)
			}
		}
		if len(addTPGs) > 0 {
			add.Targets = append(add.Targets, Target{IQN: nt.IQN, TPGs: addTPGs})
		}
	}
	// Every LUN in the delta must be accompanied by the backstore it names,
	// even when that backstore is UNCHANGED. ensureLUN resolves the name
	// through the config it is given, so a LUN pointing at an untouched
	// backstore would otherwise fail with "references unknown backstore" --
	// a delta that Diff called expressible but ApplyDelta cannot apply.
	//
	// This keeps `add` self-contained, which is the property callers
	// reasonably expect. Re-including an unchanged backstore is cheap:
	// ensureBackstore takes its already-configured early return.
	addReferencedBackstores(&add, next)
	return Delta{Add: add, Remove: rm}, true
}

// addReferencedBackstores ensures every backstore named by a LUN in add is
// present in add.Backstores, pulling unchanged ones from next.
func addReferencedBackstores(add *Config, next Config) {
	have := map[string]bool{}
	for _, b := range add.Backstores {
		have[b.Name] = true
	}
	byName := map[string]Backstore{}
	for _, b := range next.Backstores {
		byName[b.Name] = b
	}
	for _, t := range add.Targets {
		for _, g := range t.TPGs {
			for _, l := range g.LUNs {
				if have[l.Backstore] {
					continue
				}
				b, ok := byName[l.Backstore]
				if !ok {
					continue // Validate/ensureLUN will report it
				}
				add.Backstores = append(add.Backstores, b)
				have[l.Backstore] = true
			}
		}
	}
}

// diffTPG computes the within-TPG delta, appending removals to rm.
//
// The returned TPG carries only the LUNs and ACLs that need applying, so
// ensureTPG does not re-walk state Diff has already established is
// unchanged. Attributes and Portals are left empty deliberately: ensureTPG
// iterates those, so empty means "touch nothing".
//
// Enable is NOT in that category and MUST be carried. ensureTPG always
// writes the enable flag from the value it is given, so a zero TPG would
// write enable=0 and disable the target on every incremental apply --
// existing sessions survive, so the damage is invisible until the next
// login times out. Diff has already proven prev.Enable == next.Enable
// (otherwise it reports !ok), so passing it through costs one read and
// no write.
func diffTPG(iqn string, prev, next TPG, rm *RemoveSet) (TPG, bool) {
	out := TPG{Tag: next.Tag, Enable: next.Enable}
	changed := false

	prevLUN := map[int]LUN{}
	for _, l := range prev.LUNs {
		prevLUN[l.Index] = l
	}
	nextLUN := map[int]bool{}
	for _, l := range next.LUNs {
		nextLUN[l.Index] = true
		if old, had := prevLUN[l.Index]; !had || old != l {
			out.LUNs = append(out.LUNs, l)
			changed = true
		}
	}
	for idx := range prevLUN {
		if !nextLUN[idx] {
			rm.LUNs = append(rm.LUNs, LUNRef{IQN: iqn, Tag: prev.Tag, Index: idx})
		}
	}

	prevACL := map[string]ACL{}
	for _, a := range prev.ACLs {
		prevACL[a.InitiatorIQN] = a
	}
	nextACL := map[string]bool{}
	for _, na := range next.ACLs {
		nextACL[na.InitiatorIQN] = true
		pa, had := prevACL[na.InitiatorIQN]
		if !had {
			out.ACLs = append(out.ACLs, na)
			changed = true
			continue
		}
		prevML := map[int]MappedLUN{}
		for _, ml := range pa.MappedLUNs {
			prevML[ml.Index] = ml
		}
		var addML []MappedLUN
		nextML := map[int]bool{}
		for _, ml := range na.MappedLUNs {
			nextML[ml.Index] = true
			if old, had := prevML[ml.Index]; !had || old != ml {
				addML = append(addML, ml)
			}
		}
		for idx := range prevML {
			if !nextML[idx] {
				rm.MappedLUNs = append(rm.MappedLUNs, MappedLUNRef{
					IQN: iqn, Tag: prev.Tag, Initiator: na.InitiatorIQN, Index: idx})
			}
		}
		if len(addML) > 0 {
			out.ACLs = append(out.ACLs, ACL{InitiatorIQN: na.InitiatorIQN, MappedLUNs: addML})
			changed = true
		}
	}
	for iqnKey := range prevACL {
		if !nextACL[iqnKey] {
			rm.ACLs = append(rm.ACLs, ACLRef{IQN: iqn, Tag: prev.Tag, Initiator: iqnKey})
		}
	}
	return out, changed
}

// movedIdentity reports whether a backstore with the same NAME existed
// previously under a different configfs identity (Type or HBA).
func movedIdentity(prev map[string]Backstore, b Backstore) bool {
	for k, p := range prev {
		if p.Name == b.Name && k != backstoreKey(b) {
			return true
		}
	}
	return false
}

// backstoreEqual compares two backstore specs. Backstore is not comparable
// with == because it carries an Attributes map, and a shallow field compare
// that skipped the map would miss a managed-attribute change (block_size,
// emulate_write_cache) and silently drop it from the delta.
func backstoreEqual(a, b Backstore) bool {
	return a.Type == b.Type && a.HBA == b.HBA && a.Name == b.Name &&
		a.Dev == b.Dev && a.Size == b.Size && a.WWN == b.WWN &&
		a.BufferedIO == b.BufferedIO &&
		a.VendorID == b.VendorID && a.ProductID == b.ProductID &&
		a.Revision == b.Revision && sameStringMap(a.Attributes, b.Attributes)
}

func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		// Test PRESENCE, not just value. `b[k] != v` returns the zero string
		// for a missing key, so {"old": ""} and {"new": ""} compared equal --
		// same length, both lookups zero. That silently classified a real
		// attribute change as no change: for a TPG it skipped the required
		// ok=false fallback, and for a backstore it dropped the changed
		// object from the delta entirely.
		bv, ok := b[k]
		if !ok || bv != v {
			return false
		}
	}
	return true
}

func samePortals(a, b []Portal) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[netip.AddrPort]int{}
	for _, p := range a {
		seen[p.key()]++
	}
	for _, p := range b {
		seen[p.key()]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

// ApplyDelta applies an incremental change: create/update everything in
// d.Add, then remove everything in d.Remove.
//
// desired MUST be the caller's COMPLETE desired config — the same `next` the
// delta was computed against, not a subset. It is what the staleness check
// verifies against the live tree, so a narrower value silently weakens that
// guard: this is exactly how an earlier version let a removal-only delta
// succeed against a tree that had entirely vanished.
//
// Additions come first so that a change which re-points a mapped LUN at a new
// TPG LUN has the new object in place before the old one goes away, and
// removals run in reverse dependency order (mapped LUNs → ACLs → LUNs →
// backstores) because each of those holds a configfs reference on the next.
//
// Like Sync it is fail-stop and NOT transactional: a failure leaves a
// partially applied tree, and the caller is expected to converge by
// re-reconciling. Unlike Sync it cannot discover objects the caller did not
// know about, so it must not be the only reconcile a system ever performs.
//
// Two things Sync does that this does NOT, because a partial config cannot
// support them:
//
//   - Config.Validate is not called. Callers that accept untrusted desired
//     state must validate the WHOLE config themselves before diffing.
//   - Restored SCSI-3 PR registrations are not verified, so the returned
//     Report.APTPLUnbound is always nil -- which reads as "all bound". A
//     caller that relies on that signal must call VerifyAPTPL explicitly;
//     treating an empty value as reassurance is a fail-open.
func (m *Manager) ApplyDelta(desired Config, d Delta) (Report, error) {
	var tm SyncTimings

	// A delta only means anything against the tree the caller believes is
	// there. Verify that belief before touching anything.
	//
	// The scope checked is DESIRED, not merely what appears in add. Checking
	// add alone leaves the two most common shapes unguarded: a detach is
	// removals-only and a no-op mutation is empty, so both skip an add-based
	// check entirely -- and removals succeed vacuously, because Rmdir treats
	// an already-absent path as success. The result was ApplyDelta reporting
	// success against a tree that had completely vanished, after which the
	// caller refreshes its cache and reports healthy while serving nothing.
	//
	// That is reachable without any bug here: reload the kernel modules, or
	// wipe /sys/kernel/config/target, while the daemon runs. Before
	// incremental reconcile every mutation rebuilt the whole tree, so this
	// self-healed; refusing here lets the caller fall back to Sync and
	// restores that.
	if err := m.checkScope(desired); err != nil {
		return Report{}, err
	}

	a := &applyCtx{fs: m.fs, stateBackstores: map[string]Backstore{}, aptplRecords: m.aptplRecords}
	for _, b := range d.Add.Backstores {
		a.stateBackstores[b.Name] = b
	}

	t0 := time.Now()
	for _, b := range d.Add.Backstores {
		if err := a.ensureBackstore(b); err != nil {
			tm.Apply = time.Since(t0)
			return Report{Changes: a.changes, Drift: a.drift, Timings: tm}, err
		}
	}
	for _, t := range d.Add.Targets {
		if err := a.ensureTarget(t); err != nil {
			tm.Apply = time.Since(t0)
			return Report{Changes: a.changes, Drift: a.drift, Timings: tm}, err
		}
	}
	tm.Apply = time.Since(t0)

	t0 = time.Now()
	if err := a.applyRemovals(d.Remove); err != nil {
		tm.Prune = time.Since(t0)
		return Report{Changes: a.changes, Drift: a.drift, Timings: tm}, err
	}
	tm.Prune = time.Since(t0)

	return Report{Changes: a.changes, Drift: a.drift, Timings: tm}, nil
}

// checkScope reports ErrStaleScope if the targets/TPGs the desired config
// relies on are not present, meaning an incremental apply would be reasoning
// about a tree that no longer exists.
func (m *Manager) checkScope(desired Config) error {
	for _, t := range desired.Targets {
		for _, g := range t.TPGs {
			ok, err := m.fs.Exists(tpgPath(t.IQN, g.Tag)...)
			if err != nil {
				return errf(KindConfigfs, "apply-delta", "tpg/"+t.IQN, err)
			}
			if !ok {
				return fmt.Errorf("%w: tpg/%s/tpgt_%d is absent, so this delta "+
					"describes a tree that no longer exists", ErrStaleScope, t.IQN, g.Tag)
			}
		}
	}
	return nil
}

// applyRemovals removes rm's objects in reverse dependency order.
func (a *applyCtx) applyRemovals(rm RemoveSet) error {
	for _, r := range rm.MappedLUNs {
		if err := a.removeMappedLUN(r.IQN, r.Tag, r.Initiator, r.Index); err != nil {
			return err
		}
		a.note(fmt.Sprintf("removed mappedlun/%s/lun_%d", r.Initiator, r.Index))
	}
	for _, r := range rm.ACLs {
		if err := a.removeACL(r.IQN, r.Tag, r.Initiator); err != nil {
			return err
		}
		a.note("removed acl/" + r.IQN + "/" + r.Initiator)
	}
	for _, r := range rm.LUNs {
		if err := a.removeLUN(r.IQN, r.Tag, r.Index); err != nil {
			return err
		}
		a.note(fmt.Sprintf("removed lun/%s/lun_%d", r.IQN, r.Index))
	}
	for _, b := range rm.Backstores {
		if err := a.removeBackstore(b); err != nil {
			return err
		}
	}
	return nil
}

// VerifyAPTPL reports restored SCSI-3 PR registrations that did not bind, for
// the given desired config. Sync does this itself; a caller reconciling
// incrementally via ApplyDelta must call it explicitly, or the pr_unbound
// signal goes stale — and a stale "all bound" answer is exactly the silent
// fail-open the reporting exists to prevent.
//
// It is a read-only check and cheap relative to a reconcile (a small file
// read, and one or two attribute reads per backstore -- the second only when
// a saved reservation holder is still exported).
//
// IT ANSWERS NOTHING UNLESS SetAPTPLRecords HAS BEEN CALLED. With no saved-PR
// provider installed there is nothing to verify restored registrations
// against, so this returns nil -- which is shaped exactly like "all bound".
// That is the same fail-open Report.APTPLUnbound documents for ApplyDelta, and
// it applies here too: a consumer that wires up this library without a
// provider gets a permanent silent reassurance from the one function whose job
// is to withhold it. Install a provider, or do not treat nil as an answer.
func (m *Manager) VerifyAPTPL(cfg Config) []string {
	a := &applyCtx{fs: m.fs, aptplRecords: m.aptplRecords}
	return a.verifyAPTPL(cfg)
}
