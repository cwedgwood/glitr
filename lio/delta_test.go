package lio

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cwedgwood/glitr/lio/configfs"
)

func baseCfg() Config {
	return Config{
		Backstores: []Backstore{
			{Type: FileIO, HBA: 0, Name: "vol_a", Dev: "/d/a.img", Size: 1 << 20, WWN: "aaaaaaaaaaaaaaaa"},
			{Type: FileIO, HBA: 1, Name: "vol_b", Dev: "/d/b.img", Size: 1 << 20, WWN: "bbbbbbbbbbbbbbbb"},
		},
		Targets: []Target{{IQN: "iqn.2026-01.dev.glitr:t", TPGs: []TPG{{
			Tag:        1,
			Enable:     true,
			Attributes: map[string]string{"authentication": "0"},
			Portals:    []Portal{{IP: mustAddr("10.0.0.1"), Port: 3260}},
			LUNs:       []LUN{{Index: 0, Backstore: "vol_a"}, {Index: 1, Backstore: "vol_b"}},
			ACLs: []ACL{{InitiatorIQN: "iqn.1993-08.org.debian:01:h1",
				MappedLUNs: []MappedLUN{{Index: 10, TPGLUN: 0}, {Index: 11, TPGLUN: 1}}}},
		}}}},
	}
}

func tpg0(c Config) *TPG { return &c.Targets[0].TPGs[0] }

// TestDiffNoChange: the whole point of the delta path is that an unchanged
// config costs nothing. If this produced work, every mutation would still
// touch every object.
func TestDiffNoChange(t *testing.T) {
	d, ok := Diff(baseCfg(), baseCfg())
	add, rm := d.Add, d.Remove
	if !ok {
		t.Fatal("identical configs must be expressible as a delta")
	}
	if len(add.Backstores) != 0 || len(add.Targets) != 0 {
		t.Errorf("nothing to add, got %+v", add)
	}
	if !rm.Empty() {
		t.Errorf("nothing to remove, got %+v", rm)
	}
}

// TestDiffAddVolume is the hot path: exporting one more volume must produce
// exactly one backstore, one LUN and one mapped LUN — not the whole tree.
func TestDiffAddVolume(t *testing.T) {
	prev := baseCfg()
	next := baseCfg()
	next.Backstores = append(next.Backstores, Backstore{
		Type: FileIO, HBA: 2, Name: "vol_c", Dev: "/d/c.img", Size: 1 << 20, WWN: "cccccccccccccccc"})
	g := tpg0(next)
	g.LUNs = append(g.LUNs, LUN{Index: 2, Backstore: "vol_c"})
	g.ACLs[0].MappedLUNs = append(g.ACLs[0].MappedLUNs, MappedLUN{Index: 12, TPGLUN: 2})

	d, ok := Diff(prev, next)
	add, rm := d.Add, d.Remove
	if !ok {
		t.Fatal("adding a volume must be expressible as a delta")
	}
	if len(add.Backstores) != 1 || add.Backstores[0].Name != "vol_c" {
		t.Fatalf("want only vol_c added, got %+v", add.Backstores)
	}
	if len(add.Targets) != 1 || len(add.Targets[0].TPGs) != 1 {
		t.Fatalf("want one TPG in the delta, got %+v", add.Targets)
	}
	ag := add.Targets[0].TPGs[0]
	if len(ag.LUNs) != 1 || ag.LUNs[0].Index != 2 {
		t.Errorf("want only lun 2, got %+v", ag.LUNs)
	}
	if len(ag.ACLs) != 1 || len(ag.ACLs[0].MappedLUNs) != 1 || ag.ACLs[0].MappedLUNs[0].Index != 12 {
		t.Errorf("want only mapped lun 12, got %+v", ag.ACLs)
	}
	// Portals and attributes are unchanged, so the delta must not re-walk
	// them: that is the work we are trying to avoid. ensureTPG iterates
	// those, so empty means "touch nothing".
	if len(ag.Portals) != 0 || len(ag.Attributes) != 0 {
		t.Errorf("unchanged portals/attributes must not be in the delta, got %+v", ag)
	}
	// Enable is NOT in that category: ensureTPG always writes it from the
	// value given, so a zero TPG would write enable=0 and disable the target
	// on every incremental apply. Existing sessions survive that, so the
	// damage stays invisible until the next login times out -- which is
	// exactly how it was found.
	if !ag.Enable {
		t.Error("delta must carry Enable, or an incremental apply disables the TPG")
	}
	if !rm.Empty() {
		t.Errorf("nothing to remove, got %+v", rm)
	}
}

// TestDiffRemoveVolume checks the removal side, including that the objects
// come back in the set at all — a missed removal leaks a live export.
func TestDiffRemoveVolume(t *testing.T) {
	prev := baseCfg()
	next := baseCfg()
	next.Backstores = next.Backstores[:1] // drop vol_b
	g := tpg0(next)
	g.LUNs = g.LUNs[:1]
	g.ACLs[0].MappedLUNs = g.ACLs[0].MappedLUNs[:1]

	d, ok := Diff(prev, next)
	add, rm := d.Add, d.Remove
	if !ok {
		t.Fatal("removing a volume must be expressible as a delta")
	}
	if len(add.Backstores) != 0 {
		t.Errorf("nothing to add, got %+v", add.Backstores)
	}
	if len(rm.Backstores) != 1 || rm.Backstores[0].Name != "vol_b" {
		t.Errorf("want vol_b removed, got %+v", rm.Backstores)
	}
	if len(rm.LUNs) != 1 || rm.LUNs[0].Index != 1 {
		t.Errorf("want lun 1 removed, got %+v", rm.LUNs)
	}
	if len(rm.MappedLUNs) != 1 || rm.MappedLUNs[0].Index != 11 {
		t.Errorf("want mapped lun 11 removed, got %+v", rm.MappedLUNs)
	}
}

// TestDiffBackstoreAttributeChange: Backstore carries a map, so a naive
// field-by-field compare would miss a managed-attribute change and silently
// drop it from the delta.
func TestDiffBackstoreAttributeChange(t *testing.T) {
	prev := baseCfg()
	prev.Backstores[0].Attributes = map[string]string{"emulate_write_cache": "0"}
	next := baseCfg()
	next.Backstores[0].Attributes = map[string]string{"emulate_write_cache": "1"}

	d, ok := Diff(prev, next)
	add := d.Add
	if !ok {
		t.Fatal("an attribute change must be expressible as a delta")
	}
	if len(add.Backstores) != 1 || add.Backstores[0].Name != "vol_a" {
		t.Fatalf("changed backstore must be in the delta, got %+v", add.Backstores)
	}
}

// TestDiffResize: a resize changes Size only, and must still be applied.
func TestDiffResize(t *testing.T) {
	prev := baseCfg()
	next := baseCfg()
	next.Backstores[0].Size = 4 << 20
	d, ok := Diff(prev, next)
	add, rm := d.Add, d.Remove
	if !ok || len(add.Backstores) != 1 || add.Backstores[0].Size != 4<<20 {
		t.Fatalf("resize must appear in the delta: ok=%v add=%+v", ok, add.Backstores)
	}
	if !rm.Empty() {
		t.Errorf("a resize removes nothing, got %+v", rm)
	}
}

// TestDiffHostLifecycle: adding and removing a whole ACL.
func TestDiffHostLifecycle(t *testing.T) {
	prev := baseCfg()
	next := baseCfg()
	tpg0(next).ACLs = append(tpg0(next).ACLs, ACL{InitiatorIQN: "iqn.1993-08.org.debian:01:h2"})
	d, ok := Diff(prev, next)
	add := d.Add
	if !ok || len(add.Targets) != 1 || len(add.Targets[0].TPGs[0].ACLs) != 1 {
		t.Fatalf("new ACL must be in the delta: ok=%v add=%+v", ok, add)
	}

	d2, ok := Diff(next, prev)
	rm := d2.Remove
	if !ok {
		t.Fatal("removing an ACL must be expressible as a delta")
	}
	if len(rm.ACLs) != 1 || rm.ACLs[0].Initiator != "iqn.1993-08.org.debian:01:h2" {
		t.Errorf("want the ACL removed, got %+v", rm.ACLs)
	}
}

// TestDiffFallsBackOnStructuralChange is the safety property. Anything the
// delta path does not handle MUST report ok=false so the caller runs a full
// Sync. Reporting "no change" for these would silently diverge from desired
// state — the failure mode would be a volume that is configured but not
// actually exported.
func TestDiffFallsBackOnStructuralChange(t *testing.T) {
	cases := map[string]func(c *Config){
		"target added": func(c *Config) {
			c.Targets = append(c.Targets, Target{IQN: "iqn.2026-01.dev.glitr:other"})
		},
		"target renamed": func(c *Config) { c.Targets[0].IQN = "iqn.2026-01.dev.glitr:renamed" },
		"tpg added": func(c *Config) {
			c.Targets[0].TPGs = append(c.Targets[0].TPGs, TPG{Tag: 2})
		},
		"portal added": func(c *Config) {
			g := tpg0(*c)
			g.Portals = append(g.Portals, Portal{IP: mustAddr("10.0.0.2"), Port: 3260})
		},
		"portal changed": func(c *Config) { tpg0(*c).Portals[0].IP = mustAddr("10.0.0.9") },
		"tpg attribute changed": func(c *Config) {
			tpg0(*c).Attributes = map[string]string{"authentication": "1"}
		},
		"tpg disabled": func(c *Config) { tpg0(*c).Enable = false },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			next := baseCfg()
			// mutate operates on the shared slice header; rebuild to be safe.
			c := next
			mutate(&c)
			if _, ok := Diff(baseCfg(), c); ok {
				t.Error("must fall back to a full Sync, got ok=true")
			}
		})
	}
}

// TestDiffTargetRemovedFallsBack: dropping the last target is structural.
func TestDiffTargetRemovedFallsBack(t *testing.T) {
	next := baseCfg()
	next.Targets = nil
	if _, ok := Diff(baseCfg(), next); ok {
		t.Error("removing a target must fall back to a full Sync")
	}
}

// TestRemoveSetFieldOrderGuardsRemovalOrder does NOT execute ApplyDelta, and
// does NOT prove removal order -- nothing ties struct declaration order to the
// loop order in applyRemovals (see TestApplyDeltaExecutesRemovals for why a
// unit test cannot prove it). It pins the field set so that a new object kind
// cannot be added to RemoveSet without the author noticing that declaration
// order is the documented statement of removal order.
func TestRemoveSetFieldOrderGuardsRemovalOrder(t *testing.T) {
	rm := RemoveSet{
		Backstores: []Backstore{{Type: FileIO, HBA: 0, Name: "vol_a"}},
		LUNs:       []LUNRef{{IQN: "t", Tag: 1, Index: 0}},
		ACLs:       []ACLRef{{IQN: "t", Tag: 1, Initiator: "i1"}},
		MappedLUNs: []MappedLUNRef{{IQN: "t", Tag: 1, Initiator: "i1", Index: 10}},
	}
	if rm.Empty() {
		t.Fatal("RemoveSet with content reported Empty")
	}
	if rm.count() != 4 {
		t.Errorf("count = %d, want 4", rm.count())
	}

	// Declaration order documents removal order; the behaviour itself is
	// exercised only by the live kernel suites (see the note on
	// TestApplyDeltaExecutesRemovals).
	want := []string{"MappedLUNs", "ACLs", "LUNs", "Backstores"}
	var got []string
	rt := reflect.TypeFor[RemoveSet]()
	for i := range rt.NumField() {
		got = append(got, rt.Field(i).Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RemoveSet fields = %v, want %v (declaration order documents removal order)", got, want)
	}
}

// TestDiffAlwaysCarriesEnable guards the regression directly: whatever else a
// delta contains, it must never hand ensureTPG a TPG whose Enable is false
// while the desired state is enabled. ensureTPG writes that flag
// unconditionally, so getting it wrong silently stops the target accepting
// new logins while every existing session carries on working.
func TestDiffAlwaysCarriesEnable(t *testing.T) {
	prev := baseCfg()
	for name, mutate := range map[string]func(c *Config){
		"add lun": func(c *Config) {
			g := tpg0(*c)
			g.LUNs = append(g.LUNs, LUN{Index: 9, Backstore: "vol_a"})
		},
		"add mapped lun": func(c *Config) {
			g := tpg0(*c)
			g.ACLs[0].MappedLUNs = append(g.ACLs[0].MappedLUNs, MappedLUN{Index: 19, TPGLUN: 0})
		},
		"add acl": func(c *Config) {
			g := tpg0(*c)
			g.ACLs = append(g.ACLs, ACL{InitiatorIQN: "iqn.1993-08.org.debian:01:h9"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			next := baseCfg()
			mutate(&next)
			d, ok := Diff(prev, next)
			add := d.Add
			if !ok {
				t.Fatal("expected a delta")
			}
			for _, tg := range add.Targets {
				for _, g := range tg.TPGs {
					if !g.Enable {
						t.Errorf("delta TPG tag %d has Enable=false; an incremental apply would disable the target", g.Tag)
					}
				}
			}
		})
	}
}

// --- ApplyDelta executed against a synthetic tree -------------------------
//
// Every test above stops at Diff. That gap is exactly how the Enable bug
// survived: a delta can look perfectly correct and still make ensure* write
// the wrong thing. These run ApplyDelta for real.

// stageTree builds a minimal live tree: one target/TPG with one backstore,
// TPG LUN 0 and a mapped LUN, mirroring what Apply would have produced.
// withAttrs stages the backstore's synthetic attribute files, which
// ensureBackstore needs. Removal tests pass false: configfs rmdir destroys an
// object and its attributes together, but a tmpdir's os.Remove refuses a
// non-empty directory, so the attribute files would be an artifact of the
// harness rather than of the code under test.
func stageTree(t *testing.T, root, iqn, ini string, withAttrs bool) {
	t.Helper()
	mk := func(parts ...string) string {
		p := filepath.Join(append([]string{root}, parts...)...)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	wr := func(val string, parts ...string) {
		p := filepath.Join(append([]string{root}, parts...)...)
		if err := os.WriteFile(p, []byte(val+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("core", "fileio_0", "vol_a")
	if withAttrs {
		for _, sub := range []string{"wwn", "pr", "attrib"} {
			mk("core", "fileio_0", "vol_a", sub)
		}
		wr("/d/a.img", "core", "fileio_0", "vol_a", "udev_path")
		wr("1", "core", "fileio_0", "vol_a", "enable")
		wr("TCM FILEIO ID: 0  File: /d/a.img  Size: 1048576  Mode: O_DSYNC",
			"core", "fileio_0", "vol_a", "info")
	}

	mk("iscsi", iqn, "tpgt_1", "np", "10.0.0.1:3260")
	wr("1", "iscsi", iqn, "tpgt_1", "enable")
	ld := mk("iscsi", iqn, "tpgt_1", "lun", "lun_0")
	if err := os.Symlink(filepath.Join(root, "core", "fileio_0", "vol_a"),
		filepath.Join(ld, "link")); err != nil {
		t.Fatal(err)
	}
	md := mk("iscsi", iqn, "tpgt_1", "acls", ini, "lun_10")
	if err := os.Symlink(ld, filepath.Join(md, "link")); err != nil {
		t.Fatal(err)
	}
}

func exists(t *testing.T, root string, parts ...string) bool {
	t.Helper()
	_, err := os.Lstat(filepath.Join(append([]string{root}, parts...)...))
	return err == nil
}

// TestApplyDeltaExecutesRemovals executes ApplyDelta and checks every named
// object is gone afterwards.
//
// It does NOT prove dependency ORDER, despite what an earlier version of this
// comment claimed. A tmpdir has no configfs reference counting: an incoming
// symlink does not pin its target directory, so removing a LUN before its
// mapped LUN succeeds here and fails EBUSY against the kernel. Verified by
// experiment -- reversing the four loops in applyRemovals leaves this test
// green.
//
// Order is therefore DOCUMENTED by the declaration-order check in
// TestRemoveSetFieldOrderGuardsRemovalOrder -- a convention reminder, not a
// guard, since reversing the loops leaves that test green too -- and GUARDED
// by the live suites -- PR persistence, snapshots and filesystem fencing --
// which unmap and delete volumes against a real kernel and would fail EBUSY
// on the wrong order. Proving it in a unit test would need a fault-injecting FS
// abstraction that lio/configfs does not currently offer.
func TestApplyDeltaExecutesRemovals(t *testing.T) {
	root := t.TempDir()
	iqn, ini := "iqn.2026-01.dev.glitr:t", "iqn.1993-08.org.debian:01:h1"
	stageTree(t, root, iqn, ini, false)

	m := New(configfs.New(root))
	rm := RemoveSet{
		MappedLUNs: []MappedLUNRef{{IQN: iqn, Tag: 1, Initiator: ini, Index: 10}},
		LUNs:       []LUNRef{{IQN: iqn, Tag: 1, Index: 0}},
		Backstores: []Backstore{{Type: FileIO, HBA: 0, Name: "vol_a"}},
	}
	if _, err := m.ApplyDelta(liveScope(iqn), Delta{Remove: rm}); err != nil {
		t.Fatalf("ApplyDelta: %v", err)
	}
	if exists(t, root, "iscsi", iqn, "tpgt_1", "acls", ini, "lun_10") {
		t.Error("mapped LUN should have been removed")
	}
	if exists(t, root, "iscsi", iqn, "tpgt_1", "lun", "lun_0") {
		t.Error("TPG LUN should have been removed")
	}
	if exists(t, root, "core", "fileio_0", "vol_a") {
		t.Error("backstore should have been removed")
	}
}

// TestApplyDeltaLUNOnUnchangedBackstore is the regression for the bug all
// four reviewers found: Diff emitted a LUN whose backstore was unchanged, so
// add carried no backstore, and ensureLUN failed with "references unknown
// backstore" on a delta Diff had declared expressible.
func TestApplyDeltaLUNOnUnchangedBackstore(t *testing.T) {
	root := t.TempDir()
	iqn, ini := "iqn.2026-01.dev.glitr:t", "iqn.1993-08.org.debian:01:h1"
	stageTree(t, root, iqn, ini, true)

	prev := Config{
		Backstores: []Backstore{{Type: FileIO, HBA: 0, Name: "vol_a", Dev: "/d/a.img", Size: 1 << 20}},
		Targets: []Target{{IQN: iqn, TPGs: []TPG{{Tag: 1, Enable: true,
			Portals: []Portal{{IP: mustAddr("10.0.0.1"), Port: 3260}},
			LUNs:    []LUN{{Index: 0, Backstore: "vol_a"}},
			ACLs:    []ACL{{InitiatorIQN: ini, MappedLUNs: []MappedLUN{{Index: 10, TPGLUN: 0}}}}}}}},
	}
	next := prev
	g := prev.Targets[0].TPGs[0]
	g.LUNs = append(append([]LUN{}, g.LUNs...), LUN{Index: 5, Backstore: "vol_a"})
	next.Targets = []Target{{IQN: iqn, TPGs: []TPG{g}}}

	d, ok := Diff(prev, next)
	add, rm := d.Add, d.Remove
	if !ok {
		t.Fatal("adding a LUN on an existing backstore must be expressible")
	}
	if len(add.Backstores) == 0 {
		t.Fatal("add must carry the backstore its LUN names, or ApplyDelta cannot resolve it")
	}
	if _, err := m0(root).ApplyDelta(next, Delta{Add: add, Remove: rm}); err != nil {
		t.Fatalf("ApplyDelta rejected a delta Diff said was expressible: %v", err)
	}
	if !exists(t, root, "iscsi", iqn, "tpgt_1", "lun", "lun_5") {
		t.Error("lun_5 should have been created")
	}
}

func m0(root string) *Manager { return New(configfs.New(root)) }

// liveScope is the minimal desired config naming the tree staged by
// stageTree, for ApplyDelta's scope check.
func liveScope(iqn string) Config {
	return Config{Targets: []Target{{IQN: iqn, TPGs: []TPG{{Tag: 1, Enable: true}}}}}
}

// TestApplyDeltaRefusesVanishedTree: a delta describes a change to a tree
// that exists. If the TPG is gone, applying anyway would CREATE it from the
// partial config -- no portals, no managed attributes -- enable it, and
// report success, leaving a healthy-looking target nobody can reach.
func TestApplyDeltaRefusesVanishedTree(t *testing.T) {
	root := t.TempDir() // deliberately empty: nothing staged
	add := Config{Targets: []Target{{IQN: "iqn.2026-01.dev.glitr:t",
		TPGs: []TPG{{Tag: 1, Enable: true}}}}}

	_, err := m0(root).ApplyDelta(add, Delta{Add: add})
	if err == nil {
		t.Fatal("ApplyDelta must refuse to apply a delta to a tree that is not there")
	}
	if !errors.Is(err, ErrStaleScope) {
		t.Errorf("error must be ErrStaleScope so the caller can fall back to Sync, got %v", err)
	}
	if exists(t, root, "iscsi", "iqn.2026-01.dev.glitr:t", "tpgt_1") {
		t.Error("ApplyDelta must not have created the target/TPG")
	}
}

// TestSameStringMapDetectsKeyRename: {"a":""} and {"b":""} have equal length
// and both lookups return the zero string, so a value-only comparison called
// them equal and silently dropped a real change.
func TestSameStringMapDetectsKeyRename(t *testing.T) {
	if sameStringMap(map[string]string{"old": ""}, map[string]string{"new": ""}) {
		t.Error("maps with different keys must not compare equal")
	}
	if sameStringMap(map[string]string{"k": "v"}, map[string]string{"k": "v"}) == false {
		t.Error("identical maps must compare equal")
	}
	prev := baseCfg()
	prev.Backstores[0].Attributes = map[string]string{"old_attr": ""}
	next := baseCfg()
	next.Backstores[0].Attributes = map[string]string{"new_attr": ""}
	d, ok := Diff(prev, next)
	add := d.Add
	if !ok || len(add.Backstores) != 1 {
		t.Errorf("a renamed attribute key must appear in the delta: ok=%v add=%+v", ok, add.Backstores)
	}
}

// TestApplyDeltaRefusesVanishedTreeOnRemovalOnly is the round-2 regression.
//
// The first version of the staleness guard only inspected add.Targets, which
// left the two commonest shapes unguarded: a detach is removals-only and a
// no-op mutation is empty. Removals then succeed vacuously — Rmdir treats an
// absent path as success — so ApplyDelta reported success against a tree that
// had entirely vanished, and the caller went on to refresh its cache and
// report healthy while serving nothing.
func TestApplyDeltaRefusesVanishedTreeOnRemovalOnly(t *testing.T) {
	iqn := "iqn.2026-01.dev.glitr:t"
	desired := liveScope(iqn)

	for name, rm := range map[string]RemoveSet{
		"removal-only": {
			MappedLUNs: []MappedLUNRef{{IQN: iqn, Tag: 1, Initiator: "iqn.x:h", Index: 10}},
			LUNs:       []LUNRef{{IQN: iqn, Tag: 1, Index: 0}},
			Backstores: []Backstore{{Type: FileIO, HBA: 0, Name: "vol_a"}},
		},
		"empty delta": {},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir() // the tree is gone
			_, err := m0(root).ApplyDelta(desired, Delta{Remove: rm})
			if err == nil {
				t.Fatal("ApplyDelta reported success against a vanished tree; " +
					"the caller would refresh its cache and report healthy while serving nothing")
			}
			if !errors.Is(err, ErrStaleScope) {
				t.Errorf("must be ErrStaleScope so the caller falls back to Sync, got %v", err)
			}
		})
	}
}

// TestDiffRefusesBackstoreIdentityMove: a backstore keeping its NAME while
// moving Type or HBA changes its configfs identity, so it is added under the
// new key and removed under the old one -- but a LUN references it by name
// only, so the LUN record is unchanged and never re-emitted. The LUN would
// still point at the object being removed, which fails EBUSY. Diff must
// refuse rather than emit a delta that cannot be applied.
func TestDiffRefusesBackstoreIdentityMove(t *testing.T) {
	for name, mutate := range map[string]func(b *Backstore){
		"HBA moved":  func(b *Backstore) { b.HBA = 7 },
		"type moved": func(b *Backstore) { b.Type = IBlock },
	} {
		t.Run(name, func(t *testing.T) {
			next := baseCfg()
			mutate(&next.Backstores[0]) // vol_a keeps its name
			if _, ok := Diff(baseCfg(), next); ok {
				t.Error("must fall back to a full Sync; the unchanged LUN would still pin the old object")
			}
		})
	}
}
