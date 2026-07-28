package lio

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cwedgwood/glitr/lio/configfs"
)

// TestPruneFakeTree checks that prune removes exactly the objects absent
// from the desired Config, on a synthetic configfs tree (prune only does
// rmdir/unlink, which work on a plain tmpdir).
func TestPruneFakeTree(t *testing.T) {
	root := t.TempDir()
	iqn := "iqn.2026-01.dev.glitr:t"
	ini := "iqn.2026-01.dev.glitr:i1"

	mk := func(parts ...string) {
		if err := os.MkdirAll(filepath.Join(append([]string{root}, parts...)...), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	wr := func(val string, parts ...string) {
		p := filepath.Join(append([]string{root}, parts...)...)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(val+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// backstore
	mk("core", "fileio_0", "test0", "wwn")
	wr("/tmp/x.img", "core", "fileio_0", "test0", "udev_path")
	// target/tpg/enable
	wr("1", "iscsi", iqn, "tpgt_1", "enable")
	// two portals
	mk("iscsi", iqn, "tpgt_1", "np", "10.10.0.1:3260")
	mk("iscsi", iqn, "tpgt_1", "np", "10.10.0.1:3261")
	// lun0 -> backstore
	ld := filepath.Join(root, "iscsi", iqn, "tpgt_1", "lun", "lun_0")
	_ = os.MkdirAll(ld, 0o755)
	_ = os.Symlink(filepath.Join(root, "core", "fileio_0", "test0"), filepath.Join(ld, "aa11"))
	// acl + mapped lun
	md := filepath.Join(root, "iscsi", iqn, "tpgt_1", "acls", ini, "lun_0")
	_ = os.MkdirAll(md, 0o755)
	_ = os.Symlink(filepath.Join(root, "iscsi", iqn, "tpgt_1", "lun", "lun_0"), filepath.Join(md, "bb22"))

	fs := configfs.New(root)
	m := New(fs)
	actual, err := m.Discover()
	if err != nil {
		t.Fatal(err)
	}

	// desired: keep target/tpg/lun/backstore, drop portal 3261 and the ACL.
	desired := Config{
		Backstores: actual.Backstores,
		Targets: []Target{{IQN: iqn, TPGs: []TPG{{
			Tag:     1,
			Enable:  true,
			Portals: []Portal{{IP: mustAddr("10.10.0.1"), Port: 3260}},
			LUNs:    []LUN{{Index: 0, Backstore: "test0"}},
		}}}},
	}

	a := &applyCtx{fs: fs}
	if err := a.prune(desired, actual); err != nil {
		t.Fatalf("prune: %v", err)
	}

	exists := func(parts ...string) bool {
		_, err := os.Stat(filepath.Join(append([]string{root}, parts...)...))
		return err == nil
	}
	if exists("iscsi", iqn, "tpgt_1", "np", "10.10.0.1:3261") {
		t.Error("portal 3261 should have been pruned")
	}
	if !exists("iscsi", iqn, "tpgt_1", "np", "10.10.0.1:3260") {
		t.Error("portal 3260 should have been kept")
	}
	if exists("iscsi", iqn, "tpgt_1", "acls", ini) {
		t.Error("acl should have been pruned")
	}
	if !exists("iscsi", iqn, "tpgt_1", "lun", "lun_0") {
		t.Error("lun_0 should have been kept")
	}
	if !exists("core", "fileio_0", "test0") {
		t.Error("backstore should have been kept (still in desired)")
	}
}

// TestSyncWildcardToExplicitPortals is the regression test for a crash loop.
//
// A wildcard and a specific address cannot share a port: SO_REUSEADDR is set
// but SO_REUSEPORT is not, so the kernel refuses the second bind with
// EADDRINUSE (measured, "kernel_bind() failed: -98"). Sync adds before it
// prunes -- correct everywhere else, because it means no LUN ever disappears
// mid-reconcile -- so moving a target from 0.0.0.0 to explicit addresses tried
// to bind the new portal against the wildcard that was still there. Both
// configurations are individually valid, so validation cannot catch it; only
// the ordering can, and under Restart=on-failure it crash-looped.
//
// A tmpdir cannot reproduce EADDRINUSE, so what this pins is the ORDERING: the
// conflicting wildcard must be gone by the time the explicit portals are
// created. That is the property the fix rests on.
func TestSyncWildcardToExplicitPortals(t *testing.T) {
	root := t.TempDir()
	iqn := "iqn.2026-01.dev.glitr:t"
	mk := func(parts ...string) {
		if err := os.MkdirAll(filepath.Join(append([]string{root}, parts...)...), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A live tree already bound to the wildcard, as configfs would present it.
	mk("iscsi", iqn, "tpgt_1", "np", "0.0.0.0:3260")
	mk("iscsi", iqn, "tpgt_1", "lun")
	mk("iscsi", iqn, "tpgt_1", "acls")
	if err := os.WriteFile(filepath.Join(root, "iscsi", iqn, "tpgt_1", "enable"),
		[]byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := New(configfs.New(root))
	explicit := Config{Targets: []Target{{IQN: iqn, TPGs: []TPG{{
		Tag: 1, Enable: true, Portals: []Portal{
			{IP: mustAddr("10.0.0.1"), Port: 3260},
			{IP: mustAddr("10.0.0.2"), Port: 3260},
		},
	}}}}}

	// The pre-prune is tested DIRECTLY rather than through Sync's end state.
	// A tmpdir cannot refuse the conflicting bind the way the kernel does, so
	// the apply succeeds either way and the tree converges with or without the
	// fix -- an end-state assertion here passes even with the ordering
	// reverted, which is what a negative control showed. What must be pinned
	// is that the wildcard is gone BEFORE anything is applied.
	if err := m.pruneConflictingPortals(explicit); err != nil {
		t.Fatalf("pre-prune: %v", err)
	}
	np := filepath.Join(root, "iscsi", iqn, "tpgt_1", "np")
	entries, err := os.ReadDir(np)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, e := range entries {
		left = append(left, e.Name())
	}
	if len(left) != 0 {
		t.Errorf("np still holds %v after the pre-prune -- the conflicting wildcard must be "+
			"removed before the explicit portals are bound, or the kernel refuses them "+
			"with EADDRINUSE and the daemon crash-loops", left)
	}

	// And the whole reconcile still converges.
	if _, err := m.Sync(explicit); err != nil {
		t.Fatalf("wildcard -> explicit must converge: %v", err)
	}
	got, err := m.Discover()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tg := range got.Targets {
		for _, g := range tg.TPGs {
			for _, p := range g.Portals {
				names = append(names, p.String())
			}
		}
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"10.0.0.1:3260", "10.0.0.2:3260"}) {
		t.Errorf("portals = %v, want the explicit pair", names)
	}
}

// TestSyncKeepsUnconflictingPortals: only genuine conflicts are pre-pruned.
// A live portal that contends with nothing desired is left to the ordinary
// prune, so this does not become a second removal path with its own ordering.
func TestSyncKeepsUnconflictingPortals(t *testing.T) {
	root := t.TempDir()
	iqn := "iqn.2026-01.dev.glitr:t"
	mk := func(parts ...string) {
		if err := os.MkdirAll(filepath.Join(append([]string{root}, parts...)...), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mk("iscsi", iqn, "tpgt_1", "np", "10.0.0.1:3260")
	mk("iscsi", iqn, "tpgt_1", "lun")
	mk("iscsi", iqn, "tpgt_1", "acls")
	if err := os.WriteFile(filepath.Join(root, "iscsi", iqn, "tpgt_1", "enable"),
		[]byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := New(configfs.New(root))
	// Adding a SECOND explicit portal: the first conflicts with nothing and
	// must survive untouched.
	cfg := Config{Targets: []Target{{IQN: iqn, TPGs: []TPG{{
		Tag: 1, Enable: true, Portals: []Portal{
			{IP: mustAddr("10.0.0.1"), Port: 3260},
			{IP: mustAddr("10.0.0.2"), Port: 3260},
		},
	}}}}}
	if _, err := m.Sync(cfg); err != nil {
		t.Fatalf("sync: %v", err)
	}
	got, _ := m.Discover()
	var names []string
	for _, tg := range got.Targets {
		for _, g := range tg.TPGs {
			for _, p := range g.Portals {
				names = append(names, p.String())
			}
		}
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"10.0.0.1:3260", "10.0.0.2:3260"}) {
		t.Errorf("portals = %v, want both kept", names)
	}
}

// TestSyncValidatesBeforeItRemovesAnything: an invalid config must not cost
// the caller a working portal.
//
// Sync removes portals that conflict with the desired set BEFORE the apply
// phase, because a wildcard and a specific address cannot both be bound. Apply
// is where validation lived, so an invalid config got as far as the prune: the
// live wildcard was torn down, then Apply rejected the config, and the target
// was left less reachable than before by a call that applied nothing.
func TestSyncValidatesBeforeItRemovesAnything(t *testing.T) {
	root := t.TempDir()
	m := New(configfs.New(root))
	const iqn = "iqn.2026-01.dev.glitr:t"

	// Staged directly: configfs materialises np/ and the TPG when the kernel
	// creates the target, and a tmpdir does not.
	np := append(tpgPath(iqn, 1), "np", "0.0.0.0:3260")
	for _, d := range [][]string{np, append(tpgPath(iqn, 1), "lun"), append(tpgPath(iqn, 1), "acls")} {
		if err := os.MkdirAll(filepath.Join(append([]string{root}, d...)...), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := configfs.New(root).WriteAttr("1", append(tpgPath(iqn, 1), "enable")...); err != nil {
		t.Fatal(err)
	}
	live := Config{Targets: []Target{{IQN: iqn, TPGs: []TPG{{
		Tag: 1, Enable: true,
		Portals: []Portal{{IP: mustAddr("0.0.0.0"), Port: 3260}},
	}}}}}
	if _, err := m.Sync(live); err != nil {
		t.Fatal(err)
	}
	if ok, _ := configfs.New(root).Exists(np...); !ok {
		t.Fatal("fixture: the wildcard portal should exist")
	}

	// Same portals, but a LUN referencing a backstore that is not declared --
	// rejected by Validate, and only by Validate.
	bad := live
	bad.Targets[0].TPGs[0].Portals = []Portal{{IP: mustAddr("10.0.0.1"), Port: 3260}}
	bad.Targets[0].TPGs[0].LUNs = []LUN{{Index: 0, Backstore: "nonexistent"}}
	if _, err := m.Sync(bad); err == nil {
		t.Fatal("a LUN referencing an undeclared backstore must be rejected")
	}
	if ok, _ := configfs.New(root).Exists(np...); !ok {
		t.Error("the live wildcard portal was removed by a Sync that then rejected the " +
			"config -- a rejected call must leave the tree as it found it")
	}
}
