package lio_test

import (
	"net/netip"
	"os"
	"testing"

	"github.com/cwedgwood/glitr/lio"
	"github.com/cwedgwood/glitr/lio/configfs"
)

// TestLive exercises the library against a real kernel LIO target. It
// runs only when GLITR_LIO_LIVE=1 (and requires root + a mounted target
// configfs), so it is skipped by a normal `go test` on a dev host.
//
// It uses deliberately isolated object names and a non-standard portal
// port so it does not disturb any other target configured on the box.
func TestLive(t *testing.T) {
	if os.Getenv("GLITR_LIO_LIVE") != "1" {
		t.Skip("set GLITR_LIO_LIVE=1 to run live LIO integration test (needs root)")
	}

	const (
		backingDir = "/var/lib/glitr"
		backing    = backingDir + "/livetest0.img"
		bsName     = "livetest0"
		targetIQN  = "iqn.2026-01.dev.glitr:livetest"
		initIQN    = "iqn.2026-01.dev.glitr:liveinit"
		portalIP   = "10.10.0.1"
		portalPort = 3299
	)

	// Backing-file creation is the harness's job, not the library's.
	if err := os.MkdirAll(backingDir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(backing)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(128 << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()

	m := lio.New(configfs.Default())

	cfg := lio.Config{
		Backstores: []lio.Backstore{{Type: lio.FileIO, HBA: 9, Name: bsName, Dev: backing}},
		Targets: []lio.Target{{IQN: targetIQN, TPGs: []lio.TPG{{
			Tag:    1,
			Enable: true,
			Attributes: map[string]string{
				"authentication":          "0",
				"generate_node_acls":      "0",
				"demo_mode_write_protect": "0",
			},
			Portals: []lio.Portal{{IP: netip.MustParseAddr(portalIP), Port: portalPort}},
			LUNs:    []lio.LUN{{Index: 0, Backstore: bsName}},
			ACLs: []lio.ACL{{InitiatorIQN: initIQN,
				MappedLUNs: []lio.MappedLUN{{Index: 0, TPGLUN: 0}}}},
		}}}},
	}

	// Always clean up, even on failure.
	t.Cleanup(func() {
		_, _ = m.Remove(cfg)
		_ = os.Remove(backing)
	})
	// Pre-clean any leftovers from a previous aborted run.
	_, _ = m.Remove(cfg)

	// 1. Apply creates everything.
	rep, err := m.Apply(cfg)
	if err != nil {
		t.Fatalf("apply: %v (kind=%s)", err, lio.KindOf(err))
	}
	if !rep.Changed() {
		t.Fatalf("first apply reported no changes")
	}
	t.Logf("apply created: %v", rep.Changes)

	// 2. Discover reflects the applied state.
	got, err := m.Discover()
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	assertPresent(t, got, bsName, targetIQN, initIQN)

	// 3. Idempotent re-apply: no changes (a core success criterion).
	rep, err = m.Apply(cfg)
	if err != nil {
		t.Fatalf("reapply: %v", err)
	}
	if rep.Changed() {
		t.Fatalf("reapply was not idempotent, changed: %v", rep.Changes)
	}

	// 4. Mutable attribute update is detected and applied.
	cfg.Targets[0].TPGs[0].Attributes["cache_dynamic_acls"] = "1"
	rep, err = m.Apply(cfg)
	if err != nil {
		t.Fatalf("attr-update apply: %v", err)
	}
	if !rep.Changed() {
		t.Fatalf("attribute change not detected")
	}
	cur, err := configfs.Default().ReadAttr("iscsi", targetIQN, "tpgt_1", "attrib", "cache_dynamic_acls")
	if err != nil || cur != "1" {
		t.Fatalf("cache_dynamic_acls = %q, %v; want 1", cur, err)
	}

	// 4b. Rewire a MAPPED LUN's backstore in place. Regression for the
	// H1 review finding: this previously EBUSY-wedged because ensureLUN
	// rmdir'd the LUN dir while mapped_lun0 still referenced it. Add a
	// second backstore and retarget lun_0 (which is mapped) to it via Sync.
	const bs2 = "livetest1"
	const backing2 = backingDir + "/livetest1.img"
	f2, err := os.Create(backing2)
	if err != nil {
		t.Fatal(err)
	}
	if err := f2.Truncate(128 << 20); err != nil {
		t.Fatal(err)
	}
	f2.Close()
	t.Cleanup(func() { _ = os.Remove(backing2) })

	cfg.Backstores = append(cfg.Backstores, lio.Backstore{Type: lio.FileIO, HBA: 10, Name: bs2, Dev: backing2})
	cfg.Targets[0].TPGs[0].LUNs[0].Backstore = bs2 // retarget the mapped LUN
	if _, err := m.Sync(cfg); err != nil {
		t.Fatalf("mapped-LUN rewire (H1 regression) did not converge: %v (kind=%s)", err, lio.KindOf(err))
	}
	got, err = m.Discover()
	if err != nil {
		t.Fatalf("discover after rewire: %v", err)
	}
	rtpg := got.Targets[0].TPGs[0]
	if len(rtpg.LUNs) != 1 || rtpg.LUNs[0].Backstore != bs2 {
		t.Fatalf("LUN not re-pointed to %q: %+v", bs2, rtpg.LUNs)
	}
	if len(rtpg.ACLs) != 1 || len(rtpg.ACLs[0].MappedLUNs) != 1 {
		t.Fatalf("mapped LUN lost during rewire: %+v", rtpg.ACLs)
	}

	// 5. Remove tears everything down.
	if _, err := m.Remove(cfg); err != nil {
		t.Fatalf("remove: %v", err)
	}
	got, err = m.Discover()
	if err != nil {
		t.Fatalf("discover after remove: %v", err)
	}
	for _, ts := range got.Targets {
		if ts.IQN == targetIQN {
			t.Fatalf("target still present after remove")
		}
	}
}

func assertPresent(t *testing.T, cfg lio.Config, bsName, targetIQN, initIQN string) {
	t.Helper()
	found := false
	for _, b := range cfg.Backstores {
		if b.Name == bsName {
			found = true
		}
	}
	if !found {
		t.Fatalf("backstore %q not discovered", bsName)
	}
	for _, ts := range cfg.Targets {
		if ts.IQN != targetIQN {
			continue
		}
		tpg := ts.TPGs[0]
		if len(tpg.LUNs) == 0 || tpg.LUNs[0].Backstore != bsName {
			t.Fatalf("LUN not wired to backstore: %+v", tpg.LUNs)
		}
		if len(tpg.ACLs) == 0 || tpg.ACLs[0].InitiatorIQN != initIQN {
			t.Fatalf("ACL not discovered: %+v", tpg.ACLs)
		}
		return
	}
	t.Fatalf("target %q not discovered", targetIQN)
}
