package appliance

import (
	"testing"

	"github.com/cwedgwood/glitr/lio"
	"github.com/cwedgwood/glitr/storage"
)

// TestDesiredLIO checks the appliance→LIO translation without touching the
// kernel: a coordinator built by hand (bypassing Open/reconcile) should
// produce the expected lio.Config.
func TestDesiredLIO(t *testing.T) {
	store, err := storage.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	v := &Object{UUID: "3f2504e0-4f89-11d3-9a0c-0305e82c3311", Name: "v", Kind: KindVolume,
		WWN: "aaaabbbbccccdddd", Capacity: 1 << 20, BlockSize: DefaultBlockSize, State: stateReady}
	if err := store.Create(v.UUID, v.Capacity); err != nil {
		t.Fatal(err)
	}

	c := &Coordinator{
		store: store,
		cfg:   Config{TargetIQN: "iqn.2026-01.dev.glitr:app", Portals: []lio.Portal{{IP: mustAddr("10.0.0.1"), Port: 3260}}},
		st: db{
			Objects: []*Object{v},
			Hosts: []*Host{
				{UUID: "h1", Name: "h1", Bindings: Bindings{IQNs: []string{"iqn.x:a", "iqn.x:b"}}}, // exported, 2 bindings
				{UUID: "h2", Name: "h2", Bindings: Bindings{IQNs: []string{"iqn.x:c"}}},            // no connections
			},
			Connections: []*Connection{
				{ObjectUUID: v.UUID, HostUUID: "h1", LUN: 5},
			},
			Exports: map[string]int{v.UUID: 3},
		},
	}

	cfg := c.desiredLIO()

	// Backstore: fileio, HBA=3, wwn from volume, dev = store disk path.
	if len(cfg.Backstores) != 1 {
		t.Fatalf("backstores = %d; want 1", len(cfg.Backstores))
	}
	b := cfg.Backstores[0]
	if b.Type != lio.FileIO || b.HBA != 3 || b.WWN != v.WWN || b.Dev != store.DiskPath(v.UUID) {
		t.Fatalf("backstore wrong: %+v (want wwn %s dev %s)", b, v.WWN, store.DiskPath(v.UUID))
	}
	// Size must be carried through: lio only performs the live fd_dev_size
	// grow when Size > 0, so omitting it silently breaks online resize of an
	// exported volume (the initiator keeps seeing the old capacity).
	if b.Size != v.Capacity {
		t.Fatalf("backstore Size = %d; want volume capacity %d", b.Size, v.Capacity)
	}

	tpg := cfg.Targets[0].TPGs[0]
	if tpg.Attributes["generate_node_acls"] != "0" || tpg.Attributes["authentication"] != "0" {
		t.Fatalf("tpg attrs wrong: %+v", tpg.Attributes)
	}
	if len(tpg.Portals) != 1 || tpg.Portals[0].IP != mustAddr("10.0.0.1") || tpg.Portals[0].Port != 3260 {
		t.Fatalf("portals wrong: %+v", tpg.Portals)
	}
	if len(tpg.LUNs) != 1 || tpg.LUNs[0].Index != 3 || tpg.LUNs[0].Backstore != b.Name {
		t.Fatalf("tpg lun wrong: %+v", tpg.LUNs)
	}

	// One ACL per IQN: h1 has a+b (each with mapped lun 5 -> tpg lun 3), h2 has c (empty).
	acls := map[string][]lio.MappedLUN{}
	for _, a := range tpg.ACLs {
		acls[a.InitiatorIQN] = a.MappedLUNs
	}
	if len(acls) != 3 {
		t.Fatalf("ACLs = %d; want 3 (a,b,c)", len(acls))
	}
	for _, iqn := range []string{"iqn.x:a", "iqn.x:b"} {
		ml := acls[iqn]
		if len(ml) != 1 || ml[0].Index != 5 || ml[0].TPGLUN != 3 {
			t.Fatalf("%s mapped luns wrong: %+v", iqn, ml)
		}
	}
	if len(acls["iqn.x:c"]) != 0 {
		t.Fatalf("host with zero attachments should have empty NodeACL, got %+v", acls["iqn.x:c"])
	}
}

func TestWwid(t *testing.T) {
	got := Wwid("1234567890abcdef")
	want := "0x60014051234567890abcdef000000000"
	if got != want {
		t.Fatalf("Wwid = %q; want %q", got, want)
	}
	if len(want) != 2+32 {
		t.Fatalf("wwid not 32 hex")
	}
}

// TestBackstorePresenceImpliesExport pins the invariant that makes a whole
// class of reconcile hazard unreachable from the appliance.
//
// A round-2 reviewer argued that reconcile caching `c.applied = &desired`
// after a delta that SKIPPED an immutable attribute leaves the engine
// believing the tree converged; then, when the volume is later unexported and
// the attribute becomes mutable again, Diff would not revisit it, so it would
// never converge without a full Sync. The mechanism is real for lio used
// directly as a library.
//
// It is not reachable through the appliance, because desiredLIO emits a
// backstore and its TPG LUN in the same breath: a backstore is in the desired
// config if and only if it is exported. "Unexported but still desired" -- the
// state the argument needs -- does not exist here. Detaching the last host
// removes both, the object is pruned, and a later re-attach recreates it on
// the create path where every attribute is writable.
//
// If desiredLIO ever grows a path that keeps a backstore without its LUN, this
// test fails and that reviewer's hazard becomes live. That is the point of it.
func TestBackstorePresenceImpliesExport(t *testing.T) {
	store, err := storage.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	v := &Object{UUID: "3f2504e0-4f89-11d3-9a0c-0305e82c3311", Name: "v", Kind: KindVolume,
		WWN: "aaaabbbbccccdddd", Capacity: 1 << 20, BlockSize: DefaultBlockSize, State: stateReady}
	if err := store.Create(v.UUID, v.Capacity); err != nil {
		t.Fatal(err)
	}
	c := &Coordinator{
		store: store,
		cfg:   Config{TargetIQN: "iqn.2026-01.dev.glitr:app", Portals: []lio.Portal{{IP: mustAddr("10.0.0.1"), Port: 3260}}},
		st: db{
			Objects: []*Object{v},
			Hosts:   []*Host{{UUID: "h1", Name: "h1", Bindings: Bindings{IQNs: []string{"iqn.x:a"}}}},
			Connections: []*Connection{
				{ObjectUUID: v.UUID, HostUUID: "h1", LUN: 5},
			},
			Exports: map[string]int{v.UUID: 3},
		},
	}

	assertCoupled := func(what string, cfg lio.Config) {
		t.Helper()
		luns := map[string]bool{}
		for _, tg := range cfg.Targets {
			for _, g := range tg.TPGs {
				for _, l := range g.LUNs {
					luns[l.Backstore] = true
				}
			}
		}
		for _, b := range cfg.Backstores {
			if !luns[b.Name] {
				t.Errorf("%s: backstore %s is desired WITHOUT a TPG LUN -- it would be "+
					"unexported and mutable while the delta engine believes it converged",
					what, b.Name)
			}
		}
		if len(cfg.Backstores) != len(luns) {
			t.Errorf("%s: %d backstores but %d LUNs; they must correspond 1:1",
				what, len(cfg.Backstores), len(luns))
		}
	}

	attached := c.desiredLIO()
	if len(attached.Backstores) != 1 {
		t.Fatalf("want the attached volume exported, got %d backstores", len(attached.Backstores))
	}
	assertCoupled("attached", attached)

	// Disconnect the only host: the object leaves the desired state entirely
	// -- backstore AND LUN -- rather than lingering as an unexported object.
	//
	// A record rather than a flag now: "detached" used to be a desired-state
	// marker on a row that stayed in the db, which meant the db carried rows
	// that described nothing. A connection either exists or it does not.
	saved := c.st.Connections
	c.st.Connections = nil
	detached := c.desiredLIO()
	if len(detached.Backstores) != 0 {
		t.Errorf("a volume with no attachments must leave the desired config completely, "+
			"got %d backstores", len(detached.Backstores))
	}
	assertCoupled("detached", detached)

	// Reconnect: it comes back, and comes back through the CREATE path, where
	// every attribute is writable.
	c.st.Connections = saved
	assertCoupled("re-attached", c.desiredLIO())
}

// TestAppliedViewRecordsLiveValueNotDesired: the delta engine must cache what
// it APPLIED, not what it asked for.
//
// c.applied is Diff's picture of the live tree, and Diff visits only what
// changed against it. Caching the desired config after a reconcile that
// skipped an immutable attribute records a convergence that did not happen --
// and then the backstore matches the cache forever, so it is never revisited,
// and if the attribute later becomes writable nothing retries it.
//
// Caching the live value instead makes the drifted backstore differ from
// desired on every pass, so each reconcile retries exactly that object and it
// converges by itself the moment the kernel stops refusing.
func TestAppliedViewRecordsLiveValueNotDesired(t *testing.T) {
	desired := lio.Config{Backstores: []lio.Backstore{
		{Type: lio.FileIO, Name: "vol_a", Dev: "/d/a", Size: 1 << 20,
			Attributes: map[string]string{"block_size": "512", "optimal_sectors": "0"}},
		{Type: lio.FileIO, Name: "vol_b", Dev: "/d/b", Size: 1 << 20,
			Attributes: map[string]string{"block_size": "512", "optimal_sectors": "0"}},
	}}
	drift := []lio.AttrDrift{{
		Backstore: "vol_a", Type: lio.FileIO, Attr: "optimal_sectors",
		Live: "16384", Desired: "0",
	}}

	applied := appliedView(desired, drift)

	if got := applied.Backstores[0].Attributes["optimal_sectors"]; got != "16384" {
		t.Errorf("drifted attribute cached as %q, want the LIVE value 16384 -- caching the "+
			"desired value records a convergence that did not happen", got)
	}
	if got := applied.Backstores[1].Attributes["optimal_sectors"]; got != "0" {
		t.Errorf("undrifted backstore must be cached as applied, got %q", got)
	}
	// The caller's config must not be mutated: these two are about to be
	// compared with each other.
	if got := desired.Backstores[0].Attributes["optimal_sectors"]; got != "0" {
		t.Errorf("appliedView mutated the caller's desired config (%q)", got)
	}

	// The point of all this: Diff must now see the drifted backstore as
	// changed, so the next reconcile revisits it and retries the write.
	d, ok := lio.Diff(*applied, desired)
	if !ok {
		t.Fatal("the difference must be expressible as a delta")
	}
	var names []string
	for _, b := range d.Add.Backstores {
		names = append(names, b.Name)
	}
	if len(names) != 1 || names[0] != "vol_a" {
		t.Errorf("Diff must revisit exactly the drifted backstore, got %v", names)
	}

	// And with no drift, nothing is revisited -- the retry is scoped to the
	// object that actually needs it, not a general loss of incrementality.
	clean := appliedView(desired, nil)
	if d, ok := lio.Diff(*clean, desired); !ok || len(d.Add.Backstores) != 0 {
		t.Errorf("a clean reconcile must leave nothing to revisit, got %v", d.Add.Backstores)
	}
}

// TestThinProvisioningIsAdvertisedByDefault pins that volumes advertise UNMAP
// unless it is explicitly turned off.
//
// The backing files are sparse either way. Without these attributes the device
// is thin on disk and claims to be fully provisioned on the wire, so the pool
// can be overcommitted and filled with space that nothing will ever return --
// the incoherent combination, and the one that used to be the default.
func TestThinProvisioningIsAdvertisedByDefault(t *testing.T) {
	attrsFor := func(cfg Config) map[string]string {
		t.Helper()
		st, err := storage.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		v := &Object{UUID: "3f2504e0-4f89-11d3-9a0c-0305e82c3321", Name: "v", Kind: KindVolume,
			WWN: "aaaabbbbccccdddd", Capacity: 1 << 20, BlockSize: DefaultBlockSize, State: stateReady}
		if err := st.Create(v.UUID, v.Capacity); err != nil {
			t.Fatal(err)
		}
		c := &Coordinator{store: st, cfg: cfg, st: db{
			Objects:     []*Object{v},
			Hosts:       []*Host{{UUID: "h", Name: "h", Bindings: Bindings{IQNs: []string{"iqn.1993-08.org.debian:01:a"}}}},
			Connections: []*Connection{{ObjectUUID: v.UUID, HostUUID: "h", LUN: 0}},
			Exports:     map[string]int{v.UUID: 0},
		}}
		bs := c.desiredLIO().Backstores
		if len(bs) != 1 {
			t.Fatalf("got %d backstores, want 1", len(bs))
		}
		return bs[0].Attributes
	}

	base := Config{TargetIQN: "iqn.2026-01.dev.glitr:t"}

	on := attrsFor(base)
	if on["emulate_tpu"] != "1" || on["emulate_tpws"] != "1" {
		t.Errorf("by default UNMAP must be advertised, got tpu=%q tpws=%q",
			on["emulate_tpu"], on["emulate_tpws"])
	}

	off := base
	off.NoUnmap = true
	got := attrsFor(off)
	if got["emulate_tpu"] != "0" || got["emulate_tpws"] != "0" {
		t.Errorf("-no-unmap must disable both, got tpu=%q tpws=%q",
			got["emulate_tpu"], got["emulate_tpws"])
	}

	// Managed either way, so a reconcile enforces the choice and any
	// divergence shows as drift. Absent would mean "whatever the kernel did".
	for _, k := range []string{"emulate_tpu", "emulate_tpws"} {
		if _, ok := on[k]; !ok {
			t.Errorf("%s is not managed, so drift cannot see it", k)
		}
	}

	// LBPRZ is deliberately not claimed: it promises reads-as-zeros for every
	// future backing store, and the safe direction for a promise is to
	// under-claim.
	if _, ok := on["unmap_zeroes_data"]; ok {
		t.Error("unmap_zeroes_data is being claimed; that promise is deliberately not made")
	}
}
