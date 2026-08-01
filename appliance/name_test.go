package appliance

import (
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cwedgwood/glitr/lio"
	"github.com/cwedgwood/glitr/lio/configfs"
	"github.com/cwedgwood/glitr/storage"
)

// Names are what callers use, so the rules about them are load-bearing: a name
// that cannot be sent back byte for byte is a name whose object the caller
// cannot find again, and it will conclude the object was lost.

func TestNameRules(t *testing.T) {
	for name, n := range map[string]string{
		"empty":          "",
		"leading space":  " db-1",
		"trailing space": "db-1 ",
		"path separator": "a/b",
		"dot":            ".",
		"dotdot":         "..",
		"control char":   "db\x00one",
		"newline":        "db\none",
		"tab":            "db\tone",
		"too long":       strings.Repeat("x", maxNameLen+1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validName(n); err == nil {
				t.Errorf("name %q must be refused", n)
			}
		})
	}
	for _, n := range []string{
		"db-1", "pvc-3f2504e0-4f89-11d3-9a0c-0305e82c3301", "a", "with space inside",
		"UPPER", "dots.are.fine", strings.Repeat("x", maxNameLen),
	} {
		if err := validName(n); err != nil {
			t.Errorf("name %q must be accepted: %v", n, err)
		}
	}
}

// The point of separate kinds: a volume and a snapshot may hold the same name,
// and asking for one must never return the other.
func TestVolumesAndSnapshotsHaveSeparateNamespaces(t *testing.T) {
	c, _ := stageHolder(t, "")

	vol, _, err := c.Create(KindVolume, CreateRequest{Name: "db-1", Size: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	snap, _, err := c.Create(KindSnapshot, CreateRequest{
		Name: "db-1", Source: "db-1", SourceKind: KindVolume})
	if err != nil {
		t.Skipf("snapshot needs a reflink filesystem: %v", err)
	}
	if snap.UUID == vol.UUID {
		t.Fatal("the snapshot reused the volume's identity")
	}

	gotVol, ok := c.Get(KindVolume, "db-1")
	if !ok || gotVol.UUID != vol.UUID {
		t.Errorf("looking up the volume returned %+v", gotVol)
	}
	gotSnap, ok := c.Get(KindSnapshot, "db-1")
	if !ok || gotSnap.UUID != snap.UUID {
		t.Errorf("looking up the snapshot returned %+v", gotSnap)
	}
	if gotSnap.Source != vol.UUID {
		t.Errorf("the snapshot must record what it was taken of, got %q", gotSnap.Source)
	}
	// And the collections do not bleed into each other.
	if vols := c.List(KindVolume); containsUUID(vols, snap.UUID) {
		t.Error("a snapshot appeared in the volume listing")
	}
	if snaps := c.List(KindSnapshot); containsUUID(snaps, vol.UUID) {
		t.Error("a volume appeared in the snapshot listing")
	}
}

func containsUUID(objs []Object, uuid string) bool {
	for _, o := range objs {
		if o.UUID == uuid {
			return true
		}
	}
	return false
}

func TestCreateWithAnExistingNameIsIdempotent(t *testing.T) {
	c, _ := stageHolder(t, "")

	first, _, err := c.Create(KindVolume, CreateRequest{Name: "db-1", Size: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := c.Create(KindVolume, CreateRequest{Name: "db-1", Size: 1 << 20})
	if err != nil {
		t.Fatalf("repeating a create with the same name must succeed: %v", err)
	}
	if second.UUID != first.UUID {
		t.Errorf("a repeat made a SECOND object: %s then %s", first.UUID, second.UUID)
	}
	// Capacity is deliberately not compared: an object can be resized after it
	// is made, so a size difference is not evidence of a different object and
	// refusing would wedge a caller that grew one and then replayed its create.
	grown, _, err := c.Create(KindVolume, CreateRequest{Name: "db-1", Size: 8 << 20})
	if err != nil {
		t.Errorf("a repeat at a different size must return the existing object: %v", err)
	}
	if grown.Capacity != first.Capacity {
		t.Errorf("a repeat create must not resize: capacity is now %d", grown.Capacity)
	}
	// Block size IS compared: it is fixed for the life of the object, so a
	// different one describes something else.
	if _, _, err := c.Create(KindVolume, CreateRequest{
		Name: "db-1", Size: 1 << 20, BlockSize: MaxBlockSize}); err == nil {
		t.Error("a repeat with a different block_size must be refused")
	}
}

func TestRenameKeepsIdentity(t *testing.T) {
	c, _ := stageHolder(t, "")

	o, _, err := c.Create(KindVolume, CreateRequest{Name: "before", Size: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := c.Rename(KindVolume, "before", "after")
	if err != nil {
		t.Fatal(err)
	}
	// The UUID and the WWN must not move. An initiator identifies the device
	// by its WWN, so a rename that changed it would pull the device out from
	// under a mounted filesystem.
	if renamed.UUID != o.UUID || renamed.WWN != o.WWN {
		t.Errorf("rename changed identity: %+v vs %+v", renamed, o)
	}
	if _, ok := c.Get(KindVolume, "before"); ok {
		t.Error("the old name still resolves")
	}
	if got, ok := c.Get(KindVolume, "after"); !ok || got.UUID != o.UUID {
		t.Error("the new name does not resolve")
	}
	// The uuid keeps working, because a caller that stored one must not be
	// broken by the API becoming name-first.
	if got, ok := c.Get(KindVolume, o.UUID); !ok || got.Name != "after" {
		t.Error("the uuid stopped resolving after a rename")
	}
	// Renaming onto a name that is taken is refused rather than silently
	// merging two objects.
	if _, _, err := c.Create(KindVolume, CreateRequest{Name: "taken", Size: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	_, err = c.Rename(KindVolume, "after", "taken")
	var se *StatusError
	if !errors.As(err, &se) || se.ErrorCode() != CodeNameTaken {
		t.Errorf("want %s, got %v", CodeNameTaken, err)
	}
}

func TestDeleteFreesTheName(t *testing.T) {
	c, _ := stageHolder(t, "")

	first, _, err := c.Create(KindVolume, CreateRequest{Name: "recycled", Size: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(KindVolume, "recycled"); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get(KindVolume, "recycled"); ok {
		t.Error("the name still resolves after delete")
	}
	// Reusable, which is the point: a caller that deletes and recreates under
	// the same name must not be locked out.
	again, _, err := c.Create(KindVolume, CreateRequest{Name: "recycled", Size: 1 << 20})
	if err != nil {
		t.Fatalf("the name must be reusable: %v", err)
	}
	if again.UUID == first.UUID {
		t.Error("the recreated object reused the old identity")
	}
}

// A host is its name and uuid, not its bindings, so one with none is a real
// host -- and it has to survive a restart, which is where accepting a mutation
// the loader rejects shows up.
func TestHostWithNoBindings(t *testing.T) {
	c, _ := stageHolder(t, "")

	// CreateHost commits, and a commit reconciles against configfs, which
	// needs a real kernel. What is under test is the record and the loader, so
	// the host is seeded and the creation path is covered by the live suites.
	c.st.Hosts = append(c.st.Hosts, &Host{
		UUID: "3f2504e0-4f89-11d3-9a0c-0305e82c3399", Name: "unbound"})
	if err := c.validateLoaded(); err != nil {
		t.Errorf("a host with no bindings must load: %v", err)
	}
	// It contributes no ACL, so it exports nothing.
	for _, tg := range c.desiredLIO().Targets {
		for _, tpg := range tg.TPGs {
			for _, acl := range tpg.ACLs {
				if acl.InitiatorIQN == "" {
					t.Error("a host with no bindings produced an empty ACL")
				}
			}
		}
	}
}

func TestBindingsAddAndRemove(t *testing.T) {
	// A FRESH coordinator per case, deliberately.
	//
	// Applying an ACL needs a real configfs tree, so the commit fails here --
	// and the first failure marks the appliance degraded, after which
	// healIfDegraded correctly refuses every later mutation before it reaches
	// the binding logic. Chaining cases through one coordinator therefore
	// tests the second and third steps against a daemon that is refusing
	// everything, which is how a passing test can mean nothing.
	seed := func(t *testing.T, iqns ...string) *Coordinator {
		c := bareCoordinator(t)
		c.st.Hosts = append(c.st.Hosts, &Host{
			UUID: "3f2504e0-4f89-11d3-9a0c-0305e82c3401", Name: "node-7",
			Bindings: Bindings{IQNs: iqns}})
		return c
	}
	bindings := func(c *Coordinator) []string { return c.hostByName("node-7").Bindings.IQNs }

	t.Run("add without restating", func(t *testing.T) {
		// Restating the whole set is how a caller accidentally drops a
		// binding, and dropping one is a fencing event.
		c := seed(t, "iqn.x:one")
		_, _, _ = c.SetBindings("node-7", nil, []string{"iqn.x:two"}, nil)
		if got := bindings(c); len(got) != 2 {
			t.Errorf("bindings = %v, want both", got)
		}
	})

	t.Run("adding an existing binding is not a duplicate", func(t *testing.T) {
		c := seed(t, "iqn.x:one", "iqn.x:two")
		_, _, _ = c.SetBindings("node-7", nil, []string{"iqn.x:two"}, nil)
		if got := bindings(c); len(got) != 2 {
			t.Errorf("bindings = %v, want the set unchanged", got)
		}
	})

	t.Run("remove", func(t *testing.T) {
		c := seed(t, "iqn.x:one", "iqn.x:two")
		_, _, _ = c.SetBindings("node-7", nil, nil, []string{"iqn.x:one"})
		if got := bindings(c); len(got) != 1 || got[0] != "iqn.x:two" {
			t.Errorf("bindings = %v, want just iqn.x:two", got)
		}
	})

	t.Run("a binding another host owns is refused", func(t *testing.T) {
		c := seed(t, "iqn.x:two")
		c.st.Hosts = append(c.st.Hosts, &Host{
			UUID: "3f2504e0-4f89-11d3-9a0c-0305e82c3402", Name: "node-8",
			Bindings: Bindings{IQNs: []string{"iqn.x:three"}}})
		_, _, err := c.SetBindings("node-7", []string{"iqn.x:two", "iqn.x:three"}, nil, nil)
		var se *StatusError
		if !errors.As(err, &se) || se.Code != http.StatusConflict {
			t.Errorf("want a conflict, got %v", err)
		}
		// Refused BEFORE any commit, so nothing moved.
		if got := bindings(c); len(got) != 1 || got[0] != "iqn.x:two" {
			t.Errorf("a refused change must not mutate: %v", got)
		}
	})

	t.Run("keeping its own binding is not a conflict with itself", func(t *testing.T) {
		c := seed(t, "iqn.x:two")
		_, _, err := c.SetBindings("node-7", []string{"iqn.x:two"}, nil, nil)
		var se *StatusError
		if errors.As(err, &se) && se.Code == http.StatusConflict {
			t.Errorf("a host keeping its own binding must not conflict: %v", err)
		}
	})
}

// The lun is never assigned. An absent one is an error rather than a number we
// pick, because in a cluster the same object usually has to appear at the same
// lun on every node and a per-connection choice cannot promise that.
func TestConnectRequiresALUN(t *testing.T) {
	c, v := stageHolder(t, "")

	_, _, err := c.Connect(KindVolume, v.UUID, hOther, 0, false)
	var se *StatusError
	if !errors.As(err, &se) || se.ErrorCode() != CodeLUNRequired {
		t.Errorf("want %s, got %v", CodeLUNRequired, err)
	}
	// An explicitly-asked-for lun gets PAST the check. It cannot get further
	// here: connecting commits, and a commit reconciles against configfs,
	// which needs a real kernel -- the live suites cover the rest.
	spare := mustObject(t, c, "lun-probe", 1<<20)
	_, _, err = c.Connect(KindVolume, spare.Name, "other", 9, true)
	if errors.As(err, &se) && se.ErrorCode() == CodeLUNRequired {
		t.Errorf("an explicit lun must satisfy the check: %v", err)
	}
}

func TestConnectIsIdempotentAndNamesTheConflict(t *testing.T) {
	c, v := stageHolder(t, "")

	// The fixture already connects this object to the holder at lun 1.
	info, _, err := c.Connect(KindVolume, v.Name, "holder", 1, true)
	if err != nil {
		t.Fatalf("repeating a connection must succeed: %v", err)
	}
	if info.LUN != 1 || info.Wwid == "" {
		t.Errorf("a retry must return usable details, got %+v", info)
	}
	_, _, err = c.Connect(KindVolume, v.Name, "holder", 4, true)
	var se *StatusError
	if !errors.As(err, &se) || se.ErrorCode() != CodeConfigurationMismatch {
		t.Fatalf("want %s, got %v", CodeConfigurationMismatch, err)
	}
	if !strings.Contains(se.Msg, "lun 1") {
		t.Errorf("the message must name the lun it actually has: %q", se.Msg)
	}
}

func TestConnectionsAreListedByName(t *testing.T) {
	c, v := stageHolder(t, "")

	all, err := c.ListConnections("", "", "")
	if err != nil {
		t.Fatalf("ListConnections: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("expected the fixture's connections")
	}
	var found *ConnectionView
	for i := range all {
		if all[i].ObjectUUID == v.UUID && all[i].Host == "holder" {
			found = &all[i]
		}
	}
	if found == nil {
		t.Fatalf("the connection under test is missing from %+v", all)
	}
	// Names AND uuids: a listing has to say which object and which host each
	// entry is about, which is what ConnInfo cannot do.
	if found.Object != v.Name || found.ObjectKind != KindVolume {
		t.Errorf("listing does not name the object: %+v", found)
	}
	if found.HostUUID == "" || found.TargetIQN == "" || found.Wwid == "" {
		t.Errorf("listing is missing identifiers: %+v", found)
	}
	if byHost, _ := c.ListConnections("", "", "other"); len(byHost) == 0 {
		t.Error("filtering by host name found nothing")
	}
	if byObj, _ := c.ListConnections(v.Name, "", ""); len(byObj) == 0 {
		t.Error("filtering by object name found nothing")
	}
	if none, _ := c.ListConnections("no-such-object", "", ""); len(none) != 0 {
		t.Errorf("an unknown object must yield no connections, got %+v", none)
	}
}

// bareCoordinator is a coordinator with nothing exported, so commit() has no
// configfs work and the record-level rules can be tested without a kernel.
func bareCoordinator(t *testing.T) *Coordinator {
	t.Helper()
	store, err := storage.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &Coordinator{
		store:  store,
		lio:    lio.New(configfs.New(t.TempDir())),
		cfg:    Config{TargetIQN: "iqn.2026-01.dev.glitr:app"},
		st:     db{Version: dbVersion, Exports: map[string]int{}},
		dbPath: filepath.Join(t.TempDir(), "appliance.json"),
	}
}

// TestCreateReportsWhetherItCreated: a repeat create succeeds, which is the
// point, but an external controller reconciling against its own records has to
// tell an adoption from a creation. Reported rather than inferred, because the
// object itself looks identical either way.
// Create is the only one of the three that can be tested here: CreateHost and
// Connect commit, and a commit reconciles against configfs, which needs a real
// kernel. Their created-ness is asserted live by the labtest suites, and the
// adopt path of Connect by TestRepeatConnectDoesNotReportCreated below.
func TestCreateReportsWhetherItCreated(t *testing.T) {
	c := bareCoordinator(t)

	if _, created, err := c.Create(KindVolume, CreateRequest{Name: "fresh", Size: 1 << 20}); err != nil {
		t.Fatal(err)
	} else if !created {
		t.Error("the first create must report created")
	}
	if _, created, err := c.Create(KindVolume, CreateRequest{Name: "fresh", Size: 1 << 20}); err != nil {
		t.Fatal(err)
	} else if created {
		t.Error("a repeat must NOT report created; it adopted an existing object")
	}

}

// TestRepeatConnectDoesNotReportCreated covers the adopt path separately:
// making a NEW export reconciles a backstore into configfs and needs a real
// kernel, while re-connecting an existing one returns before the commit. The
// created=true side is asserted live, by the labtest suites.
func TestRepeatConnectDoesNotReportCreated(t *testing.T) {
	c, v := stageHolder(t, "")

	if _, created, err := c.Connect(KindVolume, v.Name, "holder", 1, true); err != nil {
		t.Fatal(err)
	} else if created {
		t.Error("a repeat Connect must not report created; it found the existing export")
	}
}

// TestConnectionFilterRefusesAnAmbiguousName: volumes and snapshots are
// separate namespaces, so one name can identify two objects. Filtering used to
// try volumes first and answer with that object's connections, reporting the
// snapshot as having none -- a wrong answer indistinguishable from a right one.
func TestConnectionFilterRefusesAnAmbiguousName(t *testing.T) {
	c, v := stageHolder(t, "")

	// A snapshot wearing the same name as the volume, seeded as a record
	// rather than made with Create.
	//
	// Create(KindSnapshot) reflinks the source (FICLONE), which needs XFS or
	// btrfs -- so a test that took a real snapshot would pass wherever /tmp
	// happens to support reflinks and fail on the ext4 that CI runs on. What
	// is under test is name resolution, which reads records and never touches
	// the bytes.
	c.st.Objects = append(c.st.Objects, &Object{
		UUID: "9e1f6c7a-0000-4000-8000-00000000cafe", Name: v.Name,
		Kind: KindSnapshot, WWN: "ddddeeeeffff0000", Source: v.UUID,
		Capacity: v.Capacity, BlockSize: v.BlockSize,
		Created: time.Now().UTC(), State: stateReady,
	})

	_, err := c.ListConnections(v.Name, "", "")
	if err == nil {
		t.Fatal("a name held by both a volume and a snapshot must be refused, not guessed")
	}
	assertCode(t, err, http.StatusBadRequest, CodeInvalidInput)

	// Saying which resolves it, and so does a uuid: it cannot be ambiguous.
	if got, err := c.ListConnections(v.Name, KindVolume, ""); err != nil {
		t.Errorf("naming the kind must resolve the ambiguity: %v", err)
	} else if len(got) == 0 {
		t.Error("the volume's connections must still be listed")
	}
	if got, err := c.ListConnections(v.UUID, "", ""); err != nil {
		t.Errorf("a uuid is never ambiguous: %v", err)
	} else if len(got) == 0 {
		t.Error("the volume's connections must be listed by uuid")
	}
	// The snapshot has none, and that is now a fact rather than an artefact of
	// which namespace was searched first.
	if got, err := c.ListConnections(v.Name, KindSnapshot, ""); err != nil {
		t.Errorf("the snapshot must be addressable: %v", err)
	} else if len(got) != 0 {
		t.Errorf("the snapshot has no connections, got %d", len(got))
	}
}

// TestRepeatCreateSurvivesADeletedSource: deleting the volume a snapshot came
// from is allowed -- the snapshot's bytes are its own -- so the snapshot
// outlives it with a source that resolves to nothing.
//
// Repeating the create then has to keep working. It did not: the source was
// resolved unconditionally and a source that resolved to NOTHING was reported
// as a source that resolved to something ELSE, so the reply to a replay went
// from "here is your snapshot" to configuration_mismatch, permanently, the
// moment the volume was deleted. A controller reconciling by replaying its
// desired state gets a hard conflict for an object that is present and
// correct.
func TestRepeatCreateSurvivesADeletedSource(t *testing.T) {
	c := bareCoordinator(t)

	vol, _, err := c.Create(KindVolume, CreateRequest{Name: "src", Size: MinVolumeSize})
	if err != nil {
		t.Fatal(err)
	}
	// Seeded rather than taken: Create(KindSnapshot) reflinks, which needs XFS
	// or btrfs, and this test is about the REPLAY -- matchExisting never
	// touches storage. A real snapshot here would pass wherever /tmp happens
	// to support FICLONE and fail on the ext4 that CI runs on.
	snap := &Object{
		UUID: "5f3a91c4-0000-4000-8000-0000000000aa", Name: "snap-1",
		Kind: KindSnapshot, WWN: "aaaabbbbccccddee", Source: vol.UUID,
		Capacity: vol.Capacity, BlockSize: vol.BlockSize,
		Created: time.Now().UTC(), State: stateReady,
	}
	c.st.Objects = append(c.st.Objects, snap)
	if err := c.Delete(KindVolume, vol.Name); err != nil {
		t.Fatal(err)
	}

	// By uuid -- what the record stores, and what a controller has kept.
	got, created, err := c.Create(KindSnapshot, CreateRequest{
		Name: "snap-1", Source: vol.UUID, SourceKind: KindVolume})
	if err != nil {
		t.Fatalf("replaying a create whose source has been deleted must return the "+
			"existing snapshot: %v", err)
	}
	if created {
		t.Error("a replay must not report created")
	}
	if got.UUID != snap.UUID {
		t.Errorf("a replay must return the same snapshot: %s then %s", snap.UUID, got.UUID)
	}

	// By NAME it cannot be matched, and must not be guessed at: names are
	// reusable, so the name may name something else now or later.
	_, _, err = c.Create(KindSnapshot, CreateRequest{
		Name: "snap-1", Source: "src", SourceKind: KindVolume})
	if err == nil {
		t.Fatal("a name that resolves to nothing must not be assumed to be the source")
	}
	assertCode(t, err, http.StatusConflict, CodeConfigurationMismatch)
	// The message has to say what is recorded, or the caller cannot act.
	if !strings.Contains(err.Error(), vol.UUID) {
		t.Errorf("the refusal must name the recorded source uuid: %v", err)
	}

	// A REUSED name resolves to a different object, and refusing that is
	// right: what wears the name today is not what this was made from.
	other, _, err := c.Create(KindVolume, CreateRequest{Name: "src", Size: MinVolumeSize})
	if err != nil {
		t.Fatal(err)
	}
	if other.UUID == vol.UUID {
		t.Fatal("the recreated volume reused the old identity")
	}
	_, _, err = c.Create(KindSnapshot, CreateRequest{
		Name: "snap-1", Source: "src", SourceKind: KindVolume})
	if err == nil {
		t.Error("a name that now resolves to a DIFFERENT object must be refused")
	}
}
