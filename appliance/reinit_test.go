package appliance

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwedgwood/glitr/lio"
	"github.com/cwedgwood/glitr/storage"
)

// stageClone writes a database as if it had been made on another machine, with
// two objects in it, and returns the root.
func stageClone(t *testing.T, machineID string) (root string, wwns []string) {
	t.Helper()
	root = t.TempDir()
	store, err := storage.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	c := &Coordinator{
		store:  store,
		st:     db{Version: dbVersion, Exports: map[string]int{}},
		dbPath: filepath.Join(root, "appliance.json"),
	}
	for _, name := range []string{"db-1", "db-2"} {
		o, _, err := c.Create(KindVolume, CreateRequest{Name: name, Size: MinVolumeSize})
		if err != nil {
			t.Fatal(err)
		}
		wwns = append(wwns, o.WWN)
	}
	c.st.TargetIQN, c.st.MachineID = IQNPrefix+machineID, machineID
	c.st.Portals = []lio.Portal{p("10.0.0.1", 3260)}
	if err := c.persist(); err != nil {
		t.Fatal(err)
	}
	return root, wwns
}

func readDB(t *testing.T, root string) db {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "appliance.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out db
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func machineIDFile(t *testing.T, id string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "machine-id")
	if err := os.WriteFile(p, []byte(id+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestReinitAdoptKeepsTheDataAndChangesEveryWWN.
//
// The WWN is the half people forget. Renaming the target stops two appliances
// answering to one name, but an initiator identifies a DEVICE by its WWN, so a
// clone that kept them still presents the original's devices -- and multipath
// gathers same-WWN devices into one path set rather than reporting a conflict.
func TestReinitAdoptKeepsTheDataAndChangesEveryWWN(t *testing.T) {
	root, before := stageClone(t, machineA)
	var out bytes.Buffer

	if err := Reinit(ReinitOptions{
		Root: root, MachineIDPath: machineIDFile(t, machineB), Out: &out,
	}); err != nil {
		t.Fatal(err)
	}

	got := readDB(t, root)
	if got.MachineID != machineB {
		t.Errorf("machine = %q, want %q", got.MachineID, machineB)
	}
	if got.TargetIQN != IQNPrefix+machineB {
		t.Errorf("target IQN = %q, want one derived from this machine", got.TargetIQN)
	}
	if len(got.Objects) != 2 {
		t.Fatalf("adopt keeps the volumes, got %d", len(got.Objects))
	}
	for i, o := range got.Objects {
		if o.WWN == before[i] {
			t.Errorf("volume %q kept wwn %s; it would collide with the appliance this "+
				"was copied from", o.Name, o.WWN)
		}
		if o.WWN == "" {
			t.Errorf("volume %q has no wwn", o.Name)
		}
	}
	// Two volumes must not be given the SAME new wwn either.
	if got.Objects[0].WWN == got.Objects[1].WWN {
		t.Error("two volumes were given one wwn")
	}
	// Portals belong to the machine, not the database: a clone is on other
	// hardware with other addresses.
	if len(got.Portals) != 0 {
		t.Errorf("portals must be cleared so the next start adopts the flag: %v", got.Portals)
	}
	if !strings.Contains(out.String(), "NEW wwn") {
		t.Errorf("re-minting must be reported; an operator has to know the devices changed:\n%s", out.String())
	}
}

// Wipe sets the bytes aside rather than deleting them: "start empty" must not
// be a synonym for "destroy the copy".
func TestReinitWipeSetsVolumesAside(t *testing.T) {
	root, _ := stageClone(t, machineA)
	var out bytes.Buffer

	if err := Reinit(ReinitOptions{
		Root: root, Wipe: true, MachineIDPath: machineIDFile(t, machineB), Out: &out,
	}); err != nil {
		t.Fatal(err)
	}

	got := readDB(t, root)
	if len(got.Objects) != 0 || len(got.Connections) != 0 {
		t.Errorf("a wipe starts empty: %d objects, %d connections",
			len(got.Objects), len(got.Connections))
	}
	store, err := storage.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if q := store.Quarantined(); len(q) != 2 {
		t.Errorf("the bytes must be set aside, not deleted: quarantined %v", q)
	}
}

// A named IQN is taken instead of a derived one; the machine is still recorded,
// because that is what makes the NEXT clone detectable.
func TestReinitAcceptsAStatedIQN(t *testing.T) {
	root, _ := stageClone(t, machineA)
	const want = "iqn.2026-01.example:appliance-b"

	if err := Reinit(ReinitOptions{
		Root: root, TargetIQN: want, MachineIDPath: machineIDFile(t, machineB), Out: nil,
	}); err != nil {
		t.Fatal(err)
	}
	got := readDB(t, root)
	if got.TargetIQN != want {
		t.Errorf("target IQN = %q, want %q", got.TargetIQN, want)
	}
	if got.MachineID != machineB {
		t.Errorf("the machine must still be recorded: %q", got.MachineID)
	}
}

// After a reinit the appliance starts: the whole point is to clear the refusal.
func TestReinitClearsTheRefusal(t *testing.T) {
	root, _ := stageClone(t, machineA)
	idPath := machineIDFile(t, machineB)

	// Before: refuses.
	pre := &Coordinator{
		cfg:    Config{MachineIDPath: idPath},
		st:     db{Version: dbVersion, Exports: map[string]int{}},
		dbPath: filepath.Join(root, "appliance.json"),
	}
	if _, err := pre.load(); err != nil {
		t.Fatal(err)
	}
	if err := pre.adoptIdentity(); err == nil {
		t.Fatal("the staged database must be refused before reinit")
	}

	if err := Reinit(ReinitOptions{Root: root, MachineIDPath: idPath}); err != nil {
		t.Fatal(err)
	}

	post := &Coordinator{
		cfg:    Config{MachineIDPath: idPath},
		st:     db{Version: dbVersion, Exports: map[string]int{}},
		dbPath: filepath.Join(root, "appliance.json"),
	}
	if _, err := post.load(); err != nil {
		t.Fatal(err)
	}
	if err := post.adoptIdentity(); err != nil {
		t.Fatalf("after reinit the appliance must start: %v", err)
	}
	if post.cfg.TargetIQN != IQNPrefix+machineB {
		t.Errorf("effective IQN = %q", post.cfg.TargetIQN)
	}
}

func TestReinitRefusesWithoutARoot(t *testing.T) {
	if err := Reinit(ReinitOptions{}); err == nil {
		t.Error("a root is required")
	}
}
