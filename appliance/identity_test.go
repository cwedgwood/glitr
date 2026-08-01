package appliance

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwedgwood/glitr/lio"
	"github.com/cwedgwood/glitr/lio/configfs"
)

// identityAt builds a coordinator whose machine ID comes from a file the test
// controls. Nothing here reaches configfs: adoptIdentity settles a name and
// writes the db, which is all that is under test.
func identityAt(t *testing.T, root, machineID string, cfg Config) *Coordinator {
	t.Helper()
	path := filepath.Join(root, "machine-id")
	if machineID != "" {
		if err := os.WriteFile(path, []byte(machineID+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg.MachineIDPath = path
	return &Coordinator{
		cfg:    cfg,
		st:     db{Version: dbVersion, Exports: map[string]int{}},
		dbPath: filepath.Join(root, "appliance.json"),
	}
}

const (
	machineA = "3d0d1672924d4022830b0bab818a0d58"
	machineB = "9f14c8aa7b6e40219c2d5f83ab0c71e6"
)

// TestIdentityIsDerivedAndRecorded: a first start with nothing stated names
// itself after the machine, and writes that down. The writing down is the
// point -- a name recomputed on every start is not identity.
func TestIdentityIsDerivedAndRecorded(t *testing.T) {
	root := t.TempDir()
	c := identityAt(t, root, machineA, Config{})

	if err := c.adoptIdentity(); err != nil {
		t.Fatal(err)
	}
	want := IQNPrefix + machineA
	if c.st.TargetIQN != want {
		t.Errorf("recorded IQN = %q, want %q", c.st.TargetIQN, want)
	}
	if c.st.MachineID != machineA {
		t.Errorf("recorded machine = %q, want %q", c.st.MachineID, machineA)
	}
	// The EFFECTIVE identity has to be what every later reader sees; they all
	// read cfg.TargetIQN.
	if c.cfg.TargetIQN != want {
		t.Errorf("effective IQN = %q, want %q", c.cfg.TargetIQN, want)
	}
	if !lio.ValidTargetIQN(c.st.TargetIQN) {
		t.Errorf("a derived IQN must be usable as one: %q", c.st.TargetIQN)
	}
	// Durable, not just in memory.
	if b, err := os.ReadFile(c.dbPath); err != nil {
		t.Fatal(err)
	} else if !strings.Contains(string(b), want) {
		t.Error("the identity must be on disk after adoption")
	}
}

// TestTwoMachinesDeriveDifferentIQNs is the whole reason the machine ID is the
// source: clone the VM, reset the machine ID, and the copy cannot answer to
// the original's name.
func TestTwoMachinesDeriveDifferentIQNs(t *testing.T) {
	a := identityAt(t, t.TempDir(), machineA, Config{})
	b := identityAt(t, t.TempDir(), machineB, Config{})
	if err := a.adoptIdentity(); err != nil {
		t.Fatal(err)
	}
	if err := b.adoptIdentity(); err != nil {
		t.Fatal(err)
	}
	if a.st.TargetIQN == b.st.TargetIQN {
		t.Fatalf("two machines must not derive one IQN: both are %q", a.st.TargetIQN)
	}
}

// A stated IQN is taken on a first start: derivation is the default, not a
// policy that overrides the operator.
func TestStatedIQNIsRecordedOnAFirstStart(t *testing.T) {
	const want = "iqn.2026-01.example:appliance-7"
	c := identityAt(t, t.TempDir(), machineA, Config{TargetIQN: want})
	if err := c.adoptIdentity(); err != nil {
		t.Fatal(err)
	}
	if c.st.TargetIQN != want {
		t.Errorf("recorded IQN = %q, want the stated %q", c.st.TargetIQN, want)
	}
}

// TestRecordedIQNWinsOverTheFlag: renaming a target destroys it, taking every
// session and every APTPL record bound to it, so a restart with a different
// flag must NOT be a rename. It is reported rather than silently ignored.
func TestRecordedIQNWinsOverTheFlag(t *testing.T) {
	root := t.TempDir()
	c := identityAt(t, root, machineA, Config{})
	if err := c.adoptIdentity(); err != nil {
		t.Fatal(err)
	}
	recorded := c.st.TargetIQN

	// Same appliance, restarted with someone's edit to the unit file.
	again := identityAt(t, root, machineA, Config{TargetIQN: "iqn.2026-01.example:other"})
	again.st = c.st
	if err := again.adoptIdentity(); err != nil {
		t.Fatal(err)
	}
	if again.cfg.TargetIQN != recorded {
		t.Errorf("the record must win: effective IQN = %q, want %q", again.cfg.TargetIQN, recorded)
	}
	if again.st.TargetIQN != recorded {
		t.Errorf("the record must not be overwritten: %q", again.st.TargetIQN)
	}
	if again.iqnFlagIgnored == "" {
		t.Error("ignoring the flag must be REPORTED; an operator who edited the unit " +
			"file and restarted has to be told nothing happened")
	}
	if !strings.Contains(again.iqnFlagIgnored, recorded) {
		t.Errorf("the report must name the IQN actually in use: %q", again.iqnFlagIgnored)
	}
}

// TestACloneRefusesToStart: the database says it was made somewhere else. The
// danger is not that the name is wrong -- it is that the ORIGINAL is probably
// still running, and two targets with one IQN, or two volumes with one WWN,
// are merged by an initiator rather than reported.
func TestACloneRefusesToStart(t *testing.T) {
	root := t.TempDir()
	c := identityAt(t, root, machineA, Config{})
	if err := c.adoptIdentity(); err != nil {
		t.Fatal(err)
	}

	clone := identityAt(t, root, machineB, Config{})
	clone.st = c.st
	err := clone.adoptIdentity()
	if err == nil {
		t.Fatal("a database created on another machine must refuse to start")
	}
	var conflict *identityConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("the refusal must be identifiable, got %T: %v", err, err)
	}
	// Both halves, because an operator cannot act on "identity mismatch".
	for _, want := range []string{machineA, machineB, "reinit", "-adopt", "-wipe"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must mention %q so it can be acted on:\n%v", want, err)
		}
	}
}

// A host with no machine ID still has to work. It just cannot have its clones
// detected, so an IQN must be stated rather than invented -- two such hosts
// would invent the same one.
func TestNoMachineID(t *testing.T) {
	root := t.TempDir()
	c := identityAt(t, root, "", Config{})
	err := c.adoptIdentity()
	if err == nil {
		t.Fatal("with nothing to derive from and nothing stated, starting must be refused")
	}
	if !strings.Contains(err.Error(), "-iqn") {
		t.Errorf("the refusal must say what to pass: %v", err)
	}

	stated := identityAt(t, root, "", Config{TargetIQN: "iqn.2026-01.example:hand-named"})
	if err := stated.adoptIdentity(); err != nil {
		t.Fatalf("a stated IQN must be enough without a machine ID: %v", err)
	}
	if stated.st.MachineID != "" {
		t.Errorf("nothing must be recorded as the machine: %q", stated.st.MachineID)
	}
	// And having recorded no machine, a later start must not read "" as a
	// mismatch and refuse -- that would brick every host without systemd.
	again := identityAt(t, root, "", Config{})
	again.st = stated.st
	if err := again.adoptIdentity(); err != nil {
		t.Errorf("restarting a host with no machine ID must work: %v", err)
	}
}

// A machine that GAINS an ID -- the file was absent, then systemd wrote one --
// adopts it rather than refusing. Nothing was recorded to conflict with.
func TestAMachineThatGainsAnIDAdoptsIt(t *testing.T) {
	root := t.TempDir()
	first := identityAt(t, root, "", Config{TargetIQN: "iqn.2026-01.example:named"})
	if err := first.adoptIdentity(); err != nil {
		t.Fatal(err)
	}
	later := identityAt(t, root, machineA, Config{})
	later.st = first.st
	if err := later.adoptIdentity(); err != nil {
		t.Fatalf("gaining a machine ID must not be read as a clone: %v", err)
	}
	if later.st.MachineID != machineA {
		t.Errorf("the new machine ID must be recorded: %q", later.st.MachineID)
	}
	if later.st.TargetIQN != "iqn.2026-01.example:named" {
		t.Errorf("gaining an ID must not rename the target: %q", later.st.TargetIQN)
	}
}

func TestReadMachineID(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "absent")
	if id, err := readMachineID(missing); err != nil || id != "" {
		t.Errorf("an absent file is not an error: %q, %v", id, err)
	}

	// systemd writes an empty file to mean "regenerate at next boot", which is
	// the state a prepared clone image is left in. Recording an identity
	// against it would record one that is about to change.
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if id, err := readMachineID(empty); err != nil || id != "" {
		t.Errorf("an empty file means unset: %q, %v", id, err)
	}

	good := filepath.Join(dir, "good")
	if err := os.WriteFile(good, []byte(machineA+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if id, err := readMachineID(good); err != nil || id != machineA {
		t.Errorf("read %q, %v; want %q", id, err, machineA)
	}

	// Present but not an ID means something is wrong that guessing would hide.
	for _, bad := range []string{"not-hex-at-all", "ABCDEF0123456789ABCDEF0123456789", "3d0d16"} {
		p := filepath.Join(dir, "bad")
		if err := os.WriteFile(p, []byte(bad), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readMachineID(p); err == nil {
			t.Errorf("%q is not a machine ID and must be refused", bad)
		}
	}
}

// TestUpgradeAdoptsTheLiveTarget: an appliance that predates the recorded IQN,
// restarting into a build that has it. It already has a name and initiators
// are logged in to it, so deriving a fresh one would rename the target --
// which destroys it and every session on it, during what the operator
// experienced as an upgrade.
func TestUpgradeAdoptsTheLiveTarget(t *testing.T) {
	const live = "iqn.2026-01.dev.glitr:appliance"
	root := t.TempDir()
	c := identityAt(t, root, machineA, Config{})

	// A kernel tree with exactly one target in it, which is what an appliance
	// that has been serving looks like. Staged as directories rather than
	// through Sync: enabling a TPG writes an attribute file the kernel
	// creates and a temp dir does not, and a test that skipped itself over
	// that would assert nothing.
	cfgRoot := t.TempDir()
	tpg := filepath.Join(cfgRoot, "iscsi", live, "tpgt_1")
	for _, d := range []string{"np", "lun", "acls"} {
		if err := os.MkdirAll(filepath.Join(tpg, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(tpg, "enable"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c.lio = lio.New(configfs.New(cfgRoot))
	if got, err := c.lio.Discover(); err != nil || len(got.Targets) != 1 {
		t.Fatalf("the fixture must present exactly one live target: %d, %v",
			len(got.Targets), err)
	}

	if err := c.adoptIdentity(); err != nil {
		t.Fatal(err)
	}
	if c.st.TargetIQN != live {
		t.Errorf("an upgrade must keep the name it is already serving: got %q, want %q",
			c.st.TargetIQN, live)
	}
	if c.st.MachineID != machineA {
		t.Errorf("the machine must still be recorded, so the NEXT clone is detectable: %q",
			c.st.MachineID)
	}
}

// A fresh host has no live target, so there is nothing to adopt and the name
// is derived. The two cases differ only in what the kernel already holds.
func TestAFreshHostDerivesRatherThanAdopts(t *testing.T) {
	c := identityAt(t, t.TempDir(), machineA, Config{})
	c.lio = lio.New(configfs.New(t.TempDir()))
	if err := c.adoptIdentity(); err != nil {
		t.Fatal(err)
	}
	if c.st.TargetIQN != DeriveTargetIQN(machineA) {
		t.Errorf("with no live target the name is derived, got %q", c.st.TargetIQN)
	}
}
