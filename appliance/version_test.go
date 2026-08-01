package appliance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// loadDB writes body as the database and reports what load() made of it.
func loadDB(t *testing.T, body string) (*Coordinator, error) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "appliance.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &Coordinator{
		st:     db{Version: dbVersion, Exports: map[string]int{}},
		dbPath: path,
	}
	_, err := c.load()
	return c, err
}

// TestLoadRefusesANewerDatabase is the one that can destroy data.
//
// A file written by a later build decodes here with its unknown fields
// silently dropped, and snapshot() serialises only the fields THIS build
// knows -- so the next write persists a truncated copy. The version was
// previously overwritten with the current one after loading, which made that
// downgrade completely silent.
func TestLoadRefusesANewerDatabase(t *testing.T) {
	_, err := loadDB(t, `{"version":`+strconv.Itoa(dbVersion+1)+`,"objects":[],"hosts":[],
		"connections":[],"exports":{},"something_new":{"kept":true}}`)
	if err == nil {
		t.Fatal("a database from a newer build must be refused, not silently rewritten")
	}
	for _, want := range []string{"NEWER", "Run the newer build"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must say what to do, missing %q: %v", want, err)
		}
	}
}

// Version 0 is the pre-name layout. Its conversion has been removed, so it is
// refused by version rather than reaching validateLoaded and failing with
// "name is required" -- which described the symptom, not the cause.
func TestLoadRefusesThePreNameLayout(t *testing.T) {
	_, err := loadDB(t, `{"volumes":[{"uuid":"3f2504e0-4f89-11d3-9a0c-0305e82c3401"}]}`)
	if err == nil {
		t.Fatal("a version 0 database must be refused")
	}
	if !strings.Contains(err.Error(), "version 0") {
		t.Errorf("the refusal must name the version it found: %v", err)
	}
	if strings.Contains(err.Error(), "name is required") {
		t.Errorf("it must not fail as a validation error; that describes the symptom: %v", err)
	}
}

// The current version loads, which is the assertion that keeps the two above
// from passing for the wrong reason.
func TestLoadAcceptsTheCurrentVersion(t *testing.T) {
	c, err := loadDB(t, `{"version":`+strconv.Itoa(dbVersion)+`,"objects":[],"hosts":[],
		"connections":[],"exports":{}}`)
	if err != nil {
		t.Fatalf("the current version must load: %v", err)
	}
	if c.st.Version != dbVersion {
		t.Errorf("version = %d, want %d", c.st.Version, dbVersion)
	}
}

// A first start has no file at all, which is not a version problem.
func TestLoadOnAFreshRoot(t *testing.T) {
	c := &Coordinator{
		st:     db{Version: dbVersion, Exports: map[string]int{}},
		dbPath: filepath.Join(t.TempDir(), "appliance.json"),
	}
	existed, err := c.load()
	if err != nil {
		t.Fatalf("a fresh root must not be an error: %v", err)
	}
	if existed {
		t.Error("nothing was there; load must say so")
	}
	if c.st.Version != dbVersion {
		t.Errorf("a fresh coordinator keeps the current version, got %d", c.st.Version)
	}
}

// The refusal must fire BEFORE anything is written back, or refusing to run
// would not protect the file it refused.
func TestARefusedDatabaseIsLeftUntouched(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "appliance.json")
	body := `{"version":` + strconv.Itoa(dbVersion+1) + `,"objects":[],"hosts":[],
		"connections":[],"exports":{},"something_new":{"kept":true}}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &Coordinator{st: db{Version: dbVersion, Exports: map[string]int{}}, dbPath: path}
	if _, err := c.load(); err == nil {
		t.Fatal("expected a refusal")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != body {
		t.Error("the database was modified by a load that refused it")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(after, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["something_new"]; !ok {
		t.Error("the field this build does not know was lost, which is the thing the " +
			"refusal exists to prevent")
	}
}
