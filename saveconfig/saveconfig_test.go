package saveconfig

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cwedgwood/glitr/lio"
	"github.com/cwedgwood/glitr/lio/configfs"
)

// TestSaveLoadRoundTrip saves the (empty) discovered config and reads it
// back. It exercises the atomic write + rename and Load/Validate plumbing
// without needing a real kernel (Manager rooted at an empty tmpdir).
func TestSaveLoadRoundTrip(t *testing.T) {
	m := lio.New(configfs.New(t.TempDir()))
	path := filepath.Join(t.TempDir(), "sub", "lio-config.json") // parent must be created
	if err := Save(m, path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	// No stray temp files left in the directory.
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 || entries[0].Name() != "lio-config.json" {
		t.Fatalf("unexpected dir contents (leftover temp?): %v", names(entries))
	}
}

// TestConcurrentSaveNoCorruption runs many Saves at once to the same path.
// Save is a read-only verb (no host lock), so a shared temp name would let
// them corrupt each other's file; the unique-temp fix must keep the result
// a single valid config.
func TestConcurrentSaveNoCorruption(t *testing.T) {
	m := lio.New(configfs.New(t.TempDir()))
	dir := t.TempDir()
	path := filepath.Join(dir, "lio-config.json")

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if err := Save(m, path); err != nil {
				t.Errorf("concurrent Save: %v", err)
			}
		})
	}
	wg.Wait()

	if _, err := Load(path); err != nil {
		t.Fatalf("config corrupted by concurrent saves: %v", err)
	}
	// Only the final config file should remain — no leftover temp files.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "lio-config.json" {
		t.Fatalf("leftover temp files after concurrent saves: %v", names(entries))
	}
}

// TestRestoreMissingFileIsNoOp verifies a missing file restores as a no-op.
func TestRestoreMissingFileIsNoOp(t *testing.T) {
	m := lio.New(configfs.New(t.TempDir()))
	if _, err := Restore(m, filepath.Join(t.TempDir(), "does-not-exist.json")); err != nil {
		t.Fatalf("Restore of a missing file should be a no-op, got: %v", err)
	}
}

func names(es []os.DirEntry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// TestLoadRefusesAForeignOrDamagedFile pins strict decoding.
//
// Restore feeds Load straight into Sync, which prunes every live object the
// config does not name. json.Unmarshal ignores unknown fields, so a file whose
// "backstores" key was misspelled -- or one from a different schema entirely --
// decoded to an EMPTY config, an empty config is deliberately valid, and the
// restore then tore down the whole live tree instead of refusing a file it did
// not understand.
func TestLoadRefusesAForeignOrDamagedFile(t *testing.T) {
	for name, body := range map[string]string{
		"misspelled key":   `{"backstore": [], "targets": []}`,
		"foreign schema":   `{"apiVersion": "v1", "kind": "ConfigMap"}`,
		"trailing content": `{"backstores": [], "targets": []} {"backstores": []}`,
		"truncated object": `{"backstores": [`,
		"not an object":    `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "lio-config.json")
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Errorf("accepted %s: a restore would then prune the live tree", name)
			}
		})
	}

	// The negative control: a genuinely empty configuration is still valid,
	// because "export nothing" is a legitimate thing to save.
	t.Run("a real empty config is accepted", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "lio-config.json")
		if err := os.WriteFile(path, []byte(`{"backstores":[],"targets":[]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err != nil {
			t.Errorf("a valid empty config was refused: %v", err)
		}
	})
}
