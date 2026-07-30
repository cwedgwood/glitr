// Package saveconfig persists and restores the full LIO configuration as
// JSON.
//
// The LIO tree lives in kernel memory and is gone after a reboot, so anything
// that should survive one has to be written down and replayed. This is
// deliberately separate from glitr/lio, which owns no persistence and no
// opinion about where state belongs.
package saveconfig

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cwedgwood/glitr/lio"
)

// DefaultPath is the canonical saved-configuration location.
const DefaultPath = "/etc/glitr/lio-config.json"

// Save discovers the live LIO state and writes it to path as indented
// JSON. The write is atomic (unique temp file + rename) and creates the
// parent directory if needed. A unique temp name (not a fixed "<path>.tmp")
// is used because Save is a read-only verb that takes no host lock, so two
// concurrent Saves must not race on a shared temp file.
func Save(m *lio.Manager, path string) error {
	cfg, err := m.Discover()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".lio-config-*.tmp") // mode 0600, unique name
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename below has moved it
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil { // durable: flush file contents before rename
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDir(dir) // durable: flush the rename
}

// syncDir fsyncs a directory so a preceding rename is durable across a crash.
func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Load reads and validates a saved Config from path.
//
// Decoding is STRICT: unknown fields are refused and trailing content after
// the object is an error. json.Unmarshal ignores both, and what that permits
// here is not a cosmetic tolerance -- Restore feeds this straight into Sync,
// which prunes every live object the config does not name. A file whose
// "backstores" key was misspelled, or which came from a different schema
// entirely, decodes to an EMPTY config; an empty config is deliberately valid;
// and the restore then tears down the whole live tree instead of refusing a
// file it did not understand.
//
// This is the durable authority after a reboot, so the failure it must not
// have is silently agreeing with a damaged file.
func Load(path string) (lio.Config, error) {
	var cfg lio.Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("saveconfig: %s: %w", path, err)
	}
	// Exactly one JSON value, then EOF. Two concatenated objects, or a
	// truncated write that left a second partial one, would otherwise decode
	// as the first and discard the rest without complaint.
	if err := dec.Decode(new(struct{})); err != io.EOF {
		return lio.Config{}, fmt.Errorf(
			"saveconfig: %s: trailing content after the configuration object", path)
	}
	return cfg, cfg.Validate()
}

// Restore reconciles the kernel to the saved configuration at path — it
// applies everything in the file and prunes any live LIO object not in
// the file (the "reconcile within a filter scope" semantics; the scope
// currently matches all). A missing file is a successful no-op (fresh
// system).
func Restore(m *lio.Manager, path string) (lio.Report, error) {
	cfg, err := Load(path)
	if err != nil {
		if os.IsNotExist(err) {
			return lio.Report{}, nil
		}
		return lio.Report{}, err
	}
	return m.Sync(cfg)
}
