package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckMountTargetRefusesToHideData pins the guard that stops a data disk
// being mounted over a data root that already holds volumes.
//
// Mounting over a non-empty directory HIDES its contents rather than deleting
// them, which to an operator is indistinguishable from data loss. The guard
// lived inline in SetupSystem, which needs root, a spare block device and a
// distro package manager, so nothing exercised it.
func TestCheckMountTargetRefusesToHideData(t *testing.T) {
	// Empty data root: the normal path, must be allowed.
	empty := t.TempDir()
	if err := checkMountTarget(empty, "/dev/vdb", false); err != nil {
		t.Errorf("refused to mount over an empty data root: %v", err)
	}

	// Non-empty: must refuse, and must name the override.
	full := t.TempDir()
	if err := os.WriteFile(filepath.Join(full, "volumes.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := checkMountTarget(full, "/dev/vdb", false)
	if err == nil {
		t.Fatal("allowed a mount that would hide an existing volumes.json")
	}
	if !strings.Contains(err.Error(), "-force-mount") {
		t.Errorf("the refusal does not name the override: %v", err)
	}

	// ...and must yield when the operator says so explicitly.
	if err := checkMountTarget(full, "/dev/vdb", true); err != nil {
		t.Errorf("-force-mount did not override the guard: %v", err)
	}

	// A data root that does not exist yet is fine -- setup creates it.
	if err := checkMountTarget(filepath.Join(empty, "not-yet"), "/dev/vdb", false); err != nil {
		t.Errorf("refused to mount at a data root that does not exist yet: %v", err)
	}

	// Unreadable must NOT read as empty. This is the fail-open direction: a
	// directory whose contents cannot be listed is exactly the one where
	// hiding data is most likely to go unnoticed.
	noRead := t.TempDir()
	inner := filepath.Join(noRead, "locked")
	if err := os.Mkdir(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inner, "volumes.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(inner, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(inner, 0o755)
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 000 does not deny a read, so this case " +
			"cannot be exercised here")
	}
	if err := checkMountTarget(inner, "/dev/vdb", false); err == nil {
		t.Error("an unreadable data root was treated as empty -- 'I could not " +
			"look' must not take the same path as 'there is nothing there'")
	}
}
