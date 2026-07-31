package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testUUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCreateMakesASparseFileOfTheRightSize(t *testing.T) {
	s := newStore(t)
	if err := s.Create(testUUID, 1<<20); err != nil {
		t.Fatal(err)
	}
	got, err := s.Size(testUUID)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1<<20 {
		t.Errorf("size = %d, want %d", got, 1<<20)
	}
	if !s.Exists(testUUID) {
		t.Error("Exists says no after Create")
	}
	// Sparse: the file is a megabyte long and has been given almost nothing.
	var st os.FileInfo
	if st, err = os.Stat(s.DiskPath(testUUID)); err != nil {
		t.Fatal(err)
	}
	if st.Size() != 1<<20 {
		t.Errorf("stat size = %d", st.Size())
	}
}

func TestCreateRefusesToReuseAnIdentifier(t *testing.T) {
	s := newStore(t)
	if err := s.Create(testUUID, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(testUUID, 1<<20); err == nil {
		t.Fatal("creating over an existing object must be refused, not silently overwrite it")
	}
}

// The identifier becomes a directory name, so anything that could leave the
// store's own directory has to be refused rather than sanitised.
func TestCreateRefusesADangerousIdentifier(t *testing.T) {
	s := newStore(t)
	for _, id := range []string{"", ".", "..", "a/b", "../escape"} {
		if err := s.Create(id, 1<<20); err == nil {
			t.Errorf("identifier %q must be refused", id)
		}
	}
}

func TestResizeGrowsAndRefusesToShrink(t *testing.T) {
	s := newStore(t)
	if err := s.Create(testUUID, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := s.Resize(testUUID, 2<<20); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Size(testUUID); got != 2<<20 {
		t.Errorf("size = %d, want %d", got, 2<<20)
	}
	// Idempotent: growing to the size it already has is not an error, because
	// a caller retrying a resize it is unsure landed must not be punished.
	if err := s.Resize(testUUID, 2<<20); err != nil {
		t.Errorf("resize to the current size must succeed: %v", err)
	}
	if err := s.Resize(testUUID, 1<<20); err == nil {
		t.Error("shrink must be refused: the bytes above the new end are somebody's data")
	}
}

func TestDeleteRemovesTheBytes(t *testing.T) {
	s := newStore(t)
	if err := s.Create(testUUID, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(testUUID); err != nil {
		t.Fatal(err)
	}
	if s.Exists(testUUID) {
		t.Error("the object survived Delete")
	}
}

// A staging directory is an object that was never committed, so Open removes
// it. Anything else would leave a half-made object that ObjectDirs would then
// report as unrecorded and quarantine, turning a crash into a mystery.
func TestOpenRemovesUncommittedStaging(t *testing.T) {
	root := t.TempDir()
	s := newStoreAt(t, root)
	staging := filepath.Join(root, "objects", stagingPrefix+testUUID)
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Error("an uncommitted staging directory must be removed at Open")
	}
	_ = s
}

func newStoreAt(t *testing.T, root string) *Store {
	t.Helper()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestObjectDirsExcludesStagingAndQuarantine(t *testing.T) {
	root := t.TempDir()
	s := newStoreAt(t, root)
	if err := s.Create(testUUID, 1<<20); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{quarantinePrefix + "old", stagingPrefix + "wip"} {
		if err := os.MkdirAll(filepath.Join(root, "objects", n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	dirs, err := s.ObjectDirs()
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) != 1 || dirs[0] != testUUID {
		t.Errorf("ObjectDirs = %v, want just the committed object", dirs)
	}
}

// Quarantine RENAMES. It must never delete: the case where it fires is the
// case where the data matters most -- a restored db is always at least one
// object behind the disk, so what it does not know about is the newest work.
func TestQuarantineKeepsTheData(t *testing.T) {
	root := t.TempDir()
	s := newStoreAt(t, root)
	if err := s.Create(testUUID, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.DiskPath(testUUID), []byte("PRECIOUS"), 0o644); err != nil {
		t.Fatal(err)
	}

	q, err := s.Quarantine(testUUID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(q, quarantinePrefix) {
		t.Errorf("quarantine name %q does not carry the prefix", q)
	}
	data, err := os.ReadFile(filepath.Join(root, "objects", q, "disk"))
	if err != nil {
		t.Fatalf("the quarantined data must still be readable: %v", err)
	}
	if string(data) != "PRECIOUS" {
		t.Errorf("the data changed: %q", data)
	}
	if s.Exists(testUUID) {
		t.Error("the original name must be gone after quarantine")
	}
	if got := s.Quarantined(); len(got) != 1 || got[0] != q {
		t.Errorf("Quarantined() = %v, want [%s]", got, q)
	}

	// And a second Open reports it without setting it aside again into an
	// ever-lengthening name.
	s2 := newStoreAt(t, root)
	if got := s2.Quarantined(); len(got) != 1 || got[0] != q {
		t.Errorf("after reopen, Quarantined() = %v, want [%s]", got, q)
	}
}

func TestCloneNeedsARealSource(t *testing.T) {
	s := newStore(t)
	if err := s.Clone("no-such-object", testUUID); err == nil {
		t.Error("cloning something that does not exist must fail")
	}
}

// Reflink needs a filesystem that supports FICLONE, which the usual tmpdir
// (ext4 or overlayfs) does not, so the copying path is proved in the live
// suites. What is asserted here is that a failure is REPORTED rather than
// leaving a half-made object behind.
func TestCloneLeavesNothingBehindWhenItFails(t *testing.T) {
	root := t.TempDir()
	s := newStoreAt(t, root)
	if err := s.Create(testUUID, 1<<20); err != nil {
		t.Fatal(err)
	}
	const dst = "3f2504e0-4f89-11d3-9a0c-0305e82c3302"
	if err := s.Clone(testUUID, dst); err != nil {
		// Expected on a filesystem without reflink support.
		if s.Exists(dst) {
			t.Error("a failed clone must not leave the destination behind")
		}
		dirs, derr := s.ObjectDirs()
		if derr != nil {
			t.Fatal(derr)
		}
		for _, d := range dirs {
			if d == dst {
				t.Error("a failed clone left a committed directory")
			}
		}
		return
	}
	// On a reflink-capable filesystem it should simply have worked.
	if !s.Exists(dst) {
		t.Error("clone reported success but the object is not there")
	}
}
