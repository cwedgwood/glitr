package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnsureFstabReplacesAStaleEntryForTheSameMountPoint is the regression
// test for a fault that took the lab target down on a fresh boot.
//
// ensureFstab used to skip only when it found the same UUID in the file. A
// reformatted disk necessarily has a NEW UUID, so re-running appended a second
// entry for the same mount point while the first still named a filesystem that
// no longer existed. systemd generates one mount unit per mount point, so the
// duplicate is never right -- the mount failed, applianced failed with it, and
// the only message was "Dependency failed", naming neither fstab nor the disk.
func TestEnsureFstabReplacesAStaleEntryForTheSameMountPoint(t *testing.T) {
	const (
		stale = "UUID=736e1872-eff6-4cf3-9d8c-bbf090f58da3 /var/lib/glitr xfs nofail,x-systemd.device-timeout=10s 0 0"
		fresh = "UUID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee /var/lib/glitr xfs nofail,x-systemd.device-timeout=10s 0 0"
	)
	path := filepath.Join(t.TempDir(), "fstab")
	original := "# /etc/fstab\nUUID=root-uuid / ext4 defaults 0 1\n" + stale + "\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	changed, err := ensureFstab(path, fresh, "/var/lib/glitr")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("replacing a stale entry reported no change")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "736e1872") {
		t.Errorf("the stale entry survived:\n%s", got)
	}
	if n := strings.Count(string(got), "/var/lib/glitr"); n != 1 {
		t.Errorf("got %d entries for /var/lib/glitr, want exactly 1:\n%s", n, got)
	}
	// Unrelated lines and comments are somebody else's data.
	if !strings.Contains(string(got), "# /etc/fstab") ||
		!strings.Contains(string(got), "UUID=root-uuid / ext4 defaults 0 1") {
		t.Errorf("unrelated content was not preserved:\n%s", got)
	}
	if !strings.HasSuffix(string(got), "\n") || strings.HasSuffix(string(got), "\n\n") {
		t.Errorf("want exactly one trailing newline, got %q", got)
	}
}

func TestEnsureFstabIsIdempotent(t *testing.T) {
	const line = "UUID=aaaa /var/lib/glitr xfs nofail 0 0"
	path := filepath.Join(t.TempDir(), "fstab")
	if err := os.WriteFile(path, []byte("UUID=root / ext4 defaults 0 1\n"+line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := ensureFstab(path, line, "/var/lib/glitr")
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("an already-correct entry reported a change")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("file rewritten when nothing needed to change:\nbefore %q\nafter  %q", before, after)
	}
}

func TestEnsureFstabAppendsWhenAbsent(t *testing.T) {
	const line = "UUID=aaaa /var/lib/glitr xfs nofail 0 0"
	path := filepath.Join(t.TempDir(), "fstab")

	// Including the case where /etc/fstab does not exist at all.
	changed, err := ensureFstab(path, line, "/var/lib/glitr")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("writing a new entry reported no change")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != line+"\n" {
		t.Errorf("got %q, want %q", got, line+"\n")
	}
}

// TestEnsureFstabIgnoresAMountPointInsideAComment guards the parse: a mount
// point named in a comment is not an entry, and a commented-out line must not
// be silently deleted as though it were a stale one.
func TestEnsureFstabIgnoresAMountPointInsideAComment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fstab")
	original := "# was: UUID=old /var/lib/glitr xfs defaults 0 0\nUUID=root / ext4 defaults 0 1\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureFstab(path, "UUID=new /var/lib/glitr xfs nofail 0 0", "/var/lib/glitr"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "# was: UUID=old") {
		t.Errorf("a comment was treated as an entry and removed:\n%s", got)
	}
}
