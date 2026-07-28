package configfs

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// configfs has two removal operations that mean different things: rmdir on an
// object directory DESTROYS a kernel object, while unlink on a symlink UNMAPS
// something -- removing a LUN's backstore link detaches storage from a live
// initiator.
//
// Both used to go through one function built on os.Remove, which tries unlink
// and falls back to rmdir, so it performed whichever the path allowed and
// reported success either way. unlinkAll genuinely relied on that fallback to
// remove symlinks through a function called Rmdir, so the conflation was real
// rather than theoretical.
//
// These tests pin that each now refuses the other's argument, which is what
// turns a future mix-up into an error instead of an unmapped LUN.

func TestRmdirRefusesASymlink(t *testing.T) {
	root := t.TempDir()
	fs := New(root)
	target := filepath.Join(root, "backstore")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "lun_link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	err := fs.Rmdir("lun_link")
	if err == nil {
		t.Fatal("Rmdir removed a SYMLINK and reported success. On a real target that " +
			"is a LUN's backstore link, so the call would have unmapped storage from a " +
			"live initiator while claiming to have destroyed an object")
	}
	if !errors.Is(err, syscall.ENOTDIR) {
		t.Errorf("expected ENOTDIR, got %v", err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("the symlink must still be there after a refused Rmdir: %v", err)
	}
}

func TestUnlinkRefusesADirectory(t *testing.T) {
	root := t.TempDir()
	fs := New(root)
	if err := os.Mkdir(filepath.Join(root, "obj"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := fs.Unlink("obj")
	if err == nil {
		t.Fatal("Unlink removed an object DIRECTORY. Destroying a kernel object is a " +
			"different act from unmapping a link, and must go through Rmdir")
	}
	if !errors.Is(err, syscall.EISDIR) && !errors.Is(err, syscall.EPERM) {
		t.Errorf("expected EISDIR (or EPERM, which some kernels return), got %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "obj")); err != nil {
		t.Errorf("the directory must survive a refused Unlink: %v", err)
	}
}

// Each must still do its own job, or the split would have broken teardown.
func TestRmdirAndUnlinkDoTheirOwnJob(t *testing.T) {
	root := t.TempDir()
	fs := New(root)
	if err := os.Mkdir(filepath.Join(root, "obj"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "obj"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := fs.Unlink("link"); err != nil {
		t.Errorf("Unlink must remove a symlink: %v", err)
	}
	if err := fs.Rmdir("obj"); err != nil {
		t.Errorf("Rmdir must remove an empty object directory: %v", err)
	}
}

// Teardown is idempotent and re-runnable, so "already gone" is success for
// both -- a reconcile that crashed halfway must be able to finish.
func TestRemovalOfSomethingAlreadyGoneIsNotAnError(t *testing.T) {
	fs := New(t.TempDir())
	if err := fs.Rmdir("never-existed"); err != nil {
		t.Errorf("Rmdir of an absent path must succeed: %v", err)
	}
	if err := fs.Unlink("never-existed"); err != nil {
		t.Errorf("Unlink of an absent path must succeed: %v", err)
	}
}

// A non-empty object directory must NOT be removed: configfs requires children
// to go first, and silently succeeding would hide a teardown-order bug.
func TestRmdirRefusesANonEmptyDirectory(t *testing.T) {
	root := t.TempDir()
	fs := New(root)
	if err := os.MkdirAll(filepath.Join(root, "obj", "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := fs.Rmdir("obj")
	if err == nil {
		t.Fatal("Rmdir removed a directory that still had children")
	}
	if !errors.Is(err, syscall.ENOTEMPTY) {
		t.Errorf("expected ENOTEMPTY, got %v", err)
	}
}
