package configfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFSPrimitives(t *testing.T) {
	root := t.TempDir()
	fs := New(root)

	if err := fs.Mkdir("a", "b"); err == nil {
		// single-level mkdir semantics: parent must exist first
		t.Fatalf("expected error creating nested dir without parent")
	}
	if err := fs.Mkdir("a"); err != nil {
		t.Fatalf("mkdir a: %v", err)
	}
	if err := fs.Mkdir("a"); err != nil {
		t.Fatalf("mkdir a (idempotent) should not error: %v", err)
	}

	ok, err := fs.Exists("a")
	if err != nil || !ok {
		t.Fatalf("Exists(a) = %v, %v; want true, nil", ok, err)
	}
	isDir, err := fs.IsDir("a")
	if err != nil || !isDir {
		t.Fatalf("IsDir(a) = %v, %v; want true, nil", isDir, err)
	}

	if err := fs.WriteAttr("hello", "a", "attr"); err != nil {
		t.Fatalf("WriteAttr: %v", err)
	}
	got, err := fs.ReadAttr("a", "attr")
	if err != nil || got != "hello" {
		t.Fatalf("ReadAttr = %q, %v; want hello", got, err)
	}

	// Symlink + FindSymlink round-trip.
	target := fs.Path("a")
	if err := fs.Mkdir("l"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Symlink(target, "l", "deadbeef01"); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := fs.Symlink(target, "l", "deadbeef01"); err != nil {
		t.Fatalf("Symlink (idempotent identical): %v", err)
	}
	name, tgt, err := fs.FindSymlink("l")
	if err != nil || name != "deadbeef01" || tgt != target {
		t.Fatalf("FindSymlink = %q,%q,%v; want deadbeef01,%q", name, tgt, err, target)
	}

	// Rmdir on missing is not an error.
	if err := fs.Rmdir("does", "not", "exist"); err != nil {
		t.Fatalf("Rmdir missing should be nil: %v", err)
	}
}

func TestReadDirSorted(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"z", "a", "m"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fs := New(root)
	names, err := fs.ReadDir()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 3 || names[0] != "a" || names[2] != "z" {
		t.Fatalf("ReadDir = %v; want sorted [a m z]", names)
	}
}

// TestPathValidation: components that could escape Root are rejected with an
// error (the layer checks and errors out on bad input; F4).
func TestPathValidation(t *testing.T) {
	fs := New(t.TempDir())
	bad := [][]string{
		{".."},
		{"a", ".."},
		{"a/b"},  // embedded separator
		{""},     // empty segment
		{"."},    // dot
		{"/etc"}, // absolute-looking
		{"a", "../.."},
	}
	for _, parts := range bad {
		if _, err := fs.Exists(parts...); err == nil {
			t.Errorf("Exists(%q) = nil err; want rejection", parts)
		}
		if err := fs.Mkdir(parts...); err == nil {
			t.Errorf("Mkdir(%q) = nil err; want rejection", parts)
		}
		if err := fs.WriteAttr("x", parts...); err == nil {
			t.Errorf("WriteAttr(%q) = nil err; want rejection", parts)
		}
	}
	// A valid single segment with LIO-legal punctuation must be accepted.
	if err := fs.Mkdir("iqn.2026-01.dev.glitr:host"); err != nil {
		t.Errorf("valid IQN-ish segment rejected: %v", err)
	}
}

// TestMkdirNonDirCollision: EEXIST against a file/symlink (not a directory)
// must be an error, not a false success (F5).
func TestMkdirNonDirCollision(t *testing.T) {
	fs := New(t.TempDir())
	if err := os.WriteFile(fs.Path("f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.Mkdir("f"); err == nil {
		t.Fatal("Mkdir over an existing regular file should error, not report success")
	}
}

// TestReadAttrPreservesTrailingSpace: only the single kernel newline is
// stripped; a legitimate trailing space round-trips (F2).
func TestReadAttrPreservesTrailingSpace(t *testing.T) {
	fs := New(t.TempDir())
	if err := fs.Mkdir("o"); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteAttr("val ", "o", "a"); err != nil {
		t.Fatal(err)
	}
	got, err := fs.ReadAttr("o", "a")
	if err != nil || got != "val " {
		t.Fatalf("ReadAttr = %q, %v; want \"val \" (trailing space preserved)", got, err)
	}
}

// TestWriteAttrTooLarge: an oversized value is rejected so the kernel never
// short-writes and the Go runtime never issues a second write(2) (F3).
func TestWriteAttrTooLarge(t *testing.T) {
	fs := New(t.TempDir())
	if err := fs.Mkdir("o"); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, maxAttrWrite) // +newline pushes over the limit
	for i := range big {
		big[i] = 'x'
	}
	if err := fs.WriteAttr(string(big), "o", "a"); err == nil {
		t.Fatal("oversized WriteAttr should be rejected")
	}
	// One byte under the limit (accounting for the appended newline) is OK.
	if err := fs.WriteAttr(string(big[:maxAttrWrite-1]), "o", "a"); err != nil {
		t.Fatalf("value at the limit should be accepted: %v", err)
	}
}

// TestSymlinkRelativeIdempotent reproduces the real-configfs case: links are
// stored RELATIVE, so an idempotent re-link must still be recognised. We
// hand-create a relative link (as configfs would) and assert fs.Symlink with
// the ABSOLUTE target is a no-op rather than an EEXIST error (F1).
func TestSymlinkRelativeIdempotent(t *testing.T) {
	fs := New(t.TempDir())
	if err := fs.Mkdir("target"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Mkdir("d"); err != nil {
		t.Fatal(err)
	}
	link := fs.Path("d", "lnk")
	// configfs would store this relative body; create it by hand.
	if err := os.Symlink("../target", link); err != nil {
		t.Fatal(err)
	}
	// Absolute target that the relative link resolves to.
	if err := fs.Symlink(fs.Path("target"), "d", "lnk"); err != nil {
		t.Fatalf("Symlink should be idempotent against a relative link resolving to the same target, got: %v", err)
	}
	// A genuinely different target must still surface a conflict.
	if err := fs.Symlink(fs.Path("d"), "d", "lnk"); err == nil {
		t.Fatal("Symlink to a different target should surface a conflict")
	}
}
