package storage

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

// TestSnapshotReflink verifies reflink snapshots on a real reflink-capable
// filesystem. It runs only when GLITR_REFLINK_DIR points at such a dir
// (XFS/btrfs), since the host tmpdir usually is not (overlayfs/ext4).
func TestSnapshotReflink(t *testing.T) {
	dir := os.Getenv("GLITR_REFLINK_DIR")
	if dir == "" {
		t.Skip("set GLITR_REFLINK_DIR to a reflink-capable dir (XFS) to run")
	}
	root, err := os.MkdirTemp(dir, "store-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)

	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Create(1<<20, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Write a known pattern at offset 0 WITHOUT truncating (the file must
	// stay full-size; Snapshot now rejects a short source).
	pattern := bytes.Repeat([]byte("AB"), 4096)
	writeAt := func(uuid string, p []byte) {
		f, err := os.OpenFile(s.DiskPath(uuid), os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteAt(p, 0); err != nil {
			t.Fatal(err)
		}
	}
	readAt := func(uuid string, n int) []byte {
		f, err := os.Open(s.DiskPath(uuid))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		buf := make([]byte, n)
		if _, err := f.ReadAt(buf, 0); err != nil {
			t.Fatal(err)
		}
		return buf
	}
	writeAt(v.UUID, pattern)

	snap, err := s.Snapshot(v.UUID)
	if err != nil {
		t.Fatalf("snapshot (reflink): %v", err)
	}
	// The snapshot's backing file must be full-size (same as source).
	if fi, err := os.Stat(s.DiskPath(snap.UUID)); err != nil || fi.Size() != int64(1<<20) {
		t.Fatalf("snapshot file size = %v (err %v); want %d", fi.Size(), err, 1<<20)
	}
	// New, independent identity + provenance.
	if snap.UUID == v.UUID || snap.WWN == v.WWN {
		t.Fatalf("snapshot did not get a new identity: %+v vs %+v", snap, v)
	}
	if snap.Parent != v.UUID {
		t.Fatalf("snapshot parent = %q; want %q", snap.Parent, v.UUID)
	}
	// Content matches at snapshot time.
	if !bytes.Equal(readAt(snap.UUID, len(pattern)), pattern) {
		t.Fatalf("snapshot content differs from source")
	}
	// Independence: mutate the source; snapshot must be unchanged (CoW).
	writeAt(v.UUID, bytes.Repeat([]byte("XY"), 4096))
	if !bytes.Equal(readAt(snap.UUID, len(pattern)), pattern) {
		t.Fatalf("snapshot changed when source was modified — not independent")
	}
}

// TestSnapshotFailsClearlyOnAFilesystemThatCannotClone pins the error that now
// carries the whole load.
//
// Capability used to be predicted ahead of time by preflight and setup-system.
// Both probes were removed: preflight ran before the data root existed, so it
// could only probe whichever filesystem currently owned that path, while the
// normal `setup-system -data-disk` flow mounts a freshly formatted disk there
// afterwards -- the answer was about a filesystem the data never lands on. Any
// errno also collapsed to "no reflink", so EACCES read as a missing feature.
//
// So the snapshot attempt IS the answer, and its error is the only thing an
// operator gets. It has to name the errno (so the cause is not guessed at) and
// the remedy (so it is actionable). Run against tmpfs, a real filesystem with
// no FICLONE, rather than a simulated failure.
func TestSnapshotFailsClearlyOnAFilesystemThatCannotClone(t *testing.T) {
	if _, err := os.Stat("/dev/shm"); err != nil {
		t.Skip("no /dev/shm to use as a known non-reflink filesystem")
	}
	root, err := os.MkdirTemp("/dev/shm", "glitr-noreflink-")
	if err != nil {
		t.Skipf("cannot create a tmpfs work dir: %v", err)
	}
	defer os.RemoveAll(root)

	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Create(1<<20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Snapshot(v.UUID); err == nil {
		t.Fatal("a snapshot on a filesystem with no FICLONE must fail, not silently copy")
	} else {
		msg := err.Error()
		if !errors.Is(err, syscall.EOPNOTSUPP) {
			t.Errorf("the kernel's own errno must survive to the caller, got %v", err)
		}
		if !strings.Contains(msg, "reflink") {
			t.Errorf("the error must name the mechanism that failed, got %q", msg)
		}
		if !strings.Contains(msg, "XFS") {
			t.Errorf("the error must say what would fix it -- it is the ONLY notice an "+
				"operator gets now that nothing predicts capability, got %q", msg)
		}
	}
}
