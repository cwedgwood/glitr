package hostlock

import (
	"path/filepath"
	"testing"
)

func TestMutualExclusion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lio.lock")

	a := New(path)
	ok, err := a.TryLock()
	if err != nil || !ok {
		t.Fatalf("first TryLock = %v,%v; want true,nil", ok, err)
	}

	// A second, independent Lock on the same path must fail (held by a).
	b := New(path)
	ok, err = b.TryLock()
	if err != nil {
		t.Fatalf("second TryLock err: %v", err)
	}
	if ok {
		t.Fatal("second TryLock succeeded while first holds the lock")
	}

	// After the first releases, the second can acquire.
	a.Unlock()
	ok, err = b.TryLock()
	if err != nil || !ok {
		t.Fatalf("TryLock after release = %v,%v; want true,nil", ok, err)
	}
	b.Unlock()
}

func TestDefaultPath(t *testing.T) {
	if New("").Path() != DefaultPath {
		t.Fatal("empty path should use DefaultPath")
	}
}

// TestTryLockRefusesToRelockItself pins that a Lock cannot quietly acquire
// twice. It used to overwrite its own descriptor: the first fd leaked, Unlock
// released only the second, and since flock is per-open-file the process went
// on holding a lock it believed it had dropped.
func TestTryLockRefusesToRelockItself(t *testing.T) {
	l := New(filepath.Join(t.TempDir(), "glitr.lock"))
	ok, err := l.TryLock()
	if err != nil || !ok {
		t.Fatalf("first TryLock: ok=%v err=%v", ok, err)
	}
	defer l.Unlock()

	if ok, err := l.TryLock(); ok || err == nil {
		t.Errorf("second TryLock on the same Lock: ok=%v err=%v, want refused", ok, err)
	}

	// And after Unlock it may be taken again, or this would pass by never
	// allowing a lock at all.
	l.Unlock()
	if ok, err := l.TryLock(); !ok || err != nil {
		t.Errorf("TryLock after Unlock: ok=%v err=%v, want granted", ok, err)
	}
}
