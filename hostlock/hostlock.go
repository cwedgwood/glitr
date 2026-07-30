// Package hostlock is the host-wide single-writer interlock for the kernel
// LIO tree.
//
// There is exactly one kernel target per host, and configfs offers no
// serialisation of its own: two processes reconciling the tree concurrently
// interleave their reads and writes and can leave it in a state neither
// intended. The kernel will not stop them. Any program that writes the LIO
// tree should therefore hold this lock while it does so, and every such
// program on the host must agree on the same path for the interlock to mean
// anything.
//
// Acquisition is non-blocking (TryLock): a writer that cannot get the lock
// fails fast with a clear error rather than hanging, so a long-running writer
// visibly refuses a concurrent one rather than the two quietly overlapping.
// A holder may keep it for its whole lifetime or take it only for the
// duration of a mutating operation; readers need not lock at all, since
// discovery tolerates a tree changing underneath it.
package hostlock

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// DefaultPath is the well-known advisory-lock file. Every program on the host
// that writes the LIO tree must use the same path for the interlock to be
// effective.
const DefaultPath = "/run/lock/glitr-lio.lock"

// Lock is an advisory (flock) exclusive lock on a file.
type Lock struct {
	path string
	f    *os.File
}

// New returns a Lock on path (its parent directory is created on Lock).
func New(path string) *Lock {
	if path == "" {
		path = DefaultPath
	}
	return &Lock{path: path}
}

// TryLock takes the exclusive lock without blocking. It returns (false, nil)
// if another process already holds it, or (true, nil) on success.
func (l *Lock) TryLock() (bool, error) {
	// A second TryLock on a Lock that already holds one used to overwrite l.f
	// without unlocking or closing the first descriptor: the old fd leaked,
	// Unlock released only the newer one, and because flock is per-open-file
	// the process kept the lock it believed it had dropped. Refused rather
	// than silently succeeding, since there is no correct interpretation of
	// locking something you are already holding.
	if l.f != nil {
		return false, fmt.Errorf("hostlock: %s is already held by this Lock", l.path)
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return false, fmt.Errorf("lock dir: %w", err)
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return false, fmt.Errorf("open lock %s: %w", l.path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if err == syscall.EWOULDBLOCK {
			return false, nil
		}
		return false, fmt.Errorf("flock %s: %w", l.path, err)
	}
	l.f = f
	return true, nil
}

// Unlock releases the lock (a no-op if not held).
func (l *Lock) Unlock() {
	if l.f == nil {
		return
	}
	syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	l.f.Close()
	l.f = nil
}

// Path returns the lock file path.
func (l *Lock) Path() string { return l.path }
