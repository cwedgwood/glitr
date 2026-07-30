package lish

import (
	"fmt"

	"github.com/cwedgwood/glitr/hostlock"
)

// DefaultLockPath is the host-wide advisory-lock file that serialises kernel
// LIO mutations between lish and the appliance ("one writer per host").
const DefaultLockPath = hostlock.DefaultPath

// Lock guards a single mutating operation. It is non-blocking: if another
// writer (typically a running appliance) holds the lock, Acquire fails fast
// so lish visibly refuses to mutate rather than hanging. Read-only verbs
// never take it.
type Lock struct {
	l *hostlock.Lock
}

// NewLock returns a Lock on path (empty means hostlock.DefaultPath).
func NewLock(path string) *Lock { return &Lock{l: hostlock.New(path)} }

// Acquire takes the exclusive lock, or returns an error if another writer
// holds it.
func (l *Lock) Acquire() error {
	ok, err := l.l.TryLock()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("another LIO writer holds %s (is applianced running?); refusing to mutate", l.l.Path())
	}
	return nil
}

// Release drops the lock.
func (l *Lock) Release() { l.l.Unlock() }
