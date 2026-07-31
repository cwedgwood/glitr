// Package storage is bytes.
//
// It allocates, clones, grows and removes the backing file for an object the
// appliance has named, and it does nothing else. It holds no records, no
// names and no state machine: those belong to whatever is deciding what the
// storage is FOR, which is the appliance.
//
// It does state one number, and only because nothing above it can know it: the
// granularity a size has to land on for the bytes to be storable the way this
// store stores them. That is not a block size presented to an initiator, which
// is the appliance's choice and can differ -- see [SizeGranularity].
//
// That split is what makes this replaceable. A real array also just gives you
// bytes behind an identifier, so anything that can do these operations against
// a UUID can stand in here without the layers above knowing.
//
// Objects are sparse files. Snapshots and clones are reflink (FICLONE) copies,
// which is why a data disk needs a filesystem that supports it -- XFS or
// btrfs. Nothing here is safe for use by two processes at once; the appliance
// is the single writer and holds the host-wide interlock.
package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// quarantinePrefix marks an object directory that was set aside. The leading
// dot keeps it out of the way, and the prefix is how a later pass recognises
// it and does not set it aside again into an ever-lengthening name.
const quarantinePrefix = ".orphan-"

// stagingPrefix marks a directory that is mid-creation. Anything wearing it at
// startup was never committed, so it is always safe to remove.
const stagingPrefix = ".staging-"

// Store is a directory of object backing files.
type Store struct {
	root        string
	mu          sync.Mutex
	quarantined []string
}

// Open prepares a store rooted at root, removing any uncommitted staging
// directories left behind by a crash.
//
// It does NOT decide what to do about directories it does not recognise. Only
// the appliance knows which objects exist, so that decision belongs there --
// see ObjectDirs and Quarantine.
func Open(root string) (*Store, error) {
	s := &Store{root: root}
	if err := os.MkdirAll(s.objsDir(), 0o755); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.objsDir())
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), stagingPrefix) {
			// Uncommitted by definition: the rename that would have made it
			// real never happened.
			_ = os.RemoveAll(filepath.Join(s.objsDir(), e.Name()))
			continue
		}
		if strings.HasPrefix(e.Name(), quarantinePrefix) {
			s.quarantined = append(s.quarantined, e.Name())
		}
	}
	slices.Sort(s.quarantined)
	return s, nil
}

func (s *Store) objsDir() string        { return filepath.Join(s.root, "objects") }
func (s *Store) objDir(u string) string { return filepath.Join(s.objsDir(), u) }

// Root is the directory this store was opened on.
func (s *Store) Root() string { return s.root }

// DiskPath is the backing file for an object.
func (s *Store) DiskPath(uuid string) string {
	return filepath.Join(s.objDir(uuid), "disk")
}

// Exists reports whether an object's backing file is present.
func (s *Store) Exists(uuid string) bool {
	_, err := os.Stat(s.DiskPath(uuid))
	return err == nil
}

// ObjectDirs lists the committed object directories, excluding staging and
// quarantine.
//
// Separate from Quarantine because the interesting case -- directories present
// but no record db -- must REFUSE rather than tidy up, and only the appliance
// can tell "no records yet" from "the records are gone".
func (s *Store) ObjectDirs() ([]string, error) {
	entries, err := os.ReadDir(s.objsDir())
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, stagingPrefix) || strings.HasPrefix(n, quarantinePrefix) {
			continue
		}
		out = append(out, n)
	}
	slices.Sort(out)
	return out, nil
}

// Quarantine sets a directory aside under a timestamped name, keeping its data.
//
// RENAMED, never deleted. An earlier version removed unrecorded directories,
// which destroyed live data during exactly the recovery it was meant to help:
// a restored db is always at least one object behind the disk, so the objects
// created since are unrecorded, and those are the ones nobody can afford to
// lose.
func (s *Store) Quarantine(uuid string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := quarantinePrefix + time.Now().UTC().Format("20060102T150405Z") + "-" + uuid
	if err := os.Rename(s.objDir(uuid), filepath.Join(s.objsDir(), q)); err != nil {
		return "", fmt.Errorf("storage: cannot quarantine unrecorded object dir %s: %w", uuid, err)
	}
	s.quarantined = append(s.quarantined, q)
	slices.Sort(s.quarantined)
	return q, nil
}

// Quarantined returns the directories set aside, for reporting.
func (s *Store) Quarantined() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.quarantined...)
}

// Create allocates a sparse backing file of size bytes for uuid.
//
// The caller supplies the identifier: identity is the appliance's to mint, and
// a store that invented its own would make the name-to-bytes binding something
// discovered after the fact rather than decided before it.
func (s *Store) Create(uuid string, size int64) error {
	if size <= 0 {
		return fmt.Errorf("storage: size must be > 0")
	}
	return s.stage(uuid, func(disk string) error {
		f, err := os.OpenFile(disk, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := f.Truncate(size); err != nil {
			return err
		}
		return f.Sync()
	})
}

// Clone makes dst a copy-on-write copy of src via FICLONE.
//
// Snapshot and clone are the same operation here. The difference between them
// is what the appliance calls the result, which is exactly where it belongs --
// the bytes are identical either way.
func (s *Store) Clone(srcUUID, dstUUID string) error {
	src := s.DiskPath(srcUUID)
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("storage: source %s: %w", srcUUID, err)
	}
	return s.stage(dstUUID, func(disk string) error { return reflink(disk, src) })
}

// Resize grows an object's backing file. Shrinking is not supported.
func (s *Store) Resize(uuid string, newSize int64) error {
	f, err := os.OpenFile(s.DiskPath(uuid), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if newSize < st.Size() {
		return fmt.Errorf("storage: shrink unsupported (%d < %d)", newSize, st.Size())
	}
	if newSize == st.Size() {
		return nil
	}
	if err := f.Truncate(newSize); err != nil {
		return err
	}
	return f.Sync()
}

// Size reports the backing file's current size.
func (s *Store) Size(uuid string) (int64, error) {
	st, err := os.Stat(s.DiskPath(uuid))
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// Delete removes an object's directory and its bytes.
func (s *Store) Delete(uuid string) error {
	if err := os.RemoveAll(s.objDir(uuid)); err != nil {
		return err
	}
	return syncDir(s.objsDir())
}

// stage builds the object directory under a staging name, invokes fill to
// create the backing file, fsyncs, then renames it into place.
//
// The rename is the commit: until it happens nothing outside can see a
// half-made object, and a crash leaves a staging directory Open removes.
// Nothing here writes a record -- the appliance commits that separately, so a
// crash between the two leaks bytes rather than producing an object that is
// half real.
func (s *Store) stage(uuid string, fill func(diskPath string) error) error {
	if uuid == "" || strings.ContainsRune(uuid, filepath.Separator) || uuid == "." || uuid == ".." {
		return fmt.Errorf("storage: refusing to use %q as an object directory name", uuid)
	}
	if _, err := os.Stat(s.objDir(uuid)); err == nil {
		return fmt.Errorf("storage: object %s already exists", uuid)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	staging := filepath.Join(s.objsDir(), stagingPrefix+uuid)
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return err
	}
	defer os.RemoveAll(staging) // a no-op once the rename has succeeded

	if err := fill(filepath.Join(staging, "disk")); err != nil {
		return err
	}
	if err := syncDir(staging); err != nil {
		return err
	}
	if err := os.Rename(staging, s.objDir(uuid)); err != nil {
		return err
	}
	return syncDir(s.objsDir())
}
