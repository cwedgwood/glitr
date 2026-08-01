package storage

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// ficloneReq is the FICLONE ioctl request number (x86_64/most arches):
// _IOW(0x94, 9, int) — a reflink/copy-on-write clone of the whole file.
const ficloneReq = 0x40049409

// Snapshot creates a new, independent volume that is a copy-on-write
// reflink of src's backing file (instant, sparse). It receives a brand-
// new identity (UUID + wwn) and records src as its parent. Requires a
// reflink-capable filesystem (XFS/btrfs).
//
// Clone uses the same implementation (snapshots and clones are uniform);
// the API distinction is which volume is the source.
//
// Note for anyone tempted to add a per-volume "space used" field: the extents
// really are shared, but du and st_blocks will double-count them. They report
// per-file block counts and have no way to know an extent is referenced by
// more than one file, so each reflinked file is charged the full amount and
// summing volumes over-counts. Working out what is shared generically is not
// something the VFS can express -- only filesystem-specific tools (FIEMAP
// shared flags, xfs_spaceman) can attribute it, and only approximately.
//
// In practice this rarely matters: the question worth answering is how much
// free space the filesystem has, and df answers that correctly. Report that
// rather than inventing a per-volume number that cannot be made to add up.
func (s *Store) Snapshot(srcUUID string) (*Volume, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	src, ok := s.vols[srcUUID]
	if !ok {
		return nil, fmt.Errorf("storage: source volume %s not found", srcUUID)
	}
	if src.State != Ready {
		return nil, fmt.Errorf("storage: source volume %s is %s", srcUUID, src.State)
	}
	srcDisk := s.DiskPath(srcUUID)
	// Verify the source backing file is actually present and full-size right
	// now (its in-memory State could be stale if the file was truncated
	// externally). Otherwise we would clone a short file yet record the full
	// capacity, producing a "Ready" snapshot that is silently incomplete.
	if fi, err := os.Stat(srcDisk); err != nil {
		return nil, fmt.Errorf("storage: source volume %s backing file: %w", srcUUID, err)
	} else if !fi.Mode().IsRegular() || fi.Size() < src.Capacity {
		return nil, fmt.Errorf("storage: source volume %s backing file is not a full-size regular file (%d < %d)", srcUUID, fi.Size(), src.Capacity)
	}

	uuid, wwn, err := newIdentity()
	if err != nil {
		return nil, err
	}
	v := &Volume{
		UUID:     uuid,
		WWN:      wwn,
		Capacity: src.Capacity,
		Parent:   srcUUID,
		Created:  time.Now().UTC(),
		State:    Ready,
		// Inherit the source's geometry. A snapshot shares the parent's
		// extents byte for byte, so presenting it with a different block size
		// would describe identical bytes as a differently-shaped device --
		// the partition table and filesystem inside it were written for the
		// parent's geometry and would be misread at another.
		BlockSize: src.BlockSizeOrDefault(),
	}
	if err := s.stage(v, func(disk string) error { return reflink(disk, srcDisk) }); err != nil {
		return nil, err
	}
	s.vols[uuid] = v
	if err := s.persist(); err != nil {
		if errors.Is(err, ErrPersistedNotDurable) {
			// The db already NAMES this snapshot: persist renames into place
			// and only then fails to fsync the directory. Rolling back here
			// dropped it from memory and RemoveAll'"'"'d the reflinked disk, so
			// the next Open found a record whose data was gone and marked the
			// volume Failed -- a phantom record whose bytes this function
			// destroyed. Create and Delete both honour the contract that
			// ErrPersistedNotDurable documents; this path did not.
			return copyVol(v), err
		}
		delete(s.vols, uuid)
		_ = os.RemoveAll(s.volDir(uuid))
		return nil, err
	}
	return copyVol(v), nil
}

// Clone is an alias for Snapshot (uniform implementation).
func (s *Store) Clone(srcUUID string) (*Volume, error) { return s.Snapshot(srcUUID) }

// reflink creates dst as a copy-on-write clone of src via FICLONE.
func reflink(dst, src string) error {
	sf, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sf.Close()
	df, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer df.Close()
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, df.Fd(), ficloneReq, sf.Fd()); errno != 0 {
		return fmt.Errorf("storage: reflink %s -> %s: %w (needs a reflink-capable fs, e.g. XFS)", src, dst, errno)
	}
	return df.Sync()
}
