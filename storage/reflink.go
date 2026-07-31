package storage

import (
	"fmt"
	"os"
	"syscall"
)

// FICLONE: make dst share src's extents, copy-on-write.
//
// The value is the ioctl request number for FICLONE on Linux
// (linux v6.6 include/uapi/linux/fs.h: _IOW(0x94, 9, int)). Spelled as a
// constant rather than composed, because a wrong _IOW composition fails as
// EINVAL at runtime rather than at build time.
const ficloneReq = 0x40049409

// reflink creates dst as a copy-on-write clone of src.
//
// The whole snapshot story rests on this: the clone is instant regardless of
// size, and the two files share extents until one of them is written, so a
// snapshot costs nothing until it diverges.
//
// It also means per-file allocation cannot be summed. Both files are charged
// for the shared extents, so adding up what the objects "use" over-counts,
// sometimes enormously -- MEASURED: snapshotting an 8MiB-written object grew
// the st_blocks sum by the full 8MiB while the filesystem gave up almost
// nothing. The question worth answering is how much free space the filesystem
// has, and statfs answers that correctly.
func reflink(dst, src string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()
	d, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer d.Close()

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, d.Fd(), ficloneReq, s.Fd())
	if errno != 0 {
		// EOPNOTSUPP / EXDEV mean the filesystem cannot do this, which is a
		// configuration answer rather than a bug: say so plainly, because the
		// fix is a different data disk and nothing about retrying will help.
		return fmt.Errorf("storage: FICLONE %s -> %s: %w (the data disk must "+
			"support reflinks -- XFS or btrfs)", src, dst, errno)
	}
	return d.Sync()
}
