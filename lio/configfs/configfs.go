// Package configfs is a thin, LIO-agnostic wrapper over the kernel
// configfs filesystem. It performs filesystem operations only —
// directory reads, attribute reads/writes, object create/remove and
// symlink handling — and contains no knowledge of LIO object semantics.
//
// This is the lowest layer: its sole job is "in-core intent -> configfs",
// best-effort. It has no notion of LIO objects, dependency ordering or
// identity (those live one layer up, in package lio).
//
// Three hard, non-obvious properties of configfs are inherited by every
// caller and are called out here so they are not rediscovered repeatedly:
//
//   - Single-write attributes: a configfs attribute MUST be delivered in
//     exactly one write(2). See WriteAttr, the single chokepoint for all
//     attribute writes.
//
//   - Blocking, uncancellable ops: these are plain synchronous file
//     operations with no timeout or cancellation. Some configfs operations
//     block *in the kernel* — e.g. removing a LUN can wait for in-flight
//     I/O to quiesce, and an enable can wait on device setup. There is no
//     way to cancel a syscall already in the kernel, so callers that hold a
//     lock across these ops (e.g. the appliance coordinator holding the
//     host writer-lock across a reconcile) can stall until the kernel
//     returns. This is a property of configfs, not a bug to be worked
//     around here.
//
//   - IN-CORE STATE, NOT DURABLE STORAGE: configfs is a kernel-memory
//     filesystem. Nothing under Root survives a reboot -- the entire tree
//     is empty on boot and is rebuilt from the caller's own durable records
//     (for glitr, the appliance db, via startup replay). It looks like a
//     filesystem and it is mounted under /sys, which invites reading it as
//     persistent configuration. It is not.
//
//     This distinction changes conclusions, so it is spelled out rather
//     than left to be inferred. Anything the kernel refuses to change on a
//     LIVE object -- LIO's create-time attributes are the main case, see
//     lio.Report.Drift -- is NOT thereby permanent. It persists only for
//     the lifetime of the object in memory. A daemon restart preserves it
//     (the tree stays up underneath the process, which is the point of
//     replay); a host reboot, a tree purge, or anything that prunes and
//     recreates the object clears it, because the object is then made
//     afresh on the create path where the kernel has no objection.
//
//     MEASURED, not assumed (Azure Linux 3.0, kernel 6.6.144.1, 2026-07):
//     a backstore carrying attrib/optimal_sectors=16384 against a desired
//     0, exported and therefore unwritable, still read 16384 after
//     upgrading and restarting the daemon -- and read 0 after a host
//     reboot, while remaining exported. Two independent code reviewers
//     concluded from the immutability alone that such a fleet could never
//     converge; the measurement refutes that, and this note exists so the
//     inference is not drawn a third time.
//
// Robust to bad input: every path component is expected to be a single
// clean segment (an object name, IQN, attribute name, portal ip:port, …).
// Each operation validates its components and returns an error for anything
// that could escape Root — "..", ".", an empty segment, or a segment
// containing a path separator. The layer checks and errors out rather than
// trusting callers to pre-validate or silently sanitizing, so an untrusted
// name (e.g. an IQN routed from the REST layer) cannot traverse outside the
// configfs subtree.
package configfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// DefaultRoot is the mount point of the LIO target configfs subtree.
const DefaultRoot = "/sys/kernel/config/target"

// FS is a handle rooted at a configfs directory. All path arguments to
// its methods are interpreted relative to Root.
type FS struct {
	Root string
}

// New returns an FS rooted at root.
func New(root string) *FS { return &FS{Root: root} }

// Default returns an FS rooted at DefaultRoot.
func Default() *FS { return &FS{Root: DefaultRoot} }

// Path joins parts onto the root and returns the absolute path. It does
// NOT validate the components (see validSeg); it is used internally after
// validation and to build symlink targets from trusted, library-generated
// segments. External callers should go through the operation methods
// (Mkdir, WriteAttr, …), which validate.
func (f *FS) Path(parts ...string) string {
	return filepath.Join(append([]string{f.Root}, parts...)...)
}

// validSeg reports whether s is a single safe path segment: non-empty, not
// "." or "..", and containing no path separator. Every configfs path
// component is a single segment, so this is the containment guard — it
// rejects traversal ("..", "a/b", absolute paths) at the boundary.
func validSeg(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsRune(s, filepath.Separator) && !strings.ContainsRune(s, '/')
}

// checkParts validates every component, returning an error on the first
// unsafe one. The layer errors out on bad input rather than sanitizing.
func checkParts(parts []string) error {
	for _, p := range parts {
		if !validSeg(p) {
			return fmt.Errorf("configfs: invalid path component %q (must be a single non-empty segment: no '/', not '.'/'..')", p)
		}
	}
	return nil
}

// safePath validates parts and joins them onto Root. All operation methods
// use it so an untrusted component cannot escape Root.
func (f *FS) safePath(parts ...string) (string, error) {
	// An empty Root is refused rather than joined. FS is a struct with one
	// exported field, so &configfs.FS{} is an easy thing for a caller to
	// write, and filepath.Join("", parts...) yields a RELATIVE path -- every
	// operation would then resolve against the process's working directory,
	// silently retargeting a library whose entire job is containment. New and
	// Default are the intended constructors; this makes forgetting them an
	// error instead of a surprise.
	if f.Root == "" {
		return "", errors.New("configfs: FS has no Root (use configfs.New or configfs.Default)")
	}
	if err := checkParts(parts); err != nil {
		return "", err
	}
	return f.Path(parts...), nil
}

// Exists reports whether the path exists (dir, file or symlink).
func (f *FS) Exists(parts ...string) (bool, error) {
	p, err := f.safePath(parts...)
	if err != nil {
		return false, err
	}
	if _, err := os.Lstat(p); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Mkdir creates a single configfs object directory. Creating the
// directory is what instantiates the corresponding kernel object.
// It is not an error if the directory already exists.
//
// This is deliberately single-level (os.Mkdir, not MkdirAll): each level
// of a configfs path is a distinct kernel object whose parent must already
// exist, so silently creating intermediate directories would mask a real
// missing-prerequisite. One consequence: the iSCSI fabric group
// (<root>/iscsi) is a "makable group" that is NOT auto-created on a fresh
// boot and must be Mkdir'd during host setup before any target is created.
func (f *FS) Mkdir(parts ...string) error {
	p, err := f.safePath(parts...)
	if err != nil {
		return err
	}
	err = os.Mkdir(p, 0o755)
	if err != nil && os.IsExist(err) {
		// EEXIST only means "a name is here", not "the object directory
		// exists". If it is a file or symlink, the kernel object was NOT
		// instantiated — surface the original error rather than reporting a
		// false success that fails cryptically at a later step.
		if fi, lerr := os.Lstat(p); lerr == nil && fi.IsDir() {
			return nil
		}
		return err
	}
	return err
}

// Rmdir destroys a configfs object directory, and ONLY a directory. It is not
// an error if it is already gone.
//
// syscall.Rmdir, not os.Remove. configfs has two removal operations that mean
// different things: rmdir on an object directory destroys a kernel object,
// while unlink on a symlink UNMAPS something -- removing a LUN's backstore
// link detaches storage from a live initiator. os.Remove tries unlink first
// and falls back to rmdir, so it silently performs whichever the path happens
// to allow, and a caller that passed the wrong one got the wrong operation and
// a success.
//
// That was not hypothetical: unlinkAll removed LUN symlinks by calling this
// function, relying on the fallback, so the code was already using one name
// for both acts. They are separate now (see Unlink), and each refuses the
// other's argument -- rmdir on a symlink is ENOTDIR, unlink on a directory is
// EISDIR -- so a future mix-up fails loudly instead of unmapping storage.
func (f *FS) Rmdir(parts ...string) error {
	p, err := f.safePath(parts...)
	if err != nil {
		return err
	}
	err = syscall.Rmdir(p)
	if err == syscall.ENOENT {
		return nil
	}
	if err != nil {
		return &os.PathError{Op: "rmdir", Path: p, Err: err}
	}
	return nil
}

// Unlink removes a configfs symlink -- the act that unmaps a LUN from its
// backstore. It is not an error if it is already gone.
//
// Deliberately refuses a directory (EISDIR from the kernel): destroying an
// object is a different act with a different consequence, and Rmdir is where
// it lives.
func (f *FS) Unlink(parts ...string) error {
	p, err := f.safePath(parts...)
	if err != nil {
		return err
	}
	err = syscall.Unlink(p)
	if err == syscall.ENOENT {
		return nil
	}
	if err != nil {
		return &os.PathError{Op: "unlink", Path: p, Err: err}
	}
	return nil
}

// ReadDir returns the child names of a directory, sorted. Only names
// are returned (configfs has no meaningful modes to expose).
func (f *FS) ReadDir(parts ...string) ([]string, error) {
	p, err := f.safePath(parts...)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

// IsDir reports whether the path is a directory (following symlinks).
func (f *FS) IsDir(parts ...string) (bool, error) {
	p, err := f.safePath(parts...)
	if err != nil {
		return false, err
	}
	fi, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return fi.IsDir(), nil
}

// ReadAttr reads an attribute file and returns its value with the single
// kernel-appended trailing newline removed.
//
// It strips exactly one trailing "\n" (via TrimSuffix), NOT all trailing
// whitespace: a value that legitimately ends in a space or tab must round-
// trip faithfully, otherwise a reconcile loop that compares written vs read
// values would see permanent drift and never converge.
func (f *FS) ReadAttr(parts ...string) (string, error) {
	p, err := f.safePath(parts...)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(string(b), "\n"), nil
}

// maxAttrWrite is the largest single-write payload configfs accepts for a
// normal (simple) attribute: SIMPLE_ATTR_SIZE (4096) minus one byte the
// kernel reserves for its NUL terminator. A write larger than this is
// truncated by the kernel to a short write, which makes the Go runtime
// issue a SECOND write(2) for the remainder — violating the single-write
// contract below. WriteAttr rejects oversized values so that can never
// happen. (All real LIO attribute values are far smaller.)
const maxAttrWrite = 4095

// WriteAttr writes value (plus one trailing newline) to a configfs
// attribute file.
//
// HARD KERNEL CONTRACT — single write(2): configfs parses each write()
// independently, so an attribute value MUST be delivered to the kernel in
// exactly one write(2) syscall. It may NOT be built up incrementally,
// streamed, chunked, or produced by multiple Write calls — a second write
// is parsed as a second (malformed) value. This is a configfs requirement,
// not something the Go runtime guarantees, which is why every attribute
// write in the whole codebase funnels through this one function: there is
// exactly one place to reason about the contract.
//
// Why the single write actually holds: it is NOT because os.WriteFile is
// magically one syscall — os.File.Write loops on a short write and would
// issue a second write(2). It holds because configfs consumes the whole
// buffer in one go and returns the full count (no short write) AS LONG AS
// the payload fits in maxAttrWrite bytes. WriteAttr enforces that bound, so
// the runtime never has a remainder to loop on. This is the load-bearing
// invariant; do not remove the length check.
//
// Do NOT replace this with buffered/streamed writing, and do NOT add a
// second write path that bypasses this function.
func (f *FS) WriteAttr(value string, parts ...string) error {
	p, err := f.safePath(parts...)
	if err != nil {
		return err
	}
	if len(value)+1 > maxAttrWrite {
		return fmt.Errorf("configfs: attribute value too large (%d bytes; max %d incl. newline)", len(value), maxAttrWrite)
	}
	return os.WriteFile(p, []byte(value+"\n"), 0o644)
}

// Symlink creates a symlink at linkParts pointing at the absolute path
// target. LIO uses such symlinks to wire LUNs to backstores and mapped
// LUNs to TPG LUNs. It is idempotent: it is not an error if a link already
// resolving to the same target exists.
//
// configfs stores link bodies RELATIVE even when created from an absolute
// target (readlink returns e.g. "../../../core/fileio_0/name"), so an
// existing link must be resolved against its own directory before it is
// compared — a naive string compare against the absolute target never
// matches on real configfs. If a link already exists pointing at a
// DIFFERENT target, the conflict is surfaced (this layer never silently
// re-points a link; resolving conflicts is the upper layer's job). The
// EEXIST from a concurrent identical create is also treated as idempotent
// (re-resolve and accept if it now matches).
func (f *FS) Symlink(target string, linkParts ...string) error {
	if err := checkParts(linkParts); err != nil {
		return err
	}
	link := f.Path(linkParts...)
	if same, err := sameLinkTarget(link, target); err == nil && same {
		return nil
	}
	if err := os.Symlink(target, link); err != nil {
		if os.IsExist(err) {
			// Raced with another creator (or a stale pre-check): accept if
			// the link now resolves to the target we wanted.
			if same, rerr := sameLinkTarget(link, target); rerr == nil && same {
				return nil
			}
		}
		return err
	}
	return nil
}

// sameLinkTarget reports whether the symlink at link resolves to the same
// absolute path as target. It resolves a relative link body (how configfs
// stores links) against the link's own directory before comparing. Returns
// a non-nil error if link is not a symlink / cannot be read.
func sameLinkTarget(link, target string) (bool, error) {
	existing, err := os.Readlink(link)
	if err != nil {
		return false, err
	}
	if !filepath.IsAbs(existing) {
		existing = filepath.Join(filepath.Dir(link), existing)
	}
	return filepath.Clean(existing) == filepath.Clean(target), nil
}

// ReadLink returns the target of the symlink at parts.
func (f *FS) ReadLink(parts ...string) (string, error) {
	p, err := f.safePath(parts...)
	if err != nil {
		return "", err
	}
	return os.Readlink(p)
}

// ListSymlinks returns the names of all symlink children of dir.
func (f *FS) ListSymlinks(dirParts ...string) ([]string, error) {
	p, err := f.safePath(dirParts...)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// FindSymlink returns the name of the first symlink child of dir and
// its resolved absolute target, or "" if none. LIO LUN/mapped-LUN
// directories contain exactly one symlink (with a kernel-assigned name)
// pointing at the linked object. configfs stores these links relative,
// so the target is resolved to a cleaned absolute path.
func (f *FS) FindSymlink(dirParts ...string) (name, target string, err error) {
	dir, err := f.safePath(dirParts...)
	if err != nil {
		return "", "", err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", "", err
	}
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			link := filepath.Join(dir, e.Name())
			t, lerr := os.Readlink(link)
			if lerr != nil {
				return "", "", lerr
			}
			if !filepath.IsAbs(t) {
				t = filepath.Join(dir, t)
			}
			return e.Name(), filepath.Clean(t), nil
		}
	}
	return "", "", nil
}
