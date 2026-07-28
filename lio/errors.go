package lio

import (
	"errors"
	"fmt"
	"syscall"
)

// ErrNoLIOTree reports that the kernel LIO tree is not present at all: the
// configfs target root does not exist. Typically configfs is not mounted or
// target_core_mod is not loaded.
//
// It is distinct from an empty configuration, and callers that persist what
// they discover must not conflate the two -- writing down "nothing is
// configured" because the subsystem was absent destroys the record of what
// actually was. Test for it with errors.Is.
//
// Unlike ErrStaleScope this carries no "lio:" prefix, because it is always
// returned wrapped in an *Error, which supplies one.
var ErrNoLIOTree = errors.New("kernel LIO tree not present (is configfs mounted and target_core_mod loaded?)")

// ErrHolderUnreadable reports that the kernel's res_holder attribute could
// not be interpreted, so whether a reservation is held is UNKNOWN.
//
// It is distinct from "no reservation is held", which is a definite answer.
// res_holder is human-formatted prose with no compatibility promise, and
// conflating an unrecognised rendering with "nobody holds this" would report a
// protected device as unprotected. Callers deciding anything about fencing
// must treat this as "I cannot tell" and take the cautious branch. Test for it
// with errors.Is.
var ErrHolderUnreadable = errors.New("res_holder could not be interpreted; whether a reservation is held is unknown")

// Kind categorises LIO library errors so callers can react
// programmatically without string matching.
type Kind int

const (
	// KindUnknown is the zero value.
	KindUnknown Kind = iota
	// KindNotFound: a required object does not exist.
	KindNotFound
	// KindInvalidSpec: the desired object description is invalid.
	KindInvalidSpec
	// KindKernelRejected: configfs accepted the operation syntactically
	// but the kernel rejected it (e.g. enabling a backstore whose file
	// is missing).
	KindKernelRejected
	// KindDependency: an operation was attempted out of dependency order
	// (e.g. a LUN referencing an absent backstore).
	KindDependency
	// KindBusy: the object is in use and cannot be modified/removed.
	KindBusy
	// KindIncompatible: an existing object differs from the desired spec
	// in an immutable way and cannot be reconciled without replacement.
	KindIncompatible
	// KindConfigfs: an underlying filesystem/configfs operation failed.
	KindConfigfs
)

func (k Kind) String() string {
	switch k {
	case KindNotFound:
		return "not-found"
	case KindInvalidSpec:
		return "invalid-spec"
	case KindKernelRejected:
		return "kernel-rejected"
	case KindDependency:
		return "dependency"
	case KindBusy:
		return "busy"
	case KindIncompatible:
		return "incompatible"
	case KindConfigfs:
		return "configfs"
	default:
		return "unknown"
	}
}

// Error is the library's structured error type.
type Error struct {
	Kind Kind
	Op   string // operation, e.g. "apply", "discover", "create"
	Obj  string // object identity, e.g. "backstore/fileio/test0"
	Err  error  // wrapped cause, if any
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("lio: %s %s: %s", e.Op, e.Obj, e.Kind)
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Err }

func errf(kind Kind, op, obj string, err error) *Error {
	return &Error{Kind: kind, Op: op, Obj: obj, Err: err}
}

// KindOf returns the Kind of err if it is (or wraps) an *Error, else
// KindUnknown.
//
// errors.As, not a hand-rolled loop: the loop this replaced followed only
// Unwrap() error, so it missed an *Error inside an errors.Join -- which is
// wrapping by the standard library's own definition, and which errors.As
// finds. This is the one function the package offers so callers can react
// without string matching, and a caller aggregating errors from several
// volumes is exactly the case that got KindUnknown and had to fall back to
// matching strings.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindUnknown
}

// classifyCreate and classifyRemove map a configfs operation's errno onto the
// Kind that actually describes it.
//
// These exist because the same operation legitimately fails for reasons in
// different categories, and the call sites used to pick one statically. Every
// mkdir in backstore.go reported KindConfigfs while every mkdir in iscsi.go
// reported KindKernelRejected -- the identical syscall, classified two ways,
// so one of them was always wrong. Every removal reported KindBusy regardless
// of cause, which says "the object is in use" about a permission error.
//
// Kind is documented as being for callers to "react programmatically without
// string matching", so a Kind that does not follow the errno is a contract
// that cannot be relied on. Today it is operator-facing text, which is reason
// enough: `kind=busy` sends someone hunting for the initiator holding an
// object when the real answer is that configfs is not mounted.
//
// A caller passes the Kind to fall back to when the errno says nothing useful,
// so an unrecognised failure keeps the call site's own best guess rather than
// being flattened to KindUnknown.

// classifyCreate maps the errno from a configfs mkdir.
//
// configfs.Mkdir already returns nil when the target exists AS A DIRECTORY, so
// an EEXIST reaching here means a file or symlink occupies the name -- a state
// problem in the filesystem, not the kernel refusing the object.
func classifyCreate(err error, fallback Kind) Kind {
	switch {
	case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.EOPNOTSUPP):
		// The kernel parsed the name and refused the object: a malformed IQN,
		// an address it will not bind, a duplicate network portal.
		return KindKernelRejected
	case errors.Is(err, syscall.ENOENT):
		// The PARENT is missing -- a LUN before its TPG, a TPG before its
		// target. That is dependency order, not a missing request object.
		return KindDependency
	case errors.Is(err, syscall.EEXIST), errors.Is(err, syscall.ENOTDIR):
		return KindConfigfs
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM),
		errors.Is(err, syscall.EROFS), errors.Is(err, syscall.ENOSPC),
		errors.Is(err, syscall.ENOMEM):
		return KindConfigfs
	}
	return fallback
}

// classifyRemove maps the errno from a configfs rmdir.
//
// configfs.Rmdir already returns nil when the object is already gone, so
// ENOENT does not reach here.
func classifyRemove(err error, fallback Kind) Kind {
	switch {
	case errors.Is(err, syscall.EBUSY):
		// The object really is in use -- an exported backstore, a TPG with a
		// live session. This is the only case KindBusy was ever right about.
		return KindBusy
	case errors.Is(err, syscall.ENOTEMPTY):
		// Children still present: the caller tore down in the wrong order.
		return KindDependency
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM),
		errors.Is(err, syscall.EROFS):
		return KindConfigfs
	}
	return fallback
}
