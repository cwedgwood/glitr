package lio

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/cwedgwood/glitr/lio/configfs"
)

// The Kind on a configfs failure used to be chosen statically per call site:
// every mkdir in backstore.go said KindConfigfs, every mkdir in iscsi.go said
// KindKernelRejected, and every removal said KindBusy. Those are claims about
// WHY an operation failed, made before the failure happened, so each site was
// wrong for half the errnos it could see. These tests pin the classification
// to the errno.

func pathErr(errno syscall.Errno) error {
	return &os.PathError{Op: "mkdir", Path: "/sys/kernel/config/target/x", Err: errno}
}

func TestClassifyCreateFollowsErrno(t *testing.T) {
	// fallback is deliberately a Kind that no case returns, so a test that
	// passes only because the fallback happens to match is impossible.
	const fallback = KindUnknown
	cases := []struct {
		errno syscall.Errno
		want  Kind
		why   string
	}{
		{syscall.EINVAL, KindKernelRejected,
			"the kernel parsed the request and refused it: a malformed IQN, an unbindable address"},
		{syscall.ENOENT, KindDependency,
			"the PARENT is missing -- a LUN created before its TPG. Not a missing request object"},
		{syscall.EEXIST, KindConfigfs,
			"configfs.Mkdir already succeeds when a DIRECTORY exists, so EEXIST here means a file " +
				"or symlink occupies the name: filesystem state, not a kernel refusal"},
		{syscall.EACCES, KindConfigfs, "not root, or configfs is not mounted"},
		{syscall.EROFS, KindConfigfs, "configfs mounted read-only"},
		{syscall.ENOSPC, KindConfigfs, "no space to instantiate the object"},
	}
	for _, c := range cases {
		if got := classifyCreate(pathErr(c.errno), fallback); got != c.want {
			t.Errorf("create failing %v: Kind=%v, want %v -- %s", c.errno, got, c.want, c.why)
		}
	}
}

func TestClassifyRemoveFollowsErrno(t *testing.T) {
	const fallback = KindUnknown
	cases := []struct {
		errno syscall.Errno
		want  Kind
		why   string
	}{
		{syscall.EBUSY, KindBusy,
			"an exported backstore or a TPG with a live session: the only case KindBusy was ever right about"},
		{syscall.ENOTEMPTY, KindDependency,
			"children still present, so the caller tore down in the wrong order"},
		{syscall.EACCES, KindConfigfs,
			"THE POINT OF THE CHANGE: a permission failure reported as KindBusy sends an operator " +
				"hunting for the initiator holding an object that nothing is holding"},
		{syscall.EROFS, KindConfigfs, "configfs mounted read-only"},
	}
	for _, c := range cases {
		if got := classifyRemove(pathErr(c.errno), fallback); got != c.want {
			t.Errorf("removal failing %v: Kind=%v, want %v -- %s", c.errno, got, c.want, c.why)
		}
	}
}

// TestClassifyFallsBackOnUnrecognisedErrno: an errno the classifier does not
// model must keep the call site's own guess rather than being flattened. If
// this ever returns KindUnknown, callers lose information the old static
// scheme did give them.
func TestClassifyFallsBackOnUnrecognisedErrno(t *testing.T) {
	if got := classifyCreate(pathErr(syscall.EIO), KindKernelRejected); got != KindKernelRejected {
		t.Errorf("unrecognised create errno must keep the call site's fallback, got %v", got)
	}
	if got := classifyRemove(pathErr(syscall.EIO), KindBusy); got != KindBusy {
		t.Errorf("unrecognised removal errno must keep the call site's fallback, got %v", got)
	}
}

// TestClassifyIgnoresNonErrnoErrors: errors.Is must not match something that
// merely stringifies similarly.
func TestClassifyIgnoresNonErrnoErrors(t *testing.T) {
	plain := os.ErrClosed
	if got := classifyCreate(plain, KindConfigfs); got != KindConfigfs {
		t.Errorf("a non-errno error must fall back, got %v", got)
	}
}

// TestCreateKindIsClassifiedEndToEnd drives a REAL errno through the real
// apply path rather than calling the classifier directly, so it also proves
// the call sites were rewired and that the errno survives configfs's
// wrapping. An unwritable parent makes the kernel-side mkdir fail EACCES.
//
// Negative control: before this change the same failure through iscsi.go
// reported KindKernelRejected -- "the kernel refused this" -- about a
// directory the kernel never saw.
func TestCreateKindIsClassifiedEndToEnd(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so no EACCES can be induced")
	}
	root := t.TempDir()
	// configfs.New roots AT the target dir, so the fabric group is root/iscsi
	// -- NOT root/target/iscsi. Getting this wrong made an earlier version of
	// this test create everything successfully in a writable tree and fail
	// later on a WriteAttr, passing for a reason that had nothing to do with
	// the classifier. Stage the fabric dir, then remove write permission so
	// the target mkdir inside it gets EACCES.
	fabric := filepath.Join(root, "iscsi")
	if err := os.MkdirAll(fabric, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fabric, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(fabric, 0o755) })

	_, err := New(configfs.New(root)).Apply(Config{
		Targets: []Target{{IQN: "iqn.2026-01.example:t", TPGs: []TPG{{Tag: 1, Enable: true}}}},
	})
	if err == nil {
		t.Fatal("creating a target under an unwritable parent must fail")
	}
	if got := KindOf(err); got != KindConfigfs {
		t.Errorf("EACCES on target mkdir: Kind=%v, want %v. The kernel never saw this "+
			"request, so reporting it as kernel-rejected misdirects the reader", got, KindConfigfs)
	}
}

// TestRemoveKindIsClassifiedEndToEnd is the half that matters most to an
// operator. Every removal used to report KindBusy, which asserts "some
// initiator or export is holding this object" -- a specific, actionable, and
// in this case entirely false claim. An unwritable parent makes rmdir fail
// EACCES with nothing holding anything.
func TestRemoveKindIsClassifiedEndToEnd(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so no EACCES can be induced")
	}
	root := t.TempDir()
	iqn := "iqn.2026-01.example:t"
	// Stage a FULLY-FORMED target. A hand-rolled skeleton (just tpgt_1/) made
	// an earlier version of this test fail during discover, on a missing np/
	// dir, and pass on a Kind that came from a completely different call site.
	stageTargets(t, root, Config{Targets: []Target{{IQN: iqn, TPGs: []TPG{{Tag: 1}}}}})
	tgt := filepath.Join(root, "iscsi", iqn)
	if err := os.Chmod(tgt, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(tgt, 0o755) })

	// Sync with no targets prunes the staged one.
	_, err := New(configfs.New(root)).Sync(Config{})
	if err == nil {
		t.Fatal("pruning a TPG under an unwritable parent must fail")
	}
	if got := KindOf(err); got != KindConfigfs {
		t.Errorf("EACCES on rmdir: Kind=%v, want %v. Nothing is holding this object; "+
			"reporting it busy sends the operator hunting for a session that does not exist",
			got, KindConfigfs)
	}
}

// TestRemoveTPGReportsUnreadableChildGroup: removeTPG used to list acls/,
// lun/ and np/ with `if names, err := ReadDir(...); err == nil`, skipping the
// whole group on ANY error. The kernel creates all three with the TPG, so a
// read failure is never routine: the children stay in place, and the final
// rmdir then fails on the SYMPTOM (children present) having already discarded
// the CAUSE (the group could not be listed).
//
// Driven white-box. Sync cannot reach this state because discover fail-stops
// on the same unreadable directory first -- correctly, and that was verified
// rather than assumed. The path still matters for direct callers and for a
// permission change landing between discover and removal.
func TestRemoveTPGReportsUnreadableChildGroup(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	root := t.TempDir()
	iqn := "iqn.2026-01.example:t"
	stageTargets(t, root, Config{Targets: []Target{{IQN: iqn, TPGs: []TPG{{Tag: 1}}}}})
	acls := filepath.Join(root, "iscsi", iqn, "tpgt_1", "acls")
	if err := os.MkdirAll(acls, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(acls, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(acls, 0o755) })

	a := &applyCtx{fs: configfs.New(root)}
	err := a.removeTPG(iqn, 1)
	if err == nil {
		t.Fatal("removing a TPG whose acls/ cannot be listed must report the failure, " +
			"not skip the group and proceed to rmdir the TPG")
	}
	if !strings.Contains(err.Error(), "acls") {
		t.Errorf("the error must name the group that could not be listed, got %v", err)
	}
}

// TestRemoveTPGTreatsAbsentChildGroupAsEmpty is the counter-test: absent must
// stay ordinary, or the fix above would turn every partially-staged teardown
// into a failure.
func TestRemoveTPGTreatsAbsentChildGroupAsEmpty(t *testing.T) {
	root := t.TempDir()
	iqn := "iqn.2026-01.example:t"
	if err := os.MkdirAll(filepath.Join(root, "iscsi", iqn, "tpgt_1"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := &applyCtx{fs: configfs.New(root)}
	if err := a.removeTPG(iqn, 1); err != nil {
		t.Errorf("a TPG with no acls/, lun/ or np/ has no children to remove; "+
			"absent must not be confused with unreadable, got %v", err)
	}
}

// TestDiscoverReportsUnreadableIdentityAttrs: discovery read vendor_id,
// product_id, revision, info and every managed attrib/* with `if v, err :=
// ...; err == nil`, so an unreadable value was discovered as ABSENT.
//
// That is not a cosmetic loss. The identity fields feed a save/restore
// round-trip, so an empty value gets written back to the kernel and
// re-identifies the device to initiators keyed on it. info is worse: it
// carries the backing mode, and the code that parses it already carries a
// comment explaining that restoring a buffered device as O_DSYNC silently
// changes the durability contract the operator chose. The parse was guarded;
// the read was not.
func TestDiscoverReportsUnreadableIdentityAttrs(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	for _, attr := range []string{"wwn/vendor_id", "wwn/product_id", "wwn/revision", "info", "attrib/block_size"} {
		t.Run(attr, func(t *testing.T) {
			root := t.TempDir()
			b := testBackstore()
			stageBackstoreDir(t, root, b)
			p := filepath.Join(append([]string{root, "core",
				string(b.Type) + "_" + strconv.Itoa(b.HBA), b.Name}, strings.Split(attr, "/")...)...)
			// Create the attribute explicitly. Relying on the staging
			// helper made every subtest SKIP, which reported as a green PASS
			// over a test that ran nothing.
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("x\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, 0o000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(p, 0o644) })

			_, err := New(configfs.New(root)).Discover()
			if err == nil {
				t.Fatalf("an unreadable %s must be reported, not discovered as absent: "+
					"an empty value is written back to the kernel on restore", attr)
			}
			if !strings.Contains(err.Error(), filepath.Base(attr)) {
				t.Errorf("the error must name the attribute that could not be read, got %v", err)
			}
		})
	}
}

// TestReportRetainsChangesMadeBeforeAFailure: Apply is explicitly not
// transactional -- it converges by being re-run -- so a caller that gets an
// error still needs to know what was already mutated. Returning a bare
// Report{} on the error paths would say "nothing happened" about a kernel
// that has already been changed.
func TestReportRetainsChangesMadeBeforeAFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	root := t.TempDir()
	// The backstore is created first and succeeds; the target mkdir then
	// fails because its parent is unwritable. core/ must exist: configfs
	// Mkdir is single-level and will not create intermediate directories.
	if err := os.MkdirAll(filepath.Join(root, "core"), 0o755); err != nil {
		t.Fatal(err)
	}
	fabric := filepath.Join(root, "iscsi")
	if err := os.MkdirAll(fabric, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fabric, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(fabric, 0o755) })

	b := testBackstore()
	rep, err := New(configfs.New(root)).Apply(Config{
		Backstores: []Backstore{b},
		Targets:    []Target{{IQN: "iqn.2026-01.example:t", TPGs: []TPG{{Tag: 1}}}},
	})
	if err == nil {
		t.Fatal("the target mkdir must fail under an unwritable parent")
	}
	if len(rep.Changes) == 0 {
		t.Error("the backstore was created before the failure; a Report with no Changes " +
			"tells the caller nothing happened when the kernel has already been mutated")
	}
}

// TestKindOfFindsAnErrorInsideAJoin pins KindOf's own contract: "if it is (or
// WRAPS) an *Error". errors.Join wrapping is wrapping by the standard
// library's definition, and errors.As finds it.
//
// The hand-rolled loop this replaced followed only Unwrap() error, so it
// returned KindUnknown here. KindOf is the one function the package offers so
// callers can react without string matching, and an orchestrator aggregating
// errors from several volumes -- the natural way to hit a joined error -- got
// nothing and had to fall back to matching strings.
func TestKindOfFindsAnErrorInsideAJoin(t *testing.T) {
	inner := errf(KindBusy, "rmdir", "backstore/vol0", errors.New("device or resource busy"))

	if got := KindOf(errors.Join(errors.New("unrelated"), inner)); got != KindBusy {
		t.Errorf("KindOf(errors.Join(..., *Error)) = %v, want %v", got, KindBusy)
	}
	// %w twice produces the same multi-unwrap shape.
	if got := KindOf(fmt.Errorf("volume a: %w; volume b: %w", errors.New("x"), inner)); got != KindBusy {
		t.Errorf("KindOf(multi-%%w) = %v, want %v", got, KindBusy)
	}
	// The single-unwrap chain must keep working.
	if got := KindOf(fmt.Errorf("wrapped: %w", inner)); got != KindBusy {
		t.Errorf("KindOf(single %%w) = %v, want %v", got, KindBusy)
	}
	// And a plain error is still unknown, so this test can fail.
	if got := KindOf(errors.New("plain")); got != KindUnknown {
		t.Errorf("KindOf(plain) = %v, want %v", got, KindUnknown)
	}
}
