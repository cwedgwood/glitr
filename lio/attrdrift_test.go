package lio

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cwedgwood/glitr/lio/configfs"
)

// stageDriftBackstore builds an already-created, already-enabled backstore
// whose managed attribute holds a value differing from the desired one, and
// which cannot be written. It returns the fs and the staged backstore.
//
// A tmpdir cannot refuse a write the way configfs does, so the refusal is
// injected with a read-only file. That produces EACCES, NOT the kernel's
// EINVAL-while-exported -- which is exactly why the tests below assert that
// this case stays FATAL. The tolerated case cannot be reproduced off a real
// kernel at all, and is covered against a live target by the block-size suite.
func stageDriftBackstore(t *testing.T, exported bool) (*configfs.FS, Backstore) {
	t.Helper()
	if os.Geteuid() == 0 {
		// root ignores the 0444 mode bits, so the write would succeed and the
		// test would prove nothing.
		t.Skip("needs to run unprivileged: the refusal is injected via file mode")
	}
	root := t.TempDir()
	b := testBackstore()
	b.Attributes = map[string]string{"optimal_sectors": "0"}
	stageBackstoreDir(t, root, b)
	fs := configfs.New(root)

	for _, kv := range [][2]string{
		{"1", "enable"},
		{b.Dev, "udev_path"},
	} {
		if err := fs.WriteAttr(kv[0], append(b.objPath(), kv[1])...); err != nil {
			t.Fatal(err)
		}
	}
	if exported {
		// Export state is derived from a TPG LUN symlink referencing the
		// backstore, because the kernel's own dev->export_count is not
		// exposed in configfs -- MEASURED on a live target, the object dir
		// has no such attribute. Stage the real thing.
		lun := []string{"iscsi", "iqn.2026-01.dev.glitr:t", "tpgt_1", "lun", "lun_0"}
		if err := os.MkdirAll(fs.Path(lun...), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := fs.Symlink(fs.Path(b.objPath()...), append(lun, "link")...); err != nil {
			t.Fatal(err)
		}
	}
	if err := fs.WriteAttr("TCM FILEIO ID: 0  File: "+b.Dev+"  Size: 1048576  Mode: O_DSYNC",
		append(b.objPath(), "info")...); err != nil {
		t.Fatal(err)
	}

	attr := filepath.Join(append([]string{root}, append(b.objPath(), "attrib", "optimal_sectors")...)...)
	if err := os.WriteFile(attr, []byte("16384\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(attr, 0o444); err != nil {
		t.Fatal(err)
	}
	return fs, b
}

// TestAttrWriteFailureIsFatalWhenNotExported is half of the regression test
// for a crash loop, and the guard against over-correcting it.
//
// The crash loop was real: adding optimal_sectors=0 to the managed set gave
// every PRE-EXISTING volume a desired value (0) that differed from its live
// one (16384, the kernel's default). Startup replay tried to enforce it,
// EINVAL'd, and applianced crash-looped through seven restarts against a
// perfectly healthy tree. The fix was to tolerate that one failure.
//
// The danger is tolerating MORE than that. A skipped write means declaring
// convergence while the live object disagrees, so on an UNEXPORTED backstore
// -- where the kernel would have accepted the write -- a failure is a real
// fault and must stay fatal. It is reachable: an object left
// enabled-but-unexported by an earlier failure takes the already-enabled path
// on the next pass, and a silently skipped write there would let it be
// LUN-mapped carrying the wrong geometry.
func TestAttrWriteFailureIsFatalWhenNotExported(t *testing.T) {
	fs, b := stageDriftBackstore(t, false)

	_, err := New(fs).Apply(Config{Backstores: []Backstore{b}})
	if err == nil {
		t.Fatal("an attribute write that fails while the backstore is NOT exported must be " +
			"fatal: the kernel would have accepted it, so the failure is a real fault and " +
			"skipping it declares a convergence that did not happen")
	}
	if !strings.Contains(err.Error(), "optimal_sectors") {
		t.Errorf("error must name the attribute, got %v", err)
	}
}

// TestAttrWriteFailureIsFatalWhenNotEINVAL checks the second half of the
// predicate: even while exported, only the kernel's own immutability refusal
// (EINVAL) may be tolerated.
//
// EACCES, EIO, ENOENT from a mistyped attribute key, or an attribute the
// running kernel does not expose are all different bugs. Narrating them as
// "immutable while exported" would make them permanently invisible -- a typo
// in the managed-attribute set would silently never apply.
func TestAttrWriteFailureIsFatalWhenNotEINVAL(t *testing.T) {
	fs, b := stageDriftBackstore(t, true)

	_, err := New(fs).Apply(Config{Backstores: []Backstore{b}})
	if err == nil {
		t.Fatal("only EINVAL means immutable-while-exported; a permission error must stay " +
			"fatal rather than being narrated as immutability")
	}
}

// TestDriftIsReportedSeparatelyFromChanges pins the reporting contract the
// daemon depends on.
//
// Drift is a standing condition, not an event: the live device does not match
// what this stack believes about it and no reconcile can fix that. Changes is
// a log a caller may reasonably ignore, so reporting drift only there is what
// made the skip invisible in applianced, which is the one place it
// accumulates.
func TestDriftIsReportedSeparatelyFromChanges(t *testing.T) {
	a := &applyCtx{}
	b := testBackstore()
	a.driftNote(b, "optimal_sectors", "16384", "0")
	a.driftNote(b, "block_size", "512", "4096")

	if len(a.changes) != 0 {
		t.Errorf("drift must not be filed as a change, got %q", a.changes)
	}
	if len(a.drift) != 2 {
		t.Fatalf("want 2 drift entries, got %q", a.drift)
	}
	if !strings.Contains(a.drift[0].String(), "optimal_sectors") || !strings.Contains(a.drift[0].String(), "immutable") {
		t.Errorf("optimal_sectors drift = %q", a.drift[0])
	}
	// block_size drift is not the same kind of problem: it means the API
	// reports one geometry while the initiator sees another. It must say so
	// rather than read like routine tuning drift.
	if !strings.Contains(a.drift[1].String(), "GEOMETRY MISMATCH") {
		t.Errorf("block_size drift must be escalated over other attributes, got %q", a.drift[1])
	}
}

// TestCountLUNRefsMatchesExportState pins the substitute for the kernel's
// dev->export_count.
//
// The kernel gates these attribute writes on dev->export_count, but that
// field is NOT exposed in configfs -- measured on a live target (Azure Linux
// 3.0, kernel 6.6.144.1), a backstore object dir contains no export_count
// attribute at all. A predicate that read one would be false on every real
// kernel, which would turn the tolerated case back into the crash loop. What
// increments the count is a TPG LUN referencing the backstore, so that is
// what gets counted; this test is what keeps the two in step.
func TestCountLUNRefsMatchesExportState(t *testing.T) {
	fs, b := stageDriftBackstore(t, false)
	a := &applyCtx{fs: fs}

	if n, err := a.countLUNRefs(b); err != nil || n != 0 {
		t.Errorf("unexported backstore: got %d refs (err %v), want 0", n, err)
	}

	fs2, b2 := stageDriftBackstore(t, true)
	a2 := &applyCtx{fs: fs2}
	if n, err := a2.countLUNRefs(b2); err != nil || n != 1 {
		t.Errorf("exported backstore: got %d refs (err %v), want 1", n, err)
	}
}

// TestImmutableWhileExportedToleratesEINVALOnAnExportedObject pins the single
// boolean that decides whether the crash loop comes back.
//
// An end-to-end Apply cannot reach the tolerated case off a real kernel (a
// tmpdir will not return EINVAL), which is why the other tests here only cover
// the fatal halves. The predicate itself is testable with a synthetic error,
// and given that the fix for a consensus finding has carried its own defect in
// four consecutive rounds, the one function that must return true exactly when
// the kernel would refuse should not rest on inspection alone.
func TestImmutableWhileExportedToleratesEINVALOnAnExportedObject(t *testing.T) {
	fs, b := stageDriftBackstore(t, true)
	a := &applyCtx{fs: fs}

	einval := &os.PathError{Op: "write", Path: "attrib/optimal_sectors", Err: syscall.EINVAL}
	if !a.immutableWhileExported(b, einval) {
		t.Error("EINVAL on an exported backstore is the one failure a reconcile must " +
			"tolerate; returning false here reinstates the crash loop")
	}
	// And the two halves that must not be tolerated, at the predicate level.
	eacces := &os.PathError{Op: "write", Path: "attrib/optimal_sectors", Err: syscall.EACCES}
	if a.immutableWhileExported(b, eacces) {
		t.Error("EACCES is not immutability")
	}
	fsUnexported, bUnexported := stageDriftBackstore(t, false)
	aUnexported := &applyCtx{fs: fsUnexported}
	if aUnexported.immutableWhileExported(bUnexported, einval) {
		t.Error("EINVAL on an UNEXPORTED backstore is a real fault: the kernel would have " +
			"accepted the write")
	}
}

// TestVerifyDriftSeesDriftApplyDeltaWouldNotReport is the regression test for
// a standing signal that vanished.
//
// ApplyDelta only visits backstores whose desired config CHANGED, so its
// Report.Drift describes that subset. Publishing it wholesale erased the
// standing view: a fleet with drifted volumes showed them at startup, then had
// them disappear from /health the moment an unrelated host was attached.
// VerifyDrift re-derives the whole-tree answer without writing.
func TestVerifyDriftSeesDriftApplyDeltaWouldNotReport(t *testing.T) {
	fs, b := stageDriftBackstore(t, true)
	// Live value differs from desired, and the object is exported.
	drift := New(fs).VerifyDrift(Config{Backstores: []Backstore{b}})
	if len(drift) != 1 {
		t.Fatalf("want the drifted attribute reported by a read-only walk, got %q", drift)
	}
	if !strings.Contains(drift[0].String(), "optimal_sectors") {
		t.Errorf("drift = %q", drift[0])
	}

	// An UNEXPORTED object with the same mismatch is not drift: the next
	// reconcile can simply write it.
	fs2, b2 := stageDriftBackstore(t, false)
	if d := New(fs2).VerifyDrift(Config{Backstores: []Backstore{b2}}); len(d) != 0 {
		t.Errorf("an unexported mismatch is not standing drift, got %q", d)
	}
}

// TestUnreadableEnableIsNotTreatedAsNotEnabled pins the absent-vs-unreadable
// distinction on the one read that decides whether an object is live.
//
// ensureBackstore used to discard this error entirely (`enabled, _ :=`), so a
// backstore whose enable state could not be READ fell through to the create
// path -- against an object that may be enabled and exported, where the
// control write sets fd_dev_size on a device an initiator is using.
//
// ENOENT is different and must stay non-fatal: no enable attribute means
// nothing is enabled, which is exactly what the create path is for. Both
// halves are asserted, because a fix that made ENOENT fatal too would break
// every create against a partially staged tree and would look like this test
// passing.
func TestUnreadableEnableIsNotTreatedAsNotEnabled(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	stageBackstoreDir(t, root, b)
	fs := configfs.New(root)

	// Absent: the object dir exists but has no enable attribute.
	if _, err := New(fs).Apply(Config{Backstores: []Backstore{b}}); err == nil {
		t.Log("absent enable proceeded to create, as it must")
	} else if strings.Contains(err.Error(), "enable state could not be read") {
		t.Errorf("an ABSENT enable must not be reported as unreadable: %v", err)
	}

	// Unreadable: the attribute exists but cannot be opened. Asserted on the
	// PREDICATE rather than end-to-end, because an apply that gets past this
	// check goes on to read info, udev_path and the attrib group -- so an
	// end-to-end error proves only that SOMETHING failed, which is exactly
	// the "any failure counts as the expected failure" shape this project
	// keeps finding. The first probe of this test did precisely that: it
	// passed on an unrelated `info` read.
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 0000 is still readable, so this cannot be tested")
	}
	p := filepath.Join(append(append([]string{root}, b.objPath()...), "enable")...)
	if err := os.WriteFile(p, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Chmod separately: WriteFile applies its mode only when it CREATES the
	// file, and the apply above already created this one -- so passing 0o000
	// to WriteFile left it readable and the test proved nothing.
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatal(err)
	}
	_, rerr := fs.ReadAttr(append(b.objPath(), "enable")...)
	if rerr == nil {
		t.Fatal("the fixture did not make enable unreadable, so this proves nothing")
	}
	if os.IsNotExist(rerr) {
		t.Fatalf("the fixture made enable ABSENT, not unreadable: %v", rerr)
	}
	// That is the error ensureBackstore must refuse on, and the one it used
	// to discard.
	_, err := New(fs).Apply(Config{Backstores: []Backstore{b}})
	if err == nil {
		t.Fatal("an unreadable enable must refuse the apply, not fall through to create " +
			"against an object that may be live and exported")
	}
	if !strings.Contains(err.Error(), "enable state could not be read") {
		t.Errorf("the error must name what could not be determined, got: %v", err)
	}
}
