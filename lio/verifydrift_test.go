package lio

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cwedgwood/glitr/lio/configfs"
)

// stageExportedFleet builds n enabled backstores, each LUN-mapped once into a
// single TPG, with the given attribute value staged live.
func stageExportedFleet(t *testing.T, n int, liveVal string) (*configfs.FS, []Backstore) {
	t.Helper()
	root := t.TempDir()
	fs := configfs.New(root)
	const iqn = "iqn.2026-01.dev.glitr:t"

	out := make([]Backstore, 0, n)
	for i := range n {
		b := testBackstore()
		b.HBA = i
		b.Name = "vol_" + strconv.Itoa(i)
		b.Dev = "/tmp/" + b.Name + ".img"
		b.Attributes = map[string]string{"optimal_sectors": "0"}
		stageBackstoreDir(t, root, b)
		for _, kv := range [][2]string{{"1", "enable"}, {b.Dev, "udev_path"}} {
			if err := fs.WriteAttr(kv[0], append(b.objPath(), kv[1])...); err != nil {
				t.Fatal(err)
			}
		}
		if err := fs.WriteAttr(liveVal, append(b.objPath(), "attrib", "optimal_sectors")...); err != nil {
			t.Fatal(err)
		}
		lun := []string{"iscsi", iqn, "tpgt_1", "lun", "lun_" + strconv.Itoa(i)}
		if err := os.MkdirAll(fs.Path(lun...), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := fs.Symlink(fs.Path(b.objPath()...), append(lun, "link")...); err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return fs, out
}

// TestVerifyDriftScalesLinearly is the regression test for an O(N^2) read
// amplification on the very path that exists to make reconcile cheap.
//
// VerifyDrift runs on every incremental reconcile, holding the coordinator's
// lock. It used to call countLUNRefs once per backstore, and each of those
// walked the ENTIRE iSCSI fabric: every IQN, every TPG, every LUN dir, with a
// readlink per LUN. With N volumes each mapped once that is N * O(N) configfs
// syscalls per mutation -- so the check added to keep the incremental path
// honest could cost more than the full Sync it was introduced to avoid.
//
// MEASURED BY ALLOCATION COUNT, NOT BY THE CLOCK. This test used to time two
// fleet sizes and compare durations, and it failed spuriously on a loaded
// machine (2.5x observed against a 2.5x bound) while passing 5/5 when the box
// was quiet. That is a test that fails for the wrong reason, which does the
// same damage as one that passes for the wrong reason: it teaches the reader
// to re-run rather than to look. Two rounds of hardening -- minimum-of-seven
// instead of a mean, the bound moved from 3.0 to 2.5 -- treated the symptom,
// because a wall-clock ratio on a shared machine cannot distinguish "the
// fabric walk came back" from "something else was running".
//
// Allocations are the right instrument because the quantity under test is a
// COUNT OF CONFIGFS OPERATIONS, and each directory read and readlink allocates
// in proportion. Being independent of machine load, they are also exactly
// reproducible: the figures below repeated byte-for-byte across runs.
//
// MEASURED on this harness, N = 150 -> 300:
//
//	fixed (one fabric walk)        5,609 ->    11,460 allocs   ratio 2.04
//	reverted to a walk per backstore 350,475 -> 1,376,834      ratio 3.93
//
// Linear predicts 2.0 and quadratic 4.0, and the two populations land on them.
// The 2.5 bound sits between, with the fixed form 22% below it and the bug 57%
// above. Note also the absolute gap: at N=150 the bug allocates 62x more, so
// this is not a marginal signal.
//
// No longer skipped under -short: there is nothing slow or timing-dependent
// left to skip.
func TestVerifyDriftScalesLinearly(t *testing.T) {
	// allocsFor returns the allocations one VerifyDrift performs over a fleet
	// of n exported backstores, all of which drift.
	allocsFor := func(n int) float64 {
		fs, bs := stageExportedFleet(t, n, "16384") // live != desired: all drift
		cfg := Config{Backstores: bs}
		m := &Manager{fs: fs}
		// One priming call, outside the measurement: it checks the fixture is
		// what this test thinks it is, and warms any lazily-built state so the
		// first measured pass is not charged for it.
		if d := m.VerifyDrift(cfg); len(d) != n {
			t.Fatalf("n=%d: drift = %d entries, want %d", n, len(d), n)
		}
		return testing.AllocsPerRun(3, func() { m.VerifyDrift(cfg) })
	}

	small := allocsFor(150)
	large := allocsFor(300)
	if small == 0 {
		t.Fatal("VerifyDrift allocated nothing, so this test is measuring the " +
			"wrong thing -- it cannot walk a fabric without allocating")
	}

	ratio := large / small
	if ratio > 2.5 {
		t.Errorf("doubling the fleet multiplied VerifyDrift's allocations by %.2fx "+
			"(%.0f -> %.0f); linear is ~2x and quadratic is ~4x, so the "+
			"per-backstore fabric walk has come back", ratio, small, large)
	}
	t.Logf("allocations %.0f -> %.0f (%.2fx)", small, large, ratio)
}

// TestVerifyDriftReportsUnreadableRatherThanConverged is the regression test
// for a fail-open.
//
// VerifyDrift is the signal that answers "does the live device match what this
// appliance says about it". It skipped on read errors -- `err != nil || !ok`
// and `err != nil || cur == want` -- so an attribute the process could not read
// was indistinguishable from one that agreed. An operator watching /health for
// drift would be told the fleet was clean by a check that had failed to look.
//
// The distinction already exists a few lines away: countLUNRefs was
// deliberately hardened so a real read failure is not treated as "no LUNs
// here", and the APTPL sibling reports unreadable saved state rather than
// claiming everything is bound. Its one new caller reintroduced the
// conflation at the call site.
func TestVerifyDriftReportsUnreadableRatherThanConverged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs to run unprivileged: the read failure is injected via file mode")
	}
	fs, bs := stageExportedFleet(t, 1, "0") // live == desired: would report clean
	b := bs[0]

	if d := (&Manager{fs: fs}).VerifyDrift(Config{Backstores: bs}); len(d) != 0 {
		t.Fatalf("fixture check: an agreeing attribute must not be drift, got %v", d)
	}

	attr := filepath.Join(fs.Path(b.objPath()...), "attrib", "optimal_sectors")
	if err := os.Chmod(attr, 0o000); err != nil {
		t.Fatal(err)
	}

	drift := (&Manager{fs: fs}).VerifyDrift(Config{Backstores: bs})
	if len(drift) != 1 {
		t.Fatalf("an unreadable attribute must be REPORTED, not silently treated as "+
			"converged: drift = %v", drift)
	}
	d := drift[0]
	if d.Err == nil {
		t.Fatalf("drift must carry the read error so a caller can tell 'differs' from "+
			"'could not tell'; got %+v", d)
	}
	if s := d.String(); !strings.Contains(s, "UNKNOWN") {
		t.Errorf("operator message must say the answer is unknown, got %q", s)
	}
	if d.Live != "" {
		t.Errorf("Live must be empty when unreadable -- a value here would be cached by "+
			"the applied view as though it had been observed; got %q", d.Live)
	}
}

// TestVerifyDriftSkipsAbsentObjects guards the other half: an absent backstore
// is the reconcile's job, so making unreadable objects loud must not also turn
// every not-yet-created one into a standing warning.
func TestVerifyDriftSkipsAbsentObjects(t *testing.T) {
	fs := configfs.New(t.TempDir())
	b := testBackstore()
	b.Attributes = map[string]string{"optimal_sectors": "0"}
	if d := (&Manager{fs: fs}).VerifyDrift(Config{Backstores: []Backstore{b}}); len(d) != 0 {
		t.Errorf("an absent backstore is not a standing condition, got %v", d)
	}
}
