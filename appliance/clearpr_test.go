package appliance

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestClearReservationRequiresConfirmationByName: this operation drops a fence
// and interrupts every initiator using the volume, so it must not be reachable
// by a caller that did not name the thing it is breaking. An empty body, or a
// name copied from the wrong row of a list, must fail before anything is torn
// down.
func TestClearReservationRequiresConfirmationByName(t *testing.T) {
	for _, confirm := range []string{"", "other", "UNDER-TEST"} {
		c, v := stageHolder(t, "iqn.x:holder")
		out, err := c.ClearReservation(context.Background(), KindVolume, v.Name, confirm)
		if err == nil {
			t.Fatalf("confirm=%q must be refused: an unconfirmed clear silently "+
				"drops fencing for every initiator on the volume", confirm)
		}
		// Assert it failed FOR THIS REASON. Checking only that some error came
		// back passes even with the confirm check deleted, because the
		// tear-down that follows then fails on its own -- which is the test
		// agreeing with the bug rather than catching it.
		if !strings.Contains(err.Error(), "confirmed by name") {
			t.Fatalf("must be refused as unconfirmed, not incidentally by a later "+
				"step; got: %v", err)
		}
		if !strings.Contains(err.Error(), v.Name) {
			t.Errorf("the refusal must name what to confirm with, got: %v", err)
		}
		var se *StatusError
		if !errors.As(err, &se) || se.Reason != CodeInvalidInput {
			t.Errorf("an unconfirmed clear is a bad request from the caller, so it "+
				"must carry %s and not read as a server fault; got: %v",
				CodeInvalidInput, err)
		}
		if out.SavedRecordDiscarded {
			t.Error("a refused clear must not have discarded the saved APTPL record")
		}
		// The refusal has to come before the tear-down, not after it.
		if c.prClearing != "" {
			t.Errorf("a refused clear left the object withheld from the desired "+
				"config (%q), so the volume would stay unexported", c.prClearing)
		}
	}
}

// TestClearReservationRefusesUnknownObject keeps the not-found path ahead of
// the confirm check, so a typo'd name cannot be "confirmed" into existence.
func TestClearReservationRefusesUnknownObject(t *testing.T) {
	c, _ := stageHolder(t, "iqn.x:holder")
	_, err := c.ClearReservation(context.Background(), KindVolume, "no-such-volume", "no-such-volume")
	if err == nil {
		t.Fatal("clearing a reservation on a volume that does not exist must fail")
	}
	// Assert it failed FOR THIS REASON, and with the right status. Checking
	// only that some error came back is the defect this file already had once
	// on the confirm test: it passes for an error from any later step, so it
	// cannot actually prove the not-found path runs first.
	var se *StatusError
	if !errors.As(err, &se) || se.Reason != CodeNotFound {
		t.Fatalf("must be refused as not-found, not incidentally by a later step; "+
			"got: %v", err)
	}
	if c.prClearing != "" {
		t.Errorf("a refused clear left an object withheld: %q", c.prClearing)
	}
}

// TestPRClearingWithholdsOnlyTheClearedObject is the core of the mechanism:
// the tear-down works by making desiredLIO omit ONE object so the reconcile
// prunes its backstore. If it omitted more, the operation would silently
// unexport unrelated volumes; if it omitted none, it would do nothing at all
// and the clear would report success having freed nothing.
func TestPRClearingWithholdsOnlyTheClearedObject(t *testing.T) {
	c, v := stageHolder(t, "iqn.x:holder")

	before := backstoreNames(c)
	if !before[backstoreName(v.UUID)] {
		t.Fatal("the fixture does not export the volume under test")
	}
	if len(before) < 2 {
		t.Fatal("the fixture needs a second exported object, or this cannot tell " +
			"'withheld one' from 'withheld everything'")
	}

	c.prClearing = v.UUID
	during := backstoreNames(c)
	if during[backstoreName(v.UUID)] {
		t.Error("the object being cleared must be absent from the desired config, " +
			"or the reconcile never prunes its backstore and nothing is freed")
	}
	for name := range before {
		if name == backstoreName(v.UUID) {
			continue
		}
		if !during[name] {
			t.Errorf("clearing one object withheld %q as well; a clear must not "+
				"unexport anything it was not asked about", name)
		}
	}

	c.prClearing = ""
	after := backstoreNames(c)
	if len(after) != len(before) {
		t.Fatalf("the desired config did not return to its previous shape: "+
			"%d backstores before, %d after", len(before), len(after))
	}
	for name := range before {
		if !after[name] {
			t.Errorf("%q did not come back after the clear; the mappings live in "+
				"the db and must be restored by the second reconcile", name)
		}
	}
}

// TestPRClearingPreservesLUNAndWWN: the promise of this operation is that only
// the reservation is lost. A rebuild that changed the LUN or the WWN would
// present the initiator with a different device, which is a far worse outcome
// than the reservation it was asked to drop.
func TestPRClearingPreservesLUNAndWWN(t *testing.T) {
	c, v := stageHolder(t, "iqn.x:holder")
	name := backstoreName(v.UUID)

	find := func() (wwn string, hba int, luns []int) {
		hba = -1
		cfg := c.desiredLIO()
		for _, b := range cfg.Backstores {
			if b.Name == name {
				wwn, hba = b.WWN, b.HBA
			}
		}
		for _, tgt := range cfg.Targets {
			for _, tpg := range tgt.TPGs {
				for _, l := range tpg.LUNs {
					if l.Backstore == name {
						luns = append(luns, l.Index)
					}
				}
			}
		}
		return wwn, hba, luns
	}

	wwn0, hba0, luns0 := find()
	if wwn0 == "" {
		t.Fatal("the fixture staged no WWN, so this cannot detect one changing")
	}

	c.prClearing = v.UUID
	_ = c.desiredLIO()
	c.prClearing = ""

	wwn1, hba1, luns1 := find()
	if wwn1 != wwn0 {
		t.Errorf("the WWN changed across a clear (%s -> %s); the initiator would "+
			"see a different device, not the same one unfenced", wwn0, wwn1)
	}
	if hba1 != hba0 {
		t.Errorf("the export index changed across a clear (%d -> %d)", hba0, hba1)
	}
	if len(luns1) != len(luns0) {
		t.Fatalf("the volume came back with %d LUN mappings, not %d", len(luns1), len(luns0))
	}
	for i := range luns0 {
		if luns0[i] != luns1[i] {
			t.Errorf("LUN mapping %d changed across a clear (%d -> %d); the volume "+
				"must return at the same LUN its initiators are using",
				i, luns0[i], luns1[i])
		}
	}
}

// backstoreNames is the set of backstores the reconcile would build right now.
func backstoreNames(c *Coordinator) map[string]bool {
	out := map[string]bool{}
	for _, b := range c.desiredLIO().Backstores {
		out[b.Name] = true
	}
	return out
}

// The tests below drive the real phase machine rather than poking
// `prClearing`. That distinction is the whole point of them: a cross-model
// review mutation-tested this file and found that deleting the APTPL discard,
// and deleting the rollback that restores a withheld object, BOTH left the
// package green -- because no test called ClearReservation past its guards.
//
// The rebuild in phase 3 cannot run against a plain temp directory (configfs
// materialises attribute files on mkdir and a tmpdir does not), so these stop
// at a phase-3 error. That is fine: phases 1 and 2 are where both mutations
// lived, and the assertions below are about what is true when the call
// returns, not about whether it succeeded.

// TestClearReservationAlwaysReleasesTheWithheld object is the regression test
// for the second surviving mutation: delete the rollback and this goes red.
//
// `prClearing` makes desiredLIO omit an object. If any exit path leaves it
// set, that object stays out of every future reconcile -- the volume is gone
// for good, from a call that reported only that it could not drop a fence.
func TestClearReservationAlwaysReleasesTheWithheldObject(t *testing.T) {
	// Two cases that leave through different returns: a phase-1 failure
	// (forced by making the tree unwritable) and the phase-3 failure the
	// fixture produces naturally.
	t.Run("phase 1 fails", func(t *testing.T) {
		c, v, root := stageHolderAt(t, "iqn.x:holder")
		c.cfg.DBRoot = t.TempDir()
		// Deny removal inside the tree so the prune cannot complete.
		if err := os.Chmod(filepath.Join(root, "core"), 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "core"), 0o755) })

		_, err := c.ClearReservation(context.Background(), KindVolume, v.Name, v.Name)
		if err == nil {
			t.Fatal("a clear that cannot prune must not report success")
		}
		if c.prClearing != "" {
			t.Fatalf("the object is still withheld (%q) after a failed clear; it "+
				"would stay absent from every future reconcile", c.prClearing)
		}
		if !backstoreNames(c)[backstoreName(v.UUID)] {
			t.Error("the volume is missing from the desired config after a failed " +
				"clear; losing the volume is far worse than failing to drop a fence")
		}
	})

	t.Run("phase 3 fails", func(t *testing.T) {
		c, v, _ := stageHolderAt(t, "iqn.x:holder")
		c.cfg.DBRoot = t.TempDir()

		_, _ = c.ClearReservation(context.Background(), KindVolume, v.Name, v.Name)
		if c.prClearing != "" {
			t.Fatalf("the object is still withheld (%q) after the clear returned",
				c.prClearing)
		}
		if !backstoreNames(c)[backstoreName(v.UUID)] {
			t.Error("the volume is missing from the desired config after the clear")
		}
	})
}

// TestDiscardSavedPRCheckedProvesRemoval: the delete path may treat this as
// best-effort because a leftover there is inert. Here it is not -- the same
// WWN comes back seconds later -- so a failure must be reported, not logged.
func TestDiscardSavedPRCheckedProvesRemoval(t *testing.T) {
	dir := t.TempDir()
	c := &Coordinator{cfg: Config{DBRoot: dir}}
	wwn := "aaaabbbbccccdddd"
	path := APTPLPath(dir, wwn)
	prDir := filepath.Dir(path)
	if err := os.MkdirAll(prDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Nothing to remove is not an error, and must not claim a removal.
	switch removed, err := c.discardSavedPRChecked(wwn); {
	case err != nil:
		t.Fatalf("absent record must not be an error: %v", err)
	case removed:
		t.Error("reported discarding a record that was never there")
	}

	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	switch removed, err := c.discardSavedPRChecked(wwn); {
	case err != nil:
		t.Fatalf("removing an existing record: %v", err)
	case !removed:
		t.Error("removed a record but did not report it")
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("record still present after a reported removal")
	}

	// A removal that cannot happen must be an error, not a log line.
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(prDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(prDir, 0o755) })
	if _, err := c.discardSavedPRChecked(wwn); err == nil {
		t.Error("a saved APTPL record that could not be removed must fail the " +
			"clear: rebuilding replays it and restores the fence, so reporting " +
			"success here is the one outcome this operation cannot have")
	}
}

// TestWarningsAccumulate: each of these facts is independently actionable, and
// assignment made them compete. The disruption warning lost precisely when an
// earlier step had already failed -- i.e. when the operator knew least.
func TestWarningsAccumulate(t *testing.T) {
	var r ClearedReservation
	r.addWarning("first")
	r.addWarning("second")
	for _, want := range []string{"first", "second"} {
		if !strings.Contains(r.Warning, want) {
			t.Errorf("warning %q was dropped, got %q", want, r.Warning)
		}
	}
}

// stageConfigfsSkeleton creates the directories the kernel materialises when a
// configfs group is created, so a reconcile can run against a temp directory.
//
// configfs is not a filesystem you can emulate with MkdirAll in general -- the
// kernel populates a group's attribute FILES on mkdir, and writing an
// attribute that does not exist fails. But the appliance only ever writes
// attributes into groups it has just made, so pre-creating the group
// directories is enough for a reconcile to succeed: os.WriteFile then creates
// the attribute file itself.
//
// This exists because without it no unit test could reach past the first
// reconcile, which is how two mutations that break the operation outright
// stayed green -- see TestClearReservationDiscardsTheSavedRecord.
// bare names backstores to leave WITHOUT their attribute subdirectories,
// which is what lets a temp directory emulate the other divergence: configfs
// rmdir removes a group together with its attributes, while a tmpdir refuses
// to remove a non-empty one. A backstore the test expects to be PRUNED must
// therefore be staged bare.
//
// So this helper is not a configfs fake and must not be mistaken for one. It
// emulates exactly two behaviours, in one direction each, and a test that
// needs more than that belongs in the live suite.
func stageConfigfsSkeleton(t *testing.T, c *Coordinator, root string, bare ...string) {
	t.Helper()
	mk := func(parts ...string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(append([]string{root}, parts...)...), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	wr := func(val string, parts ...string) {
		t.Helper()
		p := filepath.Join(append([]string{root}, parts...)...)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(val+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	desired := c.desiredLIO()
	for _, b := range desired.Backstores {
		hba := fmt.Sprintf("fileio_%d", b.HBA)
		if slices.Contains(bare, b.Name) {
			mk("core", hba, b.Name)
			continue
		}
		for _, sub := range []string{"attrib", "wwn", "pr"} {
			mk("core", hba, b.Name, sub)
		}
		// info is READ, not written, and the reconcile refuses a backing mode
		// it cannot parse. O_DSYNC is what the kernel reports for the
		// write-through mode this fixture's config asks for.
		wr("TCM FILEIO ID: 0  File: "+b.Dev+"  Size: 1  Mode: O_DSYNC  Async: 0",
			"core", hba, b.Name, "info")
	}
	for _, tgt := range desired.Targets {
		for _, tpg := range tgt.TPGs {
			tp := []string{"iscsi", tgt.IQN, fmt.Sprintf("tpgt_%d", tpg.Tag)}
			for _, sub := range []string{"np", "acls", "lun", "attrib", "param"} {
				mk(append(append([]string{}, tp...), sub)...)
			}
			for _, l := range tpg.LUNs {
				mk(append(append([]string{}, tp...), "lun", fmt.Sprintf("lun_%d", l.Index))...)
			}
			for _, a := range tpg.ACLs {
				mk(append(append([]string{}, tp...), "acls", a.InitiatorIQN)...)
				for _, ml := range a.MappedLUNs {
					mk(append(append([]string{}, tp...), "acls", a.InitiatorIQN,
						fmt.Sprintf("lun_%d", ml.Index))...)
				}
			}
		}
	}
}

// TestClearReservationRunsThePhasesInOrder drives the real phase machine far
// enough to prove the discard actually happens, on a tree a reconcile can act
// on. This is the test that makes deleting the discard call go red.
func TestClearReservationRunsThePhasesInOrder(t *testing.T) {
	c, v, root := stageHolderAt(t, "")
	dbRoot := t.TempDir()
	c.cfg.DBRoot = dbRoot
	// The object under test must be prunable, so it is staged bare -- and the
	// fixture's own pr/res_holder has to go with it, for the same reason: on
	// configfs an rmdir takes the attributes with it, on a tmpdir they block
	// it.
	name := backstoreName(v.UUID)
	stageConfigfsSkeleton(t, c, root, name)
	for _, b := range c.desiredLIO().Backstores {
		if b.Name == name {
			if err := os.RemoveAll(filepath.Join(root, "core",
				fmt.Sprintf("fileio_%d", b.HBA), name, "pr")); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Seed the incremental-reconcile cache with the CURRENT desired config,
	// so withholding one object produces a REMOVAL-ONLY delta. Removals are
	// rmdir and unlink, which work on a temp directory; a full Sync instead
	// re-creates configfs groups whose attribute files the kernel would have
	// materialised and a tmpdir does not.
	//
	// That distinction is the difference between a unit test that can reach
	// phase 2 and one that cannot -- and not reaching phase 2 is precisely
	// why deleting the discard call went unnoticed.
	c.applied = appliedView(c.desiredLIO(), nil)

	saved := APTPLPath(dbRoot, v.WWN)
	if err := os.MkdirAll(filepath.Dir(saved), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(saved, []byte("PR_REG_START: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := c.ClearReservation(context.Background(), KindVolume, v.Name, v.Name)

	// The record must be gone whatever the call returned. If it survives, the
	// rebuild replays it and the clear silently restores the fence it was
	// asked to drop.
	if _, statErr := os.Stat(saved); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("the saved APTPL record %s survived the clear (err=%v, stat=%v)",
			saved, err, statErr)
	}
	if !out.SavedRecordDiscarded {
		t.Error("the record was removed but the result does not say so")
	}
	if c.prClearing != "" {
		t.Errorf("the object is still withheld after the clear: %q", c.prClearing)
	}
}

// TestClearInProgressIsVisibleAndTransient: for the duration of a clear the
// object is deliberately absent from the kernel while the db still maps it,
// and the reconcile inside the operation publishes an ordinary "ok" for the
// remaining tree. /health does not take c.mu, so without a signal that crosses
// that boundary a monitor can read a clean bill of health for a volume its
// initiators cannot see.
func TestClearInProgressIsVisibleAndTransient(t *testing.T) {
	c, v, _ := stageHolderAt(t, "iqn.x:holder")
	c.cfg.DBRoot = t.TempDir()

	if got := c.HealthSnapshot().ClearInProgress; got != "" {
		t.Fatalf("nothing is being cleared, got %q", got)
	}
	// The signal must be set while mu is held, so observe it from another
	// goroutine -- which is exactly how /health sees it.
	seen := make(chan string, 1)
	c.mu.Lock()
	c.setClearing(v.Name)
	go func() { seen <- c.HealthSnapshot().ClearInProgress }()
	if got := <-seen; got != v.Name {
		t.Errorf("a reader that does not hold mu must see the clear in flight; got %q", got)
	}
	c.setClearing("")
	c.mu.Unlock()

	// And it must not survive the operation, whatever the outcome.
	_, _ = c.ClearReservation(context.Background(), KindVolume, v.Name, v.Name)
	if got := c.HealthSnapshot().ClearInProgress; got != "" {
		t.Errorf("the clear finished but /health still reports it in progress: %q", got)
	}
}

// stagePR writes a pr/ group for the object under test, so verifyCleared and
// fenceStateOf can be driven directly.
//
// These exist because a cross-model review MEASURED that the entire
// verifyCleared function was dead code under this suite: replacing its body
// with `return nil` left the package green. Every fail-closed condition below
// is therefore a negative control, not decoration -- each one was confirmed to
// go red when the condition it guards is removed.
func stagePR(t *testing.T, c *Coordinator, root string, v Object, holder, regs string) {
	t.Helper()
	var hba = -1
	name := backstoreName(v.UUID)
	for _, b := range c.desiredLIO().Backstores {
		if b.Name == name {
			hba = b.HBA
		}
	}
	if hba < 0 {
		t.Fatal("the object under test is not exported; the fixture is wrong")
	}
	dir := filepath.Join(root, "core", fmt.Sprintf("fileio_%d", hba), name, "pr")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "No SPC-3 Reservation holder"
	if holder != "" {
		body = "SPC-3 Reservation: iSCSI Initiator: " + holder
	}
	if err := os.WriteFile(filepath.Join(dir, "res_holder"), []byte(body+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "res_pr_registered_i_pts"),
		[]byte(regs), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyClearedFailsClosed drives every refusal condition directly.
//
// The bar each case must meet: deleting the check it exercises makes it fail.
// A clear that reports success it cannot prove is the one outcome this
// operation must never produce.
func TestVerifyClearedFailsClosed(t *testing.T) {
	const regHeader = "SPC-3 PR Registrations:\n"
	oneReg := regHeader + "iSCSI Node: iqn.x:other Key: 0x00000000b5b5b5b5\n"

	cases := []struct {
		name     string
		holder   string
		regs     string
		wantErr  bool
		wantIn   string
		wantCode string
	}{
		{name: "clean", holder: "", regs: regHeader + "None\n", wantErr: false},
		{
			name: "holder survived", holder: "iqn.x:holder", regs: regHeader + "None\n",
			wantErr: true, wantIn: "still held by",
		},
		{
			name: "registration survived", holder: "", regs: oneReg,
			wantErr: true, wantIn: "registration(s) survived",
			// fence_dropped, not clear_unverified: this branch has PROVEN the
			// holder is gone. Telling automation "unverified" is telling it
			// the node is probably still fenced.
			wantCode: CodeFenceDropped,
		},
		{
			name: "holder unreadable", holder: "", regs: regHeader + "None\n",
			wantErr: true, wantIn: "could not be interpreted",
		},
		{
			// Truncation makes the REGISTRATION SET unknown, not the
			// reservation: the holder was read cleanly and is gone. So this
			// must carry fence_dropped, not a code a caller reads as "may
			// still be fenced".
			name: "registration list truncated", holder: "",
			regs:    regHeader + "this line is not a registration the parser knows\n",
			wantErr: true, wantIn: "truncated", wantCode: CodeFenceDropped,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, v, root := stageHolderAt(t, "")
			stagePR(t, c, root, v, tc.holder, tc.regs)
			if tc.name == "holder unreadable" {
				// Prose the kernel never emits: HolderKnown must go false, and
				// that must NOT be read as "nothing is held".
				var hba = -1
				name := backstoreName(v.UUID)
				for _, b := range c.desiredLIO().Backstores {
					if b.Name == name {
						hba = b.HBA
					}
				}
				p := filepath.Join(root, "core", fmt.Sprintf("fileio_%d", hba), name, "pr", "res_holder")
				if err := os.WriteFile(p, []byte("something the kernel never says\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			err := c.verifyCleared(v.UUID, KindVolume, v.Name)
			if tc.wantErr && err == nil {
				t.Fatalf("%s must be refused: reporting success here claims a fence "+
					"is gone without proving it", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("a clean state must verify, got: %v", err)
			}
			if tc.wantErr {
				if !strings.Contains(err.Error(), tc.wantIn) {
					t.Errorf("refused for the wrong reason; want %q, got: %v", tc.wantIn, err)
				}
				if !errors.Is(err, errClearVerify) {
					t.Errorf("must match errClearVerify so callers can branch, got: %v", err)
				}
				wantCode := tc.wantCode
				if wantCode == "" {
					wantCode = CodeClearUnverified
				}
				var se *StatusError
				if !errors.As(err, &se) || se.Reason != wantCode {
					t.Errorf("must carry %s, got: %v", wantCode, err)
				}
			}
		})
	}
}

// TestUnattachedObjectVerifiesClean is the counter-test, and a regression test
// for a measured bug: verifyCleared used to refuse unconditionally when there
// was no backstore, which made clearing an unattached object impossible --
// exactly the leftover-registration case the operation advertises.
func TestUnattachedObjectVerifiesClean(t *testing.T) {
	c, v, _ := stageHolderAt(t, "")
	// Drop every mapping, so the object legitimately has no LIO device.
	c.st.Connections = nil
	if c.backstoreOf(v.UUID) != nil {
		t.Fatal("the fixture still exports the object; this cannot test the case")
	}
	if err := c.verifyCleared(v.UUID, KindVolume, v.Name); err != nil {
		t.Fatalf("an object with no attachments has no device and so nothing can "+
			"be reserving it; refusing makes a legitimate clear impossible: %v", err)
	}
	verdict, _, haveBackstore, err := c.fenceStateOf(v.UUID)
	if err != nil {
		t.Fatal(err)
	}
	if haveBackstore {
		t.Error("reported a backstore for an unattached object")
	}
	if verdict != fenceDown {
		t.Errorf("no device means nothing is reserving it -- that is knowledge, "+
			"not fenceUnknown; got verdict %v", verdict)
	}
}

// TestFenceStateIsSeparateFromFullVerification is the regression test for the
// round-2 finding: recoverFromFailedPrune asked "did everything succeed?" to
// answer "is the fence down?", so a released reservation with a surviving
// registration was reported as a generic failure whose safe reading is "still
// fenced". That is the under-fence class this operation exists to avoid.
func TestFenceStateIsSeparateFromFullVerification(t *testing.T) {
	c, v, root := stageHolderAt(t, "")
	stagePR(t, c, root, v, "",
		"SPC-3 PR Registrations:\niSCSI Node: iqn.x:other Key: 0x00000000b5b5b5b5\n")

	// The full check must fail -- registrations survived.
	if err := c.verifyCleared(v.UUID, KindVolume, v.Name); err == nil {
		t.Fatal("surviving registrations must fail the full verification")
	}
	// The fence question must still be answered, and answered DOWN.
	verdict, st, _, err := c.fenceStateOf(v.UUID)
	if err != nil {
		t.Fatal(err)
	}
	if verdict != fenceDown {
		t.Fatalf("the holder is gone, so the fence is provably down; reporting "+
			"anything else lets a caller believe the volume is still fenced "+
			"(got verdict %v)", verdict)
	}
	if len(st.Registrations) == 0 {
		t.Error("the fixture staged a registration that was not read back")
	}
}

// TestClearPublishesInProgressWhileRunning: the previous version of this test
// called setClearing ITSELF and then asserted HealthSnapshot saw it, so it was
// a property of the test. Deleting the publish from ClearReservation left it
// green -- MEASURED. This drives the real operation instead.
func TestClearPublishesInProgressWhileRunning(t *testing.T) {
	c, v, root := stageHolderAt(t, "")
	c.cfg.DBRoot = t.TempDir()
	stageConfigfsSkeleton(t, c, root)

	seen := make(chan string, 64)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				if s := c.HealthSnapshot().ClearInProgress; s != "" {
					seen <- s
					return
				}
			}
		}
	}()
	_, _ = c.ClearReservation(context.Background(), KindVolume, v.Name, v.Name)
	close(stop)

	select {
	case got := <-seen:
		if got != v.Name {
			t.Errorf("reported %q in progress, want %q", got, v.Name)
		}
	default:
		t.Error("a reader that does not hold c.mu never saw the clear in flight; " +
			"for its duration the object is absent from the kernel while the db " +
			"still maps it, so /health would report a clean bill for a volume " +
			"its initiators cannot see")
	}
	if got := c.HealthSnapshot().ClearInProgress; got != "" {
		t.Errorf("still reported in progress after returning: %q", got)
	}
}

// TestVerifyClearedRefusesATruncatedList: the kernel renders the registration
// list into one page and simply stops, with no marker and no error. So a short
// list is not evidence of an empty one, and "no registrations visible" must not
// be reported as "no registrations" -- that is the fail-open direction in the
// one check that proves a fence was dropped cleanly.
func TestVerifyClearedRefusesATruncatedList(t *testing.T) {
	c, v, root := stageHolderAt(t, "")
	// An unparsable line makes PRState set Truncated: absence from a list it
	// could not fully read stops being evidence of anything.
	stagePR(t, c, root, v, "",
		"SPC-3 PR Registrations:\nthis line is not a registration the parser knows\n")

	err := c.verifyCleared(v.UUID, KindVolume, v.Name)
	if err == nil {
		t.Fatal("a registration list the kernel may have truncated must not be " +
			"reported as proven empty")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("refused for the wrong reason, got: %v", err)
	}
}

// TestFailedPruneReportsADroppedFence is the regression test for the round-2
// finding, and the negative control for the fence/contract split.
//
// A prune that fails after the holder's mapped LUN is removed has ALREADY
// released the reservation. Reporting that as a plain "could not clear" lets a
// caller conclude the volume is still fenced when it is not.
func TestFailedPruneReportsADroppedFence(t *testing.T) {
	c, v, root := stageHolderAt(t, "")
	// Fence provably down, but a registration survived -- the exact shape that
	// used to be reported as a generic failure.
	// The restoring reconcile must be able to succeed against a temp
	// directory, or this measures the double-failure path instead.
	stageConfigfsSkeleton(t, c, root)
	stagePR(t, c, root, v, "",
		"SPC-3 PR Registrations:\niSCSI Node: iqn.x:other Key: 0x00000000b5b5b5b5\n")
	c.applied = appliedView(c.desiredLIO(), nil)

	out, err := c.recoverFromFailedPrune(context.Background(), ClearedReservation{Object: v.Name},
		KindVolume, v.Name, v.UUID, errors.New("injected prune failure"))
	if err == nil {
		t.Fatal("a failed prune must still be an error")
	}
	var se *StatusError
	if !errors.As(err, &se) || se.Reason != CodeFenceDropped {
		t.Fatalf("the reservation was already released, so this must carry %s -- "+
			"a caller reading a generic failure as 'still fenced' would be wrong; "+
			"got: %v", CodeFenceDropped, err)
	}
	if !strings.Contains(err.Error(), "fence is DOWN") {
		t.Errorf("the error must say the fence is down, got: %v", err)
	}
	if !strings.Contains(out.Warning, "registration") {
		t.Errorf("surviving registrations keep write access under a "+
			"registrants-only reservation and must be reported, got: %q", out.Warning)
	}
}

// TestFailedPruneWithASurvivingHolderReadsAsStillFenced is the counter-test.
// When the reservation genuinely survived, a plain failure is correct and must
// NOT claim the fence dropped.
func TestFailedPruneWithASurvivingHolderReadsAsStillFenced(t *testing.T) {
	c, v, root := stageHolderAt(t, "")
	stageConfigfsSkeleton(t, c, root)
	stagePR(t, c, root, v, "iqn.x:holder", "SPC-3 PR Registrations:\nNone\n")
	c.applied = appliedView(c.desiredLIO(), nil)

	_, err := c.recoverFromFailedPrune(context.Background(), ClearedReservation{Object: v.Name},
		KindVolume, v.Name, v.UUID, errors.New("injected prune failure"))
	if err == nil {
		t.Fatal("a failed prune must be an error")
	}
	var se *StatusError
	if !errors.As(err, &se) || se.Reason == CodeFenceDropped {
		t.Fatalf("the reservation survived, so this must not claim the fence "+
			"dropped; got: %v", err)
	}
	if !strings.Contains(err.Error(), "still held by") {
		t.Errorf("must say the reservation is still held, got: %v", err)
	}
}

// TestPhase2FailurePublishesWithheldAndNamesTheFile covers the two measured
// defects on the discard-failure path at once.
//
// First: the object is deliberately left out of the desired config, and no
// reconcile restores it -- healIfDegraded cannot, because phase 1 SUCCEEDED so
// lastReconcileErr is nil. Without a standing health signal, /health answers
// "ok" for a volume its initiators cannot see, for the life of the process.
//
// Second: the error has to name the FILE to delete. An earlier version mixed
// an explicit %[1]s into an implicit argument list, which re-based the cursor
// so the trailing verb printed the OBJECT NAME -- telling an operator of a
// storage appliance to "Remove <volume>". go vet does not catch it.
func TestPhase2FailurePublishesWithheldAndNamesTheFile(t *testing.T) {
	c, v, root := stageHolderAt(t, "")
	dbRoot := t.TempDir()
	c.cfg.DBRoot = dbRoot
	name := backstoreName(v.UUID)
	stageConfigfsSkeleton(t, c, root, name)
	for _, b := range c.desiredLIO().Backstores {
		if b.Name == name {
			if err := os.RemoveAll(filepath.Join(root, "core",
				fmt.Sprintf("fileio_%d", b.HBA), name, "pr")); err != nil {
				t.Fatal(err)
			}
		}
	}
	c.applied = appliedView(c.desiredLIO(), nil)

	// Make the discard fail: the record exists but its directory is not
	// writable, so os.Remove cannot unlink it.
	saved := APTPLPath(dbRoot, v.WWN)
	prDir := filepath.Dir(saved)
	if err := os.MkdirAll(prDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(saved, []byte("PR_REG_START: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(prDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(prDir, 0o755) })

	out, err := c.ClearReservation(context.Background(), KindVolume, v.Name, v.Name)
	if err == nil {
		t.Fatal("a clear that cannot discard the saved record must fail: rebuilding " +
			"replays it and silently restores the fence")
	}
	// Pin the INSTRUCTION, not just the presence of the path. The wrapped
	// cause from discardSavedPRChecked already contains the path, so asserting
	// on the path alone passes even when the instructional verb prints the
	// object name -- MEASURED: the mutation that swapped %[4]s for %[2]s left
	// this test green until it checked the whole clause.
	if want := "Delete the FILE " + saved; !strings.Contains(err.Error(), want) {
		t.Errorf("the error must instruct the operator to delete the FILE (%q), or "+
			"they are told to remove the object instead; got: %v", want, err)
	}
	if strings.Contains(err.Error(), "Delete the FILE "+v.Name) {
		t.Error("the instruction names the OBJECT, not the file; in a storage " +
			"appliance that reads as 'delete the volume'")
	}
	// Pin the CODE, not only the message. The code is the only part of the
	// answer a program reads, and phase 1 succeeded here -- the prune already
	// freed every registration, so the fence is provably down. A code whose
	// documented reading is "still fenced" would be the under-fence.
	var se *StatusError
	if !errors.As(err, &se) || se.Reason != CodeFenceDropped {
		t.Errorf("a phase-2 failure happens AFTER a successful prune, so the fence "+
			"is down and this must carry %s; got: %v", CodeFenceDropped, err)
	}
	if got := c.HealthSnapshot().Withheld; !slices.Contains(got, v.Name) {
		t.Errorf("the object is withheld from every future reconcile and nothing "+
			"else can report it, so /health must say so; got Withheld=%v", got)
	}
	if c.prClearing == "" {
		t.Error("the object must stay withheld -- rebuilding it now replays the record")
	}
	if !strings.Contains(out.Warning, "withheld_after_failed_clear") {
		t.Errorf("the result must point at the health signal, got: %q", out.Warning)
	}
}

// TestClearRefusesWhileDegraded: every other kernel-touching mutation gates on
// healIfDegraded, and the rule at that function is stated for all of them, not
// just commit(). A clear reasons about the desired tree and then tears down and
// rebuilds part of it; doing that against a tree already known to disagree with
// the database is how a recovery operation destroys the wrong object's fencing.
func TestClearRefusesWhileDegraded(t *testing.T) {
	c, v, root := stageHolderAt(t, "")
	c.cfg.DBRoot = t.TempDir()
	// A previous reconcile failed, and it still cannot succeed.
	c.lastReconcileErr = errors.New("previous reconcile failed")
	if err := os.Chmod(root, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })

	_, err := c.ClearReservation(context.Background(), KindVolume, v.Name, v.Name)
	if err == nil {
		t.Fatal("a clear must not run against a kernel tree known to disagree " +
			"with the database")
	}
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusServiceUnavailable {
		t.Errorf("must be refused as degraded (503), not by a later step; got: %v", err)
	}
	if c.prClearing != "" {
		t.Errorf("a refused clear left an object withheld: %q", c.prClearing)
	}
}

// Not covered here, deliberately: that ClearReservation PROPAGATES a
// verifyCleared failure. Reaching it needs a successful phase-3 rebuild, which
// configfs semantics make impossible on a temp directory -- see
// stageConfigfsSkeleton. It is a live-suite property: cmd/labtest's clear-pr
// asserts on the real device that no holder and no registrations remain after
// a successful clear, so a clear that ignored its own verification would fail
// there. Recorded rather than left as an unexplained gap.

// TestAClearOfOneObjectDoesNotReleaseAnother is the regression test for the
// round-3 consensus finding, and it is an under-fence.
//
// The withheld state began as a single string beside prClearing. A clear of B
// therefore released A: desiredLIO excluded only the one current value, so B's
// reconcile ADDED A back -- ApplyDelta applies additions before removals --
// while A's saved APTPL record was still on disk, replaying it and restoring
// the fence the operator had asked to drop, with A's health signal erased in
// the same call. The worse reachable form: if A's record had been REMOVED but
// its absence not proven, A returns with no record at all, unfenced and
// unreported.
func TestAClearOfOneObjectDoesNotReleaseAnother(t *testing.T) {
	c, v, root := stageHolderAt(t, "")
	other := c.objectByName(KindVolume, "other")
	if other == nil {
		t.Fatal("the fixture no longer stages a second object")
	}

	// A failed clear left "other" withheld.
	c.holdBack(other.UUID, other.Name)
	if !slices.Contains(backstoreNamesOf(c), backstoreName(v.UUID)) {
		t.Fatal("the object under test should still be exported")
	}
	if slices.Contains(backstoreNamesOf(c), backstoreName(other.UUID)) {
		t.Fatal("a withheld object must be absent from the desired config")
	}

	// Now clear a DIFFERENT object, and let that clear REACH PHASE 2 -- where
	// the hold is released. A clear that fails earlier never gets there, so it
	// could not detect a release that is wholesale rather than per-object.
	c.cfg.DBRoot = t.TempDir()
	name := backstoreName(v.UUID)
	stageConfigfsSkeleton(t, c, root, name)
	for _, b := range c.desiredLIO().Backstores {
		if b.Name == name {
			if err := os.RemoveAll(filepath.Join(root, "core",
				fmt.Sprintf("fileio_%d", b.HBA), name, "pr")); err != nil {
				t.Fatal(err)
			}
		}
	}
	c.applied = appliedView(c.desiredLIO(), nil)
	_, _ = c.ClearReservation(context.Background(), KindVolume, v.Name, v.Name)

	if slices.Contains(backstoreNamesOf(c), backstoreName(other.UUID)) {
		t.Error("clearing one object re-exported a DIFFERENT object that a failed " +
			"clear had withheld; its saved APTPL record is still on disk, so the " +
			"rebuild replays it and silently restores the fence")
	}
	if got := c.HealthSnapshot().Withheld; !slices.Contains(got, other.Name) {
		t.Errorf("clearing one object erased another's standing health signal; "+
			"got Withheld=%v", got)
	}
}

// backstoreNamesOf is the desired backstore set as a slice, for slices.Contains.
func backstoreNamesOf(c *Coordinator) []string {
	var out []string
	for _, b := range c.desiredLIO().Backstores {
		out = append(out, b.Name)
	}
	return out
}

// TestDeletingAWithheldObjectReleasesTheHold: a deleted object cannot still be
// withheld. Leaving the hold keeps /health reporting a standing condition for
// something that no longer exists, and leaves a UUID in the set that
// desiredLIO would exclude forever.
func TestDeletingAWithheldObjectReleasesTheHold(t *testing.T) {
	c, _, _ := stageHolderAt(t, "")
	other := c.objectByName(KindVolume, "other")
	if other == nil {
		t.Fatal("the fixture no longer stages a second object")
	}
	c.holdBack(other.UUID, other.Name)

	// Delete needs it unconnected.
	c.st.Connections = slices.DeleteFunc(c.st.Connections, func(cn *Connection) bool {
		return cn.ObjectUUID == other.UUID
	})
	if err := c.Delete(context.Background(), KindVolume, other.Name); err != nil {
		t.Fatal(err)
	}
	if got := c.HealthSnapshot().Withheld; slices.Contains(got, other.Name) {
		t.Errorf("a deleted object is still reported withheld: %v", got)
	}
}

// TestPreClearReadFailureIsNotReportedAsKnown: an unreadable pre-clear state
// must leave HeldKnown false. Reporting it as known says "nothing was held" to
// a machine at the exact moment something may have been -- the fail-open
// direction in a machine-readable field.
func TestPreClearReadFailureIsNotReportedAsKnown(t *testing.T) {
	c, v, root := stageHolderAt(t, "")
	// Prose the kernel never emits: ReservationHolder fails closed on it.
	stagePR(t, c, root, v, "", "SPC-3 PR Registrations:\nNone\n")
	var hba = -1
	name := backstoreName(v.UUID)
	for _, b := range c.desiredLIO().Backstores {
		if b.Name == name {
			hba = b.HBA
		}
	}
	p := filepath.Join(root, "core", fmt.Sprintf("fileio_%d", hba), name, "pr", "res_holder")
	if err := os.WriteFile(p, []byte("something the kernel never says\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	c.cfg.DBRoot = t.TempDir()
	out, _ := c.ClearReservation(context.Background(), KindVolume, v.Name, v.Name)
	if out.HeldKnown {
		t.Error("the pre-clear state was unreadable, so held_known must be false; " +
			"true tells a machine 'nothing was held' when something may have been")
	}
	if !strings.Contains(out.Warning, "could not be read before clearing") {
		t.Errorf("the operator must be told the state was unreadable, got: %q", out.Warning)
	}
}

// TestSPC2ReservationIsReportedAsHeld: an SPC-2 reservation is not what this
// operation is named for, but destroying the device clears it too. Reporting
// held=false would tell an operator no fence was broken when one was.
func TestSPC2ReservationIsReportedAsHeld(t *testing.T) {
	c, v, root := stageHolderAt(t, "")
	var hba = -1
	name := backstoreName(v.UUID)
	for _, b := range c.desiredLIO().Backstores {
		if b.Name == name {
			hba = b.HBA
		}
	}
	dir := filepath.Join(root, "core", fmt.Sprintf("fileio_%d", hba), name, "pr")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "res_holder"),
		[]byte("SPC-2 Reservation: iSCSI Initiator: iqn.x:holder\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	c.cfg.DBRoot = t.TempDir()
	out, _ := c.ClearReservation(context.Background(), KindVolume, v.Name, v.Name)
	if !out.Held || !out.HeldKnown {
		t.Errorf("an SPC-2 reservation is cleared by the tear-down and must be "+
			"reported as held; got held=%v held_known=%v", out.Held, out.HeldKnown)
	}
	if out.Type != "SPC-2 reservation" {
		t.Errorf("it must be distinguished from a SCSI-3 holder, got type=%q", out.Type)
	}
}

// TestFailedPruneWithUnreadableStateIsFenceUnknown pins the third fence code.
//
// When the prune fails AND the state cannot be interpreted afterwards, neither
// reading is safe. fence_unknown exists to say exactly that; without it the
// caller gets a code meaning "still fenced" or "dropped", and both are guesses.
func TestFailedPruneWithUnreadableStateIsFenceUnknown(t *testing.T) {
	c, v, root := stageHolderAt(t, "")
	stageConfigfsSkeleton(t, c, root)
	// Prose the kernel never emits: readable, uninterpretable.
	stagePR(t, c, root, v, "", "SPC-3 PR Registrations:\nNone\n")
	var hba = -1
	name := backstoreName(v.UUID)
	for _, b := range c.desiredLIO().Backstores {
		if b.Name == name {
			hba = b.HBA
		}
	}
	p := filepath.Join(root, "core", fmt.Sprintf("fileio_%d", hba), name, "pr", "res_holder")
	if err := os.WriteFile(p, []byte("something the kernel never says\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c.applied = appliedView(c.desiredLIO(), nil)

	_, err := c.recoverFromFailedPrune(context.Background(), ClearedReservation{Object: v.Name},
		KindVolume, v.Name, v.UUID, errors.New("injected prune failure"))
	if err == nil {
		t.Fatal("a failed prune must be an error")
	}
	var se *StatusError
	if !errors.As(err, &se) || se.Reason != CodeFenceUnknown {
		t.Fatalf("the fence state could not be established, so this must carry %s "+
			"-- neither 'still fenced' nor 'dropped' is a safe reading; got: %v",
			CodeFenceUnknown, err)
	}
	// And it must say WHICH happened, not print a nil error.
	if strings.Contains(err.Error(), "<nil>") {
		t.Errorf("the message printed a nil error instead of naming the cause: %v", err)
	}
}
