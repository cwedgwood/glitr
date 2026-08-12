package appliance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwedgwood/glitr/lio"
	"github.com/cwedgwood/glitr/lio/configfs"
	"github.com/cwedgwood/glitr/storage"
)

// stageHolder builds a Coordinator whose kernel tree shows `holder` holding a
// reservation on the object, and returns the object and the coordinator.
func stageHolder(t *testing.T, holder string) (*Coordinator, Object) {
	t.Helper()
	c, o, _ := stageHolderAt(t, holder)
	return c, o
}

// stageHolderAt is stageHolder plus the configfs root, for tests that need to
// stage further attributes or make the tree unwritable.
func stageHolderAt(t *testing.T, holder string) (*Coordinator, Object, string) {
	t.Helper()
	store, err := storage.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	c := &Coordinator{
		store:  store,
		lio:    lio.New(configfs.New(root)),
		cfg:    Config{TargetIQN: "iqn.2026-01.dev.glitr:app"},
		st:     db{Version: dbVersion, Exports: map[string]int{}},
		dbPath: filepath.Join(t.TempDir(), "appliance.json"),
	}
	// TWO objects, and the one under test is deliberately NOT first.
	//
	// HBA is an allocated index, not a constant. An earlier version of the
	// code built the backstore by hand with HBA: 0, which read the wrong
	// object for anything that did not land on fileio_0 -- and an earlier
	// version of THIS fixture staged its object at fileio_0, so the test
	// agreed with the bug and passed. Only the live run caught it. Staging
	// off-zero is what makes this able to fail for the right reason.
	other := mustObject(t, c, "other", 1<<20)
	v := mustObject(t, c, "under-test", 1<<20)

	c.st.Hosts = []*Host{
		{UUID: hHolder, Name: "holder", Bindings: Bindings{IQNs: []string{"iqn.x:holder"}}},
		{UUID: hOther, Name: "other", Bindings: Bindings{IQNs: []string{"iqn.x:other"}}},
	}
	c.st.Connections = []*Connection{
		{ObjectUUID: other.UUID, HostUUID: hHolder, LUN: 0},
		{ObjectUUID: v.UUID, HostUUID: hHolder, LUN: 1},
		{ObjectUUID: v.UUID, HostUUID: hOther, LUN: 1},
	}
	// Seeded so the index is deterministic: exportIndex allocates while
	// ranging a map, so leaving it empty makes which object gets 0 a coin
	// flip -- and a flaky fixture is worse than a weak one.
	c.st.Exports = map[string]int{other.UUID: 0, v.UUID: 1}

	// Stage the tree where the reconcile would actually have built it, rather
	// than at a guessed path. The HBA is an allocated index, so hard-coding
	// one makes the fixture describe a tree the appliance never creates.
	name := backstoreName(v.UUID)
	var hba = -1
	for _, b := range c.desiredLIO().Backstores {
		if b.Name == name {
			hba = b.HBA
		}
	}
	if hba < 0 {
		t.Fatal("the volume under test is not in the desired config; the fixture is wrong")
	}
	// The test can only catch a hard-coded HBA if the real one is not 0.
	// Assert that rather than assume it, or this stops discriminating the
	// moment index allocation changes.
	if hba == 0 {
		t.Fatalf("the volume landed on HBA 0, so this fixture cannot distinguish the " +
			"correct lookup from a hard-coded one; adjust the staging so it does")
	}
	bsDir := filepath.Join(root, "core", fmt.Sprintf("fileio_%d", hba), name, "pr")
	if err := os.MkdirAll(bsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "No SPC-3 Reservation holder"
	if holder != "" {
		body = "SPC-3 Reservation: iSCSI Initiator: " + holder + ",i,0x00023d000004"
	}
	if err := os.WriteFile(filepath.Join(bsDir, "res_holder"), []byte(body+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return c, v, root
}

// TestDetachingTheHolderWarns: the detach still happens -- an operator must be
// able to unmap a host that may itself be dead -- but it must not happen
// SILENTLY. Removing the holder's mapped LUN releases the reservation
// (core_scsi3_free_pr_reg_from_nacl, linux v6.6), so initiators this
// reservation was fencing can write immediately, and re-attaching does not
// restore it.
func TestDetachingTheHolderWarns(t *testing.T) {
	c, v := stageHolder(t, "iqn.x:holder")
	got := c.fenceLossWarning(v.UUID, hHolder)
	if got == "" {
		t.Fatal("detaching the reservation holder releases the fence and must warn; " +
			"silence here is how two nodes end up writing to one filesystem")
	}
	for _, want := range []string{"RELEASED", "iqn.x:holder", "re-attaching does not restore"} {
		if !strings.Contains(got, want) {
			t.Errorf("the warning must contain %q so it is actionable, got: %s", want, got)
		}
	}
}

// TestDetachingANonHolderDoesNotWarn is the counter-test. Detaching a host
// that holds nothing removes only its own access, which OVER-fences -- the
// safe direction -- and leaves the reservation protecting whoever remains.
// Warning there would train an operator to ignore the warning that matters.
func TestDetachingANonHolderDoesNotWarn(t *testing.T) {
	c, v := stageHolder(t, "iqn.x:holder")
	if got := c.fenceLossWarning(v.UUID, hOther); got != "" {
		t.Errorf("detaching a non-holder is safe and must be silent, got: %s", got)
	}
}

func TestNoReservationDoesNotWarn(t *testing.T) {
	c, v := stageHolder(t, "")
	if got := c.fenceLossWarning(v.UUID, hHolder); got != "" {
		t.Errorf("no reservation means nothing to lose, got: %s", got)
	}
}

// TestUnreadableReservationStateDoesNotFailTheUnmap: this is a report channel.
// Failing an unmap because the kernel state could not be read would trade a
// real operation for a diagnostic, and the operator may be detaching precisely
// because something is already wrong.
//
// It must not be SILENT, though, which is what it used to be. Returning ""
// gave an unreadable holder the same outcome as "no reservation is held", so
// the operator was told nothing in the one moment they most needed to know
// that fencing might be dropping. The unmap still proceeds; the difference is
// that the uncertainty is now reported.
func TestUnreadableReservationStateDoesNotFailTheUnmap(t *testing.T) {
	c, v := stageHolder(t, "iqn.x:holder")
	c.lio = lio.New(configfs.New(t.TempDir())) // empty tree: nothing to read
	got := c.fenceLossWarning(v.UUID, hHolder)
	if got == "" {
		t.Fatal("an unreadable holder must say so, not be silent: silence is " +
			"indistinguishable from 'no reservation is held'")
	}
	for _, want := range []string{"could NOT be determined", "verify fencing"} {
		if !strings.Contains(got, want) {
			t.Errorf("the warning must contain %q so it is actionable, got: %s", want, got)
		}
	}
}

// TestUnrecognisedHolderProseIsNotReadAsNoHolder is the regression test for
// the fail-open three of four reviewers looked at and two identified.
//
// res_holder is human-formatted prose with no compatibility promise. parseHolder
// used to return ("", "") for anything it did not recognise, and "" is an
// ANSWER -- it means no reservation is held. So a kernel wording change would
// have reported a protected device as unprotected, silently, in the one place
// this project cannot afford it.
func TestUnrecognisedHolderProseIsNotReadAsNoHolder(t *testing.T) {
	c, v, root := stageHolderAt(t, "iqn.x:holder")

	// A plausible future rendering that does not contain " Initiator: ".
	name := backstoreName(v.UUID)
	for _, b := range c.desiredLIO().Backstores {
		if b.Name != name {
			continue
		}
		p := filepath.Join(root, "core", fmt.Sprintf("fileio_%d", b.HBA), name, "pr", "res_holder")
		if err := os.WriteFile(p, []byte("SPC-3 Reservation held by iqn.x:holder\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got := c.fenceLossWarning(v.UUID, hHolder)
	if got == "" {
		t.Fatal("unrecognised res_holder prose was read as 'no reservation held' and " +
			"produced no warning -- the fail-open direction")
	}
	if !strings.Contains(got, "could NOT be determined") {
		t.Errorf("the warning must say the state is unknown, got: %s", got)
	}
}

// stageResType writes pr/res_pr_type for the volume under test.
func stageResType(t *testing.T, c *Coordinator, v Object, root, resType string) {
	t.Helper()
	name := backstoreName(v.UUID)
	for _, b := range c.desiredLIO().Backstores {
		if b.Name != name {
			continue
		}
		dir := filepath.Join(root, "core", fmt.Sprintf("fileio_%d", b.HBA), name, "pr")
		if err := os.WriteFile(filepath.Join(dir, "res_pr_type"),
			[]byte("SPC-3 Reservation Type: "+resType+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("the volume under test is not in the desired config; the fixture is wrong")
}

// TestAllRegistrantsDoesNotWarn: for the ALL REGISTRANTS types, removing the
// nominal holder enters __core_scsi3_complete_pro_release with unreg=1, which
// TRANSFERS the reservation to the next registration rather than dropping it
// (linux v6.6 drivers/target/target_core_pr.c:2463-2478). Nothing is lost, so
// warning would be a false alarm -- and a warning that fires when nothing was
// lost trains an operator to ignore the one that matters.
func TestAllRegistrantsDoesNotWarn(t *testing.T) {
	for _, rt := range []string{
		"Write Exclusive Access, All Registrants",
		"Exclusive Access, All Registrants",
	} {
		c, v, root := stageHolderAt(t, "iqn.x:holder")
		stageResType(t, c, v, root, rt)
		if got := c.fenceLossWarning(v.UUID, hHolder); got != "" {
			t.Errorf("%s: the reservation transfers rather than releasing, so there is "+
				"nothing to warn about, got %q", rt, got)
		}
	}

	// Control: the identical fixture with a type that DOES release must warn,
	// or the assertions above would pass for any reason at all.
	c, v, root := stageHolderAt(t, "iqn.x:holder")
	stageResType(t, c, v, root, "Write Exclusive Access, Registrants Only")
	if got := c.fenceLossWarning(v.UUID, hHolder); got == "" {
		t.Error("control: a registrants-only reservation IS released and must warn")
	}
}

// TestSPC2ReservationDoesNotWarn: res_holder renders a legacy SPC-2
// reservation through the same " Initiator: " shape
// (linux v6.6 drivers/target/target_core_configfs.c:1804), but
// core_scsi3_free_pr_reg_from_nacl never touches dev->reservation_holder where
// one lives. So an unmap does not release it, and naming it a SCSI-3
// reservation would be wrong twice over.
func TestSPC2ReservationDoesNotWarn(t *testing.T) {
	c, v, root := stageHolderAt(t, "iqn.x:holder")
	name := backstoreName(v.UUID)
	for _, b := range c.desiredLIO().Backstores {
		if b.Name != name {
			continue
		}
		dir := filepath.Join(root, "core", fmt.Sprintf("fileio_%d", b.HBA), name, "pr")
		if err := os.WriteFile(filepath.Join(dir, "res_holder"),
			[]byte("SPC-2 Reservation: iSCSI Initiator: iqn.x:holder\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := c.fenceLossWarning(v.UUID, hHolder); got != "" {
		t.Errorf("an unmap does not release an SPC-2 reservation, got %q", got)
	}
}

// TestLastAttachmentSaysTheReservationMayReturn: whether the release is
// PERMANENT depends on whether the backstore survives. It survives only while
// some other host is attached; if this is the last attachment, reconcile
// removes it and a later attach recreates it and replays the saved APTPL
// records. Both are fence loss now, but "re-attaching does not restore it" is
// false in the second case, and the original text said it unconditionally.
func TestLastAttachmentSaysTheReservationMayReturn(t *testing.T) {
	c, v, _ := stageHolderAt(t, "iqn.x:holder")

	withOther := c.fenceLossWarning(v.UUID, hHolder)
	if !strings.Contains(withOther, "does not restore it") {
		t.Errorf("with another host attached the backstore survives, so the release "+
			"is permanent: %q", withOther)
	}

	// Drop the other attachment: this detach now removes the last one.
	kept := c.st.Connections[:0]
	for _, a := range c.st.Connections {
		if a.ObjectUUID == v.UUID && a.HostUUID == hOther {
			continue
		}
		kept = append(kept, a)
	}
	c.st.Connections = kept

	last := c.fenceLossWarning(v.UUID, hHolder)
	if !strings.Contains(last, "may return") {
		t.Errorf("as the last attachment the backstore is removed and recreated, so "+
			"the saved records can replay: %q", last)
	}
	if strings.Contains(last, "does not restore it") {
		t.Errorf("this claims permanence the code did not establish: %q", last)
	}
}

// TestUnmapWarningSurvivesACommitFailure is the regression test for the one
// finding a merge review rated HIGH.
//
// commit PERSISTS before it reconciles, and its own contract is that "a
// reconcile failure AFTER a valid, durable commit is reported but not rolled
// back (the db is the source of truth; startup replay re-reconciles)". So on
// that path the detach still happens and the reservation is still released --
// yet the code returned ("", err), dropping the warning entirely, on the one
// path where an operator is least likely to go looking because the response
// already reports a failure. It was not logged either: the log line sat after
// commit.
//
// The fixture stages res_holder but not the target tree, so the reconcile
// inside commit fails after the db write succeeds.
func TestUnmapWarningSurvivesACommitFailure(t *testing.T) {
	c, v := stageHolder(t, "iqn.x:holder")

	warning, err := c.Disconnect(context.Background(), KindVolume, v.UUID, hHolder)
	if err == nil {
		t.Fatal("this fixture must fail in reconcile, or it is not testing the path")
	}
	if warning == "" {
		t.Fatal("the detach is durable and the reservation is released, so the " +
			"warning must be returned WITH the error, not discarded")
	}
	if !strings.Contains(warning, "RELEASED") {
		t.Errorf("the warning must name the loss, got %q", warning)
	}
}

// TestUnmapRESTBodyCarriesTheWarning: the warning is only useful if it reaches
// the person issuing the detach. Nothing tested the REST field, which is the
// unreachable-field class of mistake this codebase has hit before -- and the
// error branch drops the body entirely unless it is handled explicitly.
func TestUnmapRESTBodyCarriesTheWarning(t *testing.T) {
	c, v := stageHolder(t, "iqn.x:holder")

	req := httptest.NewRequest(http.MethodDelete,
		APIPrefix+"/volumes/"+v.Name+"/connections/holder", nil)
	rec := httptest.NewRecorder()
	Handler(c).ServeHTTP(rec, req)

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response %q: %v", rec.Body.String(), err)
	}
	if got["warning"] == nil || got["warning"] == "" {
		t.Errorf("status %d body %v: the warning must reach the caller, on the error "+
			"path too -- that is the whole point of returning it rather than only "+
			"logging it", rec.Code, got)
	}
}

// The fixture's host uuids, named so the connections below read as intent
// rather than as two indistinguishable strings.
const (
	hHolder = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	hOther  = "3f2504e0-4f89-11d3-9a0c-0305e82c3302"
)

// mustObject creates a volume through the appliance, which is the only way an
// object exists now: the record and the bytes are committed together.
func mustObject(t *testing.T, c *Coordinator, name string, size int64) Object {
	t.Helper()
	o, _, err := c.Create(context.Background(), KindVolume, CreateRequest{Name: name, Size: size})
	if err != nil {
		t.Fatalf("creating %q: %v", name, err)
	}
	return o
}
