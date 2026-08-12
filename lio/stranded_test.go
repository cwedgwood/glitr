package lio

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwedgwood/glitr/lio/configfs"
)

// stageStranded builds a tree with one backstore holding a reservation and one
// ACL, so the ISID comparison has both sides to read.
func stageStranded(t *testing.T, holderISID, sessionISID string) (Config, *configfs.FS) {
	t.Helper()
	holder := "No SPC-3 Reservation holder"
	if holderISID != "" {
		holder = "SPC-3 Reservation: iSCSI Initiator: " + strandedInitiator + ",i,0x" + holderISID
	}
	return stageStrandedFull(t, holder, sessionISID, "Write Exclusive Access, Registrants Only")
}

const (
	strandedTargetIQN = "iqn.2026-01.example:t"
	strandedInitiator = "iqn.1993-08.org.debian:01:a"
)

// stageStrandedFull stages the res_holder line, res_pr_type and the ACL info
// verbatim, so a test can exercise a holder rendering the convenience wrapper
// does not build.
//
// Every caller gets a cfg that carries BOTH the backstore and the target. An
// earlier version of TestHolderWithoutAnISIDIsNotReported staged only the
// backstore, so liveISIDs found no ACL and StrandedReservations returned early
// on "no live session" -- the test passed without ever reaching the holder
// parse it was written to check, and passed identically when the holder DID
// carry an ISID.
func stageStrandedFull(t *testing.T, holderLine, sessionISID, resType string) (Config, *configfs.FS) {
	t.Helper()
	root := t.TempDir()
	b := testBackstore()
	stageBackstoreDir(t, root, b)
	fs := configfs.New(root)

	if err := fs.WriteAttr(holderLine, append(b.objPath(), "pr", "res_holder")...); err != nil {
		t.Fatal(err)
	}
	if resType != "" {
		if err := fs.WriteAttr("SPC-3 Reservation Type: "+resType,
			append(b.objPath(), "pr", "res_pr_type")...); err != nil {
			t.Fatal(err)
		}
	}

	stageACL(t, root, strandedTargetIQN, 1, strandedInitiator, sessionISID)
	// The kernel publishes how many sessions are live, and the check compares
	// against it: without this the fixture describes a target whose session
	// count cannot be read, which is deliberately undecidable rather than
	// stranded. One session, one visible ACL -- the case where a mismatch IS
	// evidence.
	live := 0
	if sessionISID != "" {
		live = 1
	}
	stageSessionCount(t, root, strandedTargetIQN, live)

	cfg := Config{
		Backstores: []Backstore{b},
		Targets:    []Target{{IQN: strandedTargetIQN, TPGs: []TPG{{Tag: 1, Enable: true}}}},
	}
	return cfg, fs
}

// stageACL writes an ACL info attribute, either logged out or carrying a
// byte-spaced ISID exactly as the kernel prints it.
func stageACL(t *testing.T, root, iqn string, tag int, initiator, sessionISID string) {
	t.Helper()
	acl := filepath.Join(append([]string{root}, aclPath(iqn, tag, initiator)...)...)
	if err := os.MkdirAll(acl, 0o755); err != nil {
		t.Fatal(err)
	}
	info := "InitiatorName: " + initiator + "\nNo active iSCSI Session\n"
	if sessionISID != "" {
		var spaced strings.Builder
		for i := 0; i < len(sessionISID); i += 2 {
			if i > 0 {
				spaced.WriteString(" ")
			}
			spaced.WriteString(sessionISID[i : i+2])
		}
		info = "InitiatorName: " + initiator + "\n" +
			"LIO Session ID: 1   ISID: 0x" + spaced.String() + "  TSIH: 1  SessionType: Normal\n"
	}
	if err := os.WriteFile(filepath.Join(acl, "info"), []byte(info), 0o644); err != nil {
		t.Fatal(err)
	}
}

// stageSessionCount writes the target's live session count exactly where the
// kernel publishes it.
func stageSessionCount(t *testing.T, root, iqn string, n int) {
	t.Helper()
	dir := filepath.Join(append([]string{root}, append(targetPath(iqn), "fabric_statistics", "iscsi_instance")...)...)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sessions"), fmt.Appendf(nil, "%d\n", n), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestStrandedIsReportedWhenTheHolderIsLoggedInWithADifferentISID is the
// condition itself: the reservation is live and enforcing, and its holder is
// present but cannot address it.
func TestStrandedIsReportedWhenTheHolderIsLoggedInWithADifferentISID(t *testing.T) {
	cfg, fs := stageStranded(t, "00023d000004", "00023d000007")
	got := New(fs).StrandedReservations(cfg).Stranded
	if len(got) != 1 {
		t.Fatalf("expected the stranded reservation to be reported, got %v", got)
	}
	if got[0].WantISID != "00023d000004" || got[0].LiveISID != "00023d000007" {
		t.Errorf("both identifiers must be reported so an operator can see the "+
			"mismatch, got %+v", got[0])
	}
	if msg := got[0].String(); msg == "" {
		t.Error("the report must render for a human")
	}
}

// TestMatchingISIDIsNotReported: the ordinary case. A target reboot PRESERVES
// the ISID, which is exactly what APTPL exists for, and reporting that would
// make the signal noise.
func TestMatchingISIDIsNotReported(t *testing.T) {
	cfg, fs := stageStranded(t, "00023d000004", "00023d000004")
	if got := New(fs).StrandedReservations(cfg).Stranded; len(got) != 0 {
		t.Errorf("a holder whose session still matches is not stranded, got %v", got)
	}
}

// TestLoggedOutHolderIsNotReported is the false-alarm guard, and the reason
// this check requires a LIVE session rather than merely a mismatch.
//
// An initiator with no session may return with the same identifier -- a target
// reboot preserves it -- so "absent" is not evidence of stranding. Reporting it
// would recreate the class of false alarm aptplcheck.go was written to remove.
func TestLoggedOutHolderIsNotReported(t *testing.T) {
	cfg, fs := stageStranded(t, "00023d000004", "")
	if got := New(fs).StrandedReservations(cfg).Stranded; len(got) != 0 {
		t.Errorf("a holder with no session may come back with the same id and is not "+
			"stranded, got %v", got)
	}
}

// TestHolderWithoutAnISIDIsNotReported: the ",i,0x..." suffix appears only when
// isid_present_at_reg is set. Without it the kernel accepts PR commands from
// any session, so the holder cannot be stranded.
//
// The cfg here carries a LIVE, MISMATCHED session deliberately. Everything
// except the missing suffix is set up to produce a report, so the suffix is
// the only thing that can suppress it -- see stageStrandedFull for the earlier
// version of this test, which staged no target and therefore passed without
// reaching the holder parse at all.
func TestHolderWithoutAnISIDIsNotReported(t *testing.T) {
	cfg, fs := stageStrandedFull(t,
		"SPC-3 Reservation: iSCSI Initiator: "+strandedInitiator,
		"00023d000007",
		"Write Exclusive Access, Registrants Only")
	if got := New(fs).StrandedReservations(cfg).Stranded; len(got) != 0 {
		t.Errorf("a registration with no ISID accepts commands from any session, got %v", got)
	}

	// The control: the SAME staging with the suffix present must report, or
	// the test above proves nothing.
	cfg, fs = stageStranded(t, "00023d000004", "00023d000007")
	if got := New(fs).StrandedReservations(cfg).Stranded; len(got) != 1 {
		t.Fatalf("control: the identical fixture WITH an ISID must report, got %v", got)
	}
}

// TestAllRegistrantsIsNotReported: for the ALL REGISTRANTS types every
// registrant is a reservation holder (linux v6.6
// drivers/target/target_core_pr.c:70-84), so any of them can release it and a
// rotated ISID on the nominal holder strands nothing.
func TestAllRegistrantsIsNotReported(t *testing.T) {
	for _, rt := range []string{
		"Write Exclusive Access, All Registrants",
		"Exclusive Access, All Registrants",
	} {
		cfg, fs := stageStrandedFull(t,
			"SPC-3 Reservation: iSCSI Initiator: "+strandedInitiator+",i,0x00023d000004",
			"00023d000007", rt)
		if got := New(fs).StrandedReservations(cfg).Stranded; len(got) != 0 {
			t.Errorf("%s: any registrant can release this, so it is not stranded, got %v", rt, got)
		}
	}
}

// TestUnreadableReservationTypeStillReports: the type QUALIFIES a holder that
// is already established, so failing to read it loses a detail rather than
// inverting the answer. Going quiet on an unreadable qualifier would hide a
// real stranded reservation behind a diagnostic failure.
func TestUnreadableReservationTypeStillReports(t *testing.T) {
	cfg, fs := stageStrandedFull(t,
		"SPC-3 Reservation: iSCSI Initiator: "+strandedInitiator+",i,0x00023d000004",
		"00023d000007", "")
	got := New(fs).StrandedReservations(cfg).Stranded
	if len(got) != 1 {
		t.Fatalf("an unreadable type must not suppress the report, got %v", got)
	}
	if got[0].ResType != "" {
		t.Errorf("the type must be reported as unknown, not guessed: %q", got[0].ResType)
	}
}

// TestMalformedSessionISIDIsNotReported: a bad extraction would manufacture a
// MISMATCH, and with it a false stranded report. The extraction is part of the
// measurement, so the shape is validated rather than trusted.
func TestMalformedSessionISIDIsNotReported(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	stageBackstoreDir(t, root, b)
	fs := configfs.New(root)
	if err := fs.WriteAttr(
		"SPC-3 Reservation: iSCSI Initiator: "+strandedInitiator+",i,0x00023d000004",
		append(b.objPath(), "pr", "res_holder")...); err != nil {
		t.Fatal(err)
	}

	acl := filepath.Join(append([]string{root}, aclPath(strandedTargetIQN, 1, strandedInitiator)...)...)
	if err := os.MkdirAll(acl, 0o755); err != nil {
		t.Fatal(err)
	}
	// Truncated ISID: matches the regex, is not a 12-hex-digit identifier.
	info := "InitiatorName: " + strandedInitiator + "\n" +
		"LIO Session ID: 1   ISID: 0x00 02  TSIH: 1  SessionType: Normal\n"
	if err := os.WriteFile(filepath.Join(acl, "info"), []byte(info), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Backstores: []Backstore{b},
		Targets:    []Target{{IQN: strandedTargetIQN, TPGs: []TPG{{Tag: 1, Enable: true}}}},
	}
	if got := New(fs).StrandedReservations(cfg).Stranded; len(got) != 0 {
		t.Errorf("a session id that failed to parse must not be compared, got %v", got)
	}
}

// TestMatchingSessionOnAnotherTPGIsNotReported: the same initiator can be
// logged in through more than one TPG, and the registration belongs to a
// specific one. Stopping at the first ACL compares the wrong session and
// reports a strand that is not there.
func TestMatchingSessionOnAnotherTPGIsNotReported(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	stageBackstoreDir(t, root, b)
	fs := configfs.New(root)
	if err := fs.WriteAttr(
		"SPC-3 Reservation: iSCSI Initiator: "+strandedInitiator+",i,0x00023d000004",
		append(b.objPath(), "pr", "res_holder")...); err != nil {
		t.Fatal(err)
	}

	// TPG 1 carries a DIFFERENT session; TPG 2 carries the one the
	// registration demands.
	stageACL(t, root, strandedTargetIQN, 1, strandedInitiator, "00023d000007")
	stageACL(t, root, strandedTargetIQN, 2, strandedInitiator, "00023d000004")

	cfg := Config{
		Backstores: []Backstore{b},
		Targets: []Target{{IQN: strandedTargetIQN, TPGs: []TPG{
			{Tag: 1, Enable: true},
			{Tag: 2, Enable: true},
		}}},
	}
	if got := New(fs).StrandedReservations(cfg).Stranded; len(got) != 0 {
		t.Errorf("a live session on another TPG matches the registration, so nothing "+
			"is stranded, got %v", got)
	}
}

// TestNoHolderIsNotReported: no reservation, nothing to strand.
func TestNoHolderIsNotReported(t *testing.T) {
	cfg, fs := stageStranded(t, "", "00023d000007")
	if got := New(fs).StrandedReservations(cfg).Stranded; len(got) != 0 {
		t.Errorf("a backstore with no reservation cannot be stranded, got %v", got)
	}
}

// TestMultipathHolderIsNotReportedStranded is the reported bug.
//
// An initiator with several concurrent sessions registers on ONE of them. The
// kernel renders only the last-active session per ACL, and under multipath
// that is routinely a different leg -- so the holder's identifier did not
// match the one visible and every multipathed volume holding a reservation was
// reported stranded, permanently, with remediation advice that would have
// disturbed healthy fencing.
//
// The count is what settles it: four sessions live, one rendered, so the
// mismatch is not evidence.
func TestMultipathHolderIsNotReportedStranded(t *testing.T) {
	cfg, fs := stageStranded(t, "00023d000003", "00023d000004")
	// Four live sessions, of which the ACL attribute renders one.
	stageSessionCount(t, fs.Root, strandedTargetIQN, 4)

	rep := New(fs).StrandedReservations(cfg)
	if len(rep.Stranded) != 0 {
		t.Errorf("a multipathed holder must NOT be reported stranded: %v", rep.Stranded)
	}
	// Not silently dropped: an operator who stops seeing strand reports has to
	// be able to find out that the detector cannot see one here.
	if len(rep.Undecided) != 1 {
		t.Fatalf("the blind spot must be reported, got %v", rep.Undecided)
	}
	u := rep.Undecided[0]
	if u.LiveSessions != 4 || u.VisibleSessions != 1 {
		t.Errorf("the report must carry both counts, got %+v", u)
	}
	if len(u.Backstores) != 1 {
		t.Errorf("the affected backstore must be named, got %v", u.Backstores)
	}
	for _, want := range []string{"multipath", "DETECTOR is blind", strandedTargetIQN} {
		if !strings.Contains(u.String(), want) {
			t.Errorf("the report must explain itself, missing %q: %s", want, u.String())
		}
	}
}

// A single-session initiator is still decided, which is the case that keeps
// genuine strand detection working -- and the case the live pr-isid suite
// exercises against a real kernel.
func TestSingleSessionStrandIsStillReported(t *testing.T) {
	cfg, fs := stageStranded(t, "00023d000003", "00023d000004")
	stageSessionCount(t, fs.Root, strandedTargetIQN, 1)

	rep := New(fs).StrandedReservations(cfg)
	if len(rep.Stranded) != 1 {
		t.Fatalf("one session and a mismatch IS a strand: %+v", rep)
	}
	if len(rep.Undecided) != 0 {
		t.Errorf("nothing is undecided when every session is accounted for: %v", rep.Undecided)
	}
}

// An unreadable session count is undecidable, not a strand. Not knowing
// whether the per-ACL view is complete is not the same as knowing that it is,
// and claiming a strand on that basis is the guess this check exists to avoid.
func TestUnreadableSessionCountIsUndecided(t *testing.T) {
	cfg, fs := stageStranded(t, "00023d000003", "00023d000004")
	if err := os.Remove(filepath.Join(fs.Root,
		filepath.Join(append(targetPath(strandedTargetIQN),
			"fabric_statistics", "iscsi_instance", "sessions")...))); err != nil {
		t.Fatal(err)
	}
	rep := New(fs).StrandedReservations(cfg)
	if len(rep.Stranded) != 0 {
		t.Errorf("without the count there is no proof: %v", rep.Stranded)
	}
	if len(rep.Undecided) != 1 || rep.Undecided[0].LiveSessions != -1 {
		t.Fatalf("it must say the count could not be read, got %+v", rep.Undecided)
	}
	if !strings.Contains(rep.Undecided[0].String(), "could not be read") {
		t.Errorf("the reason must be stated: %s", rep.Undecided[0].String())
	}
}
