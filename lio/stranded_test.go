package lio

import (
	"os"
	"path/filepath"
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
		var spaced string
		for i := 0; i < len(sessionISID); i += 2 {
			if i > 0 {
				spaced += " "
			}
			spaced += sessionISID[i : i+2]
		}
		info = "InitiatorName: " + initiator + "\n" +
			"LIO Session ID: 1   ISID: 0x" + spaced + "  TSIH: 1  SessionType: Normal\n"
	}
	if err := os.WriteFile(filepath.Join(acl, "info"), []byte(info), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestStrandedIsReportedWhenTheHolderIsLoggedInWithADifferentISID is the
// condition itself: the reservation is live and enforcing, and its holder is
// present but cannot address it.
func TestStrandedIsReportedWhenTheHolderIsLoggedInWithADifferentISID(t *testing.T) {
	cfg, fs := stageStranded(t, "00023d000004", "00023d000007")
	got := New(fs).StrandedReservations(cfg)
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
	if got := New(fs).StrandedReservations(cfg); len(got) != 0 {
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
	if got := New(fs).StrandedReservations(cfg); len(got) != 0 {
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
	if got := New(fs).StrandedReservations(cfg); len(got) != 0 {
		t.Errorf("a registration with no ISID accepts commands from any session, got %v", got)
	}

	// The control: the SAME staging with the suffix present must report, or
	// the test above proves nothing.
	cfg, fs = stageStranded(t, "00023d000004", "00023d000007")
	if got := New(fs).StrandedReservations(cfg); len(got) != 1 {
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
		if got := New(fs).StrandedReservations(cfg); len(got) != 0 {
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
	got := New(fs).StrandedReservations(cfg)
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
	if got := New(fs).StrandedReservations(cfg); len(got) != 0 {
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
	if got := New(fs).StrandedReservations(cfg); len(got) != 0 {
		t.Errorf("a live session on another TPG matches the registration, so nothing "+
			"is stranded, got %v", got)
	}
}

// TestNoHolderIsNotReported: no reservation, nothing to strand.
func TestNoHolderIsNotReported(t *testing.T) {
	cfg, fs := stageStranded(t, "", "00023d000007")
	if got := New(fs).StrandedReservations(cfg); len(got) != 0 {
		t.Errorf("a backstore with no reservation cannot be stranded, got %v", got)
	}
}
