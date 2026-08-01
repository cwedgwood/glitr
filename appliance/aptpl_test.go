package appliance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwedgwood/glitr/lio"
)

// realKernelFile is a verbatim capture of what LIO wrote to
// /var/target/pr/aptpl_8e1fe111494a471c on the AL3 target after an
// initiator registered key 0xaaaa (43690) and took a Write
// Exclusive-Registrants Only reservation. Framing and all.
const realKernelFile = `PR_REG_START: 0
initiator_fabric=iSCSI
initiator_node=iqn.1993-08.org.debian:01:glitr-init-b
initiator_sid=00023d000001
sa_res_key=48059
res_holder=0
res_type=00
res_scope=00
res_all_tg_pt=0
mapped_lun=40
target_fabric=iSCSI
target_node=iqn.2026-01.dev.glitr:appliance
tpgt=1
port_rtpi=1
target_lun=0
PR_REG_END: 0
PR_REG_START: 1
initiator_fabric=iSCSI
initiator_node=iqn.1993-08.org.debian:01:glitr-init-a
initiator_sid=00023d000001
sa_res_key=43690
res_holder=1
res_type=05
res_scope=00
res_all_tg_pt=0
mapped_lun=40
target_fabric=iSCSI
target_node=iqn.2026-01.dev.glitr:appliance
tpgt=1
port_rtpi=1
target_lun=0
PR_REG_END: 1
`

func TestParseAPTPLRealKernelOutput(t *testing.T) {
	recs, err := ParseAPTPL(realKernelFile)
	if err != nil {
		t.Fatalf("real kernel output must parse: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2: %q", len(recs), recs)
	}

	// The framing must not survive: the kernel's parser tokenises on ","
	// and "\n" and rejects unknown tokens with EINVAL.
	for i, r := range recs {
		if strings.Contains(r, "PR_REG_START") || strings.Contains(r, "PR_REG_END") {
			t.Errorf("record %d still carries framing: %q", i, r)
		}
		if strings.Contains(r, "\n") {
			t.Errorf("record %d contains a newline: %q", i, r)
		}
	}

	// The reservation holder must round-trip exactly, or the restored
	// reservation is wrong.
	want := "initiator_fabric=iSCSI,initiator_node=iqn.1993-08.org.debian:01:glitr-init-a," +
		"initiator_sid=00023d000001,sa_res_key=43690,res_holder=1,res_type=05,res_scope=00," +
		"res_all_tg_pt=0,mapped_lun=40,target_fabric=iSCSI," +
		"target_node=iqn.2026-01.dev.glitr:appliance,tpgt=1,port_rtpi=1,target_lun=0"
	if recs[1] != want {
		t.Errorf("holder record mismatch:\n got %q\nwant %q", recs[1], want)
	}
}

func TestParseAPTPLNoRegistrations(t *testing.T) {
	// The kernel's placeholder for a device with no PR state. This is the
	// ONLY input that legitimately yields zero records without an error.
	// The kernel writes strlen(buf)+1 bytes, so the trailing NUL must not
	// defeat the comparison.
	for _, in := range []string{
		"No Registrations or Reservations\n",
		"No Registrations or Reservations\n\x00",
	} {
		recs, err := ParseAPTPL(in)
		if err != nil || len(recs) != 0 {
			t.Errorf("placeholder %q: got (%q, %v), want (none, nil)", in, recs, err)
		}
	}
}

// TestParseAPTPLEmptyFailsClosed is the regression test for the fail-open the
// merge-readiness panel caught: an EMPTY saved file parsed as "no
// reservations" and exported the volume unreserved.
//
// That is the likeliest damage of all, not an exotic one. The kernel rewrites
// this file with O_TRUNC followed by a write, so on EVERY PR OUT there is a
// window where it exists and is zero bytes -- and a crash in that window is
// precisely the crash APTPL exists to survive. Truncation INSIDE a block
// already failed closed; the same crash truncated slightly further must not
// fail open.
func TestParseAPTPLEmptyFailsClosed(t *testing.T) {
	for name, in := range map[string]string{
		"zero length":     "",
		"only whitespace": "  \n\n",
		"only NUL":        "\x00",
		"lost framing":    "initiator_node=iqn.x:a\nsa_res_key=1\n",
		"garbage":         "<<corrupt>>\n",
	} {
		t.Run(name, func(t *testing.T) {
			recs, err := ParseAPTPL(in)
			if err == nil {
				t.Errorf("parsed as %q with no error; a file that is not the kernel placeholder "+
					"must not be read as \"nothing was reserved\"", recs)
			}
		})
	}
}

// TestParseAPTPLDamagedFailsClosed covers the fail-open path the review
// panel flagged: a structurally damaged file must not be mistaken for "no
// reservations". Truncation is a realistic result of the very crash this
// feature exists to survive, and silently returning zero records would
// export the volume unreserved.
func TestParseAPTPLDamagedFailsClosed(t *testing.T) {
	cases := map[string]string{
		"unterminated block": "PR_REG_START: 0\ninitiator_fabric=iSCSI\nsa_res_key=1\n",
		"end without start":  "initiator_node=x\nPR_REG_END: 0\n",
		"nested start":       "PR_REG_START: 0\nPR_REG_START: 1\nPR_REG_END: 1\n",
		"garbage in block":   "PR_REG_START: 0\n<<corrupt>>\nPR_REG_END: 0\n",
		"empty block":        "PR_REG_START: 0\nPR_REG_END: 0\n",
		"missing required":   "PR_REG_START: 0\nres_holder=1\nPR_REG_END: 0\n",
		"comma injection":    "PR_REG_START: 0\ninitiator_node=iqn.x:a,res_holder=1\nsa_res_key=1\nmapped_lun=0\ntarget_node=t\nPR_REG_END: 0\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			recs, err := ParseAPTPL(in)
			if err == nil {
				t.Errorf("damaged input parsed as %q with no error; must fail closed", recs)
			}
		})
	}
}

func TestAPTPLProviderAbsentVsUnreadable(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pr"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := APTPLProvider(dir)

	// No WWN: nothing to look up.
	if recs, err := p(lio.Backstore{}); err != nil || recs != nil {
		t.Errorf("no WWN: got (%v, %v), want (nil, nil)", recs, err)
	}

	// Absent file is normal — a volume that never had a reservation.
	if recs, err := p(lio.Backstore{WWN: "deadbeef00000000"}); err != nil || recs != nil {
		t.Errorf("absent file: got (%v, %v), want (nil, nil)", recs, err)
	}

	// Present and readable.
	if err := os.WriteFile(APTPLPath(dir, "cafebabe00000000"), []byte(realKernelFile), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, err := p(lio.Backstore{WWN: "cafebabe00000000"})
	if err != nil {
		t.Fatalf("readable file: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}

	// A malformed WWN must never reach the filesystem as a path component.
	if _, err := p(lio.Backstore{WWN: "../../../etc/shadow"}); err == nil {
		t.Error("malformed WWN must be rejected, got nil")
	}
}

// TestAPTPLProviderUnreadable is separate so that running as root (which is
// how the daemon itself runs) skips ONLY this case rather than silently
// downgrading the rest of the provider assertions to SKIP.
func TestAPTPLProviderUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: an unreadable file is not exercisable")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pr"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Present but unreadable must NOT be silently treated as "no
	// reservations" — that would hand a fenced initiator its access back.
	if err := os.WriteFile(APTPLPath(dir, "beefcafe00000000"), []byte(realKernelFile), 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := APTPLProvider(dir)(lio.Backstore{WWN: "beefcafe00000000"}); err == nil {
		t.Error("unreadable file must propagate an error, got nil")
	}
}

// TestDiscardSavedPR covers orphan cleanup: the kernel writes
// db_root/pr/aptpl_<wwn> but never removes it, so a deleted volume's saved
// reservations would accumulate for the life of the appliance.
func TestDiscardSavedPR(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pr"), 0o755); err != nil {
		t.Fatal(err)
	}
	doomed := "1111222233334444"
	live := "5555666677778888"
	for _, w := range []string{doomed, live} {
		if err := os.WriteFile(APTPLPath(dir, w), []byte(realKernelFile), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	c := &Coordinator{cfg: Config{DBRoot: dir}}
	c.discardSavedPR(doomed)

	if _, err := os.Stat(APTPLPath(dir, doomed)); !os.IsNotExist(err) {
		t.Errorf("deleted volume's saved PR state should be gone, stat err = %v", err)
	}
	// The critical negative: another volume's state must be untouched.
	if _, err := os.Stat(APTPLPath(dir, live)); err != nil {
		t.Errorf("a live volume's saved PR state was destroyed: %v", err)
	}

	// Idempotent, and silent when there was never any saved state.
	c.discardSavedPR(doomed)
	c.discardSavedPR("9999aaaabbbbcccc")

	// Disabled when no DBRoot is configured: must not touch anything.
	(&Coordinator{cfg: Config{}}).discardSavedPR(live)
	if _, err := os.Stat(APTPLPath(dir, live)); err != nil {
		t.Errorf("cleanup ran with no DBRoot configured: %v", err)
	}
}

func TestOrphanPRState(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pr"), 0o755); err != nil {
		t.Fatal(err)
	}
	live := "1111222233334444"
	orphan := "5555666677778888"
	for _, w := range []string{live, orphan} {
		if err := os.WriteFile(APTPLPath(dir, w), []byte(realKernelFile), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// An unrelated file must not be mistaken for saved PR state.
	if err := os.WriteFile(filepath.Join(dir, "pr", "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := OrphanPRState(dir, []string{live})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != APTPLPath(dir, orphan) {
		t.Errorf("got %q, want exactly [%s]", got, APTPLPath(dir, orphan))
	}

	// All accounted for.
	if got, err := OrphanPRState(dir, []string{live, orphan}); err != nil || len(got) != 0 {
		t.Errorf("no orphans expected, got (%q, %v)", got, err)
	}
	// Absent pr/ directory is normal on a host that never had reservations.
	if got, err := OrphanPRState(t.TempDir(), nil); err != nil || len(got) != 0 {
		t.Errorf("missing pr dir should be quiet, got (%q, %v)", got, err)
	}
	// Unconfigured disables it.
	if got, err := OrphanPRState("", []string{live}); err != nil || len(got) != 0 {
		t.Errorf("unconfigured dbRoot should be quiet, got (%q, %v)", got, err)
	}
}
