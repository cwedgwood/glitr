package lio

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/cwedgwood/glitr/lio/configfs"
)

// stageBackstoreDir prepares a synthetic configfs object directory. The
// wwn/ and pr/ subdirectories exist automatically on real configfs but not
// in a tmpdir, and WriteAttr does not create parents. Leaving "enable"
// absent makes ensureBackstore take its create path (Mkdir is idempotent).
func stageBackstoreDir(t *testing.T, root string, b Backstore) {
	t.Helper()
	obj := filepath.Join(append([]string{root}, b.objPath()...)...)
	for _, sub := range []string{"wwn", "pr", "attrib"} {
		if err := os.MkdirAll(filepath.Join(obj, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func testBackstore() Backstore {
	return Backstore{Type: FileIO, HBA: 0, Name: "vol_test", Dev: "/tmp/vol_test.img", Size: 1 << 20}
}

func aptplFile(t *testing.T, root string, b Backstore) (string, bool) {
	t.Helper()
	p := filepath.Join(append(append([]string{root}, b.objPath()...), "pr", "res_aptpl_metadata")...)
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data), true
}

// TestAPTPLLoadedOnCreate checks that saved PR records are written at
// backstore creation, and that each record is written SEPARATELY: the
// kernel parses one registration per store, so a joined blob would be
// rejected with EINVAL. A plain file truncates on each write, so observing
// only the final record is what proves the writes were separate.
func TestAPTPLLoadedOnCreate(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	stageBackstoreDir(t, root, b)

	var gotFor []string
	m := New(configfs.New(root))
	m.SetAPTPLRecords(func(bs Backstore) ([]string, error) {
		gotFor = append(gotFor, bs.Name)
		return []string{"sa_res_key=1,res_holder=0", "sa_res_key=2,res_holder=1"}, nil
	})

	if _, err := m.Apply(Config{Backstores: []Backstore{b}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Called at least once for this backstore (the create path). The
	// post-apply verification pass consults it again, read-only.
	if len(gotFor) == 0 || gotFor[0] != b.Name {
		t.Fatalf("provider called for %v, want at least [%s]", gotFor, b.Name)
	}
	got, ok := aptplFile(t, root, b)
	if !ok {
		t.Fatal("res_aptpl_metadata was never written")
	}
	if want := "sa_res_key=2,res_holder=1\n"; got != want {
		t.Errorf("res_aptpl_metadata = %q, want %q (records must be written one at a time)", got, want)
	}
}

// TestAPTPLNotLoadedForExistingBackstore is the important negative case.
// The kernel rejects res_aptpl_metadata with EINVAL once the device is
// exported (dev->export_count > 0), so a steady-state reconcile must not
// attempt it — otherwise every reconcile after the first would fail.
func TestAPTPLNotLoadedForExistingBackstore(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	stageBackstoreDir(t, root, b)

	// Present and already enabled, with a matching backing path.
	fs := configfs.New(root)
	if err := fs.WriteAttr("1", append(b.objPath(), "enable")...); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteAttr(b.Dev, append(b.objPath(), "udev_path")...); err != nil {
		t.Fatal(err)
	}
	// reconcileBackstoreMutable reads the current size from the info line.
	if err := fs.WriteAttr("TCM FILEIO ID: 0  File: "+b.Dev+"  Size: 1048576  Mode: O_DSYNC",
		append(b.objPath(), "info")...); err != nil {
		t.Fatal(err)
	}

	m := New(fs)
	m.SetAPTPLRecords(func(Backstore) ([]string, error) {
		return []string{"sa_res_key=1"}, nil
	})

	if _, err := m.Apply(Config{Backstores: []Backstore{b}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// The property that matters is that no WRITE is attempted: the kernel
	// rejects res_aptpl_metadata with EINVAL once the device is exported, so
	// a steady-state reconcile that tried would fail every time. The provider
	// itself may still be consulted read-only by the verification pass.
	if _, ok := aptplFile(t, root, b); ok {
		t.Error("res_aptpl_metadata was written for an already-enabled backstore; the kernel would reject it with EINVAL")
	}
}

// TestAPTPLProviderErrorIsFailStop: losing saved reservations must not be
// silent. If we cannot determine what was reserved, the apply fails rather
// than quietly bringing the volume up unreserved.
func TestAPTPLProviderErrorIsFailStop(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	stageBackstoreDir(t, root, b)

	sentinel := errors.New("saved PR state unreadable")
	m := New(configfs.New(root))
	m.SetAPTPLRecords(func(Backstore) ([]string, error) { return nil, sentinel })

	_, err := m.Apply(Config{Backstores: []Backstore{b}})
	if err == nil {
		t.Fatal("apply succeeded despite an unreadable saved-PR-state error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error does not wrap the provider error: %v", err)
	}
}

// TestAPTPLNoProviderIsNoop: the hook is optional; without it nothing is
// written and behaviour is unchanged.
func TestAPTPLNoProviderIsNoop(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	stageBackstoreDir(t, root, b)

	m := New(configfs.New(root))
	if _, err := m.Apply(Config{Backstores: []Backstore{b}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := aptplFile(t, root, b); ok {
		t.Error("res_aptpl_metadata written with no provider installed")
	}
}

// TestAPTPLEmptyRecordsSkipped: a provider returning nothing (or blank
// entries) must not write, since an empty store is rejected by the kernel.
func TestAPTPLEmptyRecordsSkipped(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	stageBackstoreDir(t, root, b)

	m := New(configfs.New(root))
	m.SetAPTPLRecords(func(Backstore) ([]string, error) { return []string{"", "   "}, nil })
	if _, err := m.Apply(Config{Backstores: []Backstore{b}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := aptplFile(t, root, b); ok {
		t.Error("blank records should not be written")
	}
}

// TestAPTPLFailureDoesNotLeaveEnabledBackstore is the regression test for the
// fail-OPEN hole found by all four reviewers.
//
// loadAPTPL runs BEFORE "enable" is written. If it failed and the object were
// left enabled, the NEXT Apply would take the already-enabled early path,
// never re-run the provider, and export a LUN whose reservations were never
// restored -- silently converging on exactly the split-brain this feature
// exists to prevent. Worse, applianced runs under Restart=on-failure, so the
// deliberate fail-stop gets retried automatically and comes up green.
//
// Fail-stop is only sound if re-reconvergence actually retries the failed
// step, so a failed restore must not leave a usable backstore behind.
func TestAPTPLFailureDoesNotLeaveEnabledBackstore(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	stageBackstoreDir(t, root, b)

	fail := true
	calls := 0
	m := New(configfs.New(root))
	m.SetAPTPLRecords(func(Backstore) ([]string, error) {
		calls++
		if fail {
			return nil, errors.New("saved PR state unreadable")
		}
		return []string{"sa_res_key=1,res_holder=1"}, nil
	})

	if _, err := m.Apply(Config{Backstores: []Backstore{b}}); err == nil {
		t.Fatal("first Apply should fail when the provider fails")
	}

	// The second pass must genuinely retry the restore.
	fail = false
	if _, err := m.Apply(Config{Backstores: []Backstore{b}}); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	// >= 2 because the provider is also consulted (read-only) by the
	// post-apply verification pass, not just by the create path.
	if calls < 2 {
		t.Errorf("provider called %d times, want >= 2 — a failed restore must be retried, not skipped", calls)
	}
	got, ok := aptplFile(t, root, b)
	if !ok {
		t.Fatal("res_aptpl_metadata never written on retry: the backstore is exportable with NO restored reservations (fail-open)")
	}
	if want := "sa_res_key=1,res_holder=1\n"; got != want {
		t.Errorf("res_aptpl_metadata = %q, want %q", got, want)
	}
}

// The fixtures below are shaped on real kernel output captured from a live
// AL3 target, because both formats are things this package only ever reads
// and an invented shape would test the parser against itself:
//
//	res_pr_registered_i_pts:
//	  SPC-3 PR Registrations:
//	  iSCSI Node: <iqn>,i,0x00023d000004 Key: 0x000000000000aaaa PRgen: 0x0
//	res_holder:
//	  SPC-3 Reservation: iSCSI Initiator: <iqn>,i,0x00023d000004
//
// and one saved record, as db_root/pr/aptpl_<wwn> renders it (note sa_res_key
// is DECIMAL there and hex in the live view -- 43690 == 0xaaaa).
const (
	iqnA = "iqn.1993-08.org.debian:01:glitr-init-a"
	iqnB = "iqn.1993-08.org.debian:01:glitr-init-b"
)

// savedRec builds one comma-joined saved record as appliance.ParseAPTPL
// produces them.
func savedRec(initiator string, key uint64, mappedLUN int, holder bool) string {
	return savedRecType(initiator, key, mappedLUN, holder, 0x05)
}

// savedRecType mirrors the kernel's own record shape: res_type and res_scope
// are written ONLY on the holder record (linux v6.6
// drivers/target/target_core_pr.c:1894), so a non-holder record must not carry
// them or the fixture would be testing a file the kernel never writes.
// resType 0x05 is Write Exclusive - Registrants Only, which is what every
// fencing suite in this repo (and fence_scsi in the field) uses.
func savedRecType(initiator string, key uint64, mappedLUN int, holder bool, resType int) string {
	tail := "res_holder=0"
	if holder {
		tail = fmt.Sprintf("res_holder=1,res_type=%02x,res_scope=00", resType)
	}
	return fmt.Sprintf("initiator_fabric=iSCSI,initiator_node=%s,initiator_sid=00023d000004,"+
		"sa_res_key=%d,%s,res_all_tg_pt=0,mapped_lun=%d,target_fabric=iSCSI,"+
		"target_node=%s,tpgt=1,port_rtpi=1,target_lun=1",
		initiator, key, tail, mappedLUN, testTargetIQN)
}

const testTargetIQN = "iqn.2026-01.dev.glitr:appliance"

// liveRegs renders the kernel's live registration view.
func liveRegs(pairs ...any) string {
	out := "SPC-3 PR Registrations:"
	if len(pairs) == 0 {
		return out + "\nNone"
	}
	for i := 0; i < len(pairs); i += 2 {
		out += fmt.Sprintf("\niSCSI Node: %s,i,0x00023d000004 Key: 0x%016x PRgen: 0x0",
			pairs[i].(string), pairs[i+1].(uint64))
	}
	return out
}

func liveHolder(iqn string) string {
	if iqn == "" {
		return "No SPC-3 Reservation holder"
	}
	return "SPC-3 Reservation: iSCSI Initiator: " + iqn + ",i,0x00023d000004"
}

// exportCfg builds a config exporting b to each (initiator, mappedLUN) pair.
func exportCfg(b Backstore, mapped map[string][]int) Config {
	var acls []ACL
	for iqn, luns := range mapped {
		var mls []MappedLUN
		for _, l := range luns {
			mls = append(mls, MappedLUN{Index: l, TPGLUN: 1})
		}
		acls = append(acls, ACL{InitiatorIQN: iqn, MappedLUNs: mls})
	}
	slices.SortFunc(acls, func(a, b ACL) int { return strings.Compare(a.InitiatorIQN, b.InitiatorIQN) })
	return Config{
		Backstores: []Backstore{b},
		Targets: []Target{{IQN: testTargetIQN, TPGs: []TPG{{
			// No Portals: an empty list means touch-nothing, and a tmpdir
			// has no pre-created np/ directory for the kernel's makable
			// group. Portals are irrelevant to what is under test.
			Tag: 1, Enable: true,
			LUNs: []LUN{{Index: 1, Backstore: b.Name}},
			ACLs: acls,
		}}}},
	}
}

// stageTargets creates what configfs materialises automatically but a
// tmpdir does not: the TPG sub-groups, and the attribute FILES the kernel
// creates inside each makable object directory. Mkdir does not create them
// as parents, so without this ensureLUN and ensureMappedLUN fail ENOENT.
func stageTargets(t *testing.T, root string, cfg Config) {
	t.Helper()
	mkdir := func(parts ...string) {
		if err := os.MkdirAll(filepath.Join(append([]string{root}, parts...)...), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	touch := func(parts ...string) {
		if err := os.WriteFile(filepath.Join(append([]string{root}, parts...)...), []byte("0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, tg := range cfg.Targets {
		for _, g := range tg.TPGs {
			tpg := []string{"iscsi", tg.IQN, "tpgt_" + strconv.Itoa(g.Tag)}
			for _, sub := range []string{"lun", "acls", "np", "param", "attrib"} {
				mkdir(append(tpg, sub)...)
			}
			touch(append(tpg, "enable")...)
			for _, l := range g.LUNs {
				mkdir(append(tpg, "lun", "lun_"+strconv.Itoa(l.Index))...)
			}
			for _, acl := range g.ACLs {
				mkdir(append(tpg, "acls", acl.InitiatorIQN)...)
				for _, ml := range acl.MappedLUNs {
					d := append(tpg, "acls", acl.InitiatorIQN, "lun_"+strconv.Itoa(ml.Index))
					mkdir(d...)
					touch(append(d, "write_protect")...)
				}
			}
		}
	}
}

// aptplHarness applies cfg against a staged tree whose live PR views are
// exactly the strings given, and returns what verification reported.
func aptplHarness(t *testing.T, cfg Config, b Backstore, registered, holder string, recs []string) []string {
	t.Helper()
	root := t.TempDir()
	// Stage every backstore in the config, not just the one under test: a
	// config that exposes a second volume (to model LUN-index reuse) must be
	// applicable, and Config.Validate requires every LUN's backstore present.
	for _, bs := range cfg.Backstores {
		stageBackstoreDir(t, root, bs)
	}
	stageTargets(t, root, cfg)
	fs := configfs.New(root)
	if err := fs.WriteAttr(registered, append(b.objPath(), "pr", "res_pr_registered_i_pts")...); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteAttr(holder, append(b.objPath(), "pr", "res_holder")...); err != nil {
		t.Fatal(err)
	}
	m := New(fs)
	// Scope the saved records to the backstore under test. A provider that
	// returned them for EVERY backstore would make an unrelated volume report
	// the same records and mask which one the check actually attributed them to.
	m.SetAPTPLRecords(func(bs Backstore) ([]string, error) {
		if bs.Name == b.Name {
			return recs, nil
		}
		return nil, nil
	})
	rep, err := m.Apply(cfg)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	return rep.APTPLUnbound
}

// TestAPTPLUnboundIsReported covers the silent-dormancy gap: a restored
// record whose saved coordinates no longer match the topology never binds,
// and because pr/res_aptpl_metadata is write-only nothing could previously
// tell that apart from success. The live registrations ARE readable, so a
// record that is still exported but not live must be reported.
func TestAPTPLUnboundIsReported(t *testing.T) {
	b := testBackstore()
	recs := []string{
		savedRec(iqnA, 0xaaaa, 62, false),
		savedRec(iqnB, 0xbbbb, 62, true),
	}
	cfg := exportCfg(b, map[string][]int{iqnA: {62}, iqnB: {62}})

	// Both bound: nothing to report.
	got := aptplHarness(t, cfg, b, liveRegs(iqnA, uint64(0xaaaa), iqnB, uint64(0xbbbb)), liveHolder(iqnB), recs)
	if len(got) != 0 {
		t.Errorf("all registrations bound, want no report, got %q", got)
	}

	// B is still exported but its registration is gone -- and B is the
	// reservation holder, so this must produce both complaints.
	got = aptplHarness(t, cfg, b, liveRegs(iqnA, uint64(0xaaaa)), liveHolder(""), recs)
	if len(got) != 2 {
		t.Fatalf("exported-but-dormant holder, want 2 reports, got %q", got)
	}
	joined := strings.Join(got, "\n")
	for _, want := range []string{iqnB, "is NOT live", "RESERVATION HOLDER", "NOT in effect"} {
		if !strings.Contains(joined, want) {
			t.Errorf("reports %q should mention %q", got, want)
		}
	}

	// None bound at all.
	got = aptplHarness(t, cfg, b, liveRegs(), liveHolder(""), recs)
	if len(got) != 3 {
		t.Errorf("no registrations bound, want 3 reports (two registrations + holder), got %q", got)
	}
}

// TestAPTPLDetachedHostIsNotReported is the regression test for the measured
// false alarm. A volume exported to A and B, both registered; the operator
// detaches B. The kernel drops B's registration but does NOT rewrite
// db_root/pr/aptpl_<wwn> -- only a PR OUT does that -- so the saved file
// keeps two records forever while one is live.
//
// Measured on a live AL3 target before this fix: /health reported pr_unbound
// permanently, surviving both an unrelated reconcile and a full restart, for
// an action the operator took on purpose. A count-based check cannot avoid
// this; matching the record against the export it was made through can.
func TestAPTPLDetachedHostIsNotReported(t *testing.T) {
	b := testBackstore()
	recs := []string{
		savedRec(iqnA, 0xaaaa, 62, false),
		savedRec(iqnB, 0xbbbb, 62, false),
	}
	// B is gone from the desired config entirely.
	cfg := exportCfg(b, map[string][]int{iqnA: {62}})
	if got := aptplHarness(t, cfg, b, liveRegs(iqnA, uint64(0xaaaa)), liveHolder(""), recs); len(got) != 0 {
		t.Errorf("detaching a host must not report anything, got %q", got)
	}

	// The subtler shape: B stays attached to OTHER volumes, so its ACL
	// survives and only the mapped LUN for this volume is gone. An
	// ACL-level test would still fire here, which is why the check is on
	// the mapped LUN.
	cfg = exportCfg(b, map[string][]int{iqnA: {62}, iqnB: {99}})
	if got := aptplHarness(t, cfg, b, liveRegs(iqnA, uint64(0xaaaa)), liveHolder(""), recs); len(got) != 0 {
		t.Errorf("host detached from THIS volume only must not report, got %q", got)
	}
}

// TestAPTPLLUNIndexReuseAcrossVolumesIsNotReported is the regression test for
// the defect all four reviewers of 13ea072 found: exported() matched a saved
// record against a mapped-LUN INDEX without checking that the index still
// reached the backstore being verified.
//
// Mapped LUN indices are caller-chosen and freely reused -- Lunmap rejects one
// only against currently-attached attachments -- so this sequence is ordinary:
//
//  1. volume X exported to hosts A and B at LUN 62; both register
//  2. detach X from B (X survives because A is still attached)
//  3. attach volume Y to B, also at LUN 62
//
// B's dormant record for X then names a mapped LUN index that still exists on
// B's ACL, but which now addresses Y. Reporting it would resurrect the exact
// permanent false alarm this check exists to remove -- and the message would
// say "still exported at mapped LUN 62" about a different volume.
func TestAPTPLLUNIndexReuseAcrossVolumesIsNotReported(t *testing.T) {
	b := testBackstore() // the volume under verification: TPG LUN 1
	recs := []string{
		savedRec(iqnA, 0xaaaa, 62, false),
		savedRec(iqnB, 0xbbbb, 62, false),
	}
	// A keeps 62 -> TPG LUN 1 (this backstore). B was detached from it and
	// re-used index 62 for a DIFFERENT volume at TPG LUN 2.
	other := Backstore{Type: FileIO, HBA: 1, Name: "vol_other", Dev: "/tmp/vol_other.img", Size: 1 << 20}
	cfg := Config{
		Backstores: []Backstore{b, other},
		Targets: []Target{{IQN: testTargetIQN, TPGs: []TPG{{
			Tag: 1, Enable: true,
			LUNs: []LUN{
				{Index: 1, Backstore: b.Name},
				{Index: 2, Backstore: other.Name},
			},
			ACLs: []ACL{
				{InitiatorIQN: iqnA, MappedLUNs: []MappedLUN{{Index: 62, TPGLUN: 1}}},
				{InitiatorIQN: iqnB, MappedLUNs: []MappedLUN{{Index: 62, TPGLUN: 2}}},
			},
		}}}},
	}
	got := aptplHarness(t, cfg, b, liveRegs(iqnA, uint64(0xaaaa)), liveHolder(""), recs)
	if len(got) != 0 {
		t.Errorf("a mapped LUN index reused for another volume must not be treated "+
			"as still exporting this one, got %q", got)
	}
}

// TestAPTPLRepointedMappedLUNIsNotReported: ensureMappedLUN re-points a reused
// index IN PLACE, so the index surviving proves nothing about what it now
// addresses. Here the index and the initiator both still exist on the same
// backstore's TPG, but the mapping was re-pointed at a different TPG LUN.
func TestAPTPLRepointedMappedLUNIsNotReported(t *testing.T) {
	b := testBackstore()
	recs := []string{savedRec(iqnA, 0xaaaa, 62, true)}
	other := Backstore{Type: FileIO, HBA: 1, Name: "vol_other", Dev: "/tmp/vol_other.img", Size: 1 << 20}
	cfg := Config{
		Backstores: []Backstore{b, other},
		Targets: []Target{{IQN: testTargetIQN, TPGs: []TPG{{
			Tag: 1, Enable: true,
			LUNs: []LUN{
				{Index: 1, Backstore: b.Name},
				{Index: 7, Backstore: other.Name},
			},
			// saved record says target_lun=1; the live mapping now points at 7
			ACLs: []ACL{{InitiatorIQN: iqnA, MappedLUNs: []MappedLUN{{Index: 62, TPGLUN: 7}}}},
		}}}},
	}
	got := aptplHarness(t, cfg, b, liveRegs(), liveHolder(""), recs)
	if len(got) != 0 {
		t.Errorf("a re-pointed mapped LUN must not be treated as still exporting "+
			"the old backstore, got %q", got)
	}
}

// TestAPTPLLapsedHolderUnfencesSurvivors covers the asymmetry between a
// registration and a reservation when an export goes away.
//
// A registration is the registering initiator's own claim, so it dies with
// that initiator's export and saying nothing is right -- that is
// TestAPTPLDetachedHostIsNotReported. A reservation is a restriction imposed
// on EVERYONE ELSE. Detach the holder and the kernel releases it, so a node
// that was fenced by it can write again while still exported. The old
// count-based check happened to fire here; identity matching would silence it
// unless the holder is tracked separately.
//
// The report is bounded because it self-clears when a survivor reserves:
// RESERVE is a PR OUT, and PR OUT is what makes the kernel rewrite the saved
// file. That is NOT true of every path -- see
// TestAPTPLLapsedHolderSilentWhenReservationTransferred, where the kernel
// promotes a registrant without any PR OUT, which is why the live holder is
// read before reporting at all.
func TestAPTPLLapsedHolderUnfencesSurvivors(t *testing.T) {
	b := testBackstore()
	// B held the reservation; A was merely registered.
	recs := []string{
		savedRec(iqnA, 0xaaaa, 62, false),
		savedRec(iqnB, 0xbbbb, 62, true),
	}

	// B detached; A still exported. A's registration is live, so the ONLY
	// thing to report is that B's reservation no longer fences A.
	cfg := exportCfg(b, map[string][]int{iqnA: {62}})
	got := aptplHarness(t, cfg, b, liveRegs(iqnA, uint64(0xaaaa)), liveHolder(""), recs)
	if len(got) != 1 {
		t.Fatalf("detaching the reservation holder while others stay exported must be "+
			"reported exactly once, got %q", got)
	}
	for _, want := range []string{iqnB, "no longer exported", "no longer excluded",
		"not registered"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("report %q should mention %q", got[0], want)
		}
	}
	// It must NOT read as the dormant-holder fault, which means something else.
	if strings.Contains(got[0], "but the live holder is") {
		t.Errorf("a lapsed holder must not be worded as a failed restore: %q", got[0])
	}

	// Nothing exported at all: nobody can reach the device, so there is
	// nothing to warn about and this must stay silent.
	if got := aptplHarness(t, exportCfg(b, map[string][]int{}), b,
		liveRegs(), liveHolder(""), recs); len(got) != 0 {
		t.Errorf("with no exports left there is nobody to un-fence, got %q", got)
	}

	// A surviving initiator re-reserved, so the kernel rewrote the saved file
	// and A is now the holder. Self-cleared.
	cleared := []string{savedRec(iqnA, 0xaaaa, 62, true)}
	if got := aptplHarness(t, cfg, b,
		liveRegs(iqnA, uint64(0xaaaa)), liveHolder(iqnA), cleared); len(got) != 0 {
		t.Errorf("a survivor re-reserving must clear the warning, got %q", got)
	}
}

// TestAPTPLLapsedHolderWithUnregisteredSurvivor is the regression test for the
// round-2 consensus defect (all four reviewers). The gate was `len(want) > 0`,
// where `want` holds SAVED RECORDS whose export survives -- not exports. An
// initiator that never registered a PR key has no saved record at all, so a
// volume left exported only to unregistered initiators scored len(want)==0 and
// went silent.
//
// That is not a corner case, it is the shape a SCSI fence leaves behind: under
// registrants-only reservations (type 5, what every fencing tool uses) PREEMPT
// removes the victim's key, so after A fences B the saved file holds only A.
// Detach A and the survivor B -- still exported, now unregistered and no
// longer excluded by anything -- was exactly who needed reporting.
func TestAPTPLLapsedHolderWithUnregisteredSurvivor(t *testing.T) {
	b := testBackstore()
	// Only the holder has a saved record; B was preempted and never re-registered.
	recs := []string{savedRec(iqnA, 0xaaaa, 62, true)}
	// A (the holder) is detached; B remains exported with no saved record.
	cfg := exportCfg(b, map[string][]int{iqnB: {62}})

	got := aptplHarness(t, cfg, b, liveRegs(), liveHolder(""), recs)
	if len(got) != 1 {
		t.Fatalf("a lapsed holder leaving an UNREGISTERED survivor exported must be "+
			"reported, got %q", got)
	}
	if !strings.Contains(got[0], "1 initiator mapping(s)") {
		t.Errorf("the count must come from the export topology, not saved records: %q", got[0])
	}
}

// TestAPTPLLapsedHolderSilentWhenReservationTransferred is the regression test
// for the permanent false alarm opus5 found in the kernel source.
//
// Removing a mapped LUN calls __core_scsi3_complete_pro_release(..., unreg=1),
// and for the ALL_REGISTRANTS types that path does NOT release the
// reservation -- it transfers it to the next registrant
// (linux v6.6 drivers/target/target_core_pr.c:2471-2480). So the saved holder
// can be gone while the device is still reserved.
//
// Reporting there would be doubly wrong: the claim is false, and it would
// never clear, because promotion is not a PR OUT so the kernel never rewrites
// the saved file. Reading the live holder first is what prevents it.
func TestAPTPLLapsedHolderSilentWhenReservationTransferred(t *testing.T) {
	b := testBackstore()
	// A held an ALL_REGISTRANTS reservation (type 7) and is now detached.
	recs := []string{
		savedRecType(iqnA, 0xaaaa, 62, true, 0x07),
		savedRec(iqnB, 0xbbbb, 62, false),
	}
	cfg := exportCfg(b, map[string][]int{iqnB: {62}})

	// The kernel promoted B: a holder IS live, so there is nothing to report.
	got := aptplHarness(t, cfg, b, liveRegs(iqnB, uint64(0xbbbb)), liveHolder(iqnB), recs)
	for _, g := range got {
		if strings.Contains(g, "no reservation is held") {
			t.Errorf("the reservation was transferred, not released; claiming otherwise "+
				"would be a permanent false alarm: %q", g)
		}
	}
}

// TestAPTPLLapsedHolderWordsTheRightPopulation: under the registrants-only
// types a REGISTERED survivor was never excluded by the reservation, so a
// report that says it was is simply wrong. The population is read from
// res_type, which the kernel writes only on the holder record.
func TestAPTPLLapsedHolderWordsTheRightPopulation(t *testing.T) {
	b := testBackstore()
	cfg := exportCfg(b, map[string][]int{iqnB: {62}})

	// Type 5, Write Exclusive - Registrants Only.
	got := aptplHarness(t, cfg, b, liveRegs(), liveHolder(""),
		[]string{savedRecType(iqnA, 0xaaaa, 62, true, 0x05)})
	if len(got) != 1 || !strings.Contains(got[0], "not registered") {
		t.Errorf("registrants-only excludes NON-registrants; report should say so: %q", got)
	}

	// Type 1, plain Write Exclusive: everyone else really was excluded.
	got = aptplHarness(t, cfg, b, liveRegs(), liveHolder(""),
		[]string{savedRecType(iqnA, 0xaaaa, 62, true, 0x01)})
	if len(got) != 1 || !strings.Contains(got[0], "every other initiator") {
		t.Errorf("plain Write Exclusive excludes everyone else; report should say so: %q", got)
	}
}

// TestAPTPLCountCannotSeeIdentity is the other half: counting satisfied two
// saved records with any two live ones. Here the count matches exactly, but
// the live keys belong to the wrong initiators -- and the saved holder is
// dormant, which is the fencing-critical case a count is blind to.
func TestAPTPLCountCannotSeeIdentity(t *testing.T) {
	b := testBackstore()
	recs := []string{
		savedRec(iqnA, 0xaaaa, 62, false),
		savedRec(iqnB, 0xbbbb, 62, true),
	}
	cfg := exportCfg(b, map[string][]int{iqnA: {62}, iqnB: {62}})

	// Two live registrations, two saved records -- but B holds the wrong
	// key, so B's saved registration (and its reservation) is not in effect.
	got := aptplHarness(t, cfg, b,
		liveRegs(iqnA, uint64(0xaaaa), iqnB, uint64(0xcccc)), liveHolder(iqnA), recs)
	if len(got) != 2 {
		t.Fatalf("count matches but identities do not, want 2 reports, got %q", got)
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "0xbbbb") {
		t.Errorf("report should name the missing key, got %q", got)
	}
	if !strings.Contains(joined, "RESERVATION HOLDER") {
		t.Errorf("a dormant saved holder must be reported on its own terms, got %q", got)
	}

	// Holder held by the right initiator: only the key mismatch remains.
	got = aptplHarness(t, cfg, b,
		liveRegs(iqnA, uint64(0xaaaa), iqnB, uint64(0xcccc)), liveHolder(iqnB), recs)
	if len(got) != 1 || strings.Contains(got[0], "RESERVATION HOLDER") {
		t.Errorf("holder is live, want only the registration report, got %q", got)
	}
}

// TestAPTPLUnreadableInputIsReported: neither a record this package cannot
// parse nor a live line it cannot parse may be silently treated as "fine".
// The first would claim a reservation is in effect on the strength of a file
// we did not understand; the second would claim one is missing because of a
// parser bug, sending an operator after a fencing fault that is not there.
func TestAPTPLUnreadableInputIsReported(t *testing.T) {
	b := testBackstore()
	cfg := exportCfg(b, map[string][]int{iqnA: {62}})

	got := aptplHarness(t, cfg, b, liveRegs(iqnA, uint64(0xaaaa)), liveHolder(""),
		[]string{"initiator_node=" + iqnA + ",sa_res_key=notanumber,mapped_lun=62,target_node=x,tpgt=1"})
	if len(got) != 1 || !strings.Contains(got[0], "unparsable") {
		t.Errorf("an unparsable saved record must be reported, got %q", got)
	}

	got = aptplHarness(t, cfg, b,
		"SPC-3 PR Registrations:\nthis is not a registration line",
		liveHolder(""), []string{savedRec(iqnA, 0xaaaa, 62, false)})
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "could not be parsed") || !strings.Contains(joined, "UNRELIABLE") {
		t.Errorf("an unparsable live line must be reported as unreliable, got %q", got)
	}
}

// TestAPTPLVerifiedOnSyncPath: verification must also run on Sync, not only
// on Apply.
//
// This replaces TestAPTPLUnboundVerifiedAfterPrune, which guarded the
// second blocker the merge-readiness panel found: Sync published a report
// computed BEFORE prune, so a registration made dormant BY the prune counted
// as live and the report said nothing.
//
// Identity matching removed that failure mode by construction rather than by
// ordering. Prune only removes objects ABSENT from the desired config, and a
// record whose coordinates are absent from the desired config is not
// expected to be live at all -- so prune can no longer make an expected
// record dormant, and computing the report before or after it now yields the
// same answer. Keeping a test named "after prune" would be claiming to guard
// an ordering that no longer decides anything.
//
// What still needs guarding is that the Sync path verifies AT ALL: Sync is
// the path every steady-state reconcile takes, so a regression that skipped
// verification there would hide the condition on every path that matters.
func TestAPTPLVerifiedOnSyncPath(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	stageBackstoreDir(t, root, b)
	fs := configfs.New(root)
	cfg := exportCfg(b, map[string][]int{iqnA: {62}})
	stageTargets(t, root, cfg)

	// Backstore already exists and is enabled: the steady state, where
	// nothing is replayed and only verification can notice anything.
	if err := fs.WriteAttr("1", append(b.objPath(), "enable")...); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteAttr(b.Dev, append(b.objPath(), "udev_path")...); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteAttr("TCM FILEIO ID: 0  File: "+b.Dev+"  Size: 1048576  Mode: O_DSYNC",
		append(b.objPath(), "info")...); err != nil {
		t.Fatal(err)
	}
	// Still exported, but the kernel holds no registration for it.
	if err := fs.WriteAttr(liveRegs(), append(b.objPath(), "pr", "res_pr_registered_i_pts")...); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteAttr(liveHolder(""), append(b.objPath(), "pr", "res_holder")...); err != nil {
		t.Fatal(err)
	}

	m := New(fs)
	m.SetAPTPLRecords(func(Backstore) ([]string, error) {
		return []string{savedRec(iqnA, 0xaaaa, 62, true)}, nil
	})

	rep, err := m.Sync(cfg)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	// The registration and the reservation it holds are both missing.
	if len(rep.APTPLUnbound) != 2 {
		t.Fatalf("Sync must verify restored PR state, got %q", rep.APTPLUnbound)
	}
	joined := strings.Join(rep.APTPLUnbound, "\n")
	if !strings.Contains(joined, iqnA) || !strings.Contains(joined, "RESERVATION HOLDER") {
		t.Errorf("report should name the initiator and the dormant holder, got %q", rep.APTPLUnbound)
	}
}

// TestAPTPLVerifyReportsProviderError: a saved file that becomes unreadable
// AFTER its backstore was created was previously reported by nothing at all,
// and the first symptom would be the appliance failing to start later.
func TestAPTPLVerifyReportsProviderError(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	stageBackstoreDir(t, root, b)
	fs := configfs.New(root)
	for k, v := range map[string]string{
		"enable": "1", "udev_path": b.Dev,
		"info": "TCM FILEIO ID: 0  File: " + b.Dev + "  Size: 1048576  Mode: O_DSYNC",
	} {
		if err := fs.WriteAttr(v, append(b.objPath(), k)...); err != nil {
			t.Fatal(err)
		}
	}

	m := New(fs)
	m.SetAPTPLRecords(func(Backstore) ([]string, error) {
		return nil, errors.New("saved PR state is corrupt")
	})

	rep, err := m.Apply(Config{Backstores: []Backstore{b}})
	if err != nil {
		t.Fatalf("a provider error during verification must not fail the reconcile: %v", err)
	}
	if len(rep.APTPLUnbound) != 1 {
		t.Fatalf("provider error during verification must be reported, got %q", rep.APTPLUnbound)
	}
	if !strings.Contains(rep.APTPLUnbound[0], "UNKNOWN") {
		t.Errorf("report %q should say the reservation state is unknown", rep.APTPLUnbound[0])
	}
}
