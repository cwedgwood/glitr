package storage

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentity(t *testing.T) {
	u, w, err := newIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if len(u) != 36 || u[8] != '-' || u[14] != '4' {
		t.Fatalf("uuid %q not a canonical v4 UUID", u)
	}
	if !validUUID(u) {
		t.Fatalf("newIdentity produced a uuid validUUID rejects: %q", u)
	}
	if !isHex16(w) {
		t.Fatalf("wwn %q is not 16 lowercase hex", w)
	}
	// wwn is the first 16 hex of the uuid (dashes stripped).
	if w != u[0:8]+u[9:13]+u[14:18] {
		t.Fatalf("wwn %q not derived from uuid %q", w, u)
	}
	// validUUID must reject path-traversal / non-canonical values.
	for _, bad := range []string{"..", "../../etc", "not-a-uuid", "", u + "x"} {
		if validUUID(bad) {
			t.Fatalf("validUUID accepted bad uuid %q", bad)
		}
	}
}

func isHex16(s string) bool {
	if len(s) != 16 {
		return false
	}
	for i := range 16 {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func TestCreateGetListDelete(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Create(1<<20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if a.State != Ready || a.Capacity != 1<<20 {
		t.Fatalf("bad volume: %+v", a)
	}
	if fi, err := os.Stat(s.DiskPath(a.UUID)); err != nil || fi.Size() != 1<<20 {
		t.Fatalf("disk file wrong: %v size=%v", err, fi)
	}
	b, _ := s.Create(2<<20, 0)
	if got := s.List(); len(got) != 2 {
		t.Fatalf("List = %d; want 2", len(got))
	}
	if _, ok := s.Get(a.UUID); !ok {
		t.Fatal("Get(a) missing")
	}
	if err := s.Delete(a.UUID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get(a.UUID); ok {
		t.Fatal("Get(a) present after delete")
	}
	if _, err := os.Stat(s.volDir(a.UUID)); !os.IsNotExist(err) {
		t.Fatal("a dir should be gone")
	}
	if _, ok := s.Get(b.UUID); !ok {
		t.Fatal("b should remain")
	}
}

func TestResizeGrowOnly(t *testing.T) {
	s, _ := Open(t.TempDir())
	v, _ := s.Create(1<<20, 0)
	if _, err := s.Resize(v.UUID, 4<<20); err != nil {
		t.Fatalf("grow: %v", err)
	}
	if got, _ := s.Get(v.UUID); got.Capacity != 4<<20 {
		t.Fatalf("capacity = %d; want %d", got.Capacity, 4<<20)
	}
	if fi, _ := os.Stat(s.DiskPath(v.UUID)); fi.Size() != 4<<20 {
		t.Fatalf("file size = %d; want %d", fi.Size(), 4<<20)
	}
	if _, err := s.Resize(v.UUID, 1<<20); err == nil {
		t.Fatal("shrink should be rejected")
	}
}

func TestPersistReload(t *testing.T) {
	root := t.TempDir()
	s, _ := Open(root)
	v, _ := s.Create(1<<20, 0)
	s2, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Get(v.UUID)
	if !ok || got.WWN != v.WWN {
		t.Fatalf("reload lost volume: %+v ok=%v", got, ok)
	}
}

func TestRepair(t *testing.T) {
	root := t.TempDir()
	s, _ := Open(root)
	good, _ := s.Create(1<<20, 0)
	short, _ := s.Create(4<<20, 0)

	// Corrupt: truncate `short`'s file below capacity; add an unrecorded
	// volume dir (quarantined, not deleted) and a staging dir (removed).
	if err := os.Truncate(s.DiskPath(short.UUID), 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(s.volsDir(), "orphan-xyz"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.volsDir(), "orphan-xyz", "disk"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(s.volsDir(), ".staging-abc"), 0o755); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(root) // triggers repair
	if err != nil {
		t.Fatal(err)
	}
	if g, _ := s2.Get(good.UUID); g.State != Ready {
		t.Errorf("good volume state = %s; want ready", g.State)
	}
	if sh, _ := s2.Get(short.UUID); sh.State != Failed {
		t.Errorf("short volume state = %s; want failed", sh.State)
	}
	if _, err := os.Stat(filepath.Join(s2.volsDir(), "orphan-xyz")); !os.IsNotExist(err) {
		t.Error("unrecorded dir should have been moved out of the volume namespace")
	}
	q := s2.Quarantined()
	if len(q) != 1 || !strings.HasSuffix(q[0], "-orphan-xyz") {
		t.Fatalf("Quarantined() = %v, want the unrecorded dir named", q)
	}
	// The point of quarantine: the DATA is still there. An unrecorded dir is
	// indistinguishable from a live volume that a restored db predates, so
	// startup must not destroy it.
	payload, err := os.ReadFile(filepath.Join(s2.volsDir(), q[0], "disk"))
	if err != nil || string(payload) != "payload" {
		t.Errorf("quarantined data must survive intact, got %q err %v", payload, err)
	}
	if _, err := os.Stat(filepath.Join(s2.volsDir(), ".staging-abc")); !os.IsNotExist(err) {
		t.Error("staging dir should have been removed")
	}

	// A second Open must not re-quarantine (which would nest the prefix) and
	// must still report it.
	s3, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := s3.Quarantined(); len(got) != 1 || got[0] != q[0] {
		t.Errorf("Quarantined() after reopen = %v, want the same single entry %v", got, q)
	}
}

// TestMissingDbRefusesToStart is the regression for the catastrophic
// data-loss bug: a lost/deleted volumes.json with volume dirs present must
// make Open FAIL (fail closed), never wipe the backing files as "orphans".
func TestMissingDbRefusesToStart(t *testing.T) {
	root := t.TempDir()
	s, _ := Open(root)
	v, _ := s.Create(1<<20, 0)
	disk := s.DiskPath(v.UUID)

	if err := os.Remove(filepath.Join(root, "volumes.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); err == nil {
		t.Fatal("Open with a missing db + existing volume dirs should refuse to start")
	}
	if _, err := os.Stat(disk); err != nil {
		t.Fatalf("backing file must be preserved after a refused start, got: %v", err)
	}
}

// TestMissingDbEmptyStoreIsFirstBoot: a missing db with NO volume dirs is a
// normal first boot and must succeed.
func TestMissingDbEmptyStoreIsFirstBoot(t *testing.T) {
	if _, err := Open(t.TempDir()); err != nil {
		t.Fatalf("fresh empty store should open cleanly: %v", err)
	}
}

// TestLoadRejectsBadRecordsButKeepsServing: an individually malformed record
// is excluded from the live set, and every OTHER volume still loads.
//
// This is the load contract's blast radius. Failing the whole Open used to
// mean one bad row took the appliance down: MEASURED on the lab, one bad
// record of three left the kernel with zero targets and zero backstores after
// a reboot, while applianced restarted every 2s with no REST left to say why.
// The two healthy volumes were lost to a problem neither of them had.
//
// Every fixture carries exactly ONE defect and an otherwise valid capacity.
// An earlier version used capacity:1 throughout, which is itself invalid --
// so the duplicate-WWN case was rejected as two malformed records and never
// reached the duplicate check it existed to test.
func TestLoadRejectsBadRecordsButKeepsServing(t *testing.T) {
	const goodUUID = "33333333-3333-4333-8333-333333333333"
	good := `{"uuid":"` + goodUUID + `","wwn":"00000000000000ff","capacity":1048576,"state":"ready","block_size":512}`

	for name, bad := range map[string]string{
		"null-record":    `null`,
		"traversal-uuid": `{"uuid":"..","wwn":"0000000000000000","capacity":1048576,"state":"ready"}`,
		"bad-uuid":       `{"uuid":"not-a-uuid","wwn":"0000000000000000","capacity":1048576,"state":"ready"}`,
		"bad-wwn":        `{"uuid":"11111111-1111-4111-8111-111111111111","wwn":"nothex","capacity":1048576,"state":"ready"}`,
		"zero-capacity":  `{"uuid":"11111111-1111-4111-8111-111111111111","wwn":"0000000000000000","capacity":0,"state":"ready"}`,
		"unknown-state":  `{"uuid":"11111111-1111-4111-8111-111111111111","wwn":"0000000000000000","capacity":1048576,"state":"weird"}`,
		"sub-block-size": `{"uuid":"11111111-1111-4111-8111-111111111111","wwn":"0000000000000000","capacity":100,"state":"ready","block_size":512}`,
		"bad-parent":     `{"uuid":"11111111-1111-4111-8111-111111111111","wwn":"0000000000000000","capacity":1048576,"state":"ready","parent":"nope"}`,
		"not-an-object":  `42`,
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "volumes"), 0o755); err != nil {
				t.Fatal(err)
			}
			db := "[" + bad + "," + good + "]"
			if err := os.WriteFile(filepath.Join(root, "volumes.json"), []byte(db), 0o644); err != nil {
				t.Fatal(err)
			}
			s, err := Open(root)
			if err != nil {
				t.Fatalf("one malformed record must not take the store down: %v", err)
			}
			if _, ok := s.vols[goodUUID]; !ok {
				t.Error("the healthy volume must still load; it has no defect of its own")
			}
			if len(s.vols) != 1 {
				t.Errorf("the malformed record must be excluded from the live set, got %d volumes", len(s.vols))
			}
			rej := s.RejectedRecords()
			if len(rej) != 1 {
				t.Fatalf("the malformed record must be REPORTED, got %d rejected", len(rej))
			}
			if rej[0].Reason == "" {
				t.Error("a rejected record must carry a reason an operator can act on")
			}
		})
	}
}

// TestLoadFailsClosedOnCrossRecordConflicts: a conflict BETWEEN records still
// takes the store down, because there is no "the bad one" to drop.
//
// A shared WWN is the dangerous case: it becomes the SCSI WWID, so two
// volumes with one identity are coalesced by multipath and writes can land on
// the wrong volume. Honouring either record risks exactly the corruption the
// check exists to prevent, so neither is honoured.
func TestLoadFailsClosedOnCrossRecordConflicts(t *testing.T) {
	for name, db := range map[string]string{
		"duplicate-wwn": `[{"uuid":"11111111-1111-4111-8111-111111111111","wwn":"0000000000000000","capacity":1048576,"state":"ready"},
		                   {"uuid":"22222222-2222-4222-8222-222222222222","wwn":"0000000000000000","capacity":1048576,"state":"ready"}]`,
		"duplicate-uuid": `[{"uuid":"11111111-1111-4111-8111-111111111111","wwn":"00000000000000aa","capacity":1048576,"state":"ready"},
		                    {"uuid":"11111111-1111-4111-8111-111111111111","wwn":"00000000000000bb","capacity":1048576,"state":"ready"}]`,
		"unparseable-file": `{not json at all`,
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "volumes"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "volumes.json"), []byte(db), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(root); err == nil {
				t.Fatalf("Open must fail closed on %s", name)
			}
		})
	}
}

// TestReturnedVolumeIsCopy: mutating a returned Volume must not corrupt the
// store's internal record.
func TestReturnedVolumeIsCopy(t *testing.T) {
	s, _ := Open(t.TempDir())
	v, _ := s.Create(1<<20, 0)
	v.UUID = "hacked"
	v.Capacity = 999
	got, ok := s.Get(mustFirstUUID(t, s))
	if !ok || got.Capacity != 1<<20 {
		t.Fatalf("internal record was mutated via the returned pointer: %+v", got)
	}
}

func mustFirstUUID(t *testing.T, s *Store) string {
	t.Helper()
	l := s.List()
	if len(l) != 1 {
		t.Fatalf("want 1 volume, got %d", len(l))
	}
	return l[0].UUID
}

// TestRejectedRecordSurvivesLaterMutation is the test that keeps this feature
// from being a worse bug than the one it fixes.
//
// persist serialises the LIVE volume map. A rejected record is deliberately
// absent from that map, so without explicit re-emission the next ordinary
// Create or Delete rewrites volumes.json WITHOUT it -- silently destroying
// the operator's only copy of the record, and orphaning its directory. That
// turns a loud, recoverable startup failure into quiet data loss.
func TestRejectedRecordSurvivesLaterMutation(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "volumes"), 0o755); err != nil {
		t.Fatal(err)
	}
	const badUUID = "11111111-1111-4111-8111-111111111111"
	bad := `{"uuid":"` + badUUID + `","wwn":"0000000000000000","capacity":100,"state":"ready","block_size":512}`
	if err := os.WriteFile(filepath.Join(root, "volumes.json"), []byte("["+bad+"]"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.RejectedRecords()) != 1 {
		t.Fatalf("setup: expected the record to be rejected, got %d", len(s.RejectedRecords()))
	}

	// Any ordinary mutation rewrites the db.
	if _, err := s.Create(1<<20, 0); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(root, "volumes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), badUUID) {
		t.Fatalf("the rejected record was erased by an unrelated mutation. Rejecting a "+
			"record must cost that volume's availability, never the record itself:\n%s", data)
	}

	// And it must still be rejected -- not silently resurrected -- on reload.
	s2, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.RejectedRecords()) != 1 {
		t.Errorf("the record must still be rejected after a round-trip, got %d", len(s2.RejectedRecords()))
	}
	if len(s2.vols) != 1 {
		t.Errorf("the newly created volume must load, got %d live volumes", len(s2.vols))
	}
}

// TestRejectedRecordDirIsNotQuarantined: repair sets aside volume dirs with no
// record, but a rejected record IS in the db -- just not in the live set.
// Renaming its directory would undo the operator's fix: they correct the
// record, restart, and find the data under a quarantine name with the volume
// marked Failed.
func TestRejectedRecordDirIsNotQuarantined(t *testing.T) {
	root := t.TempDir()
	const badUUID = "11111111-1111-4111-8111-111111111111"
	if err := os.MkdirAll(filepath.Join(root, "volumes", badUUID), 0o755); err != nil {
		t.Fatal(err)
	}
	bad := `{"uuid":"` + badUUID + `","wwn":"0000000000000000","capacity":100,"state":"ready","block_size":512}`
	if err := os.WriteFile(filepath.Join(root, "volumes.json"), []byte("["+bad+"]"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if q := s.Quarantined(); len(q) != 0 {
		t.Errorf("a rejected record's directory must be left where the record points, got %v", q)
	}
	if _, err := os.Stat(filepath.Join(root, "volumes", badUUID)); err != nil {
		t.Errorf("the directory must still be at its original name: %v", err)
	}
}

// TestSnapshotDoesNotDestroyDataOnANonDurablePersist pins the contract
// ErrPersistedNotDurable documents: "Callers must NOT roll back in-memory
// state on this error."
//
// persist renames the db into place and only THEN fsyncs the directory, so by
// the time it reports this the db already names the snapshot. Snapshot used to
// roll back anyway -- dropping it from memory and RemoveAll'ing the reflinked
// disk -- so the next Open found a record whose data was gone and marked the
// volume Failed. Create and Delete already honoured the contract.
//
// The trigger is narrow (rename succeeded, directory fsync failed), so this
// asserts the CODE PATH rather than trying to make fsync fail: whatever
// Snapshot does on this error, it must not be to delete the volume.
func TestSnapshotDoesNotDestroyDataOnANonDurablePersist(t *testing.T) {
	// Snapshot is reflink-backed, so this needs a filesystem that supports
	// FICLONE. The package convention is GLITR_REFLINK_DIR (see
	// TestSnapshotReflink): the usual tmpdir is ext4 or overlayfs and cannot
	// do it. CI proved that by failing here while the same test passed on the
	// machine that wrote it, whose tmpdir happened to be capable -- a test
	// that silently depends on the filesystem underneath it is not portable,
	// and the one that wrote it is the last place that shows up.
	dir := os.Getenv("GLITR_REFLINK_DIR")
	if dir == "" {
		t.Skip("set GLITR_REFLINK_DIR to a reflink-capable dir (XFS/btrfs) to run")
	}
	root, err := os.MkdirTemp(dir, "store-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	src, err := s.Create(1<<20, 0)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot(src.UUID)
	if err != nil && !errors.Is(err, ErrPersistedNotDurable) {
		t.Fatal(err)
	}
	// Whether or not the fsync succeeded, the snapshot must exist in memory
	// and on disk -- the failure mode being pinned is a snapshot that the db
	// names but whose bytes were deleted.
	if snap == nil {
		t.Fatal("Snapshot returned no volume")
	}
	if _, err := os.Stat(s.DiskPath(snap.UUID)); err != nil {
		t.Errorf("the snapshot's backing file is missing: %v", err)
	}

	// And it survives a reopen, which is what a rollback would have broken.
	s2, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Get(snap.UUID)
	if !ok {
		t.Fatal("the snapshot did not survive a reopen")
	}
	if got.State == Failed {
		t.Error("the snapshot reopened as Failed -- its record outlived its data")
	}
}
