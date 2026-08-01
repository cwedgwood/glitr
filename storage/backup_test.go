package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func backupsOf(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "volumes.json.bak.") {
			out = append(out, e.Name())
		}
	}
	return out
}

// TestBackupHoldsThePreWriteContents is the property the whole mechanism
// exists for: after a mutation, the backup must contain what the db held
// BEFORE it, not after.
//
// This is what makes a hard link the right primitive rather than a copy. The
// db is replaced by rename(2), which swaps the directory entry and leaves the
// inode alone, so the link still names the old inode with the old bytes. A
// copy would have to read a file that is about to be overwritten.
func TestBackupHoldsThePreWriteContents(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.Create(1<<20, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Create(1<<20, 0)
	if err != nil {
		t.Fatal(err)
	}

	baks := backupsOf(t, root)
	if len(baks) == 0 {
		t.Fatal("no backup was written")
	}
	// The newest backup was linked just before the second Create's write, so
	// it must hold exactly one volume: the first.
	newest, err := latestBackup(filepath.Join(root, "volumes.json"))
	if err != nil || newest == "" {
		t.Fatalf("latestBackup: %q %v", newest, err)
	}
	data, err := os.ReadFile(newest)
	if err != nil {
		t.Fatal(err)
	}
	var recs []Volume
	if err := json.Unmarshal(data, &recs); err != nil {
		t.Fatalf("backup is not valid JSON -- a torn copy would look like this: %v", err)
	}
	if len(recs) != 1 || recs[0].UUID != first.UUID {
		t.Errorf("backup holds %d record(s), want exactly the pre-write state (%s)",
			len(recs), first.UUID)
	}

	// And the live db has both -- the backup is not a substitute for it.
	live, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := live.Get(second.UUID); !ok {
		t.Error("the live db must hold the newest write")
	}
}

// TestBackupRotation: backups are bounded, and it is the OLDEST that go.
func TestBackupRotation(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	for range dbBackupsKept + 5 {
		if _, err := s.Create(1<<20, 0); err != nil {
			t.Fatal(err)
		}
	}
	baks := backupsOf(t, root)
	if len(baks) > dbBackupsKept {
		t.Errorf("%d backups retained, want at most %d", len(baks), dbBackupsKept)
	}
	// Lexical order is chronological (fixed-width timestamp), so the retained
	// set must be a contiguous newest-N.
	newest, err := latestBackup(filepath.Join(root, "volumes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(newest) != baks[len(baks)-1] {
		t.Errorf("latestBackup returned %s, want the lexically greatest %s",
			filepath.Base(newest), baks[len(baks)-1])
	}
}

// TestFirstWriteNeedsNoBackup: there is nothing to preserve before the db
// exists, and that must not be an error.
func TestFirstWriteNeedsNoBackup(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(1<<20, 0); err != nil {
		t.Fatalf("the first write must succeed with no db to back up: %v", err)
	}
	if err := s.BackupErr(); err != nil {
		t.Errorf("a missing source is not a backup failure, got %v", err)
	}
	if n := len(backupsOf(t, root)); n != 0 {
		t.Errorf("%d backups after the first write, want 0", n)
	}
}

// TestBackupFailureDoesNotFailTheMutation: a recovery convenience must never
// cost a real operation -- but it must be reported, because the documented
// recovery for a lost db is "restore a backup".
func TestBackupFailureDoesNotFailTheMutation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs to run unprivileged: the failure is injected via directory mode")
	}
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(1<<20, 0); err != nil { // creates the db
		t.Fatal(err)
	}
	// Injected directly rather than by breaking the filesystem: an unwritable
	// directory would block the rename too, so it would test the write path
	// rather than the backup path.
	s.bakMu.Lock()
	s.backupErr = os.ErrPermission
	s.bakMu.Unlock()

	if _, err := s.Create(1<<20, 0); err != nil {
		t.Errorf("a backup problem must not fail a volume operation: %v", err)
	}
	if s.BackupErr() == nil {
		t.Error("a backup failure must remain reportable")
	}
}

// TestRecoveryFromBackup is the end-to-end story the mechanism exists for: a
// lost db, a refusal to start that NAMES the backup, and a successful restore.
//
// The refusal is deliberate -- treating every backing file as an orphan and
// deleting it would be far worse -- but it is only humane if there is
// something to restore from and the operator is told where it is, at what is
// by definition a bad moment.
func TestRecoveryFromBackup(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Create(1<<20, 0)
	if err != nil {
		t.Fatal(err)
	}
	// b is created AFTER the newest backup was linked, so no backup can ever
	// contain it. That is not an edge case: every backup is written BEFORE
	// the mutation it protects, so the newest is always at least one volume
	// behind the directories on disk. Any volume in that gap is what repair
	// used to delete.
	b, err := s.Create(1<<20, 0) // this write links a backup holding only a
	if err != nil {
		t.Fatal(err)
	}

	db := filepath.Join(root, "volumes.json")
	if err := os.Remove(db); err != nil {
		t.Fatal(err)
	}

	_, err = Open(root)
	if err == nil {
		t.Fatal("a missing db with live volume dirs must refuse to start rather than " +
			"treat the backing files as orphans and delete them")
	}
	if !strings.Contains(err.Error(), ".bak.") {
		t.Errorf("the refusal must name the backup to restore, got: %v", err)
	}

	// Restore, exactly as the message instructs.
	bak, err := latestBackup(db)
	if err != nil || bak == "" {
		t.Fatalf("latestBackup: %q %v", bak, err)
	}
	data, err := os.ReadFile(bak)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(db, data, 0o600); err != nil {
		t.Fatal(err)
	}

	restored, err := Open(root)
	if err != nil {
		t.Fatalf("the store must open from a restored backup: %v", err)
	}
	if _, ok := restored.Get(a.UUID); !ok {
		t.Error("the restored db must hold the volume the backup captured")
	}

	// The part this test used to miss. It set up the data loss exactly and
	// then asserted only that `a` survived, so it passed while demonstrating
	// the bug: b post-dates the restored db, looks like an orphan, and was
	// RemoveAll'd -- destroying live backing data at the one moment the
	// operator was already recovering from losing the record db.
	if _, ok := restored.Get(b.UUID); ok {
		t.Fatal("the restored db predates b, so it cannot know about it -- " +
			"check the fixture, not the code")
	}
	q := restored.Quarantined()
	if len(q) != 1 || !strings.HasSuffix(q[0], "-"+b.UUID) {
		t.Fatalf("Quarantined() = %v, want b (%s) set aside", q, b.UUID)
	}
	disk := filepath.Join(root, "volumes", q[0], "disk")
	if _, err := os.Stat(disk); err != nil {
		t.Errorf("b's backing data must survive recovery, not be deleted as an orphan: %v", err)
	}
}
