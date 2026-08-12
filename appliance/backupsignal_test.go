package appliance

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBackupSignalClearsWhenBackupsRecover.
//
// db_backup_failing exists to tell an operator that the documented "restore a
// backup" recovery has quietly stopped being possible. Its whole value is
// describing the posture RIGHT NOW, so it has to clear when the cause is
// fixed. Recording only failures made it survive for the life of the process:
// an operator who freed space still saw "backups are failing" until a restart,
// and a stale alarm on a resolved condition is how a real one gets ignored.
//
// The failure is SEEDED here on purpose, and narrowly: this test is only about
// whether a SUCCESSFUL backup clears a remembered failure, which is the branch
// that regressed. Seeding removes every other variable from that question.
//
// It is NOT seeded because a real failure cannot be induced -- an earlier
// version of this comment claimed that, and it was wrong.
// TestBackupSignalRecordsARealLinkFailure induces one with NAME_MAX and covers
// the recording path end to end.
func TestBackupSignalClearsWhenBackupsRecover(t *testing.T) {
	c := bareCoordinator(t)

	// A remembered failure, as a previous persist would have left it.
	c.healthMu.Lock()
	c.backupErr = errors.New("link /db.bak: no space left on device")
	c.healthMu.Unlock()

	if c.HealthSnapshot().BackupErr == "" {
		t.Fatal("the fixture did not take; this cannot test anything")
	}

	// A persist whose backup succeeds must clear it.
	if err := c.persist(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if got := c.HealthSnapshot().BackupErr; got != "" {
		t.Errorf("backups recovered but /health still reports them failing (%q); "+
			"the signal describes the CURRENT posture, so a resolved condition "+
			"must not persist until a restart", got)
	}
}

// TestBackupSignalRecordsARealLinkFailure induces a failure in the BACKUP
// alone, leaving the database write itself intact.
//
// That is the shape the signal describes -- "the record database is being
// written, but no backup of it is" -- and it is worth inducing rather than
// seeding, because a seeded counter-test proves only that HealthSnapshot
// returns what was put into it. The first version of this test did exactly
// that and would have passed even if persist had stopped recording failures
// altogether.
//
// The lever is NAME_MAX, not permissions. linkBackup appends a 31-byte suffix
// (".bak." plus a nanosecond timestamp), so a 225-byte database basename makes
// the link target 256 bytes and link(2) fails with ENAMETOOLONG -- while the
// temp file, at basename + ".tmp" = 229 bytes, is still writable and the
// rename still succeeds. Permissions cannot separate the two: the temp file
// and the link live in the same directory.
func TestBackupSignalRecordsARealLinkFailure(t *testing.T) {
	c := bareCoordinator(t)
	dir := filepath.Dir(c.dbPath)
	c.dbPath = filepath.Join(dir, strings.Repeat("d", 225))

	// First persist: nothing to link yet, so this must be clean.
	if err := c.persist(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if got := c.HealthSnapshot().BackupErr; got != "" {
		t.Fatalf("a first write has nothing to back up and must not report a "+
			"failure, got %q", got)
	}

	// Second persist: the database now exists, so linkBackup runs -- and the
	// link target is one byte over NAME_MAX.
	if err := c.persist(context.Background(), nil); err != nil {
		t.Fatalf("a failing BACKUP must not fail the persist: the backup is a "+
			"recovery convenience, and refusing the write would turn tidy-up "+
			"into an outage: %v", err)
	}
	got := c.HealthSnapshot().BackupErr
	if got == "" {
		t.Fatal("a backup that could not be written was not reported; this is the " +
			"one signal meant to be acted on before it matters")
	}
	if !strings.Contains(got, "file name too long") {
		t.Errorf("reported something other than the induced failure: %q", got)
	}

	// The database itself must still have been written -- otherwise this is
	// measuring a broken persist rather than a failing backup.
	if _, err := os.Stat(c.dbPath); err != nil {
		t.Errorf("the database was not written: %v", err)
	}

	// Now recover: a normal-length path makes the link fit, and the next
	// successful persist must clear the signal.
	c.dbPath = filepath.Join(dir, "appliance.json")
	if err := c.persist(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := c.persist(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if got := c.HealthSnapshot().BackupErr; got != "" {
		t.Errorf("backups recovered but /health still reports them failing (%q)", got)
	}
}

// TestHealthServesTheBackupSignal closes the wire contract from the server
// end.
//
// Issue #9 was precisely a key that existed on one side and not the other, and
// the client test hand-writes the JSON -- so on its own it proves the client
// parses a string the test author chose, not the one the appliance sends. This
// asserts the served body, through the real Handler, under the key the client
// decodes. It also pins the deliberate verdict: a failing backup leaves status
// "ok", which is exactly why the field has to be readable.
func TestHealthServesTheBackupSignal(t *testing.T) {
	c := bareCoordinator(t)
	c.healthMu.Lock()
	c.backupErr = errors.New("link /db.bak: no space left on device")
	c.healthMu.Unlock()

	srv := httptest.NewServer(Handler(c))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	got, _ := body["db_backup_failing"].(string)
	if got == "" {
		t.Fatalf("the served body carries no db_backup_failing; the client decodes "+
			"that exact key, and a mismatch is what issue #9 was: %v", body)
	}
	if !strings.Contains(got, "no space left") {
		t.Errorf("db_backup_failing = %q", got)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok -- a failing backup is deliberately not part "+
			"of the verdict, which is the whole reason the field must be readable",
			body["status"])
	}
}
