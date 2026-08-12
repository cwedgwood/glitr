package appliance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cwedgwood/glitr/applog"
	"github.com/cwedgwood/glitr/lio"
)

// Tests for the operation, reconcile and health events.
//
// Each asserts on a JSON stream from a logger the test owns, which is the same
// path a daemon takes -- Config.Logger with applog's handler -- rather than a
// bespoke recorder that could pass while the real wiring is broken.

// events captures records emitted to a logger under test.
type events struct {
	buf bytes.Buffer
	log *slog.Logger
}

func newEvents(t *testing.T) *events {
	t.Helper()
	e := &events{}
	l, _, err := applog.New(applog.Options{Format: "json", Level: "debug", Out: &e.buf})
	if err != nil {
		t.Fatal(err)
	}
	e.log = l
	return e
}

// find returns every record with the given event name.
func (e *events) find(t *testing.T, name string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(e.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("a record was not valid JSON: %v\n%s", err, line)
		}
		if m["event"] == name {
			out = append(out, m)
		}
	}
	return out
}

// one returns the single record with the given name, failing otherwise.
func (e *events) one(t *testing.T, name string) map[string]any {
	t.Helper()
	got := e.find(t, name)
	if len(got) != 1 {
		t.Fatalf("want exactly one %s event, got %d\nstream:\n%s", name, len(got), e.buf.String())
	}
	return got[0]
}

func (e *events) none(t *testing.T, name string) {
	t.Helper()
	if got := e.find(t, name); len(got) != 0 {
		t.Fatalf("want no %s event, got %d\nstream:\n%s", name, len(got), e.buf.String())
	}
}

func want(t *testing.T, m map[string]any, key string, val any) {
	t.Helper()
	if got, ok := m[key]; !ok {
		t.Errorf("field %q is absent; a consumer cannot branch on a field that is not there\nrecord: %v", key, m)
	} else if got != val {
		t.Errorf("field %q = %v (%T), want %v (%T)", key, got, got, val, val)
	}
}

func eventCoordinator(t *testing.T) (*Coordinator, *events) {
	t.Helper()
	e := newEvents(t)
	c := bareCoordinator(t)
	c.log = e.log
	return c, e
}

// TestCreateEmitsAnOperationEvent covers the ordinary success shape, including
// the three fields that exist to describe the commit/reconcile split.
//
// reconcile_outcome is "not-required" rather than reconciled=false alone: a
// create genuinely never reconciles, and a consumer that read the boolean by
// itself could not tell that steady state from a reconcile that failed.
func TestCreateEmitsAnOperationEvent(t *testing.T) {
	c, e := eventCoordinator(t)

	o, created, err := c.Create(context.Background(), KindVolume,
		CreateRequest{Name: "vol-1", Size: MinVolumeSize})
	if err != nil || !created {
		t.Fatalf("create: %v (created=%v)", err, created)
	}

	m := e.one(t, "volume.create")
	want(t, m, "outcome", outcomeSucceeded)
	want(t, m, "created", true)
	want(t, m, "durable", true)
	want(t, m, "durable_proven", true)
	want(t, m, "reconciled", false)
	want(t, m, "reconcile_outcome", reconcileNotRequired)
	want(t, m, "resource_name", "vol-1")
	want(t, m, "resource_id", o.UUID)
	want(t, m, "wwn", o.WWN)
	want(t, m, "service", "applianced")
	if _, ok := m["error"]; ok {
		t.Errorf("a successful create carried an error field: %v", m)
	}
}

// TestASnapshotReportsItsOwnEvent. The two kinds share an implementation, and
// flattening them into one event name would make a consumer parse a field to
// learn what happened.
//
// Deliberately creates the snapshot with NO source, so it needs no reflink and
// runs everywhere. The claim under test is that the event name follows the
// kind; making it depend on FICLONE would mean this passed locally and was
// skipped on the CI that actually gates the merge -- which is the same as not
// asserting it.
func TestASnapshotReportsItsOwnEvent(t *testing.T) {
	c, e := eventCoordinator(t)

	if _, _, err := c.Create(context.Background(), KindVolume,
		CreateRequest{Name: "vol-1", Size: MinVolumeSize}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Create(context.Background(), KindSnapshot,
		CreateRequest{Name: "snap", Size: MinVolumeSize}); err != nil {
		t.Fatal(err)
	}

	want(t, e.one(t, "snapshot.create"), "resource_name", "snap")
	want(t, e.one(t, "volume.create"), "resource_name", "vol-1")
}

// TestACloneNamesItsSource covers the provenance fields, which only a real
// copy produces.
//
// This one genuinely needs a reflink filesystem, so it skips where there is
// none -- CI runs on ext4. Kept separate from the test above precisely so that
// skip costs only the provenance assertions and not the event-naming claim.
func TestACloneNamesItsSource(t *testing.T) {
	c, e := eventCoordinator(t)

	src, _, err := c.Create(context.Background(), KindVolume,
		CreateRequest{Name: "src", Size: MinVolumeSize})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Create(context.Background(), KindSnapshot,
		CreateRequest{Name: "snap", Source: "src", SourceKind: KindVolume}); err != nil {
		t.Skipf("a clone needs a reflink filesystem: %v", err)
	}

	m := e.one(t, "snapshot.create")
	want(t, m, "source_name", "src")
	want(t, m, "source_kind", string(KindVolume))
	// The uuid too: a source can be renamed, or deleted, after the copy is
	// made, and then the name in this record resolves to nothing or to
	// something else.
	want(t, m, "source_id", src.UUID)
}

// TestAdoptionIsNotACreation. created=false is the same distinction the
// 200-vs-201 status carries, and it is what a controller replaying an
// uncertain request needs.
func TestAdoptionIsNotACreation(t *testing.T) {
	c, e := eventCoordinator(t)
	req := CreateRequest{Name: "vol-1", Size: MinVolumeSize}

	if _, _, err := c.Create(context.Background(), KindVolume, req); err != nil {
		t.Fatal(err)
	}
	o, created, err := c.Create(context.Background(), KindVolume, req)
	if err != nil || created {
		t.Fatalf("the replay should have adopted: created=%v err=%v", created, err)
	}

	got := e.find(t, "volume.create")
	if len(got) != 2 {
		t.Fatalf("want two create events, got %d", len(got))
	}
	want(t, got[0], "created", true)
	want(t, got[1], "created", false)
	// The adoption still identifies what it returned, or a caller learns
	// nothing from the event it most needs to read.
	want(t, got[1], "resource_id", o.UUID)
	want(t, got[1], "outcome", outcomeSucceeded)
}

// TestARefusedRequestIsLoggedAtInfoWithItsCode.
//
// A 4xx is the caller's request being refused and is already visible in
// rest.access; logging it at error would flood the stream an operator watches
// for the appliance's own problems. The machine-readable code is what makes
// the record actionable without parsing prose.
func TestARefusedRequestIsLoggedAtInfoWithItsCode(t *testing.T) {
	c, e := eventCoordinator(t)

	_, _, err := c.Create(context.Background(), KindVolume,
		CreateRequest{Name: "vol-1", Size: 1})
	if err == nil {
		t.Fatal("a size below the minimum should have been refused")
	}

	m := e.one(t, "volume.create")
	want(t, m, "outcome", outcomeFailed)
	want(t, m, "durable", false)
	want(t, m, "error_code", CodeInvalidInput)
	want(t, m, "level", "INFO")
}

// TestAnAppliancesOwnFailureIsLoggedAtError, in contrast: a 5xx, or an error
// carrying no status at all, is the appliance's problem.
func TestAnAppliancesOwnFailureIsLoggedAtError(t *testing.T) {
	c, e := eventCoordinator(t)
	// No database path: persist refuses rather than writing relative to the
	// process's working directory.
	c.dbPath = ""

	if _, _, err := c.Create(context.Background(), KindVolume,
		CreateRequest{Name: "vol-1", Size: MinVolumeSize}); err == nil {
		t.Fatal("a create with no db path should have failed")
	}

	m := e.one(t, "volume.create")
	want(t, m, "outcome", outcomeFailed)
	want(t, m, "level", "ERROR")
	want(t, m, "error_code", CodeInternal)
}

// TestTheRequestIDReachesTheOperationEvent. Correlation is the whole point of
// phase 1; an operation event that cannot be joined to the request that caused
// it leaves a consumer no better off.
func TestTheRequestIDReachesTheOperationEvent(t *testing.T) {
	c, e := eventCoordinator(t)
	ctx := applog.WithRequestID(context.Background(), "abc123")

	if _, _, err := c.Create(ctx, KindVolume,
		CreateRequest{Name: "vol-1", Size: MinVolumeSize}); err != nil {
		t.Fatal(err)
	}
	want(t, e.one(t, "volume.create"), "request_id", "abc123")
}

// TestRenameNamesBothNames. An event about two names must say which is which:
// a polymorphic "name" would make a consumer know the verb before it could
// read the record.
func TestRenameNamesBothNames(t *testing.T) {
	c, e := eventCoordinator(t)
	if _, _, err := c.Create(context.Background(), KindVolume,
		CreateRequest{Name: "before", Size: MinVolumeSize}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Rename(context.Background(), KindVolume, "before", "after"); err != nil {
		t.Fatal(err)
	}

	m := e.one(t, "volume.rename")
	want(t, m, "old_name", "before")
	want(t, m, "new_name", "after")
	want(t, m, "outcome", outcomeSucceeded)
}

// TestBackupPostureIsEdgeTriggered.
//
// A backup is attempted on every mutation, so a record per success would
// drown the stream in the case where nothing is wrong. Both edges are logged
// and the steady state is silent.
func TestBackupPostureIsEdgeTriggered(t *testing.T) {
	c, e := eventCoordinator(t)

	// Steady state: a persist whose backup works says nothing.
	if err := c.persist(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	e.none(t, eventBackupFailed)
	e.none(t, eventBackupRecovered)

	// A remembered failure, as a previous persist would have left it, then a
	// persist that succeeds: the falling edge.
	c.healthMu.Lock()
	c.backupErr = errors.New("link /db.bak: no space left on device")
	c.healthMu.Unlock()
	if err := c.persist(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	e.one(t, eventBackupRecovered)
	e.none(t, eventBackupFailed)
}

// TestReconcileReportsBothEdges.
//
// The falling edge is the one that justifies the event: without it the log's
// last word on a resolved outage is still the failure, and an operator reading
// back cannot see that it ended.
func TestReconcileReportsBothEdges(t *testing.T) {
	c, e := eventCoordinator(t)
	boom := errors.New("configfs is unreachable")

	// Rise.
	c.setReconcileErr(context.Background(), boom, "full", lio.Report{Changes: []string{"a", "b"}})
	m := e.one(t, eventReconcileFailed)
	want(t, m, "level", "ERROR")
	// ApplyDelta is fail-stop and not transactional, so how far it got is a
	// fact about the kernel, not a statistic.
	want(t, m, "changes_applied", float64(2))

	// Still broken: no second record. A wedged kernel must not become a log
	// flood, and the condition is already standing in /health.
	c.setReconcileErr(context.Background(), boom, "full", lio.Report{})
	if got := e.find(t, eventReconcileFailed); len(got) != 1 {
		t.Errorf("a repeated failure logged again (%d records); the edge is the event", len(got))
	}

	// Fall.
	c.setReconcileOK(context.Background(), "full", lio.Report{}, nil, nil, nil, nil)
	if got := e.find(t, eventReconcileRecovered); len(got) != 1 {
		t.Fatalf("want one recovery record, got %d\n%s", len(got), e.buf.String())
	}
}

// TestReconcileFailureCarriesTheKernelErrorAsFields.
//
// Unwrapped at the coordinator boundary, deliberately not by logging inside
// lio: that package is silent by design.
func TestReconcileFailureCarriesTheKernelErrorAsFields(t *testing.T) {
	c, e := eventCoordinator(t)

	c.setReconcileErr(context.Background(), &lio.Error{
		Kind: lio.KindKernelRejected, Op: "apply", Obj: "backstore/fileio/vol-1",
		Err: errors.New("device busy"),
	}, "full", lio.Report{})

	m := e.one(t, eventReconcileFailed)
	want(t, m, "error_kind", lio.KindKernelRejected.String())
	want(t, m, "error_op", "apply")
	want(t, m, "error_object", "backstore/fileio/vol-1")
}

// TestHealthTransitionsReportBothDirections, and name what changed.
func TestHealthTransitionsReportBothDirections(t *testing.T) {
	c, e := eventCoordinator(t)

	// Establish a baseline; the first observation is not a transition.
	c.noteHealth(context.Background())
	e.none(t, eventHealthChanged)

	// A fencing warning arrives.
	c.publishReconcile(context.Background(), nil, []string{"vol-1: not in effect"}, nil, nil, nil)
	m := e.one(t, eventHealthChanged)
	want(t, m, "from", healthOK)
	want(t, m, "to", healthWarning)
	want(t, m, "level", "WARN")
	added, _ := m["fields_added"].([]any)
	if len(added) != 1 || added[0] != "pr_unbound" {
		t.Errorf("fields_added = %v, want [pr_unbound]", m["fields_added"])
	}

	// And clears.
	c.publishReconcile(context.Background(), nil, nil, nil, nil, nil)
	got := e.find(t, eventHealthChanged)
	if len(got) != 2 {
		t.Fatalf("want two transitions, got %d\n%s", len(got), e.buf.String())
	}
	want(t, got[1], "to", healthOK)
	want(t, got[1], "level", "INFO")
	cleared, _ := got[1]["fields_cleared"].([]any)
	if len(cleared) != 1 || cleared[0] != "pr_unbound" {
		t.Errorf("fields_cleared = %v, want [pr_unbound]", got[1]["fields_cleared"])
	}
}

// TestAConditionThatDoesNotChangeTheVerdictStillReportsItsEdges.
//
// db_backup_failing and attribute_drift never move the status, so without this
// the only way to notice one is to be polling when it happens.
func TestAConditionThatDoesNotChangeTheVerdictStillReportsItsEdges(t *testing.T) {
	c, e := eventCoordinator(t)
	c.noteHealth(context.Background())

	c.healthMu.Lock()
	c.backupErr = errors.New("no space left on device")
	c.healthMu.Unlock()
	c.noteHealth(context.Background())

	m := e.one(t, eventHealthChanged)
	want(t, m, "from", healthOK)
	want(t, m, "to", healthOK)
	added, _ := m["fields_added"].([]any)
	if len(added) != 1 || added[0] != "db_backup_failing" {
		t.Fatalf("fields_added = %v, want [db_backup_failing]", m["fields_added"])
	}
}

// TestAnUnchangedHealthSaysNothing. Edge-triggered means edge-triggered: this
// is called from every publish path, several of which run per reconcile.
func TestAnUnchangedHealthSaysNothing(t *testing.T) {
	c, e := eventCoordinator(t)
	for range 5 {
		c.noteHealth(context.Background())
	}
	e.none(t, eventHealthChanged)
}

// TestHealthStatusMatchesWhatHealthServes pins the two together.
//
// The verdict used to live only in the /health handler. A second copy for the
// transition event would eventually disagree, and the disagreement would be
// invisible: the log would announce a recovery for an appliance still serving
// "warning". Status is now the single rule, and this checks each branch of it.
func TestHealthStatusMatchesWhatHealthServes(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    Health
		want string
	}{
		{"empty", Health{}, healthOK},
		{"degraded wins", Health{Degraded: true, PRUnbound: []string{"x"}}, healthDegraded},
		{"unbound warns", Health{PRUnbound: []string{"x"}}, healthWarning},
		{"stranded warns", Health{PRStranded: []string{"x"}}, healthWarning},
		{"withheld warns", Health{Withheld: []string{"x"}}, healthWarning},
		{"clearing warns", Health{ClearInProgress: "vol-1"}, healthWarning},
		// Deliberately NOT a warning: it says the appliance cannot answer the
		// strand question, which is normal under multipath.
		{"undecided does not warn", Health{PRStrandUndecided: []string{"x"}}, healthOK},
		{"drift does not warn", Health{Drift: []string{"x"}}, healthOK},
		{"backup failure does not warn", Health{BackupErr: "no space"}, healthOK},
	} {
		if got := tc.h.Status(); got != tc.want {
			t.Errorf("%s: Status() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestPartialIsWhatADurableChangeWithAFailureReports.
//
// This is the distinction the whole issue turns on. A mutation commits before
// it reconciles, so a call can return an error over a change that is on disk
// and will be replayed at the next start. Reporting that as "failed" would
// invite a controller to recreate an object that already exists, or to assume
// old state that is gone.
//
// Driven through opLog directly because the two ways to reach it -- a
// directory fsync that fails after a successful rename, and a reconcile that
// fails after a durable commit -- both need either a kernel or an induced
// filesystem fault, and neither is what this asserts. What this asserts is the
// classification, which is the part that decides what a consumer does.
func TestPartialIsWhatADurableChangeWithAFailureReports(t *testing.T) {
	for _, tc := range []struct {
		name      string
		persisted bool
		proven    bool
		reconcile string
		err       error
		outcome   string
		level     string
	}{
		{"clean success", true, true, reconcileNotRequired, nil, outcomeSucceeded, "INFO"},
		{"refused before anything happened", false, false, reconcileNotRequired,
			statusErrCode(400, CodeInvalidInput, "no"), outcomeFailed, "INFO"},
		{"durable, but the reconcile failed", true, true, reconcileFailed,
			errors.New("configfs is unreachable"), outcomePartial, "WARN"},
		{"on disk, but not proven durable", true, false, reconcileNotRequired,
			errPersistedNotDurable, outcomePartial, "WARN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, e := eventCoordinator(t)
			ev := c.beginOp(context.Background(), "volume.create")
			ev.noteCommit(tc.persisted, tc.proven)
			ev.noteReconcile(tc.reconcile)
			ev.finish(tc.err)

			m := e.one(t, "volume.create")
			want(t, m, "outcome", tc.outcome)
			want(t, m, "level", tc.level)
			want(t, m, "durable", tc.persisted)
			want(t, m, "durable_proven", tc.proven)
			want(t, m, "reconcile_outcome", tc.reconcile)
			want(t, m, "reconciled", tc.reconcile == reconcileSucceeded)
		})
	}
}

// TestNotDurableIsItsOwnEventBesideThePartialOutcome.
//
// The operation event says the outcome was partial; this says which part. Warn
// rather than error because the change IS in effect -- only its survival
// across a power cut in the next moments is unproven.
func TestNotDurableIsItsOwnEventBesideThePartialOutcome(t *testing.T) {
	c, e := eventCoordinator(t)
	c.logNotDurable(context.Background(), errors.New("fsync: input/output error"))

	m := e.one(t, eventCommitNotDurable)
	want(t, m, "level", "WARN")
	if !strings.Contains(m["msg"].(string), "not proven durable") {
		t.Errorf("the message does not say what is unproven: %v", m)
	}
}

// TestAFenceReleaseIsAttributableToItsRequest.
//
// It is emitted BEFORE the commit -- the reservation it reports exists only
// while the ACLs do -- so it cannot be a field on the operation event alone.
// What it can be is joinable, which is what it was not: two operators
// detaching two hosts produced two bare warnings and no way to tell which was
// whose.
func TestAFenceReleaseIsAttributableToItsRequest(t *testing.T) {
	c, e := eventCoordinator(t)
	ctx := applog.WithRequestID(context.Background(), "req-7")

	c.logFenceReleased(ctx, "detaching holder releases the reservation on vol-1",
		"volume", "vol-1", "uuid-1")

	m := e.one(t, eventPRReleased)
	want(t, m, "request_id", "req-7")
	want(t, m, "resource_name", "vol-1")
	want(t, m, "level", "WARN")
}

// TestARequestJoinsToTheOperationItCaused is the end-to-end claim.
//
// Phase 1 could say a request arrived and what status it returned. Phase 2
// says what the appliance did about it. Neither is worth much unless the two
// records can be joined, which is a property of the whole path -- the access
// middleware minting or honouring the id, the handler deriving an
// uncancellable context from the request, and the coordinator attaching it --
// and not of any single function. Every part of that can be individually
// correct while the chain is broken, so it is asserted through a real HTTP
// request against the real handler.
func TestARequestJoinsToTheOperationItCaused(t *testing.T) {
	c, e := eventCoordinator(t)

	h := applog.AccessLog(e.log, Handler(c))
	body := strings.NewReader(`{"name":"vol-1","size":1048576}`)
	req := httptest.NewRequest(http.MethodPost, APIPrefix+"/volumes", body)
	req.Header.Set(applog.HeaderRequestID, "caller-supplied-id")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create returned %d, want 201: %s", rec.Code, rec.Body.String())
	}
	// Honoured, not replaced: a CSI driver's own id is more useful than one
	// the appliance invents, and it is echoed so the caller can log the join.
	if got := rec.Header().Get(applog.HeaderRequestID); got != "caller-supplied-id" {
		t.Errorf("the response echoed %q, want the id the caller sent", got)
	}

	access := e.one(t, "rest.access")
	op := e.one(t, "volume.create")
	want(t, access, "request_id", "caller-supplied-id")
	want(t, op, "request_id", "caller-supplied-id")

	// The two halves of the question, on records a consumer can join.
	want(t, access, "status", float64(http.StatusCreated))
	want(t, op, "outcome", outcomeSucceeded)
	want(t, op, "durable", true)
	want(t, op, "created", true)
}

// TestTheAccessLogKeepsCallerNamesOutOfTheRouteField.
//
// rest.access logs the routed PATTERN, not the concrete path, which keeps
// caller-chosen volume names out of the log and the cardinality bounded. The
// operation event is where the name belongs, because there it is the subject
// rather than an incidental part of a URL.
func TestTheAccessLogKeepsCallerNamesOutOfTheRouteField(t *testing.T) {
	c, e := eventCoordinator(t)
	h := applog.AccessLog(e.log, Handler(c))

	body := strings.NewReader(`{"name":"secret-customer-name","size":1048576}`)
	req := httptest.NewRequest(http.MethodPost, APIPrefix+"/volumes", body)
	h.ServeHTTP(httptest.NewRecorder(), req)

	access := e.one(t, "rest.access")
	if route, _ := access["route"].(string); strings.Contains(route, "secret-customer-name") {
		t.Errorf("the route field carried a caller-chosen name: %q", route)
	}
	want(t, e.one(t, "volume.create"), "resource_name", "secret-customer-name")
}
