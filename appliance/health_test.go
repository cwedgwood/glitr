package appliance

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cwedgwood/glitr/storage"
)

// TestHealthSnapshotIsAtomic is the regression test for the torn read the
// round-2 panel flagged: /health took two separate lock acquisitions
// (Healthy() then PRUnbound()), so a reconcile landing between them could pair
// an older verdict with a newer warning.
//
// It also covers the non-atomic PUBLICATION the round-2 panel flagged
// separately: a reconcile announced success, then walked configfs to verify
// fencing state, then published the warnings, so /health paired a fresh "ok"
// with the previous generation's warnings for the length of a kernel walk --
// the fail-open direction in the signal that reports fencing.
//
// It drives concurrent writers and asserts the pair is always self-consistent:
// this appliance only publishes PR warnings from a reconcile that succeeded,
// so "degraded with warnings from the same generation" is the combination that
// must never appear torn.
func TestHealthSnapshotIsAtomic(t *testing.T) {
	// The publishers log each newly-seen warning, and this writer alternates
	// thousands of times, so every publish looks new.
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	c := &Coordinator{}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer: flip between the two states a reconcile can leave behind,
	// THROUGH THE PRODUCTION PUBLISHERS.
	//
	// This is the point of the test and it used to be wrong: the writer set
	// healthErr and prUnbound together under one lock it took itself, which is
	// exactly what production did NOT do. Production published the verdict,
	// then walked configfs, then published the warnings -- three acquisitions
	// -- so the test passed while proving nothing about the code path it
	// exists for. An assertion that cannot fail for the reason it claims.
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				c.publishReconcile(nil, []string{"vol_a: not in effect"}, nil, nil)
			} else {
				c.publishReconcile(errors.New("reconcile failed"), nil, nil, nil)
			}
		}
	})

	// Reader: every snapshot must match one of the two written states, never
	// a mixture of both.
	for range 20000 {
		h := c.HealthSnapshot()
		if h.Degraded && len(h.PRUnbound) > 0 {
			close(stop)
			wg.Wait()
			t.Fatalf("torn snapshot: degraded=%v with %d warning(s) — the two halves "+
				"came from different generations", h.Degraded, len(h.PRUnbound))
		}
		if !h.Degraded && h.Detail != "" {
			close(stop)
			wg.Wait()
			t.Fatalf("torn snapshot: not degraded but carries detail %q", h.Detail)
		}
	}
	close(stop)
	wg.Wait()
}

// TestRecheckPRSkipsWhenBusy: the periodic re-verify must not queue behind an
// in-flight mutation. c.mu is held across reconcile, whose configfs work can
// block uncancellably in the kernel, so a blocking ticker would pile up
// goroutines on a lock that may never be released -- and the reconcile
// publishes its own fresher result on the way out anyway.
func TestRecheckPRSkipsWhenBusy(t *testing.T) {
	c := &Coordinator{}
	c.mu.Lock() // stand in for a reconcile in flight

	done := make(chan struct{})
	go func() {
		c.RecheckPR() // must return immediately, not block on c.mu
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RecheckPR blocked while a mutation held c.mu; it must skip the tick")
	}
	c.mu.Unlock()
}

// TestHealthSnapshotReportsCheckTime: "no pr_unbound" is ambiguous between
// "checked, nothing wrong" and "never successfully checked" once the check is
// periodic rather than per-request, so the timestamp has to be exposed.
func TestHealthSnapshotReportsCheckTime(t *testing.T) {
	c := &Coordinator{}
	if got := c.HealthSnapshot(); !got.CheckedAt.IsZero() {
		t.Errorf("a coordinator that has never checked must report a zero time, got %v", got.CheckedAt)
	}
	now := time.Now()
	c.healthMu.Lock()
	c.prCheckedAt = now
	c.healthMu.Unlock()
	if got := c.HealthSnapshot(); !got.CheckedAt.Equal(now) {
		t.Errorf("CheckedAt = %v, want %v", got.CheckedAt, now)
	}
}

// TestHealthCheckedAtDiscriminatesWithinASecond pins the resolution of
// pr_checked_at AS THE HANDLER RENDERS IT.
//
// The field exists so a caller can tell "checked, nothing wrong" from "never
// successfully checked", and so a test can tell a fresh computation from a
// stale one re-served. Rendered as RFC3339 it had SECOND resolution, and a
// reconcile plus the /health read that follows it routinely land in the same
// second -- so two genuinely distinct checks stamped identically and the
// distinction the field exists for was unavailable.
//
// The first version of this test called time.Format itself and compared the
// two strings. That tested the standard library: reverting rest.go to
// time.RFC3339 left it passing. All three reviewers of the fix caught it --
// a regression test for a product change that never touches the product is
// the same fail-open shape as the assertion that prompted the change.
//
// It now drives Handler and reads pr_checked_at out of the response body.
func TestHealthCheckedAtDiscriminatesWithinASecond(t *testing.T) {
	base := time.Date(2026, 8, 1, 17, 40, 45, 0, time.UTC)
	// 94ms apart: the same second, so a second-resolution rendering cannot
	// tell them apart, which is precisely the case that broke.
	times := []time.Time{base.Add(3 * time.Millisecond), base.Add(97 * time.Millisecond)}

	var rendered []string
	for _, at := range times {
		c := &Coordinator{}
		c.healthMu.Lock()
		c.prCheckedAt = at
		c.healthMu.Unlock()

		rec := httptest.NewRecorder()
		Handler(c).ServeHTTP(rec, httptest.NewRequest("GET", "/health", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("/health returned %d", rec.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decoding /health: %v (body %q)", err, rec.Body.String())
		}
		v, ok := body["pr_checked_at"].(string)
		if !ok {
			t.Fatalf("pr_checked_at missing or not a string in %v", body)
		}
		if _, err := time.Parse(time.RFC3339, v); err != nil {
			t.Errorf("pr_checked_at %q is not valid RFC3339: %v -- existing "+
				"consumers parse it with that layout", v, err)
		}
		rendered = append(rendered, v)
	}

	if rendered[0] == rendered[1] {
		t.Errorf("two checks %v apart both render as %q -- /health cannot "+
			"distinguish a fresh computation from a stale one re-served, which "+
			"is the only question this field exists to answer",
			times[1].Sub(times[0]), rendered[0])
	}

	// The negative control: these two instants MUST be indistinguishable at
	// second resolution, or the test would pass without the handler having
	// changed anything.
	if times[0].UTC().Format(time.RFC3339) != times[1].UTC().Format(time.RFC3339) {
		t.Fatal("the two sample times differ at second resolution, so this test " +
			"would pass against the old rendering too -- its premise is wrong")
	}
}

// TestHealthReportsRejectedRecords: the appliance must be able to SAY that a
// volume is missing because its record was rejected.
//
// This is the half of the fix that is not about availability. A malformed
// record used to fail storage.Open, which exited applianced, which systemd
// restarted every 2s -- so the one interface capable of explaining the problem
// was guaranteed to be down, and the only diagnosis was the journal. Serving
// the healthy volumes is worth little if the operator cannot find out what
// happened to the one that vanished.
func TestHealthReportsRejectedRecords(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "volumes"), 0o755); err != nil {
		t.Fatal(err)
	}
	// One unusable record (capacity below a block) beside one good volume.
	db := `[{"uuid":"11111111-1111-4111-8111-111111111111","wwn":"0000000000000000","capacity":100,"state":"ready","block_size":512},
	        {"uuid":"33333333-3333-4333-8333-333333333333","wwn":"00000000000000ff","capacity":1048576,"state":"ready","block_size":512}]`
	if err := os.WriteFile(filepath.Join(root, "volumes.json"), []byte(db), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := storage.Open(root)
	if err != nil {
		t.Fatalf("one bad record must not fail the store: %v", err)
	}
	c := &Coordinator{store: st}

	h := c.HealthSnapshot()
	if len(h.RejectedRecords) != 1 {
		t.Fatalf("health must report the rejected record, got %d", len(h.RejectedRecords))
	}
	if !h.Degraded {
		t.Error("a volume that exists in the db but is not exported is degraded")
	}
	if !strings.Contains(h.Detail, "rejected") {
		t.Errorf("the detail must say what happened, got %q", h.Detail)
	}
	if h.RejectedRecords[0].UUID != "11111111-1111-4111-8111-111111111111" {
		t.Errorf("the rejected record must be identifiable so an operator can find it, got %+v",
			h.RejectedRecords[0])
	}
}

// TestDegradedHealthBodyCarriesRejectedRecords: /health must report the
// rejected records on the DEGRADED path.
//
// Caught in the lab, not in review: the field was added only to the healthy
// response body, but a rejected record always sets Degraded and that branch
// returns early -- so the field could never appear. It was dead the moment it
// was written. An operator asking "where did my volume go" is by definition
// asking a degraded appliance.
func TestDegradedHealthBodyCarriesRejectedRecords(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "volumes"), 0o755); err != nil {
		t.Fatal(err)
	}
	db := `[{"uuid":"11111111-1111-4111-8111-111111111111","wwn":"0000000000000000","capacity":100,"state":"ready","block_size":512}]`
	if err := os.WriteFile(filepath.Join(root, "volumes.json"), []byte(db), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := storage.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	c := &Coordinator{store: st}

	rec := httptest.NewRecorder()
	Handler(c).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a rejected record must read as degraded, got HTTP %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["rejected_records"]; !ok {
		t.Fatalf("the degraded body must name the rejected records, got %s", rec.Body.String())
	}
	if s, _ := body["error"].(string); !strings.Contains(s, "rejected") {
		t.Errorf("the degraded error must say what happened, got %q", s)
	}
}

// TestOldAttachmentRecordsWithStateStillLoad: Attachment carried an observed
// "state" field that was written once as "ready" and never read. It was
// removed, but appliance.json files written before that still contain the key
// -- including on every deployed appliance.
//
// This pins that removing a persisted field is backward-compatible:
// encoding/json ignores keys with no matching struct field, so an old record
// loads with everything else intact. Without this, the claim is an assumption
// about the JSON decoder made at the moment of deleting live data's schema.
func TestOldAttachmentRecordsWithStateStillLoad(t *testing.T) {
	// Exactly the shape the appliance used to write, "state" included.
	const old = `{
	  "hosts": [{"uuid":"h1","iqns":["iqn.1993-08.org.debian:01:a"]}],
	  "attachments": [{"volume_uuid":"v1","host_uuid":"h1","lun":3,
	                   "desired":"attached","state":"ready"}],
	  "exports": {"v1": 1}
	}`
	var st dbState
	if err := json.Unmarshal([]byte(old), &st); err != nil {
		t.Fatalf("an appliance.json written before the field was removed must still "+
			"load: %v", err)
	}
	if len(st.Attachments) != 1 {
		t.Fatalf("the attachment was dropped, got %d", len(st.Attachments))
	}
	a := st.Attachments[0]
	if a.VolumeUUID != "v1" || a.HostUUID != "h1" || a.LUN != 3 {
		t.Errorf("the surviving fields must be intact, got %+v", a)
	}
	if a.Desired != "attached" {
		t.Errorf("Desired is still live and must load, got %q", a.Desired)
	}
}

// TestStrandedReservationIsReportedButNotDegraded pins both halves of the
// contract.
//
// A stranded reservation is one that IS in effect, whose holder can no longer
// address it because its session identifier rotated. It must be visible --
// otherwise an operator waits for a holder that can never release -- but it
// must NOT read as degraded, because the fence is working. Marking it degraded
// would put a healthy appliance into a 503 for doing its job correctly.
//
// The field was added to the healthy body deliberately: unlike rejected db
// records, this condition does not set Degraded, so a field placed only on the
// degraded path would be unreachable. That mistake has been made in this file
// before.
func TestStrandedReservationIsReportedButNotDegraded(t *testing.T) {
	c := &Coordinator{}
	c.publishReconcile(nil, nil, []string{
		"backstore/fileio/vol_x: reservation held by iqn.1993-08.org.debian:01:a " +
			"cannot be released by it",
	}, nil)

	h := c.HealthSnapshot()
	if len(h.PRStranded) != 1 {
		t.Fatalf("the stranded reservation must be reported, got %v", h.PRStranded)
	}
	if h.Degraded {
		t.Error("a stranded reservation is still ENFORCING, so the appliance is not " +
			"degraded; reporting it as such would 503 a healthy appliance for " +
			"fencing correctly")
	}

	rec := httptest.NewRecorder()
	Handler(c).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["pr_stranded"]; !ok {
		t.Errorf("the healthy body must carry pr_stranded, or the field is unreachable "+
			"for a condition that never sets Degraded: %s", rec.Body.String())
	}
	if _, ok := body["pr_unbound"]; ok {
		t.Error("pr_unbound means a fence is NOT in effect and must not be conflated " +
			"with pr_stranded, which means it is")
	}
}

// TestHealthReportsFencingSignalsOnEveryPath pins two defects that made the
// fencing signals invisible in exactly the conditions they exist for.
//
// The verdict used to be "ok" with pr_unbound sitting in the same object: an
// ordinary monitor reads the status code or the status field, not every
// optional key, so the appliance reported itself healthy while a reservation
// somebody relied on was not in effect. And the degraded branch built its own
// body from scratch, dropping the fencing fields entirely -- a failed
// reconcile establishes nothing new about fencing, which is why
// publishReconcileFailure deliberately KEEPS the previous warnings, and the
// handler then threw them away.
func TestHealthReportsFencingSignalsOnEveryPath(t *testing.T) {
	get := func(c *Coordinator) (int, map[string]any) {
		t.Helper()
		srv := httptest.NewServer(Handler(c))
		defer srv.Close()
		resp, err := http.Get(srv.URL + "/health")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, body
	}

	t.Run("unbound reservations are not reported as ok", func(t *testing.T) {
		c := &Coordinator{}
		// Through the production publisher, not by setting fields: a test that
		// stages state its own way can pass while the real path is broken.
		c.publishReconcile(nil, []string{"vol0: saved registration did not bind"}, nil, nil)
		code, body := get(c)
		if body["status"] == "ok" {
			t.Error("a reservation that is not in effect was reported as status ok")
		}
		if body["pr_unbound"] == nil {
			t.Error("pr_unbound missing from the body")
		}
		// Still 200: the appliance is alive and serving, and a 503 would have
		// a liveness probe restart a working daemon without restoring
		// anything.
		if code != http.StatusOK {
			t.Errorf("status code %d, want 200 -- the appliance is serving", code)
		}
	})

	t.Run("degraded keeps the fencing fields", func(t *testing.T) {
		c := &Coordinator{}
		// Establish the warnings, THEN fail a reconcile. That is the real
		// sequence: publishReconcileFailure deliberately keeps the previous
		// warnings because a failed reconcile learned nothing new about
		// fencing.
		c.publishReconcile(nil,
			[]string{"vol0: saved registration did not bind"},
			[]string{"vol1: holder cannot release"}, nil)
		c.publishReconcileFailure(errors.New("reconcile failed"))
		code, body := get(c)
		if code != http.StatusServiceUnavailable {
			t.Errorf("status code %d, want 503", code)
		}
		if body["pr_unbound"] == nil {
			t.Error("pr_unbound was dropped from the degraded body -- the failure " +
				"that degrades the appliance is when fencing state matters most")
		}
		if body["pr_stranded"] == nil {
			t.Error("pr_stranded was dropped from the degraded body")
		}
	})

	t.Run("a clean appliance is still ok", func(t *testing.T) {
		if _, body := get(&Coordinator{}); body["status"] != "ok" {
			t.Errorf("a healthy appliance reported %v, want ok", body["status"])
		}
	})
}
