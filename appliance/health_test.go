package appliance

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
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
				c.publishReconcile(context.Background(), nil, []string{"vol_a: not in effect"}, nil, nil, nil)
			} else {
				c.publishReconcile(context.Background(), errors.New("reconcile failed"), nil, nil, nil, nil)
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
		c.RecheckPR(context.Background()) // must return immediately, not block on c.mu
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
		Handler(c).ServeHTTP(rec, httptest.NewRequest("GET", APIPrefix+"/health", nil))
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
	c.publishReconcile(context.Background(), nil, nil, []string{
		"backstore/fileio/vol_x: reservation held by iqn.1993-08.org.debian:01:a " +
			"cannot be released by it",
	}, nil, nil)

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
	Handler(c).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, APIPrefix+"/health", nil))
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
		resp, err := http.Get(srv.URL + APIPrefix + "/health")
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
		c.publishReconcile(context.Background(), nil, []string{"vol0: saved registration did not bind"}, nil, nil, nil)
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
		c.publishReconcile(context.Background(), nil,
			[]string{"vol0: saved registration did not bind"},
			[]string{"vol1: holder cannot release"}, nil, nil)
		c.publishReconcileFailure(context.Background(), errors.New("reconcile failed"))
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

// TestUndecidedStrandIsNotAWarning: the reported bug was not only a wrong
// entry in pr_stranded, it was a permanent status of "warning" on every
// multipathed volume holding a reservation. Being unable to answer a question
// is not a fault in the storage, so it must not spend the appliance's one
// attention-getting signal.
func TestUndecidedStrandIsNotAWarning(t *testing.T) {
	c := &Coordinator{}
	c.publishReconcile(context.Background(), nil, nil, nil,
		[]string{"iqn.x:t: cannot tell whether these reservations are stranded — " +
			"the kernel reports 8 live sessions but renders only 1"}, nil)

	h := c.HealthSnapshot()
	if len(h.PRStrandUndecided) != 1 {
		t.Fatalf("the blind spot must be reported: %+v", h)
	}
	if len(h.PRStranded) != 0 {
		t.Errorf("it must not be reported as a strand: %v", h.PRStranded)
	}

	srv := httptest.NewServer(Handler(c))
	defer srv.Close()
	resp, err := http.Get(srv.URL + APIPrefix + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200: not being able to answer is not degraded",
			resp.StatusCode)
	}
	if got := body["status"]; got != "ok" {
		t.Errorf("status = %v, want ok -- this is what made every multipathed "+
			"appliance sit permanently at warning", got)
	}
	if _, ok := body["pr_strand_undecided"]; !ok {
		t.Error("the field must still be served, or the detector goes blind in silence")
	}
}
