package applog

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// decode reads one JSON record.
func decode(t *testing.T, b *bytes.Buffer) map[string]any {
	t.Helper()
	line := strings.TrimSpace(b.String())
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("record is not JSON (%v): %s", err, line)
	}
	return m
}

// TestTextIsTheDefault: this changes the output of a running deployment if it
// gets it wrong, which is not something a logging change may do.
func TestTextIsTheDefault(t *testing.T) {
	var b bytes.Buffer
	l, _, err := New(Options{Out: &b})
	if err != nil {
		t.Fatal(err)
	}
	Info(context.Background(), l, "lifecycle.start", "started")
	if strings.HasPrefix(strings.TrimSpace(b.String()), "{") {
		t.Fatalf("default format is JSON; it must be text: %s", b.String())
	}
	if !strings.Contains(b.String(), "event=lifecycle.start") {
		t.Errorf("the event name must be a field, got: %s", b.String())
	}
}

// TestEnvelopeIsOnEveryRecord: service and schema_version are the contract a
// consumer parses against, and schema_version is what lets it survive a
// later field change.
func TestEnvelopeIsOnEveryRecord(t *testing.T) {
	var b bytes.Buffer
	l, _, err := New(Options{Format: "json", Out: &b})
	if err != nil {
		t.Fatal(err)
	}
	Info(context.Background(), l, "pr.unbound", "a restored registration did not bind")

	m := decode(t, &b)
	if m["service"] != "applianced" {
		t.Errorf("service = %v", m["service"])
	}
	if m["schema_version"] != float64(SchemaVersion) {
		t.Errorf("schema_version = %v, want %d", m["schema_version"], SchemaVersion)
	}
	if m["event"] != "pr.unbound" {
		t.Errorf("event = %v", m["event"])
	}
	if m["msg"] != "a restored registration did not bind" {
		t.Errorf("the human wording must survive as msg, got %v", m["msg"])
	}
}

// TestNoticeIsItsOwnLevel. A stranded reservation is still ENFORCING, so it is
// doing its job: logging it at WARN trains an operator to ignore warnings, and
// at INFO buries it. It must render as a readable name, not slog's "INFO+2".
func TestNoticeIsItsOwnLevel(t *testing.T) {
	var b bytes.Buffer
	l, _, err := New(Options{Format: "json", Out: &b})
	if err != nil {
		t.Fatal(err)
	}
	Notice(context.Background(), l, "pr.stranded", "a reservation cannot be released by its holder")

	m := decode(t, &b)
	if m["level"] != "NOTICE" {
		t.Errorf("level = %v, want NOTICE -- INFO buries this and WARN is a false alert", m["level"])
	}
}

// TestNoticeSurvivesAtInfoLevel: NOTICE is above INFO, so an operator running
// the default level must still see it. If the ordering were reversed, the
// level would exist and never be emitted.
func TestNoticeSurvivesAtInfoLevel(t *testing.T) {
	var b bytes.Buffer
	l, _, err := New(Options{Format: "json", Level: "info", Out: &b})
	if err != nil {
		t.Fatal(err)
	}
	Notice(context.Background(), l, "pr.stranded", "still enforcing")
	if b.Len() == 0 {
		t.Fatal("a NOTICE was dropped at the default level")
	}
}

// TestUnknownFormatAndLevelAreRefused: a typo must not silently become the
// default and hide the output someone is waiting for.
func TestUnknownFormatAndLevelAreRefused(t *testing.T) {
	if _, _, err := New(Options{Format: "logfmt"}); err == nil {
		t.Error("an unknown format must be refused, not silently defaulted")
	}
	if _, _, err := New(Options{Level: "verbose"}); err == nil {
		t.Error("an unknown level must be refused, not silently defaulted")
	}
}

// TestStdlibLogIsRouted: ~45 existing log.Printf sites carry good wording. They
// must land in the same stream rather than bypassing the handler and
// interleaving raw text with structured records.
func TestStdlibLogIsRouted(t *testing.T) {
	var b bytes.Buffer
	l, _, err := New(Options{Format: "json", Out: &b})
	if err != nil {
		t.Fatal(err)
	}
	Install(l)
	t.Cleanup(func() { log.SetFlags(log.LstdFlags) })

	log.Printf("warning: could not remove saved SCSI-3 PR state")
	m := decode(t, &b)
	if !strings.Contains(m["msg"].(string), "saved SCSI-3 PR state") {
		t.Errorf("a stdlib log line did not route through the handler: %v", m)
	}
	if m["service"] != "applianced" {
		t.Errorf("a routed line lost the envelope: %v", m)
	}
}

// TestAccessLogRecordsTheRequest. This is the appliance's only accountability
// record: the REST API is unauthenticated by design, so without it there is no
// trace of who asked for what -- including the requests that drop fencing.
func TestAccessLogRecordsTheRequest(t *testing.T) {
	var b bytes.Buffer
	l, _, err := New(Options{Format: "json", Out: &b})
	if err != nil {
		t.Fatal(err)
	}

	// The REAL topology: an inner mux owning the leaf patterns, mounted behind
	// http.StripPrefix. A bare mux does NOT reproduce it -- StripPrefix clones
	// the request, so the leaf pattern is written on a clone the access log
	// never sees, and an earlier version of this test used a bare mux and
	// therefore passed while production logged "/v1/" for every request.
	inner := http.NewServeMux()
	inner.HandleFunc("POST /volumes/{name}/connections", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"lun":3}`))
	})
	top := http.NewServeMux()
	top.Handle("/v1/", http.StripPrefix("/v1", CaptureRoute(inner)))
	srv := httptest.NewServer(AccessLog(l, top))
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/v1/volumes/db-1/connections", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	m := decode(t, &b)
	if m["event"] != "rest.access" {
		t.Fatalf("event = %v", m["event"])
	}
	if m["status"] != float64(http.StatusCreated) {
		t.Errorf("status = %v, want 201", m["status"])
	}
	if m["bytes_out"] != float64(len(`{"lun":3}`)) {
		t.Errorf("bytes_out = %v", m["bytes_out"])
	}
	// The ROUTE, not the path: low-cardinality, and it keeps caller-chosen
	// volume names out of every log line.
	route, _ := m["route"].(string)
	if !strings.Contains(route, "{name}") {
		t.Errorf("route = %q, want the LEAF pattern; %q means only the mount "+
			"pattern was seen, which is the same string for every request and "+
			"therefore useless", route, "/v1/")
	}
	if strings.Contains(route, "db-1") {
		t.Errorf("the volume name leaked into the route field: %q", route)
	}
	// Not merely "is a float" -- encoding/json decodes every JSON number as a
	// float64, so that assertion passed even for an integer field. Assert a
	// SUB-MILLISECOND value survives, which is what an integer would round to
	// zero and what these requests routinely are.
	d, ok := m["duration_ms"].(float64)
	if !ok {
		t.Fatalf("duration_ms missing: %v", m)
	}
	if d <= 0 || d >= 1000 {
		t.Errorf("duration_ms = %v; a local request should be sub-millisecond and "+
			"non-zero, which is exactly what an integer field would lose", d)
	}
}

// TestAccessLogHonoursAndEchoesAnInboundID: a caller's own id joins across
// systems better than one minted here, and echoing it lets a caller correlate
// even when it did not send one.
func TestAccessLogHonoursAndEchoesAnInboundID(t *testing.T) {
	var b bytes.Buffer
	l, _, err := New(Options{Format: "json", Out: &b})
	if err != nil {
		t.Fatal(err)
	}

	var seen string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The handler must be able to correlate its own logging with the
		// access record.
		seen = RequestID(r.Context())
	})
	srv := httptest.NewServer(AccessLog(l, h))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/v1/volumes", nil)
	req.Header.Set(HeaderRequestID, "csi-driver-42")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if seen != "csi-driver-42" {
		t.Errorf("the handler saw request id %q; the caller's own id must be honoured", seen)
	}
	if got := resp.Header.Get(HeaderRequestID); got != "csi-driver-42" {
		t.Errorf("the id was not echoed back: %q", got)
	}
	if m := decode(t, &b); m["request_id"] != "csi-driver-42" {
		t.Errorf("request_id = %v", m["request_id"])
	}
}

// TestHealthProbesAreQuiet: a liveness prober every couple of seconds would
// otherwise dominate the stream and bury the events that matter.
func TestHealthProbesAreQuiet(t *testing.T) {
	var b bytes.Buffer
	l, _, err := New(Options{Format: "json", Level: "info", Out: &b})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})
	top := http.NewServeMux()
	top.Handle("/v1/", http.StripPrefix("/v1", CaptureRoute(mux)))
	srv := httptest.NewServer(AccessLog(l, top))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if b.Len() != 0 {
		t.Errorf("a successful health probe was logged at the default level: %s", b.String())
	}

	// But a FAILING probe must still be visible.
	b.Reset()
	mux2 := http.NewServeMux()
	mux2.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	top2 := http.NewServeMux()
	top2.Handle("/v1/", http.StripPrefix("/v1", CaptureRoute(mux2)))
	srv2 := httptest.NewServer(AccessLog(l, top2))
	defer srv2.Close()
	resp2, err := http.Get(srv2.URL + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if b.Len() == 0 {
		t.Error("a health probe that FAILED was suppressed; the carve-out is for " +
			"routine success only")
	}
}

// TestObservabilityContextCannotBeCancelled is the guard on the invariant the
// whole correlation design rests on.
//
// rest.go deliberately does not plumb r.Context() into operations, because
// configfs writes block uncancellably in the kernel and a context would
// advertise a cancellation that cannot happen. A request id must never smuggle
// cancellation in behind it.
func TestObservabilityContextCannotBeCancelled(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	ctx := Observability(WithRequestID(parent, "abc"))
	cancel()

	if RequestID(ctx) != "abc" {
		t.Error("the request id must survive; values are the whole point")
	}
	select {
	case <-ctx.Done():
		t.Fatal("the derived context was cancelled; this would reintroduce " +
			"cancellation into operations that cannot be cancelled")
	default:
	}
	if err := ctx.Err(); err != nil {
		t.Errorf("ctx.Err() = %v, want nil", err)
	}
}

// TestServerErrorLogIsStructured: net/http writes its own errors -- including
// "http: panic serving" and a stack -- to the stdlib default logger. Under a
// JSON handler that interleaves raw text into the stream at the worst moment.
func TestServerErrorLogIsStructured(t *testing.T) {
	var b bytes.Buffer
	_, h, err := New(Options{Format: "json", Out: &b})
	if err != nil {
		t.Fatal(err)
	}
	ServerErrorLog(h).Printf("http: panic serving 10.0.0.1:1234")

	m := decode(t, &b)
	if m["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", m["level"])
	}
	if !strings.Contains(m["msg"].(string), "panic serving") {
		t.Errorf("the server error did not reach the handler: %v", m)
	}
}

var _ = slog.LevelInfo

// TestStdlibLogBridgesAtInfo pins the level the stdlib bridge runs at, and
// the consequence of that choice.
//
// It ran at WARN during the migration, because slog DROPS a bridged record
// when the handler rejects its level: bridging at Info would have silently
// lost the ~45 log.Printf sites that existed then -- several of which said
// WARNING -- the moment an operator ran -log-level=warn, while structured
// warnings kept appearing. That is the worst possible shape for a gap.
//
// Those sites now carry their own level and event name, so the blanket WARN
// became an inaccuracy rather than a safeguard. The second half of this test
// is the price, asserted rather than left implicit: a stdlib line IS dropped
// at -log-level=warn now. That is only acceptable because nothing the
// appliance reports as an anomaly still arrives this way, which
// TestNoProseLoggingRemains checks.
func TestStdlibLogBridgesAtInfo(t *testing.T) {
	var b bytes.Buffer
	l, _, err := New(Options{Format: "json", Level: "info", Out: &b})
	if err != nil {
		t.Fatal(err)
	}
	Install(l)
	t.Cleanup(func() { log.SetFlags(log.LstdFlags) })

	log.Printf("a line from a package that has not been converted")
	if b.Len() == 0 {
		t.Fatal("a stdlib log line vanished at -log-level=info; the bridge is not installed")
	}
	m := decode(t, &b)
	if m["level"] != "INFO" {
		t.Errorf("level = %v, want INFO -- the bridge no longer promotes to WARN", m["level"])
	}

	b.Reset()
	l2, _, err := New(Options{Format: "json", Level: "warn", Out: &b})
	if err != nil {
		t.Fatal(err)
	}
	Install(l2)
	log.Printf("a line from a package that has not been converted")
	if b.Len() != 0 {
		t.Errorf("a bridged line survived -log-level=warn; the bridge level was "+
			"expected to be Info, so this test no longer describes the code: %s", b.String())
	}
}
func TestPayloadLevelAttrCollides(t *testing.T) {
	var b bytes.Buffer
	l, _, err := New(Options{Format: "json", Out: &b})
	if err != nil {
		t.Fatal(err)
	}
	// A STRING value: the type assertion rejects it, so it survives untouched.
	Notice(context.Background(), l, "storage.pool", "pool state", "level", "critical")

	// Both must appear in the RAW record: the envelope's, formatted, and the
	// payload's, untouched. Asserting on the decoded map cannot express this
	// -- JSON allows duplicate keys and encoding/json keeps the last, so the
	// payload wins there. That collision is a real limitation of flat
	// attribute names and is documented on Options; the property under test
	// here is narrower and is the one ReplaceAttr controls: it must not
	// REWRITE a nested attr that happens to share the level key.
	raw := b.String()
	if !strings.Contains(raw, `"level":"NOTICE"`) {
		t.Errorf("the record level was not formatted: %s", raw)
	}
	if !strings.Contains(raw, `"level":"critical"`) {
		t.Errorf("a payload attr named 'level' was rewritten by the level "+
			"formatter: %s", raw)
	}

	// Now the case that DOES collide, asserted as the trap it is.
	b.Reset()
	Notice(context.Background(), l, "storage.pool", "pool state", "level", LevelNotice)
	raw = b.String()
	if strings.Count(raw, `"level":`) != 2 {
		t.Errorf("expected the envelope's level and the payload's to BOTH appear "+
			"as duplicate keys, got: %s", raw)
	}
	if !strings.Contains(raw, `"level":"NOTICE"`) {
		t.Errorf("a slog.Level-valued payload attr named 'level' is rewritten by "+
			"the formatter -- that is the documented collision, and this asserts "+
			"it rather than pretending it cannot happen: %s", raw)
	}
}

// TestRecorderExposesTheUnderlyingWriter: http.ResponseController finds
// optional capabilities through Unwrap. Without it, a wrapper silently
// removes every capability it does not forward by hand.
func TestRecorderExposesTheUnderlyingWriter(t *testing.T) {
	var b bytes.Buffer
	l, _, err := New(Options{Format: "json", Out: &b})
	if err != nil {
		t.Fatal(err)
	}
	var deadlineErr error
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// SetReadDeadline reaches the real writer only via Unwrap.
		deadlineErr = http.NewResponseController(w).SetReadDeadline(time.Now().Add(time.Minute))
	})
	srv := httptest.NewServer(AccessLog(l, h))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/volumes")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if deadlineErr != nil {
		t.Errorf("ResponseController could not reach the real writer: %v -- the "+
			"wrapper is swallowing capabilities", deadlineErr)
	}
}
