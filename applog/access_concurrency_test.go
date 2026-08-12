package applog

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestRouteHolderUnderConcurrency: each request must get ITS OWN route. The
// holder is per-request, but a shared or leaked one would attribute another
// request's pattern -- and the field exists to tell requests apart.
func TestRouteHolderUnderConcurrency(t *testing.T) {
	var mu sync.Mutex
	var buf bytes.Buffer
	l, _, err := New(Options{Format: "json", Out: &lockedWriter{mu: &mu, w: &buf}})
	if err != nil {
		t.Fatal(err)
	}
	inner := http.NewServeMux()
	inner.HandleFunc("GET /volumes/{name}", func(w http.ResponseWriter, r *http.Request) {})
	inner.HandleFunc("GET /hosts/{name}", func(w http.ResponseWriter, r *http.Request) {})
	top := http.NewServeMux()
	top.Handle("/v1/", http.StripPrefix("/v1", CaptureRoute(inner)))
	srv := httptest.NewServer(AccessLog(l, top))
	defer srv.Close()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); get(t, srv.URL+"/v1/volumes/a") }()
		go func() { defer wg.Done(); get(t, srv.URL+"/v1/hosts/b") }()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	vol, host := 0, 0
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		route, _ := m["route"].(string)
		switch route {
		case "GET /volumes/{name}":
			vol++
		case "GET /hosts/{name}":
			host++
		default:
			t.Fatalf("unexpected route %q -- a request was attributed the wrong pattern", route)
		}
	}
	if vol != 100 || host != 100 {
		t.Errorf("routes mis-attributed: volumes=%d hosts=%d, want 100 each", vol, host)
	}
}

func get(t *testing.T, url string) {
	resp, err := http.Get(url)
	if err != nil {
		t.Error(err)
		return
	}
	resp.Body.Close()
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// TestPanickingHandlerStillLogs: the access record is this appliance's only
// accountability trail for an unauthenticated API, and without a deferred emit
// it goes missing precisely when a handler blew up -- net/http recovers, logs
// its own line, and the request that caused it is never recorded.
func TestPanickingHandlerStillLogs(t *testing.T) {
	var mu sync.Mutex
	var buf bytes.Buffer
	l, lh, err := New(Options{Format: "json", Out: &lockedWriter{mu: &mu, w: &buf}})
	if err != nil {
		t.Fatal(err)
	}
	inner := http.NewServeMux()
	inner.HandleFunc("GET /volumes/{name}", func(w http.ResponseWriter, r *http.Request) {
		panic("handler blew up")
	})
	top := http.NewServeMux()
	top.Handle("/v1/", http.StripPrefix("/v1", CaptureRoute(inner)))

	srv := httptest.NewUnstartedServer(AccessLog(l, top))
	// Keep net/http's own panic line out of the test output; it is expected.
	srv.Config.ErrorLog = ServerErrorLog(lh)
	srv.Start()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/volumes/db-1")
	if err == nil {
		resp.Body.Close()
	}

	mu.Lock()
	defer mu.Unlock()
	var access map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		if m["event"] == "rest.access" {
			access = m
		}
	}
	if access == nil {
		t.Fatal("a panicking request produced no access record; the audit trail " +
			"is missing at the one moment it matters most")
	}
	if access["panicked"] != true {
		t.Errorf("the record does not say the handler failed to finish: %v", access)
	}
	if route, _ := access["route"].(string); !strings.Contains(route, "{name}") {
		t.Errorf("route = %q -- the pattern must survive a panic, or the concrete "+
			"path leaks a caller-chosen name on the most-read request", route)
	}
}

// TestInformationalStatusDoesNotLatch: net/http allows a 1xx before the real
// response. Recording it as final would log 100 for a request that went on to
// answer 201 or 500 -- and status is the field an operator filters on first.
func TestInformationalStatusDoesNotLatch(t *testing.T) {
	var mu sync.Mutex
	var buf bytes.Buffer
	l, _, err := New(Options{Format: "json", Out: &lockedWriter{mu: &mu, w: &buf}})
	if err != nil {
		t.Fatal(err)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"ok":true}`))
	})
	srv := httptest.NewServer(AccessLog(l, h))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/volumes")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	var m map[string]any
	line := strings.TrimSpace(buf.String())
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatal(err)
	}
	if m["status"] != float64(http.StatusCreated) {
		t.Errorf("status = %v, want 201 -- an informational 1xx was recorded as "+
			"the final status", m["status"])
	}
}

// TestAccessLogLevelsMatchTheStatus pins the level, not just the status field.
//
// Mutation testing found that a 4xx or a 5xx could be logged at INFO with the
// whole suite green. Level is what routes and alerts -- a 500 arriving at INFO
// is a 500 nobody is paged for -- so it is as much a part of the contract as
// the status field itself, and it was the half nothing asserted.
func TestAccessLogLevelsMatchTheStatus(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   string
	}{
		{"success", http.StatusOK, "INFO"},
		{"client error", http.StatusBadRequest, "WARN"},
		{"server error", http.StatusInternalServerError, "ERROR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var buf bytes.Buffer
			l, _, err := New(Options{Format: "json", Out: &lockedWriter{mu: &mu, w: &buf}})
			if err != nil {
				t.Fatal(err)
			}
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
			})
			srv := httptest.NewServer(AccessLog(l, h))
			defer srv.Close()

			resp, err := http.Get(srv.URL + "/v1/volumes")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()

			mu.Lock()
			defer mu.Unlock()
			var m map[string]any
			line := strings.TrimSpace(buf.String())
			if i := strings.IndexByte(line, '\n'); i >= 0 {
				line = line[:i]
			}
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Fatal(err)
			}
			if m["level"] != tc.want {
				t.Errorf("status %d logged at %v, want %s -- level is what routes "+
					"and alerts, so a mismatch here is a failure nobody is paged for",
					tc.status, m["level"], tc.want)
			}
		})
	}
}
