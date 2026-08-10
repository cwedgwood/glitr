package applianceclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewRejectsUnusableEndpoints(t *testing.T) {
	for name, ep := range map[string]string{
		"empty":     "",
		"no scheme": "127.0.0.1:8080",
		"no host":   "http://",
		"ftp":       "ftp://example/",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(ep); err == nil {
				t.Errorf("endpoint %q must be refused", ep)
			}
		})
	}
}

// The version prefix is the client's business, not the caller's, and a
// trailing slash in the endpoint must not change the path that is built.
func TestPathsCarryTheVersionPrefixExactlyOnce(t *testing.T) {
	for _, ep := range []string{"http://h:8080", "http://h:8080/", "http://h:8080///"} {
		c, err := New(ep)
		if err != nil {
			t.Fatal(err)
		}
		got := c.url(nil, "volumes")
		if got != "http://h:8080/v1/volumes" {
			t.Errorf("endpoint %q built %q", ep, got)
		}
	}
}

func TestMethodsAndBodies(t *testing.T) {
	var gotMethod, gotPath, gotQuery, gotBody, gotCT string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotQuery = r.Method, r.URL.Path, r.URL.RawQuery
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		// List endpoints answer with an array; everything else with an object.
		if r.Method == http.MethodGet &&
			(strings.HasSuffix(r.URL.Path, "/volumes") ||
				strings.HasSuffix(r.URL.Path, "/connections") ||
				strings.HasSuffix(r.URL.Path, "/hosts")) {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_, _ = w.Write([]byte(`{"uuid":"u1","name":"e1"}`))
	})
	ctx := context.Background()

	v, _, err := c.CreateVolume(ctx, CreateRequest{Name: "e1", Size: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/volumes" {
		t.Errorf("%s %s, want POST /v1/volumes", gotMethod, gotPath)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	if !strings.Contains(gotBody, `"name":"e1"`) {
		t.Errorf("body = %s", gotBody)
	}
	if v.UUID != "u1" || v.Name != "e1" {
		t.Errorf("decoded %+v", v)
	}

	if _, err := c.ListConnections(ctx, "a b/c", "", ""); err != nil {
		t.Fatal(err)
	}
	if gotQuery != "object=a+b%2Fc" {
		t.Errorf("query = %q; the value must be encoded, it is caller data", gotQuery)
	}

	// A UUID is interpolated into the path, so its separators must be escaped:
	// what matters is that it cannot introduce new path SEGMENTS, not that the
	// dots disappear (dots are harmless once the slashes are encoded).
	built := c.url(nil, "volumes", "a/../b")
	if strings.Count(built, "/") != strings.Count(c.url(nil, "volumes", "x"), "/") {
		t.Errorf("built %q; an interpolated id must not add path segments", built)
	}
	if !strings.Contains(built, "%2F") {
		t.Errorf("built %q; the separator must be escaped", built)
	}
	if strings.Contains(built, "%25") {
		t.Errorf("built %q; the segment was escaped twice", built)
	}
}

func TestTypedErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		status   int
		body     string
		wantCode string
		wantMsg  string
	}{
		"appliance error": {
			http.StatusConflict,
			`{"error":"volume is attached; detach first","code":"resource_connected"}`,
			CodeResourceConnected, "volume is attached; detach first",
		},
		"code but no match": {
			http.StatusNotFound, `{"error":"nope","code":"not_found"}`,
			CodeNotFound, "nope",
		},
		// A proxy in front of the appliance returns HTML. That must still be
		// an *Error carrying the status, not a decode failure -- the status is
		// the thing the caller needs and hiding it helps nobody.
		"html from a proxy": {
			http.StatusBadGateway, `<html>502 Bad Gateway</html>`,
			"", "<html>502 Bad Gateway</html>",
		},
		"empty body": {
			http.StatusInternalServerError, ``,
			"", "500 Internal Server Error",
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			_, err := c.List(context.Background(), KindVolume)
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("want *Error, got %v", err)
			}
			if e.StatusCode != tc.status {
				t.Errorf("StatusCode = %d, want %d", e.StatusCode, tc.status)
			}
			if e.Code != tc.wantCode {
				t.Errorf("Code = %q, want %q", e.Code, tc.wantCode)
			}
			if !strings.Contains(e.Message, strings.TrimSpace(tc.wantMsg)) {
				t.Errorf("Message = %q, want %q", e.Message, tc.wantMsg)
			}
			if e.Error() == "" {
				t.Error("Error() must not be empty")
			}
			if tc.wantCode != "" && !IsCode(err, tc.wantCode) {
				t.Errorf("IsCode(%q) was false", tc.wantCode)
			}
		})
	}
}

func TestContextCancellationPropagates(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.List(ctx, KindVolume); err == nil {
		t.Fatal("a cancelled context must surface as an error")
	}
}

func TestWithHTTPClientIsUsed(t *testing.T) {
	used := false
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		used = true
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`[]`)),
			Header:     http.Header{},
		}, nil
	})
	c, err := New("http://example", WithHTTPClient(&http.Client{Transport: rt}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.List(context.Background(), KindVolume); err != nil {
		t.Fatal(err)
	}
	if !used {
		t.Error("the supplied http.Client was ignored")
	}
}

// A nil IQN list must go out as [], not null.
func TestCreateHostSendsAnEmptyListNotNull(t *testing.T) {
	var body string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		_, _ = w.Write([]byte(`{"uuid":"h1"}`))
	})
	if _, _, err := c.CreateHost(context.Background(), "h1", nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"iqns":[]`) {
		t.Errorf("body = %s, want an explicit empty list", body)
	}
}

// The warning must be decoded, because discarding it can silently drop a
// fence. This asserts the field is wired, not that the appliance produces one.
func TestWarningsAreDecoded(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"host":{"uuid":"h1"},"warning":"RELEASED the reservation"}`))
	})
	r, err := c.SetBindings(context.Background(), "h1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Warning == "" {
		t.Error("the warning must be decoded, not dropped")
	}
	if r.Host.UUID != "h1" {
		t.Errorf("host = %+v", r.Host)
	}
}

func TestDisconnectWarningIsDecoded(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"disconnected":"v1","warning":"RELEASED"}`))
	})
	r, err := c.Disconnect(context.Background(), KindVolume, "v1", "h1")
	if err != nil {
		t.Fatal(err)
	}
	if r.Warning == "" || r.Disconnected != "v1" {
		t.Errorf("decoded %+v", r)
	}
}

// A response body larger than the error cap must not be buffered whole.
func TestErrorBodyIsBounded(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(strings.Repeat("x", maxErrorBody*2)))
	})
	_, err := c.List(context.Background(), KindVolume)
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want *Error, got %v", err)
	}
	if len(e.Message) > maxErrorBody {
		t.Errorf("message is %d bytes, over the %d cap", len(e.Message), maxErrorBody)
	}
}

func TestListConnectionsFilters(t *testing.T) {
	var query string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		_, _ = w.Write([]byte(`[]`))
	})
	ctx := context.Background()

	if _, err := c.ListConnections(ctx, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if query != "" {
		t.Errorf("no filter must send no query, got %q", query)
	}
	if _, err := c.ListConnections(ctx, "v1", KindVolume, "h1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(query, "object=v1") || !strings.Contains(query, "host=h1") {
		t.Errorf("query = %q", query)
	}
}

// Decoding a body that is not what the method expects must be an error rather
// than a zero value, or a caller cannot tell "empty" from "wrong endpoint".
func TestMalformedSuccessBodyIsAnError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"uuid":`))
	})
	if _, err := c.Get(context.Background(), KindVolume, "u1"); err == nil {
		t.Fatal("a truncated body must be reported")
	}
}

// A method with no response value must still succeed on an empty body.
func TestDeleteToleratesAnEmptyBody(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	if err := c.Delete(context.Background(), KindVolume, "u1"); err != nil {
		t.Fatalf("delete with an empty body must succeed: %v", err)
	}
}

func TestHealthDecodesTheVerdict(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"warning","pr_stranded":["vol1: stranded"]}`))
	})
	h, err := c.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.Status != "warning" || len(h.PRStranded) != 1 {
		t.Errorf("decoded %+v", h)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestHealthKeepsTheBodyOnDegraded: the appliance answers 503 for "degraded"
// and puts the reason -- and the fencing signals -- in the body. Turning that
// into a bare error, which this client used to do, threw away pr_unbound at
// exactly the moment it means something.
func TestHealthKeepsTheBodyOnDegraded(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, `{"status":"degraded","error":"reconcile failed",
			"pr_unbound":["vol-a"],"pr_stranded":["vol-b"]}`)
	})

	h, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("a 503 carrying a verdict is not an error: %v", err)
	}
	if h.Status != "degraded" {
		t.Errorf("status = %q, want degraded", h.Status)
	}
	if h.Error != "reconcile failed" {
		t.Errorf("error = %q, want the body's detail", h.Error)
	}
	// The whole reason to decode rather than reconstitute from the error: an
	// *Error has nowhere to carry these.
	if len(h.PRUnbound) != 1 || h.PRUnbound[0] != "vol-a" {
		t.Errorf("pr_unbound must survive the 503, got %v", h.PRUnbound)
	}
	if len(h.PRStranded) != 1 || h.PRStranded[0] != "vol-b" {
		t.Errorf("pr_stranded must survive the 503, got %v", h.PRStranded)
	}
}

// A 503 that is NOT the appliance -- a proxy, a load balancer -- must stay an
// error. Inventing a verdict from it would report the fabric's opinion as the
// appliance's.
func TestHealthStillErrsOnANonApplianceBody(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "<html><body>503 Service Unavailable</body></html>")
	})

	h, err := c.Health(context.Background())
	if err == nil {
		t.Fatalf("a body with no verdict must be an error, got %+v", h)
	}
	var e *Error
	if !errors.As(err, &e) || e.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("the status must survive: %v", err)
	}
	if h.Status != "" {
		t.Errorf("no verdict must be invented, got %q", h.Status)
	}
}

// A warning is served with 200 and the same body shape, and must read the same
// way: the status field is the verdict either way.
func TestHealthReadsAWarning(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":"warning","pr_unbound":["vol-a"]}`)
	})

	h, err := c.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.Status != "warning" || len(h.PRUnbound) != 1 {
		t.Errorf("warning body not read: %+v", h)
	}
}

func TestTarget(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/target" {
			t.Errorf("path = %q", r.URL.Path)
		}
		io.WriteString(w, `{"target_iqn":"iqn.2026-01.dev.glitr:app",
			"portals":[{"ip":"10.0.0.1","port":3260},{"ip":"::1","port":3261}]}`)
	})

	tgt, err := c.Target(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tgt.TargetIQN != "iqn.2026-01.dev.glitr:app" {
		t.Errorf("target_iqn = %q", tgt.TargetIQN)
	}
	if len(tgt.Portals) != 2 {
		t.Fatalf("portals = %v", tgt.Portals)
	}
	// Each portal carries its OWN port; there is no target-wide one.
	if tgt.Portals[1].IP != "::1" || tgt.Portals[1].Port != 3261 {
		t.Errorf("second portal = %+v", tgt.Portals[1])
	}
}

// The created flag comes from the status code, so it is the one piece of the
// reply with no field to decode. 201 means this call made it; 200 means it was
// already there and was returned unchanged.
func TestCreateReportsCreatedFromTheStatusCode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		created bool
	}{
		{"created", http.StatusCreated, true},
		{"adopted", http.StatusOK, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, `{"uuid":"u","name":"db-1","kind":"volume"}`)
			})
			o, created, err := c.CreateVolume(context.Background(),
				CreateRequest{Name: "db-1", Size: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			if created != tc.created {
				t.Errorf("created = %v, want %v", created, tc.created)
			}
			if o.Name != "db-1" {
				t.Errorf("the object must decode either way: %+v", o)
			}
		})
	}
}

// TestFencingWarningSurvivesAFailedMutation.
//
// The appliance attaches the warning to the FAILURE response deliberately: a
// disconnect can be durable before the reconcile that follows it fails, so the
// fence is already gone and the caller still has to be told. This client threw
// that away -- it decoded only "error" and "code" from an error body, and left
// the result struct zero -- so the one message saying "initiators this was
// fencing can write NOW" was lost at exactly the moment it was true.
//
// Worse than lost: retrying takes the appliance's idempotent path, which
// succeeds and says nothing, so the information could not be recovered
// through the API at all.
func TestFencingWarningSurvivesAFailedMutation(t *testing.T) {
	// The real warning text contains quotes, so the body is MARSHALLED rather
	// than pasted together: the first version of this test built it by
	// concatenation, produced invalid JSON, and failed against a correct fix
	// because the client fell back to treating the whole body as a message.
	const warning = `disconnecting host "holder" RELEASED the SCSI-3 reservation it held`
	raw, err := json.Marshal(map[string]string{
		"error": "reconcile failed", "code": "internal", "warning": warning,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)

	t.Run("disconnect", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, body)
		})
		resp, err := c.Disconnect(context.Background(), KindVolume, "vol-1", "host-1")
		if err == nil {
			t.Fatal("the call failed and must report an error")
		}
		// On the error, so a caller that only logs err still sees it.
		var e *Error
		if !errors.As(err, &e) {
			t.Fatalf("expected *Error, got %T", err)
		}
		if e.Warning != warning {
			t.Errorf("Error.Warning = %q, want the fencing statement", e.Warning)
		}
		if !strings.Contains(err.Error(), "RELEASED") {
			t.Errorf("Error() must render the warning: %q", err.Error())
		}
		// And on the result, which is not zero just because the call failed.
		if resp.Warning != warning {
			t.Errorf("DisconnectResponse.Warning = %q, want the fencing statement", resp.Warning)
		}
	})

	t.Run("bindings", func(t *testing.T) {
		for name, call := range map[string]func(*Client) (HostResponse, error){
			"set": func(c *Client) (HostResponse, error) {
				return c.SetBindings(context.Background(), "host-1", []string{"iqn.x:a"})
			},
			"add": func(c *Client) (HostResponse, error) {
				return c.AddBindings(context.Background(), "host-1", []string{"iqn.x:a"})
			},
			"remove": func(c *Client) (HostResponse, error) {
				return c.RemoveBindings(context.Background(), "host-1", []string{"iqn.x:a"})
			},
		} {
			t.Run(name, func(t *testing.T) {
				c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					io.WriteString(w, body)
				})
				resp, err := call(c)
				if err == nil {
					t.Fatal("the call failed and must report an error")
				}
				var e *Error
				if !errors.As(err, &e) || e.Warning != warning {
					t.Errorf("the warning was lost on the error: %v", err)
				}
				if resp.Warning != warning {
					t.Errorf("the warning was lost on the result: %+v", resp)
				}
			})
		}
	})
}

// A failure with no warning must not invent one, and an error body that is not
// the appliance's must still yield a usable status rather than "decode
// failed".
func TestFailedMutationWithoutAWarning(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		io.WriteString(w, `{"error":"already connected","code":"configuration_mismatch"}`)
	})
	_, err := c.Disconnect(context.Background(), KindVolume, "vol-1", "host-1")
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *Error, got %v", err)
	}
	if e.Warning != "" {
		t.Errorf("no warning was sent; none must be reported: %q", e.Warning)
	}
	if strings.Contains(err.Error(), "WARNING") {
		t.Errorf("Error() must not mention a warning that does not exist: %q", err.Error())
	}
	if e.StatusCode != http.StatusConflict || e.Code != "configuration_mismatch" {
		t.Errorf("the status and code must survive: %+v", e)
	}
}
