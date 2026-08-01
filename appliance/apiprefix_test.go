package appliance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The REST surface is served under APIPrefix and nowhere else.
//
// This is a contract an external client codes against, so it is worth pinning
// rather than leaving to the handlers' own tests: those all build their
// request with APIPrefix, so a change to the mount point would move them in
// lockstep and assert nothing.
func TestAPIIsServedOnlyUnderTheVersionPrefix(t *testing.T) {
	h := Handler(&Coordinator{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, APIPrefix+"/health", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("%s/health = %d, want %d", APIPrefix, rec.Code, http.StatusOK)
	}
}

func TestUnversionedPathsSayWhereTheAPIWent(t *testing.T) {
	h := Handler(&Coordinator{})

	// A bare 404 on a healthy daemon is a genuinely confusing thing to debug,
	// so the miss names the prefix. It is still a 404: the unversioned paths
	// are not aliases and are not served.
	for _, path := range []string{"/health", "/volumes", "/hosts", "/", "/v2/health"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want %d", path, rec.Code, http.StatusNotFound)
			continue
		}
		var body struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Errorf("GET %s: body is not JSON: %v (%s)", path, err, rec.Body.String())
			continue
		}
		if !strings.Contains(body.Error, APIPrefix) {
			t.Errorf("GET %s: %q does not name %q, so a caller cannot tell where the API went",
				path, body.Error, APIPrefix)
		}
	}
}
