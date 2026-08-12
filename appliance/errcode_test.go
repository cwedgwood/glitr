package appliance

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every error response carries a machine-readable code.
//
// The point is that a caller never has to parse prose to decide what to do,
// and never has to handle "no code at all" -- which it could not tell from a
// code it does not recognise.

func decodeErr(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not JSON: %v (%s)", err, rec.Body.String())
	}
	return body
}

func TestEveryErrorCarriesACode(t *testing.T) {
	c, _ := stageHolder(t, "")
	h := Handler(c)
	if _, _, err := c.Create(context.Background(), KindVolume, CreateRequest{Name: "taken", Size: 1 << 20}); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		method, path, body string
		wantStatus         int
		wantCode           string
	}{
		"unknown volume": {
			http.MethodGet, "/volumes/no-such-volume", "",
			http.StatusNotFound, CodeNotFound,
		},
		"unknown host": {
			http.MethodGet, "/hosts/nope", "",
			http.StatusNotFound, CodeNotFound,
		},
		"volume too small": {
			http.MethodPost, "/volumes", `{"name":"tiny","size":1}`,
			http.StatusBadRequest, CodeInvalidInput,
		},
		"size not a multiple of 4096": {
			http.MethodPost, "/volumes", `{"name":"odd","size":1048576+512}`,
			http.StatusBadRequest, CodeInvalidInput,
		},
		"bad block size": {
			http.MethodPost, "/volumes", `{"name":"bs","size":1048576,"block_size":777}`,
			http.StatusBadRequest, CodeInvalidInput,
		},
		"missing name": {
			http.MethodPost, "/volumes", `{"size":1048576}`,
			http.StatusBadRequest, CodeInvalidInput,
		},
		"duplicate name, different shape": {
			http.MethodPost, "/volumes", `{"name":"taken","size":1048576,"block_size":4096}`,
			http.StatusConflict, CodeConfigurationMismatch,
		},
		"unversioned path": {
			http.MethodGet, "", "",
			http.StatusNotFound, CodeNotFound,
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := APIPrefix + tc.path
			if tc.path == "" {
				path = "/volumes" // deliberately unversioned
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, path, jsonBody(tc.body)))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			body := decodeErr(t, rec)
			if body["error"] == "" {
				t.Error("the human-readable message must still be there")
			}
			if body["code"] != tc.wantCode {
				t.Errorf("code = %q, want %q", body["code"], tc.wantCode)
			}
		})
	}
}

// The three conflicts a controller must tell apart all share HTTP 409, so the
// code is the only thing that distinguishes them.
func TestConflictsAreDistinguishable(t *testing.T) {
	c, v := stageHolder(t, "iqn.x:holder")

	// Already connected at a different lun.
	_, _, err := c.Connect(context.Background(), KindVolume, v.UUID, hHolder, 7, true)
	assertCode(t, err, http.StatusConflict, CodeConfigurationMismatch)

	// Lun occupied by a different object.
	other := mustObject(t, c, "conflict-probe", 1<<20)
	_, _, err = c.Connect(context.Background(), KindVolume, other.UUID, hHolder, 1, true)
	assertCode(t, err, http.StatusConflict, CodeLUNConflict)

	// A lun is never assigned, so omitting one is an error and says so.
	_, _, err = c.Connect(context.Background(), KindVolume, other.UUID, hHolder, 0, false)
	assertCode(t, err, http.StatusBadRequest, CodeLUNRequired)

	// Still connected.
	err = c.Delete(context.Background(), KindVolume, v.UUID)
	assertCode(t, err, http.StatusConflict, CodeResourceConnected)
}

func assertCode(t *testing.T, err error, wantStatus int, wantCode string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error with code %s", wantCode)
	}
	se, ok := err.(*StatusError)
	if !ok {
		t.Fatalf("not a StatusError: %v", err)
	}
	if se.Code != wantStatus {
		t.Errorf("status = %d, want %d (%v)", se.Code, wantStatus, err)
	}
	if got := se.ErrorCode(); got != wantCode {
		t.Errorf("code = %q, want %q (%v)", got, wantCode, err)
	}
}

// An error with no explicit code must still report one, or a caller would have
// to handle an empty string as a fourth possibility.
func TestErrorCodeIsNeverEmpty(t *testing.T) {
	for _, status := range []int{
		http.StatusNotFound, http.StatusBadRequest, http.StatusConflict,
		http.StatusServiceUnavailable, http.StatusInternalServerError, 418,
	} {
		e := statusErr(status, "x").(*StatusError)
		if e.ErrorCode() == "" {
			t.Errorf("status %d produced an empty code", status)
		}
	}
}

// jsonBody makes a request body; an empty string means no body at all, which
// several handlers have to tolerate.
func jsonBody(s string) io.Reader {
	if s == "" {
		return nil
	}
	return strings.NewReader(s)
}
