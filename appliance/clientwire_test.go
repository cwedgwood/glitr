package appliance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/cwedgwood/glitr/applog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cwedgwood/glitr/applianceclient"
)

// The published client, driven against the REAL handler.
//
// applianceclient's own tests answer with hand-written bodies, which prove it
// parses what the test author thinks the appliance sends. This proves it
// parses what the appliance ACTUALLY sends. That gap is the failure mode the
// client's design invites: its types are deliberately copies rather than
// aliases, so nothing at compile time notices when the two drift, and a
// renamed JSON tag would silently decode as a zero value.
//
// It lives here rather than in applianceclient because building a Coordinator
// needs the unexported fixtures; the client does not import the appliance, so
// there is no cycle.
func TestPublishedClientMatchesTheWireFormat(t *testing.T) {
	c := bareCoordinator(t)
	srv := httptest.NewServer(Handler(c))
	defer srv.Close()

	cl, err := applianceclient.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	v, _, err := cl.CreateVolume(ctx, applianceclient.CreateRequest{Name: "wire-1", Size: 1 << 20})
	if err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	// Each of these is a field the client copies by hand. A tag that drifted
	// would decode as a zero value rather than fail, so they are checked one
	// by one instead of trusting the call to have succeeded.
	if v.UUID == "" {
		t.Error("uuid did not decode")
	}
	if v.Name != "wire-1" {
		t.Errorf("name = %q, want wire-1", v.Name)
	}
	if v.Kind != applianceclient.KindVolume {
		t.Errorf("kind = %q, want volume", v.Kind)
	}
	if v.WWN == "" {
		t.Error("wwn did not decode")
	}
	if v.Capacity != 1<<20 {
		t.Errorf("capacity = %d", v.Capacity)
	}
	if v.BlockSize == 0 {
		t.Error("block_size did not decode")
	}
	if v.State == "" {
		t.Error("state did not decode")
	}
	if v.Created == "" {
		t.Error("created did not decode")
	}

	got, err := cl.Get(ctx, applianceclient.KindVolume, "wire-1")
	if err != nil || got.UUID != v.UUID {
		t.Fatalf("Get by name: %v %+v", err, got)
	}
	// A uuid works wherever a name does.
	if got, err = cl.Get(ctx, applianceclient.KindVolume, v.UUID); err != nil || got.Name != "wire-1" {
		t.Errorf("Get by uuid: %v %+v", err, got)
	}

	// A replayed create returns the same object through the client too.
	again, _, err := cl.CreateVolume(ctx, applianceclient.CreateRequest{Name: "wire-1", Size: 1 << 20})
	if err != nil || again.UUID != v.UUID {
		t.Errorf("replayed create: %v, uuid %s want %s", err, again.UUID, v.UUID)
	}

	// A mismatching repeat arrives as a code the caller can branch on.
	_, _, err = cl.CreateVolume(ctx, applianceclient.CreateRequest{
		Name: "wire-1", Size: 1 << 20, BlockSize: 4096})
	if !applianceclient.IsCode(err, applianceclient.CodeConfigurationMismatch) {
		t.Errorf("want %s, got %v", applianceclient.CodeConfigurationMismatch, err)
	}
	// And the codes the two packages declare must be the same strings.
	if applianceclient.CodeConfigurationMismatch != CodeConfigurationMismatch ||
		applianceclient.CodeNotFound != CodeNotFound ||
		applianceclient.CodeLUNConflict != CodeLUNConflict ||
		applianceclient.CodeLUNRequired != CodeLUNRequired ||
		applianceclient.CodeNameTaken != CodeNameTaken ||
		applianceclient.CodeResourceConnected != CodeResourceConnected {
		t.Error("the client's error codes have drifted from the appliance's")
	}

	renamed, err := cl.Rename(ctx, applianceclient.KindVolume, "wire-1", "wire-2")
	if err != nil || renamed.Name != "wire-2" || renamed.WWN != v.WWN {
		t.Errorf("Rename: %v %+v", err, renamed)
	}

	// Hosts are SEEDED rather than created through the client: creating one
	// commits, and a commit reconciles the whole target -- including enabling
	// the TPG -- which needs a real configfs tree. The wire format is what is
	// under test, and the read path exercises every field the client copies.
	// Creating a host through the client is covered by the live suites.
	c.mu.Lock()
	c.st.Hosts = append(c.st.Hosts, &Host{
		UUID: "3f2504e0-4f89-11d3-9a0c-0305e82c3501", Name: "wire-host",
		Bindings: Bindings{IQNs: []string{"iqn.2026-01.wire:a"}}})
	c.mu.Unlock()

	gh, err := cl.GetHost(ctx, "wire-host")
	if err != nil {
		t.Fatalf("GetHost: %v", err)
	}
	if gh.UUID == "" || gh.Name != "wire-host" {
		t.Errorf("host decoded as %+v", gh)
	}
	if len(gh.Bindings.IQNs) != 1 || gh.Bindings.IQNs[0] != "iqn.2026-01.wire:a" {
		t.Errorf("bindings did not decode: %+v", gh.Bindings)
	}

	// Listings decode as arrays.
	if vs, err := cl.List(ctx, applianceclient.KindVolume); err != nil || len(vs) == 0 {
		t.Errorf("List volumes: %v (%d)", err, len(vs))
	}
	if snaps, err := cl.List(ctx, applianceclient.KindSnapshot); err != nil || len(snaps) != 0 {
		t.Errorf("List snapshots: %v (%d) -- a volume must not appear here", err, len(snaps))
	}
	if hs, err := cl.ListHosts(ctx); err != nil || len(hs) == 0 {
		t.Errorf("ListHosts: %v (%d)", err, len(hs))
	}
	if _, err := cl.ListConnections(ctx, "", "", ""); err != nil {
		t.Errorf("ListConnections: %v", err)
	}

	// A missing object arrives typed.
	if _, err := cl.Get(ctx, applianceclient.KindVolume, "no-such-volume"); !applianceclient.IsCode(
		err, applianceclient.CodeNotFound) {
		t.Errorf("want %s, got %v", applianceclient.CodeNotFound, err)
	}
	// So does a connect with no lun, which the appliance never invents.
	_, _, err = cl.Connect(ctx, applianceclient.KindVolume, "wire-2", "wire-host", -1)
	if err == nil {
		t.Error("a negative lun must be refused")
	}

	// Health decodes with a verdict.
	if hl, err := cl.Health(ctx); err == nil && hl.Status == "" {
		t.Error("health decoded with no status")
	}

	// Delete frees the name, seen through the client.
	if err := cl.Delete(ctx, applianceclient.KindVolume, "wire-2"); err != nil {
		t.Errorf("Delete: %v", err)
	}
	if _, err := cl.Get(ctx, applianceclient.KindVolume, "wire-2"); !applianceclient.IsCode(
		err, applianceclient.CodeNotFound) {
		t.Errorf("the name still resolves after delete: %v", err)
	}
}

// TestPublishedClientReadsCreatedAndTarget: the created flag and Target are
// wire-level facts -- created is carried by the STATUS CODE, which no body
// field records, so only a real exchange can prove the client reads it.
func TestPublishedClientReadsCreatedAndTarget(t *testing.T) {
	c := bareCoordinator(t)
	srv := httptest.NewServer(Handler(c))
	defer srv.Close()

	cl, err := applianceclient.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	req := applianceclient.CreateRequest{Name: "dup-1", Size: 1 << 20}
	if _, created, err := cl.CreateVolume(ctx, req); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	} else if !created {
		t.Error("the first create must report created (201)")
	}
	// Same request again. This is the call an external controller makes when
	// it cannot tell whether its first attempt landed.
	second, created, err := cl.CreateVolume(ctx, req)
	if err != nil {
		t.Fatalf("repeating a create must succeed: %v", err)
	}
	if created {
		t.Error("a repeat must report created=false (200), not 201")
	}
	if second.Name != "dup-1" {
		t.Errorf("the existing object must come back: name = %q", second.Name)
	}

	// Hosts and connections carry the same signal by the same mechanism (the
	// client reads the status code, not a body field), but registering a host
	// commits and a commit reconciles configfs, so those are asserted live.

	// Target: the IQN and portals an initiator needs, which no connection
	// carries.
	tgt, err := cl.Target(ctx)
	if err != nil {
		t.Fatalf("Target: %v", err)
	}
	if tgt.TargetIQN != c.cfg.TargetIQN {
		t.Errorf("target_iqn = %q, want %q", tgt.TargetIQN, c.cfg.TargetIQN)
	}
}

// TestPublishedClientReadsADegradedHealthBody: degraded is served as HTTP 503,
// and the body is the only place the reason lives. The client used to turn any
// non-2xx into a bare error, discarding pr_unbound and the detail at the one
// moment a caller needs them.
func TestPublishedClientReadsADegradedHealthBody(t *testing.T) {
	c := bareCoordinator(t)
	c.healthErr = errors.New("reconcile failed: staged detail")
	srv := httptest.NewServer(Handler(c))
	defer srv.Close()

	cl, err := applianceclient.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	h, err := cl.Health(context.Background())
	if err != nil {
		t.Fatalf("a degraded appliance must still yield a verdict, got error: %v", err)
	}
	if h.Status != "degraded" {
		t.Errorf("status = %q, want degraded", h.Status)
	}
	if !strings.Contains(h.Error, "staged detail") {
		t.Errorf("the detail must survive the 503: error = %q", h.Error)
	}
}

// TestPublishedClientReadsTheFlagWarnings: both warnings were reachable only
// through the health BODY, and iqn_flag_ignored was populated on the server
// without ever being written to it -- a field that existed, was set, and could
// not be read by anyone. Asserted end to end so it cannot happen again to
// either of them.
func TestPublishedClientReadsTheFlagWarnings(t *testing.T) {
	c := bareCoordinator(t)
	c.portalFlagIgnored = "the -portals flag says X but the record says Y"
	c.iqnFlagIgnored = "the -iqn flag says A but the recorded target IQN is B"
	srv := httptest.NewServer(Handler(c))
	defer srv.Close()

	cl, err := applianceclient.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	h, err := cl.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.PortalFlagIgnored, "-portals") {
		t.Errorf("portal_flag_ignored did not reach the client: %q", h.PortalFlagIgnored)
	}
	if !strings.Contains(h.IQNFlagIgnored, "-iqn") {
		t.Errorf("iqn_flag_ignored did not reach the client: %q", h.IQNFlagIgnored)
	}
	// Neither is an error: the record winning is the design, not a fault.
	if h.Status != "ok" {
		t.Errorf("an ignored flag must not make the appliance unhealthy: %q", h.Status)
	}
}

// TestPublishedClientKeepsTheWarningOnAFailedDisconnect closes the loop the
// two halves of this project each got right on their own.
//
// The coordinator returns the warning WITH the error, because commit persists
// before it reconciles and the detach is durable by the time the reconcile
// fails. The handler puts it in the failure body for the same reason. The
// client then decoded only "error" and "code" and left the result struct zero,
// so the sentence saying a reservation was released never reached the caller.
// Each layer was tested against its own idea of the other; nothing tested the
// whole path, which is where it was lost.
//
// The fixture stages a reservation holder but not the target tree, so the
// reconcile inside commit fails after the db write succeeds -- the same one
// TestUnmapWarningSurvivesACommitFailure uses, driven end to end here.
func TestPublishedClientKeepsTheWarningOnAFailedDisconnect(t *testing.T) {
	c, v := stageHolder(t, "iqn.x:holder")
	srv := httptest.NewServer(Handler(c))
	defer srv.Close()

	cl, err := applianceclient.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.Disconnect(context.Background(), applianceclient.KindVolume, v.UUID, "holder")
	if err == nil {
		t.Fatal("this fixture must fail in reconcile, or it is not testing the path")
	}
	var e *applianceclient.Error
	if !errors.As(err, &e) {
		t.Fatalf("expected an appliance error, got %T: %v", err, err)
	}
	if !strings.Contains(e.Warning, "RELEASED") {
		t.Errorf("the fencing warning did not survive to the client: %q", e.Warning)
	}
	if !strings.Contains(err.Error(), "RELEASED") {
		t.Errorf("a caller that only logs err must still see it: %q", err.Error())
	}
	if !strings.Contains(resp.Warning, "RELEASED") {
		t.Errorf("the result is not zero just because the call failed: %+v", resp)
	}
}

// TestClearedReservationMatchesTheWireFormat covers the newest hand-copied
// struct, for the reason this file exists: applianceclient.ClearedReservation
// is a copy of the appliance's, not an alias, so a drifted JSON tag would
// decode as a zero value with nothing failing at compile time.
//
// Zero values are the whole risk here. This type reports whether a fence was
// broken and whether the saved record that would restore it was discarded --
// a tag that silently decoded to false would tell an operator "nothing was
// held, nothing was discarded" about an operation that did both.
func TestClearedReservationMatchesTheWireFormat(t *testing.T) {
	c := bareCoordinator(t)
	srv := httptest.NewServer(Handler(c))
	defer srv.Close()

	cl, err := applianceclient.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	v, _, err := cl.CreateVolume(ctx, applianceclient.CreateRequest{Name: "wire-clear", Size: 1 << 20})
	if err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}

	// Wrong confirmation: proves the endpoint is reachable through the client
	// and that a refusal is surfaced as an error rather than a zero result.
	if _, err := cl.ClearReservation(ctx, applianceclient.KindVolume, v.Name, "not-the-name"); err == nil {
		t.Fatal("an unconfirmed clear must be refused through the client too")
	}

	// The clear itself cannot succeed against a temp directory (the rebuild
	// needs configfs), and that is exactly the case worth asserting: the
	// appliance now serves the record on the FAILURE path, and the client
	// decodes it there. Before respondCleared it served only {error, code},
	// so everything below decoded as a zero value at the one moment the
	// fence may already be down.
	out, err := cl.ClearReservation(ctx, applianceclient.KindVolume, v.Name, v.Name)
	if err == nil {
		t.Fatal("expected the rebuild to fail against a temp directory; if this " +
			"now succeeds the assertions below need revisiting")
	}
	if out.Object != v.Name {
		t.Errorf("object did not decode on the failure path: got %q, want %q -- "+
			"either the json tag drifted or the error response dropped the record",
			out.Object, v.Name)
	}
	// The volume is unattached, so nothing is held -- but the state WAS
	// readable, and that must be reported as knowledge rather than as the zero
	// value, which means "could not tell".
	if !out.HeldKnown {
		t.Error("held_known did not decode; false here means 'could not tell', " +
			"which is not what happened")
	}
	if out.Held {
		t.Error("held decoded true for a volume with no reservation")
	}
	if out.Warning == "" {
		t.Error("warning did not decode on the failure path")
	}
}

// TestAccessLogSeesTheLeafRoute drives the access log against the REAL
// Handler, not a stand-in.
//
// The applog package can only test its own idea of the topology. This asserts
// the wiring: appliance.Handler mounts the API behind http.StripPrefix, which
// clones the request, so a leaf pattern is written on a clone the access log
// never sees. Without CaptureRoute inside the strip, every request in
// production logs the mount pattern "/v1/" -- one useless string for the whole
// API -- while a package-level test using a bare mux passes. That happened.
func TestAccessLogSeesTheLeafRoute(t *testing.T) {
	c := bareCoordinator(t)
	var buf bytes.Buffer
	l, _, err := applog.New(applog.Options{Format: "json", Out: &buf})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(applog.AccessLog(l, Handler(c)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/volumes")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	var m map[string]any
	line := strings.TrimSpace(buf.String())
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("access record is not JSON: %v: %s", err, line)
	}
	route, _ := m["route"].(string)
	if route == "/v1/" || route == "" {
		t.Fatalf("route = %q -- the leaf pattern did not reach the access log, so "+
			"every request in production logs the same string", route)
	}
	if !strings.Contains(route, "volumes") {
		t.Errorf("route = %q, want the matched leaf pattern", route)
	}
}
