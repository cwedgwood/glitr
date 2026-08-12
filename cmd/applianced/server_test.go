package main

import (
	"errors"
	"github.com/cwedgwood/glitr/applog"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cwedgwood/glitr/appliance"
)

// TestRESTServerDropsASilentClient: the daemon used to build its server as
// &http.Server{Addr, Handler} with no timeouts at all, so a client that
// connected and then sent nothing held the connection -- and its goroutine --
// until the process restarted. A half-open TCP session left by a network
// partition does exactly that, and an appliance is precisely the thing sitting
// on the far side of one.
//
// Behaviour, not constants: asserting ReadHeaderTimeout == 5s would only
// restate the constructor. This connects, stays silent, and requires the
// server to hang up.
//
// The deadline is derived from the server's OWN setting, so lowering the
// timeout makes the test faster rather than wrong; removing it makes the test
// fail, which is the point.
func TestRESTServerDropsASilentClient(t *testing.T) {
	srv := newRESTServer("127.0.0.1:0", http.NotFoundHandler(), testLogHandler(t))
	if srv.ReadHeaderTimeout <= 0 {
		t.Fatal("no ReadHeaderTimeout: a client that never sends a request line " +
			"holds this connection forever")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Say nothing at all, then wait for the server to give up on us.
	slack := 3 * time.Second
	if err := conn.SetReadDeadline(time.Now().Add(srv.ReadHeaderTimeout + slack)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatalf("the server sent data to a client that never made a request")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Errorf("the connection was still open %v after opening it without sending a "+
			"request; ReadHeaderTimeout is %v but nothing enforced it",
			srv.ReadHeaderTimeout+slack, srv.ReadHeaderTimeout)
	}
	// Any other error (EOF / connection reset) means the server hung up, which
	// is the required behaviour.
}

// TestRESTServerStillServesRealRequests is the counter-test: bounding a
// connection's life must not break an ordinary request. A WriteTimeout set too
// aggressively would truncate responses instead of leaking connections, which
// is a worse failure because it looks like data corruption.
func TestRESTServerStillServesRealRequests(t *testing.T) {
	srv := newRESTServer("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	}), testLogHandler(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	resp, err := http.Get("http://" + ln.Addr().String() + appliance.APIPrefix + "/health")
	if err != nil {
		t.Fatalf("an ordinary request must still succeed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got HTTP %d", resp.StatusCode)
	}
	if srv.WriteTimeout < 10*time.Second {
		t.Errorf("WriteTimeout is %v, tight enough to risk truncating a real response; "+
			"the reason it can be generous is that no endpoint here streams or blocks",
			srv.WriteTimeout)
	}
}

// TestRunServerWaitsForInFlightHandlers pins the drain JOIN, not merely the
// presence of a Shutdown call.
//
// Shutdown closes the listener before it waits for handlers, so serveFn returns
// ErrServerClosed almost immediately. Code that returns there exits the process
// while Shutdown is still draining -- the handlers it was supposed to protect
// die anyway. That is exactly what this daemon did: the comment claimed
// "Shutdown drains in-flight HTTP handlers, and that is what waits for a
// reconcile" while nothing joined the goroutine.
//
// A handler that is still running when runServer returns is the failure. The
// handler here stands in for a reconcile: the operation that must not be cut.
func TestRunServerWaitsForInFlightHandlers(t *testing.T) {
	var finished atomic.Bool
	const handlerWork = 300 * time.Millisecond

	started := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(handlerWork)
		finished.Store(true)
		w.WriteHeader(http.StatusOK)
	})}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	drained := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runServer(slog.Default(), func() error { return srv.Serve(ln) }, srv, stop, drained, 5*time.Second)
	}()

	// Put a request in flight, then signal shutdown while it is still running.
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/")
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never started; the fixture is wrong")
	}
	close(stop)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("clean shutdown must not error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runServer never returned")
	}

	if !finished.Load() {
		t.Error("runServer returned while a handler was still running: the drain was " +
			"started but never joined, so the process would exit mid-reconcile")
	}
}

// TestRunServerReturnsAListenerError: a real serve failure must propagate
// rather than block forever waiting for a drain that will never be signalled.
func TestRunServerReturnsAListenerError(t *testing.T) {
	srv := &http.Server{Handler: http.NotFoundHandler()}
	want := errors.New("listener exploded")

	done := make(chan error, 1)
	go func() {
		done <- runServer(slog.Default(), func() error { return want }, srv,
			make(chan struct{}), make(chan struct{}), time.Second)
	}()

	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Errorf("got %v, want the serve error propagated", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a serve error must not block on the drain: nothing will close stop")
	}
}

// testLogHandler gives newRESTServer a handler for http.Server.ErrorLog
// without putting net/http's internal chatter on the test output.
func testLogHandler(t *testing.T) slog.Handler {
	t.Helper()
	_, h, err := applog.New(applog.Options{Out: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	return h
}
