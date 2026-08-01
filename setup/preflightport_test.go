package setup

import (
	"net"
	"strings"
	"testing"
)

// TestCheckPortAcceptsTheExpectedHolder pins the fix for `applianced
// preflight` answering NOT READY, exit 1, on a healthy host that was serving
// volumes at that moment: both of the appliance's ports are legitimately in
// use once it is running, and the check reported that as FATAL.
func TestCheckPortAcceptsTheExpectedHolder(t *testing.T) {
	// A real listener, so the bind really fails with EADDRINUSE rather than
	// the test asserting against a simulated error.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	t.Run("identified holder passes", func(t *testing.T) {
		var ok bool
		var detail string
		checkPort(func(_ string, pass bool, _ Severity, d string) { ok, detail = pass, d },
			"port:test", addr, func() string { return "a running appliance" })
		if !ok {
			t.Errorf("a port held by the expected holder failed the check: %s", detail)
		}
		if !strings.Contains(detail, "a running appliance") {
			t.Errorf("detail does not name the holder: %q", detail)
		}
	})

	// The negative control. Without it this check could not fail, and a check
	// that cannot fail is exactly what this commit is fixing.
	t.Run("unidentified holder still fails", func(t *testing.T) {
		var ok bool
		var detail string
		checkPort(func(_ string, pass bool, _ Severity, d string) { ok, detail = pass, d },
			"port:test", addr, func() string { return "" })
		if ok {
			t.Errorf("a port held by an unknown process passed the check: %s", detail)
		}
		if !strings.Contains(detail, "not bindable") {
			t.Errorf("detail does not explain the failure: %q", detail)
		}
	})

	t.Run("nil probe still fails", func(t *testing.T) {
		var ok bool
		checkPort(func(_ string, pass bool, _ Severity, _ string) { ok = pass },
			"port:test", addr, nil)
		if ok {
			t.Error("a held port passed with no holder probe at all")
		}
	})
}

// TestCheckPortFreePortPasses guards the ordinary pre-install case, where
// nothing is listening and the probe must never be consulted.
func TestCheckPortFreePortPasses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // now free, and very unlikely to be retaken

	var ok bool
	var detail string
	checkPort(func(_ string, pass bool, _ Severity, d string) { ok, detail = pass, d },
		"port:test", addr, func() string {
			t.Error("the holder probe was consulted for a port that was free")
			return "wrong"
		})
	if !ok {
		t.Errorf("a free port failed the check: %s", detail)
	}
	if !strings.Contains(detail, "is free") {
		t.Errorf("detail = %q, want it to say the port is free", detail)
	}
}

// TestCheckPortRejectsANonEADDRINUSEFailure pins that only "already in use"
// takes the holder path. A bind refused for permission, or to an address this
// host does not have, is a real fault and the probe must not excuse it.
func TestCheckPortRejectsANonEADDRINUSEFailure(t *testing.T) {
	var ok bool
	var detail string
	// An address no host has: bind fails with EADDRNOTAVAIL, not EADDRINUSE.
	checkPort(func(_ string, pass bool, _ Severity, d string) { ok, detail = pass, d },
		"port:test", "192.0.2.1:3260", func() string { return "a running appliance" })
	if ok {
		t.Errorf("a non-EADDRINUSE bind failure was excused by the holder probe: %s", detail)
	}
}
