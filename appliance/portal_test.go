package appliance

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cwedgwood/glitr/lio"
	"github.com/cwedgwood/glitr/lio/configfs"
	"github.com/cwedgwood/glitr/storage"
)

// TestPortalDuplicateDetectionIsAddressBased is the regression test for a
// crash loop reachable through the validation meant to prevent it.
//
// The duplicate and wildcard-overlap checks compared the literal text of the
// address. One IPv6 address has many spellings, so fd00::1 and
// fd00:0:0:0:0:0:0:1 were accepted as two distinct portals. The kernel then
// created two np directories for one endpoint and refused the second bind
// with EADDRINUSE, which configfs flattens to a bare EINVAL naming nothing --
// applianced exits, systemd restarts it, and the log never mentions portals.
func TestPortalDuplicateDetectionIsAddressBased(t *testing.T) {
	for _, tc := range []struct{ name, spec string }{
		{"expanded IPv6", "fd00::1,fd00:0:0:0:0:0:0:1"},
		{"uppercase IPv6", "fd00::1,FD00::1"},
		{"leading-zero IPv6", "fd00::1,fd00::0001"},
		{"v4-mapped v6", "10.0.0.1,::ffff:10.0.0.1"},
		{"expanded v6 wildcard", "0:0:0:0:0:0:0:0,fd00::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			portals, err := ParsePortals(tc.spec, 3260)
			if err != nil {
				t.Fatalf("ParsePortals: %v", err)
			}
			cfg := Config{TargetIQN: "iqn.2026-01.dev.glitr:appliance", Portals: portals}
			if err := cfg.Validate(); err == nil {
				t.Errorf("%q must be rejected: both entries are the same address, so the "+
					"kernel binds it once and fails the second with EADDRINUSE -- the "+
					"exact crash loop this validation exists to prevent", tc.spec)
			}
		})
	}
}

// TestPortalSpellingsAreCanonicalised guards the other half: distinct
// addresses written unusually must still be accepted, and must reach configfs
// under one spelling so the discovered tree compares equal to the desired one.
func TestPortalSpellingsAreCanonicalised(t *testing.T) {
	portals, err := ParsePortals("FD00::1,[fd00:0:0:0:0:0:0:2]:3261", 3260)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{TargetIQN: "iqn.2026-01.dev.glitr:appliance", Portals: portals}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("two different addresses must be accepted: %v", err)
	}
	if portals[0].IP != mustAddr("fd00::1") {
		t.Errorf("portal[0].IP = %q, want the canonical %q", portals[0].IP, "fd00::1")
	}
	if portals[1].IP != mustAddr("fd00::2") || portals[1].Port != 3261 {
		t.Errorf("portal[1] = %v, want fd00::2 port 3261", portals[1])
	}
}

// TestParsePortalsRejectsWhatIsNotAnAddress covers the checks that used to
// live in Config.Validate.
//
// They moved because they became impossible to express there: Portal.IP is a
// netip.Addr, so a hostname, a leading space or an empty element cannot reach
// a Config at all. This is the boundary where text becomes an address, and the
// only place those inputs still exist.
func TestParsePortalsRejectsWhatIsNotAnAddress(t *testing.T) {
	for _, tc := range []struct{ name, spec string }{
		{"hostname", "localhost"},
		{"hostname with a port", "target.example.com:3260"},
		// A stray comma yields an empty element. Dropping it silently would
		// leave the target listening somewhere the operator did not intend.
		{"stray comma", "10.0.0.1,"},
		{"leading whitespace", " 10.0.0.1"},
		{"trailing whitespace", "10.0.0.1 "},
		{"non-numeric port", "10.0.0.1:iscsi"},
		{"out-of-range octet", "10.0.0.999"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := ParsePortals(tc.spec, 3260); err == nil {
				t.Errorf("ParsePortals(%q) = %v, want an error naming -portals", tc.spec, got)
			} else if !strings.Contains(err.Error(), "-portals") {
				t.Errorf("the error must name the setting so the operator knows what to "+
					"fix, got: %v", err)
			}
		})
	}
}

// TestSamePortalSetIsOrderIndependent pins that portal identity is a SET.
//
// The reconciler reorders portals on purpose -- lio.portalApplyOrder puts
// wildcards first, because the kernel will not bind one while another address
// holds its port -- so comparing lists positionally would report a change on
// every reconcile and bounce the fabric.
func TestSamePortalSetIsOrderIndependent(t *testing.T) {
	mk := func(ss ...string) []lio.Portal {
		var out []lio.Portal
		for _, s := range ss {
			p, ok := lio.ParsePortal(s)
			if !ok {
				t.Fatalf("ParsePortal(%q)", s)
			}
			out = append(out, p)
		}
		return out
	}

	a := mk("10.10.0.1:3260", "[fd00::1]:3260")
	if !samePortalSet(a, mk("[fd00::1]:3260", "10.10.0.1:3260")) {
		t.Error("the same two portals in the other order compared unequal")
	}
	// The negative controls: a real difference must still register.
	if samePortalSet(a, mk("10.10.0.1:3260")) {
		t.Error("a shorter list compared equal")
	}
	if samePortalSet(a, mk("10.10.0.1:3260", "[fd00::2]:3260")) {
		t.Error("a different address compared equal")
	}
	if samePortalSet(a, mk("10.10.0.1:3270", "[fd00::1]:3260")) {
		t.Error("a different PORT compared equal -- a portal is an endpoint")
	}
	// Duplicates must not let a multiset masquerade as a set.
	if samePortalSet(mk("10.10.0.1:3260", "10.10.0.1:3260"), mk("10.10.0.1:3260", "[fd00::1]:3260")) {
		t.Error("a doubled entry compared equal to a two-address list")
	}
	if !samePortalSet(nil, nil) {
		t.Error("two empty lists compared unequal")
	}
}

// TestSetPortalsRefusesToRemoveEveryPortal pins the one change this API must
// never make.
//
// Emptying the list takes away every address the target answers on. The REST
// listener is a SEPARATE socket, so the caller keeps its connection and gets a
// success -- having made the fabric unreachable, with no way back through the
// same API.
func TestSetPortalsRefusesToRemoveEveryPortal(t *testing.T) {
	t.Chdir(t.TempDir()) // so a stray write lands somewhere disposable
	c := &Coordinator{cfg: Config{TargetIQN: "iqn.2026-01.dev.glitr:t"}}
	if _, err := c.SetPortals(nil); err == nil {
		t.Fatal("accepted an empty portal list")
	} else if !strings.Contains(err.Error(), "every portal") {
		t.Errorf("refusal does not explain itself: %v", err)
	}

	// The negative control: a non-empty list must not be refused BY THIS
	// GUARD. It fails later here (a bare Coordinator has no database path),
	// so assert on which failure it is, not merely that one happened.
	p, _ := lio.ParsePortal("10.10.0.1:3260")
	if _, err := c.SetPortals([]lio.Portal{p}); err != nil &&
		strings.Contains(err.Error(), "every portal") {
		t.Errorf("the empty-list guard fired on a one-portal list: %v", err)
	}
}

// TestAdoptPortalsPrecedence pins the flag-vs-record rule, which is the part
// of this feature with a real footgun.
//
// Rule: an unrecorded list adopts the boot flag and is persisted, so
// "unrecorded" stops existing. Once recorded, the RECORD WINS -- otherwise a
// portal set changed over REST is silently undone by the next restart and the
// API is a lie. Because that inverts the usual expectation that a flag
// controls the daemon, a flag that DISAGREES is reported rather than ignored.
func TestAdoptPortalsPrecedence(t *testing.T) {
	mk := func(ss ...string) []lio.Portal {
		var out []lio.Portal
		for _, s := range ss {
			p, ok := lio.ParsePortal(s)
			if !ok {
				t.Fatalf("ParsePortal(%q)", s)
			}
			out = append(out, p)
		}
		return out
	}
	newC := func(flag, recorded []lio.Portal) *Coordinator {
		return &Coordinator{
			cfg:    Config{TargetIQN: "iqn.2026-01.dev.glitr:t", Portals: flag},
			dbPath: filepath.Join(t.TempDir(), "appliance.json"),
			st:     dbState{Exports: map[string]int{}, Portals: recorded},
		}
	}

	// 1. Unrecorded adopts the flag, and persists it.
	c := newC(mk("10.10.0.1:3260"), nil)
	if err := c.adoptPortals(); err != nil {
		t.Fatal(err)
	}
	if !samePortalSet(c.st.Portals, mk("10.10.0.1:3260")) {
		t.Errorf("did not adopt the flag: %v", c.st.Portals)
	}
	if c.portalFlagIgnored != "" {
		t.Errorf("warned about a flag it just adopted: %q", c.portalFlagIgnored)
	}
	if _, err := os.Stat(c.dbPath); err != nil {
		t.Errorf("adoption was not persisted, so it would re-adopt every boot: %v", err)
	}

	// 2. A record that AGREES with the flag is kept, silently.
	c = newC(mk("10.10.0.1:3260"), mk("10.10.0.1:3260"))
	if err := c.adoptPortals(); err != nil {
		t.Fatal(err)
	}
	if c.portalFlagIgnored != "" {
		t.Errorf("warned when flag and record agree: %q", c.portalFlagIgnored)
	}

	// 3. A record that DISAGREES wins, and the disagreement is REPORTED. This
	//    is the footgun: an operator edits the unit, restarts, and nothing
	//    changes. Silence here would be the defect.
	c = newC(mk("10.10.0.1:3260"), mk("[fd00::1]:3260"))
	if err := c.adoptPortals(); err != nil {
		t.Fatal(err)
	}
	if !samePortalSet(c.portals(), mk("[fd00::1]:3260")) {
		t.Errorf("the flag overrode the record: %v", c.portals())
	}
	if c.portalFlagIgnored == "" {
		t.Fatal("the record silently overrode the flag with no warning")
	}
	for _, must := range []string{"10.10.0.1:3260", "fd00::1", "appliance.json"} {
		if !strings.Contains(c.portalFlagIgnored, must) {
			t.Errorf("the warning omits %q, so it does not say what to do: %q",
				must, c.portalFlagIgnored)
		}
	}

	// 4. Order alone is not a disagreement -- the reconciler reorders portals
	//    deliberately, so this must not warn on every boot.
	c = newC(mk("10.10.0.1:3260", "[fd00::1]:3260"), mk("[fd00::1]:3260", "10.10.0.1:3260"))
	if err := c.adoptPortals(); err != nil {
		t.Fatal(err)
	}
	if c.portalFlagIgnored != "" {
		t.Errorf("a reordering was reported as a disagreement: %q", c.portalFlagIgnored)
	}
}

// TestPersistRefusesAnEmptyDBPath pins that a misconfigured Coordinator says
// so rather than writing state into the process's working directory.
//
// persist() builds its temp file as dbPath+".tmp". With an empty dbPath that
// is ".tmp" relative to the CWD, and the rename to "" then fails, leaving the
// file behind. That is how appliance/.tmp -- containing a lab portal address
// -- came to be committed to this repository: a test constructed a bare
// Coordinator, and every subsequent `go test ./appliance/` recreated it.
func TestPersistRefusesAnEmptyDBPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	err := (&Coordinator{}).persist()
	if err == nil {
		t.Fatal("persist() with an empty dbPath returned no error")
	}
	if !strings.Contains(err.Error(), "no database path") {
		t.Errorf("refusal does not explain itself: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, ".tmp")); statErr == nil {
		t.Error("persist() wrote .tmp into the working directory")
	}
}

// TestOpenRefusesNilDependencies pins that a caller's mistake arrives as an
// error and not as a panic. Open performs a startup reconcile, which calls
// straight into the lio manager, so a nil one surfaced as a nil-pointer
// dereference inside lio.Sync -- a stack trace naming neither Open nor the
// argument that was wrong, in a daemon that is now dead.
func TestOpenRefusesNilDependencies(t *testing.T) {
	cfg := Config{TargetIQN: "iqn.2026-01.dev.glitr:t"}

	if _, err := Open(t.TempDir(), nil, nil, cfg); err == nil {
		t.Fatal("Open accepted a nil store")
	} else if !strings.Contains(err.Error(), "nil storage store") {
		t.Errorf("refusal does not name the problem: %v", err)
	}

	st, err := storage.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.TempDir(), st, nil, cfg); err == nil {
		t.Fatal("Open accepted a nil lio manager")
	} else if !strings.Contains(err.Error(), "nil lio manager") {
		t.Errorf("refusal does not name the problem: %v", err)
	}
}

// TestTargetIsSafeUnderConcurrentSetPortals is the regression test for a data
// race that -race could not see because nothing drove the two paths at once.
//
// portals() requires c.mu; Target did not take it, while SetPortals writes
// c.st.Portals under the lock. net/http serves each request on its own
// goroutine, so GET /target racing PUT /target/portals read a slice header
// mid-replacement. Every sibling accessor locked; this one was the outlier.
func TestTargetIsSafeUnderConcurrentSetPortals(t *testing.T) {
	c := &Coordinator{
		cfg:    Config{TargetIQN: "iqn.2026-01.dev.glitr:t"},
		lio:    lio.New(configfs.New(t.TempDir())),
		dbPath: filepath.Join(t.TempDir(), "appliance.json"),
		st: dbState{
			Exports: map[string]int{},
			Portals: []lio.Portal{{IP: mustAddr("10.0.0.1"), Port: 3260}},
		},
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				iqn, portals := c.Target()
				if iqn == "" {
					t.Error("Target returned an empty IQN")
					return
				}
				_ = portals
			}
		}
	})
	// SetPortals will fail here (no lio manager reachable), which is fine:
	// it takes c.mu and mutates c.st.Portals on the way, and that is the
	// write this test races against.
	for i := range 60 {
		_, _ = c.SetPortals([]lio.Portal{{IP: mustAddr("10.0.0.2"), Port: uint16(3260 + i%3)}})
	}
	close(stop)
	wg.Wait()
}
