package lio

import (
	"net/netip"
	"testing"

	"github.com/cwedgwood/glitr/lio/configfs"
)

// TestPortalNameRoundTrip pins the configfs naming rule for portals.
//
// IPv6 addresses contain colons, so an unbracketed "fd00::1:3260" is ambiguous
// and the kernel refuses it. MEASURED on Azure Linux 3.0, kernel 6.6.144.1,
// by mkdir into a live TPG's np/ directory:
//
//	np/fd00::1:3260    -> EINVAL (Invalid argument)
//	np/[fd00::1]:3260  -> accepted, reads back as [fd00::1]:3260
//	np/::1:3260        -> EINVAL
//	np/[::1]:3260      -> accepted
//
// Both directions matter and they failed for different reasons. Writing the
// bare form meant an IPv6 portal could never be created at all. Reading the
// bracketed form back without stripping would leave discovery reporting
// "[fd00::1]" against a desired "fd00::1" -- a portal the caller never asked
// for beside one it did, so every reconcile would try to create the second and
// prune the first, forever.
func TestPortalNameRoundTrip(t *testing.T) {
	cases := []struct {
		ip   string
		port uint16
		name string
	}{
		{"10.0.0.1", 3260, "10.0.0.1:3260"},
		{"0.0.0.0", 3260, "0.0.0.0:3260"},
		{"fd00::1", 3260, "[fd00::1]:3260"},
		{"::1", 3260, "[::1]:3260"},
		{"::", 3260, "[::]:3260"},
		{"fe80::5054:ff:fe12:350a", 3260, "[fe80::5054:ff:fe12:350a]:3260"},
		// A non-default port, so the test cannot pass by ignoring the port.
		{"fd00::1", 3261, "[fd00::1]:3261"},
	}
	for _, c := range cases {
		want := Portal{IP: mustAddr(c.ip), Port: c.port}
		if got := want.String(); got != c.name {
			t.Errorf("Portal{%s:%d}.String() = %q, want %q", c.ip, c.port, got, c.name)
		}
		got, ok := ParsePortal(c.name)
		if !ok {
			t.Errorf("ParsePortal(%q) failed", c.name)
			continue
		}
		if got != want {
			t.Errorf("ParsePortal(%q) = %s, want %s -- discovery must return the same "+
				"value the desired config holds or reconcile churns against it",
				c.name, got, want)
		}
	}
}

// TestPortalSpellingsAreOneValue is what moving the address off a string
// bought.
//
// One IPv6 address has many textual forms. While Portal.IP was a string they
// were distinct portals: validation's duplicate check passed, and the kernel
// then got two np directories for one endpoint and refused the second bind
// with EADDRINUSE -- a startup crash loop out of a config that looked fine.
// As netip.Addr values they are simply equal, and Portal is comparable, so
// the whole class is gone rather than guarded against.
func TestPortalSpellingsAreOneValue(t *testing.T) {
	for _, spellings := range [][]string{
		{"fd00::1", "fd00:0:0:0:0:0:0:1", "FD00::1", "fd00::0001", "[fd00::1]"},
		{"::", "0:0:0:0:0:0:0:0", "[::]"},
		{"10.0.0.1", "::ffff:10.0.0.1", "[10.0.0.1]"},
	} {
		first, ok := ParsePortal(spellings[0])
		if !ok {
			t.Fatalf("ParsePortal(%q) failed", spellings[0])
		}
		for _, s := range spellings[1:] {
			got, ok := ParsePortal(s)
			if !ok {
				t.Errorf("ParsePortal(%q) failed", s)
				continue
			}
			if got != first {
				t.Errorf("ParsePortal(%q) = %s, want it to equal ParsePortal(%q) = %s -- "+
					"these are one address, and treating them as two hands the kernel "+
					"the same endpoint twice", s, got, spellings[0], first)
			}
		}
	}
}

// TestParsePortalDefaultsThePort: a bare address is a portal on the standard
// iSCSI port, which is what an operator writing just an address means.
func TestParsePortalDefaultsThePort(t *testing.T) {
	for _, s := range []string{"10.0.0.1", "fd00::1", "[fd00::1]"} {
		p, ok := ParsePortal(s)
		if !ok {
			t.Fatalf("ParsePortal(%q) failed", s)
		}
		// 0 is the model's "unset", which port() renders as DefaultPortalPort.
		// Reported rather than filled in so a caller can tell an assumed port
		// from a written one and substitute its own default.
		if p.Port != 0 {
			t.Errorf("ParsePortal(%q).Port = %d, want 0 (unset)", s, p.Port)
		}
		if got := p.String(); got != s7(s) {
			t.Errorf("ParsePortal(%q).String() = %q, want the default port applied", s, got)
		}
	}
}

// TestParsePortalRejectsNonAddresses: hostnames and junk must fail rather
// than reach configfs, where the kernel reports a bare EINVAL naming nothing.
func TestParsePortalRejectsNonAddresses(t *testing.T) {
	for _, s := range []string{"", "target.example.com", "target.example.com:3260",
		"10.0.0.1:notaport", "10.0.0.999", "[fd00::1]:notaport", "[fd00::1"} {
		if p, ok := ParsePortal(s); ok {
			t.Errorf("ParsePortal(%q) = %s, want failure", s, p)
		}
	}
}

// TestUnbracketedIPv6WithAPortIsADifferentAddress is why the brackets are
// mandatory rather than a formality.
//
// "fd00::1:3260" looks like "fd00::1 port 3260" and is not: 3260 is four hex
// digits, so the whole string is a perfectly valid IPv6 address in its own
// right. Nothing can detect the operator's intent, and this is precisely the
// ambiguity that made the kernel refuse an unbracketed np/ name.
//
// Pinned as a test because it is the one input where a typo produces a
// working portal on an address nobody can reach -- IP_FREEBIND means the bind
// succeeds even though the host does not hold the address -- rather than an
// error. The defence is that /target and `applianced inspect` render portals
// through Portal.String, so what is listening is shown back bracketed and in
// full.
func TestUnbracketedIPv6WithAPortIsADifferentAddress(t *testing.T) {
	got, ok := ParsePortal("fd00::1:3260")
	if !ok {
		t.Fatal("fd00::1:3260 is a valid IPv6 address and must parse as one")
	}
	want := Portal{IP: mustAddr("fd00::1:3260")}
	if got != want {
		t.Errorf("ParsePortal(\"fd00::1:3260\") = %s, want %s", got, want)
	}
	if bracketed, _ := ParsePortal("[fd00::1]:3260"); got.IP == bracketed.IP {
		t.Error("the two forms name DIFFERENT addresses; if they ever compare equal " +
			"the brackets have stopped meaning anything")
	}
}

// TestPortalZeroPortRenders: Port 0 means "the default", and String must show
// the port the kernel will actually use -- the configfs directory is named
// with it.
func TestPortalZeroPortRenders(t *testing.T) {
	if got := (Portal{IP: netip.MustParseAddr("10.0.0.1")}).String(); got != "10.0.0.1:3260" {
		t.Errorf("Portal with unset port = %q, want 10.0.0.1:3260", got)
	}
}

// s7 renders the expected default-port form of a bare address.
func s7(bare string) string {
	p, _ := ParsePortal(bare)
	return netip.AddrPortFrom(p.IP, DefaultPortalPort).String()
}

// TestParsePortalRejectsZone pins that a link-local zone is refused.
//
// netip.ParseAddr accepts "fe80::1%eth0" and Portal.String renders it back
// verbatim, which produces a configfs directory name the kernel rejects with
// EINVAL -- a failure several layers away from the text that caused it.
func TestParsePortalRejectsZone(t *testing.T) {
	for _, s := range []string{
		"fe80::1%eth0",
		"[fe80::1%eth0]",
		"[fe80::1%eth0]:3260",
	} {
		if p, ok := ParsePortal(s); ok {
			t.Errorf("ParsePortal(%q) accepted a zoned address as %v", s, p)
		}
	}
	// The negative control: the same addresses without a zone must parse, so
	// this test cannot pass by rejecting everything.
	for _, s := range []string{"fe80::1", "[fe80::1]", "[fe80::1]:3260"} {
		if _, ok := ParsePortal(s); !ok {
			t.Errorf("ParsePortal(%q) rejected an unzoned address", s)
		}
	}
}

// TestWildcardPrecludesEverythingOnItsPort pins the workaround for the LIO
// np-match bug.
//
// iscsit_check_np_match (linux v6.6 drivers/target/iscsi/iscsi_target.c:265)
// casts both addresses using the NEW address's family, so adding 0.0.0.0 reads
// an existing IPv6 portal's sin6_flowinfo (normally 0) as sin_addr and
// false-matches it. MEASURED on kernel 6.6: with [fd00:10:10::1]:9270 present,
// 0.0.0.0:9270 was REJECTED while 10.10.0.99:9270 was ACCEPTED.
//
// The rule used to be "0.0.0.0 conflicts with IPv4 only", which left the live
// IPv6 portal in place and let the add fail -- crash-looping applianced under
// Restart=on-failure.
func TestWildcardPrecludesEverythingOnItsPort(t *testing.T) {
	v4any := netip.MustParseAddr("0.0.0.0")
	v6any := netip.MustParseAddr("::")
	v4 := netip.MustParseAddr("10.10.0.1")
	v6 := netip.MustParseAddr("fd00:10:10::1")

	// Both wildcards must preclude both families. The IPv4 one is the
	// regression: it is the case the kernel gets wrong.
	for _, tc := range []struct{ w, other netip.Addr }{
		{v4any, v6}, {v4any, v4}, {v6any, v4}, {v6any, v6},
	} {
		if !wildcardPrecludes(tc.w, tc.other) {
			t.Errorf("wildcardPrecludes(%v, %v) = false; a live %v would be left "+
				"in place and the %v add would fail", tc.w, tc.other, tc.other, tc.w)
		}
	}

	// The negative control: a SPECIFIC address precludes nothing, or every
	// reconcile would tear down portals it had no reason to touch.
	for _, tc := range []struct{ w, other netip.Addr }{
		{v4, v6}, {v4, v4}, {v6, v4}, {v6, v6},
	} {
		if wildcardPrecludes(tc.w, tc.other) {
			t.Errorf("wildcardPrecludes(%v, %v) = true, but %v is not a wildcard",
				tc.w, tc.other, tc.w)
		}
	}

	// An invalid address is not a wildcard either -- a zero netip.Addr must not
	// read as "unspecified" and prune the whole port.
	if wildcardPrecludes(netip.Addr{}, v4) || wildcardPrecludes(v4any, netip.Addr{}) {
		t.Error("an invalid address took part in a conflict decision")
	}
}

// TestPortalApplyOrderPutsWildcardsFirst pins that a valid portal set applies
// regardless of the order it was written in.
//
// The kernel accepts 0.0.0.0 alongside an IPv6 portal only if the wildcard goes
// first, so applying in the operator's written order made the same desired
// state succeed or fail on the spelling of a flag.
func TestPortalApplyOrderPutsWildcardsFirst(t *testing.T) {
	mk := func(ss ...string) []Portal {
		var out []Portal
		for _, s := range ss {
			p, ok := ParsePortal(s)
			if !ok {
				t.Fatalf("ParsePortal(%q) failed", s)
			}
			out = append(out, p)
		}
		return out
	}

	// The order that used to crash-loop the daemon.
	in := mk("[fd00:10:10::1]:3260", "10.10.0.1:3260", "0.0.0.0:3260")
	got := portalApplyOrder(in)
	if !got[0].IP.IsUnspecified() {
		t.Errorf("applied %v first; the wildcard must lead or the kernel refuses it", got[0])
	}

	// Specific addresses keep their relative order, so the output stays
	// predictable and a diff of two runs is readable.
	if got[1].IP.String() != "fd00:10:10::1" || got[2].IP.String() != "10.10.0.1" {
		t.Errorf("specific portals were reordered: %v", got)
	}

	// The input must not be mutated: it is the caller's desired state, and a
	// reconciler that edits its own input starts disagreeing with itself.
	if in[0].IP.String() != "fd00:10:10::1" {
		t.Errorf("portalApplyOrder mutated its input: %v", in)
	}

	// The negative control: a set with no wildcard must come back untouched,
	// or this function is reordering things for no reason.
	plain := mk("[fd00:10:10::1]:3260", "10.10.0.1:3260")
	out := portalApplyOrder(plain)
	for i := range plain {
		if out[i].key() != plain[i].key() {
			t.Errorf("a set with no wildcard was reordered: %v -> %v", plain, out)
			break
		}
	}
}

// TestPortalPruneClearsTheWayForAWildcard pins the transition that this whole
// prune phase exists for, and the steady state it must not disturb.
//
// REPRODUCED before the fix: live [fd00:10:10::1]:3260, desired
// {[fd00:10:10::1]:3260, 0.0.0.0:3260}. The live portal is itself desired, so
// "identical to a desired portal never conflicts" declined to prune it, the
// wildcard could not bind (see wildcardPrecludes), and applianced sat in
// state=activating restarting forever with "mkdir .../np/0.0.0.0:3260:
// invalid argument".
func TestPortalPruneClearsTheWayForAWildcard(t *testing.T) {
	mk := func(s string) Portal {
		p, ok := ParsePortal(s)
		if !ok {
			t.Fatalf("ParsePortal(%q) failed", s)
		}
		return p
	}
	v6 := mk("[fd00:10:10::1]:3260")
	any4 := mk("0.0.0.0:3260")
	v4 := mk("10.10.0.1:3260")
	other := mk("10.10.0.1:9260") // different port: never involved

	// The transition: the wildcard is desired but not yet live, so the
	// specific portal must go even though it is itself desired.
	if !portalConflictsWithAny(v6, []Portal{v6, any4}, []Portal{v6}) {
		t.Error("did not prune a live portal blocking a desired wildcard; the " +
			"wildcard cannot bind and the daemon crash-loops")
	}

	// The steady state: both live, both desired. Nothing may be pruned, or the
	// portal flaps on every reconcile -- and reconcile runs on every volume
	// operation.
	if portalConflictsWithAny(v6, []Portal{v6, any4}, []Portal{v6, any4}) {
		t.Error("pruned a portal in the steady state; this flaps on every reconcile")
	}
	if portalConflictsWithAny(any4, []Portal{v6, any4}, []Portal{v6, any4}) {
		t.Error("pruned the wildcard itself")
	}

	// A wildcard already live must not be pruned to make way for itself.
	if portalConflictsWithAny(any4, []Portal{any4}, []Portal{any4}) {
		t.Error("the wildcard was treated as blocking itself")
	}

	// A portal on a DIFFERENT port is untouched by a wildcard elsewhere.
	if portalConflictsWithAny(other, []Portal{other, any4}, []Portal{other}) {
		t.Error("pruned a portal on an unrelated port")
	}

	// The ordinary conflict still works: live wildcard, desired specific.
	if !portalConflictsWithAny(any4, []Portal{v4}, []Portal{any4}) {
		t.Error("a live wildcard no longer conflicts with a desired specific address")
	}

	// The negative control: a live portal that is simply not desired is NOT a
	// conflict -- it belongs to the ordinary prune, and pruning it here would
	// make this a second, differently-ordered removal path.
	if portalConflictsWithAny(v4, []Portal{v6}, []Portal{v4, v6}) {
		t.Error("an unrelated undesired portal was treated as a conflict")
	}
}

// TestConfigfsZeroValueIsRefused pins that a forgotten constructor is an error
// rather than a silent retarget.
//
// configfs.FS is a struct with one exported field, so &configfs.FS{} is easy
// to write, and filepath.Join("", parts...) is RELATIVE -- every operation
// would have resolved against the process's working directory, pointing a
// library whose whole job is containment at $PWD.
func TestConfigfsZeroValueIsRefused(t *testing.T) {
	m := New(&configfs.FS{})
	if _, err := m.Discover(); err == nil {
		t.Error("Discover on a zero-value FS returned no error")
	}
	// A real root still works, so this cannot pass by rejecting everything.
	if _, err := New(configfs.New(t.TempDir())).Discover(); err != nil {
		t.Errorf("a properly constructed FS was refused: %v", err)
	}
}

// TestPoisonBackstoreNamesAreRejected: "." and ".." pass the character check
// but configfs will never accept them, so a record carrying one validates when
// it is persisted and then fails every reconcile afterwards, startup replay
// included.
func TestPoisonBackstoreNamesAreRejected(t *testing.T) {
	for _, name := range []string{".", ".."} {
		cfg := Config{Backstores: []Backstore{{Type: FileIO, Name: name, Dev: "/tmp/x", Size: 1 << 20}}}
		if err := cfg.Validate(); err == nil {
			t.Errorf("backstore name %q was accepted", name)
		}
	}
	ok := Config{Backstores: []Backstore{{Type: FileIO, Name: "vol0", Dev: "/tmp/x", Size: 1 << 20}}}
	if err := ok.Validate(); err != nil {
		t.Errorf("a normal name was rejected: %v", err)
	}
}
