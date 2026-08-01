package appliance

import (
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/cwedgwood/glitr/lio"
	"github.com/cwedgwood/glitr/lio/configfs"
	"github.com/cwedgwood/glitr/storage"
)

// TestDesiredLIOValidateGate is the poison-record guard: a host carrying an
// invalid IQN must make desiredLIO().Validate() fail, so commit() rejects the
// request BEFORE persisting (a persisted bad record would brick startup replay).
func TestDesiredLIOValidateGate(t *testing.T) {
	store, err := storage.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := &Coordinator{
		store: store,
		cfg:   Config{TargetIQN: "iqn.2026-01.dev.glitr:app"},
		st: dbState{
			Hosts:   []*Host{{UUID: "h1", IQNs: []string{"NOT_A_VALID_IQN"}}},
			Exports: map[string]int{},
		},
	}
	if err := c.desiredLIO().Validate(); err == nil {
		t.Fatal("desiredLIO().Validate() must reject an invalid initiator IQN (poison guard)")
	}
}

func TestValidIQN(t *testing.T) {
	if !validIQN("iqn.2026-01.dev.glitr:host") {
		t.Fatal("valid IQN rejected")
	}
	for _, bad := range []string{"", "host", "naa.123", "IQN.x"} {
		if validIQN(bad) {
			t.Errorf("validIQN accepted %q", bad)
		}
	}
}

func TestCopyHostIndependent(t *testing.T) {
	h := Host{UUID: "h", IQNs: []string{"iqn.x:a"}}
	cp := copyHost(h)
	cp.IQNs[0] = "mutated"
	if h.IQNs[0] != "iqn.x:a" {
		t.Fatal("copyHost did not copy the IQNs slice (shared backing array)")
	}
}

// TestBackstoreNameFullUUID: the backstore name uses the full 32-hex UUID
// (no truncation) so two volumes cannot collide on a duplicate name.
func TestBackstoreNameFullUUID(t *testing.T) {
	a := backstoreName("0be90312-8dad-4786-b28e-af4cc210d023")
	b := backstoreName("0be90312-8dad-4786-ffff-ffffffffffff") // same first 12 hex
	if a == b {
		t.Fatalf("backstore names collide on a shared 12-hex prefix: %s", a)
	}
	if !strings.HasPrefix(a, "vol_") || len(a) != len("vol_")+32 {
		t.Fatalf("unexpected backstore name %q", a)
	}
}

func TestStatusErrorMapping(t *testing.T) {
	var se *StatusError
	err := statusErr(http.StatusConflict, "conflict %d", 1)
	if !errors.As(err, &se) || se.Code != http.StatusConflict || se.Msg != "conflict 1" {
		t.Fatalf("statusErr wrong: %+v", err)
	}
}

// TestValidateLoadedRejectsCorruptDb: a corrupt/foreign appliance.json must
// fail startup with a clear error rather than panic (null records) or load a
// record set that can only fail later, three layers down, inside reconcile.
func TestValidateLoadedRejectsCorruptDb(t *testing.T) {
	const hostA = "11111111-1111-4111-8111-111111111111"
	const hostB = "22222222-2222-4222-8222-222222222222"
	const volA = "33333333-3333-4333-8333-333333333333"
	const volB = "44444444-4444-4444-8444-444444444444"
	iqn := "iqn.2025-01.example:init1"

	for name, st := range map[string]dbState{
		"null-host":       {Hosts: []*Host{nil}},
		"null-attachment": {Attachments: []*Attachment{nil}},
		"bad-host-uuid":   {Hosts: []*Host{{UUID: "not-a-uuid", IQNs: []string{iqn}}}},
		"no-iqns":         {Hosts: []*Host{{UUID: hostA}}},
		"bad-iqn":         {Hosts: []*Host{{UUID: hostA, IQNs: []string{"iqn.bad/evil"}}}},
		"duplicate-host": {Hosts: []*Host{
			{UUID: hostA, IQNs: []string{iqn}}, {UUID: hostA, IQNs: []string{iqn + "x"}}}},
		"iqn-claimed-twice": {Hosts: []*Host{
			{UUID: hostA, IQNs: []string{iqn}}, {UUID: hostB, IQNs: []string{iqn}}}},
		"dangling-host": {
			Hosts:       []*Host{{UUID: hostA, IQNs: []string{iqn}}},
			Attachments: []*Attachment{{VolumeUUID: volA, HostUUID: hostB, Desired: "attached"}}},
		"lun-out-of-range": {
			Hosts:       []*Host{{UUID: hostA, IQNs: []string{iqn}}},
			Attachments: []*Attachment{{VolumeUUID: volA, HostUUID: hostA, LUN: 1 << 20, Desired: "attached"}}},
		"duplicate-lun-on-host": {
			Hosts: []*Host{{UUID: hostA, IQNs: []string{iqn}}},
			Attachments: []*Attachment{
				{VolumeUUID: volA, HostUUID: hostA, LUN: 1, Desired: "attached"},
				{VolumeUUID: volB, HostUUID: hostA, LUN: 1, Desired: "attached"}}},
		// Two volumes at one TPG LUN index cannot both be exported.
		"export-index-collision": {Exports: map[string]int{volA: 0, volB: 0}},
		"export-bad-uuid":        {Exports: map[string]int{"../etc": 0}},
	} {
		t.Run(name, func(t *testing.T) {
			c := &Coordinator{dbPath: "test.json", st: st}
			if err := c.validateLoaded(); err == nil {
				t.Fatalf("validateLoaded accepted corrupt db %+v", st)
			}
		})
	}

	// A well-formed db must still load.
	good := dbState{
		Hosts:       []*Host{{UUID: hostA, IQNs: []string{iqn}}},
		Attachments: []*Attachment{{VolumeUUID: volA, HostUUID: hostA, LUN: 1, Desired: "attached"}},
		Exports:     map[string]int{volA: 0},
	}
	c := &Coordinator{dbPath: "test.json", st: good}
	if err := c.validateLoaded(); err != nil {
		t.Fatalf("validateLoaded rejected a valid db: %v", err)
	}
}

// TestMinVolumeSize: the floor is appliance policy, not a kernel or storage
// limit, so it is enforced at the API boundary and stated in the error.
func TestMinVolumeSize(t *testing.T) {
	st, err := storage.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := &Coordinator{store: st}

	for _, size := range []int64{1, 512, 4096, MinVolumeSize - 512} {
		if _, err := c.CreateVolume(size, 0); err == nil {
			t.Errorf("size %d is below the %d-byte minimum and must be refused",
				size, MinVolumeSize)
		}
	}
	// The floor itself is valid, and is a whole number of blocks in both
	// geometries -- so it does not interact with the block-size policy.
	for _, bs := range []int{0, 512, 4096} {
		if _, err := c.CreateVolume(MinVolumeSize, bs); err != nil {
			t.Errorf("the minimum size must be creatable at block_size %d: %v", bs, err)
		}
	}
}

// p is a shorthand for building portals in tests.
func p(ip string, port uint16) lio.Portal { return lio.Portal{IP: netip.MustParseAddr(ip), Port: port} }

// TestParsePortals: a portal is an ENDPOINT, so the spec has to carry a port
// per entry.
//
// IPv6 addresses must be bracketed when a port is given, for the same reason
// the kernel insists on it in configfs names: the address contains colons, so
// "fd00::1:3261" cannot be split unambiguously.
func TestParsePortals(t *testing.T) {
	cases := []struct {
		spec string
		want []lio.Portal
	}{
		{"10.0.0.1", []lio.Portal{p("10.0.0.1", 3260)}},
		{"10.0.0.1:3261", []lio.Portal{p("10.0.0.1", 3261)}},
		{"fd00::1", []lio.Portal{p("fd00::1", 3260)}},
		{"[fd00::1]:3261", []lio.Portal{p("fd00::1", 3261)}},
		{"[fd00::1]", []lio.Portal{p("fd00::1", 3260)}},
		{"::", []lio.Portal{p("::", 3260)}},
		{"0.0.0.0", []lio.Portal{p("0.0.0.0", 3260)}},
		// Mixed families and mixed ports in one spec -- the case the old
		// []string + single Port model could not express at all.
		{"10.0.0.1,[fd00::1]:3261,10.0.0.2:3262",
			[]lio.Portal{p("10.0.0.1", 3260), p("fd00::1", 3261), p("10.0.0.2", 3262)}},
	}
	for _, c := range cases {
		got, err := ParsePortals(c.spec, 3260)
		if err != nil {
			t.Errorf("ParsePortals(%q): %v", c.spec, err)
			continue
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("ParsePortals(%q) = %v, want %v", c.spec, got, c.want)
		}
	}
	if _, err := ParsePortals("10.0.0.1:http", 3260); err == nil {
		t.Error("a non-numeric port must be rejected")
	}
}

// TestConfigValidate: a typo in a flag or environment file must produce a
// message naming the setting, not a kernel path several layers down.
//
// Before this, these values were unexamined until they reached configfs, so a
// mistyped IQN failed as a reconcile error after the host lock was taken --
// and under Restart=on-failure that is a crash loop whose log never mentions
// the setting responsible, from a daemon that never gets far enough to serve
// /health and explain itself.
func TestConfigValidate(t *testing.T) {
	ok := Config{TargetIQN: "iqn.2026-01.dev.glitr:app", Portals: []lio.Portal{p("10.0.0.1", 3260)}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a well-formed config must validate: %v", err)
	}
	// naa. is legal for a target even though initiators may not use it.
	naa := ok
	naa.TargetIQN = "naa.6001405123456789"
	if err := naa.Validate(); err != nil {
		t.Errorf("naa. target names are legal: %v", err)
	}
	// IPv6 and the wildcard are ordinary portal addresses.
	for _, ip := range []string{"0.0.0.0", "::", "fd00::1"} {
		v := ok
		v.Portals = []lio.Portal{p(ip, 3260)}
		if err := v.Validate(); err != nil {
			t.Errorf("portal %q must be accepted: %v", ip, err)
		}
	}
	// The same address on two DIFFERENT ports is two portals, not a duplicate.
	multi := ok
	multi.Portals = []lio.Portal{p("10.0.0.1", 3260), p("10.0.0.1", 3261)}
	if err := multi.Validate(); err != nil {
		t.Errorf("one address on two ports is legal: %v", err)
	}

	bad := []struct {
		name string
		cfg  Config
		want string
	}{
		{"empty IQN", Config{Portals: ok.Portals}, "-iqn"},
		{"IQN without a scheme", Config{TargetIQN: "myTarget", Portals: ok.Portals}, "-iqn"},
		{"IQN with a slash", Config{TargetIQN: "iqn.2025-01.dev/x", Portals: ok.Portals}, "-iqn"},
		{"no portals", Config{TargetIQN: ok.TargetIQN}, "-portals"},
		// Hostnames, whitespace and empty elements are no longer testable
		// here: Portal.IP is a netip.Addr, so none of them can be built. They
		// are rejected where text becomes an address, in ParsePortals -- see
		// TestParsePortalsRejectsWhatIsNotAnAddress. What remains
		// representable is an address nobody set.
		{"unset address", Config{TargetIQN: ok.TargetIQN, Portals: []lio.Portal{{Port: 3260}}}, "-portals"},
		{"port zero", Config{TargetIQN: ok.TargetIQN, Portals: []lio.Portal{p("10.0.0.1", 0)}}, "-portals"},
		// "port out of range" is no longer testable here, and that is the
		// improvement: lio.Portal.Port is a uint16, so p("10.0.0.1", 70000) is
		// now a COMPILE error rather than a value that reached String() and
		// silently rendered as ":3260" -- the default port, not a visible
		// fault. The type rejects it; Validate no longer has to.
		{"duplicate portal", Config{TargetIQN: ok.TargetIQN, Portals: []lio.Portal{p("10.0.0.1", 3260), p("10.0.0.1", 3260)}}, "twice"},
		{"relative db root", Config{TargetIQN: ok.TargetIQN, Portals: ok.Portals, DBRoot: "target"}, "absolute"},
	}
	for _, tc := range bad {
		err := tc.cfg.Validate()
		if err == nil {
			t.Errorf("%s: must be rejected", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error should point at %q so the operator knows what to fix, got: %v",
				tc.name, tc.want, err)
		}
	}
}

// TestOpenRejectsBadConfig: validation has to be wired into Open, not merely
// available on the type.
//
// Without this, removing the call from Open breaks no test -- the rules are
// still correct and still unit-tested, while nothing enforces them. Open must
// fail before it touches storage or the kernel, so the operator gets the
// message about the setting rather than a later failure about a kernel path.
func TestOpenRejectsBadConfig(t *testing.T) {
	store, err := storage.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := lio.New(configfs.New(t.TempDir()))

	// The bad value must not itself contain the string being asserted on.
	// It first read "not-an-iqn", which CONTAINS "-iqn" -- so the assertion
	// matched the lower layer's error quoting the test's own input, and the
	// test passed with the validation removed from Open entirely. Caught by
	// negative control, which is the only thing that would have caught it.
	_, err = Open(t.TempDir(), store, m, Config{
		TargetIQN: "bogus",
		Portals:   []lio.Portal{{IP: mustAddr("10.0.0.1"), Port: 3260}},
	})
	if err == nil {
		t.Fatal("Open must reject a malformed target IQN rather than carry it to configfs")
	}
	// "(-iqn)" with the parentheses appears only in this package's message,
	// never in lio's.
	if !strings.Contains(err.Error(), "(-iqn)") {
		t.Errorf("the error must come from config validation and name the setting, got: %v", err)
	}
}

// TestPortalOverlap: a wildcard and a specific address cannot share a port,
// and the config is rejected before anything touches the kernel.
//
// Every case below is MEASURED against a live kernel (Azure Linux 3.0,
// 6.6.144.1) by mkdir into a TPG's np/ directory -- including the asymmetry,
// which is not guessable: 0.0.0.0 does NOT collide with an IPv6 address, while
// "::" collides with IPv4 as well, because Linux defaults to dual-stack
// (net.ipv6.bindv6only=0).
//
// Left to the kernel, this presented as a bare EINVAL from configfs naming
// nothing, in a daemon that then crash-looped under Restart=on-failure. The
// real cause is only visible as "kernel_bind() failed: -98" in dmesg.
func TestPortalOverlap(t *testing.T) {
	iqn := "iqn.2026-01.dev.glitr:app"
	conflict := []struct {
		name    string
		portals []lio.Portal
	}{
		{"v4 wildcard with a v4 address", []lio.Portal{p("0.0.0.0", 3260), p("10.0.0.1", 3260)}},
		{"v6 wildcard with a v6 address", []lio.Portal{p("::", 3260), p("fd00::1", 3260)}},
		{"v6 wildcard with a v4 address", []lio.Portal{p("::", 3260), p("10.0.0.1", 3260)}},
		{"both wildcards", []lio.Portal{p("::", 3260), p("0.0.0.0", 3260)}},
		// Order must not matter: the specific address listed first is the same
		// clash, and only the ORDER of application would differ.
		{"specific address listed first", []lio.Portal{p("10.0.0.1", 3260), p("0.0.0.0", 3260)}},
	}
	for _, tc := range conflict {
		err := Config{TargetIQN: iqn, Portals: tc.portals}.Validate()
		if err == nil {
			t.Errorf("%s: must be rejected -- the kernel refuses the second bind with "+
				"EADDRINUSE and the daemon crash-loops", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), "-portals") {
			t.Errorf("%s: error must name the setting, got: %v", tc.name, err)
		}
	}

	fine := []struct {
		name    string
		portals []lio.Portal
	}{
		// The v4 wildcard is v4-only, so an IPv6 portal beside it is legal --
		// measured, and the reason an IPv6 portal coexisted with 0.0.0.0
		// throughout the IPv6 bring-up.
		{"v4 wildcard with a v6 address", []lio.Portal{p("0.0.0.0", 3260), p("fd00::1", 3260)}},
		{"wildcard and specific on DIFFERENT ports", []lio.Portal{p("0.0.0.0", 3260), p("10.0.0.1", 3261)}},
		{"two specific addresses", []lio.Portal{p("10.0.0.1", 3260), p("10.0.0.2", 3260)}},
		{"wildcard alone", []lio.Portal{p("0.0.0.0", 3260)}},
	}
	for _, tc := range fine {
		if err := (Config{TargetIQN: iqn, Portals: tc.portals}).Validate(); err != nil {
			t.Errorf("%s: must be accepted, got: %v", tc.name, err)
		}
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
