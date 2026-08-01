package appliance

import (
	"errors"
	"fmt"
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
		st: db{
			Hosts:   []*Host{{UUID: "h1", Name: "h1", Bindings: Bindings{IQNs: []string{"NOT_A_VALID_IQN"}}}},
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
	h := Host{UUID: "h", Name: "h", Bindings: Bindings{IQNs: []string{"iqn.x:a"}}}
	cp := copyHost(h)
	cp.Bindings.IQNs[0] = "mutated"
	if h.Bindings.IQNs[0] != "iqn.x:a" {
		t.Fatal("copyHost did not copy the bindings slice (shared backing array)")
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

	obj := func(uuid, name string, kind Kind) *Object {
		return &Object{UUID: uuid, Name: name, Kind: kind, WWN: "aaaabbbbccccdddd",
			Capacity: 1 << 20, BlockSize: DefaultBlockSize, State: stateReady}
	}
	host := func(uuid, name string, iqns ...string) *Host {
		return &Host{UUID: uuid, Name: name, Bindings: Bindings{IQNs: iqns}}
	}

	for name, st := range map[string]db{
		"null-object":     {Objects: []*Object{nil}},
		"null-host":       {Hosts: []*Host{nil}},
		"null-connection": {Connections: []*Connection{nil}},

		"bad-object-uuid": {Objects: []*Object{obj("not-a-uuid", "v", KindVolume)}},
		"unnamed-object":  {Objects: []*Object{obj(volA, "", KindVolume)}},
		"unknown-kind":    {Objects: []*Object{obj(volA, "v", Kind("neither"))}},
		"duplicate-object-uuid": {Objects: []*Object{
			obj(volA, "one", KindVolume), obj(volA, "two", KindVolume)}},
		// Two of a kind may not share a name...
		"duplicate-volume-name": {Objects: []*Object{
			obj(volA, "same", KindVolume), obj(volB, "same", KindVolume)}},
		"object-name-with-slash": {Objects: []*Object{obj(volA, "a/b", KindVolume)}},

		"bad-host-uuid":  {Hosts: []*Host{host("not-a-uuid", "h", iqn)}},
		"unnamed-host":   {Hosts: []*Host{host(hostA, "", iqn)}},
		"duplicate-host": {Hosts: []*Host{host(hostA, "a", iqn), host(hostA, "b", iqn+"x")}},
		"duplicate-host-name": {Hosts: []*Host{
			host(hostA, "same", iqn), host(hostB, "same", iqn+"x")}},
		"bad-iqn":           {Hosts: []*Host{host(hostA, "h", "iqn.bad/evil")}},
		"iqn-claimed-twice": {Hosts: []*Host{host(hostA, "a", iqn), host(hostB, "b", iqn)}},

		"connection-to-unknown-object": {
			Hosts:       []*Host{host(hostA, "h", iqn)},
			Connections: []*Connection{{ObjectUUID: volA, HostUUID: hostA}}},
		"connection-to-unknown-host": {
			Objects:     []*Object{obj(volA, "v", KindVolume)},
			Connections: []*Connection{{ObjectUUID: volA, HostUUID: hostB}}},
		"lun-out-of-range": {
			Objects:     []*Object{obj(volA, "v", KindVolume)},
			Hosts:       []*Host{host(hostA, "h", iqn)},
			Connections: []*Connection{{ObjectUUID: volA, HostUUID: hostA, LUN: 1 << 20}}},
		"duplicate-connection": {
			Objects: []*Object{obj(volA, "v", KindVolume)},
			Hosts:   []*Host{host(hostA, "h", iqn)},
			Connections: []*Connection{
				{ObjectUUID: volA, HostUUID: hostA, LUN: 1},
				{ObjectUUID: volA, HostUUID: hostA, LUN: 2}}},
		"duplicate-lun-on-host": {
			Objects: []*Object{obj(volA, "a", KindVolume), obj(volB, "b", KindVolume)},
			Hosts:   []*Host{host(hostA, "h", iqn)},
			Connections: []*Connection{
				{ObjectUUID: volA, HostUUID: hostA, LUN: 1},
				{ObjectUUID: volB, HostUUID: hostA, LUN: 1}}},

		// Two objects at one TPG LUN index cannot both be exported.
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
	good := db{
		Objects:     []*Object{obj(volA, "vol-a", KindVolume)},
		Hosts:       []*Host{host(hostA, "host-a", iqn)},
		Connections: []*Connection{{ObjectUUID: volA, HostUUID: hostA, LUN: 1}},
		Exports:     map[string]int{volA: 0},
	}
	c := &Coordinator{dbPath: "test.json", st: good}
	if err := c.validateLoaded(); err != nil {
		t.Fatalf("validateLoaded rejected a valid db: %v", err)
	}

	// A volume and a snapshot may hold the SAME name. Separate kinds mean
	// separate namespaces, which is the distinction the model exists to make.
	shared := db{Objects: []*Object{
		obj(volA, "db-1", KindVolume),
		obj(volB, "db-1", KindSnapshot),
	}}
	c = &Coordinator{dbPath: "test.json", st: shared}
	if err := c.validateLoaded(); err != nil {
		t.Errorf("a volume and a snapshot must be allowed the same name: %v", err)
	}
}

// TestMinVolumeSize: the floor is appliance policy, not a kernel or storage
// limit, so it is enforced at the API boundary and stated in the error.
func TestSizeRules(t *testing.T) {
	c, _ := stageHolder(t, "")

	for _, size := range []int64{1, 512, 4096, MinVolumeSize - 4096} {
		if _, _, err := c.Create(KindVolume, CreateRequest{Name: "too-small", Size: size}); err == nil {
			t.Errorf("size %d is below the %d-byte minimum and must be refused",
				size, MinVolumeSize)
		}
	}
	// Every size is a whole number of the BACKING STORE's granularity,
	// whatever the object's own block size is. A size that is a whole number
	// of 512-byte blocks can still end part-way through a 4096-byte one, and
	// holding everything to the store's granularity is what lets the same
	// bytes be re-presented at 4Kn later. Read from the store rather than
	// written down here, so this test follows a store that reports another
	// value instead of asserting a number this package no longer owns.
	gran := c.store.SizeGranularity()
	for _, size := range []int64{MinVolumeSize + 512, MinVolumeSize + 1024, MinVolumeSize + 2048} {
		if size%gran == 0 {
			continue // not an unaligned case on a store with this granularity
		}
		for _, bs := range []int{DefaultBlockSize, MaxBlockSize} {
			_, _, err := c.Create(KindVolume, CreateRequest{Name: "unaligned", Size: size, BlockSize: bs})
			if err == nil {
				t.Errorf("size %d is not a multiple of %d and must be refused at block_size %d",
					size, gran, bs)
			}
		}
	}
	// The floor itself is valid and is a whole number of the granularity, so
	// it does not interact with that rule.
	if MinVolumeSize%gran != 0 {
		t.Fatalf("the %d-byte floor is not a multiple of the store's %d-byte granularity",
			int64(MinVolumeSize), gran)
	}
	for i, bs := range []int{0, DefaultBlockSize, MaxBlockSize} {
		name := fmt.Sprintf("floor-%d", i)
		if _, _, err := c.Create(KindVolume, CreateRequest{Name: name, Size: MinVolumeSize, BlockSize: bs}); err != nil {
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
		// An empty IQN is no longer invalid: it means "derive one from this
		// machine", which is how an appliance gets a name that a second one
		// built from the same unit file will not share. It is asserted as
		// ACCEPTED below rather than dropped, so the change is visible here
		// instead of being an absence.
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
	// Empty means "derive", so it must pass validation and be settled later,
	// at startup, where the machine ID is readable.
	if err := (Config{Portals: ok.Portals}).Validate(); err != nil {
		t.Errorf("an empty IQN means derive-one and must be accepted: %v", err)
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
