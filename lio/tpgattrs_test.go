package lio

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cwedgwood/glitr/lio/configfs"
)

// kernelTPGAttrs is what the KERNEL exposes, recorded independently of what
// the code chooses to manage so the two can be compared.
//
// MEASURED on Azure Linux 3.0, kernel 6.6.144.1-1.azl3, by listing
// iscsi/<iqn>/tpgt_N/attrib/ on a freshly created TPG. All thirteen are mode
// 0644, and each was written to a different value successfully with the TPG
// both disabled and enabled.
var kernelTPGAttrs = []string{
	"authentication", "cache_dynamic_acls", "default_cmdsn_depth", "default_erl",
	"demo_mode_discovery", "demo_mode_write_protect", "fabric_prot_type",
	"generate_node_acls", "login_keys_workaround", "login_timeout",
	"prod_mode_write_protect", "t10_pi", "tpg_enabled_sendtargets",
}

// TestTPGAttributesSurviveARoundTrip: lish would set ANY TPG attribute, while
// discovery read back only three, so anything else was written to the kernel
// and never read again -- present until the next reboot, then silently gone.
// A configuration that disappears on restart is worse than one that is
// refused, because nothing reports it.
//
// The gap was self-demonstrating: lio/live_test.go sets cache_dynamic_acls,
// which was one of the lost ones. This walks the same path a save/restore
// takes -- Discover, then feed the result back through Apply -- and requires
// the value to survive.
func TestTPGAttributesSurviveARoundTrip(t *testing.T) {
	const iqn = "iqn.2026-01.example:t"
	root := t.TempDir()
	fs := configfs.New(root)

	// Stage a TPG carrying a value for every attribute the kernel exposes.
	base := filepath.Join(root, "iscsi", iqn, "tpgt_1")
	for _, d := range []string{"attrib", "np", "lun", "acls", "param"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "enable"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Staged from the MEASURED kernel set, deliberately not from
	// discoveredTPGAttrs. Driving both the fixture and the assertion off the
	// same variable made this tautological: with the old three-key list it
	// staged three keys, checked three, and passed -- unable to detect the
	// very narrowing it exists to catch.
	want := map[string]string{}
	for i, k := range kernelTPGAttrs {
		v := itoa(i + 1) // distinct per key, so a mix-up is visible
		want[k] = v
		if err := os.WriteFile(filepath.Join(base, "attrib", k), []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cfg, err := New(fs).Discover()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Targets) != 1 || len(cfg.Targets[0].TPGs) != 1 {
		t.Fatalf("expected one target with one TPG, got %+v", cfg.Targets)
	}
	got := cfg.Targets[0].TPGs[0].Attributes
	for k, v := range want {
		if got[k] != v {
			t.Errorf("attribute %q was not discovered (got %q, want %q) -- it would be "+
				"written to the kernel and then lost at the next reboot, with nothing "+
				"reporting it", k, got[k], v)
		}
	}

	// The APPLY half. Discovery alone proves the keys can be READ; a save is
	// only useful if restoring it puts the values back. An earlier version of
	// this test stopped above while its comment claimed it fed the result
	// through Apply, so it could not have failed if restore wrote a key
	// wrongly, in an unsafe order, or not at all.
	//
	// Applied onto a SECOND, empty tree rather than the one just read, so a
	// value that was never written cannot be mistaken for one that survived.
	dstRoot := t.TempDir()
	dstBase := filepath.Join(dstRoot, "iscsi", iqn, "tpgt_1")
	for _, d := range []string{"attrib", "np", "lun", "acls", "param"} {
		if err := os.MkdirAll(filepath.Join(dstBase, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dstBase, "enable"), []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Every attribute starts at a value the config does NOT ask for, so a key
	// Apply skips stays visibly wrong instead of matching by luck.
	for _, k := range kernelTPGAttrs {
		if err := os.WriteFile(filepath.Join(dstBase, "attrib", k), []byte("999\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := New(configfs.New(dstRoot)).Apply(cfg); err != nil {
		t.Fatalf("applying the discovered config must succeed: %v", err)
	}

	back, err := New(configfs.New(dstRoot)).Discover()
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Targets) != 1 || len(back.Targets[0].TPGs) != 1 {
		t.Fatalf("expected one target with one TPG after apply, got %+v", back.Targets)
	}
	applied := back.Targets[0].TPGs[0].Attributes
	for k, v := range want {
		if applied[k] != v {
			t.Errorf("attribute %q did not survive the round trip (got %q, want %q) -- "+
				"discovery reads it but restore does not put it back, so a saved "+
				"configuration is silently incomplete", k, applied[k], v)
		}
	}
}

// TestApplySkipsATPGAttributeThisKernelLacks: discoverTPG tolerates ENOENT
// because a key may be absent on an older kernel, so a config discovered on
// one kernel can legitimately name a key another does not have. ensureTPG
// treated that as fatal, which -- once the managed set went from 3 keys to 13
// -- turned a restore onto such a kernel into a total reconcile failure, and
// applianced runs under Restart=on-failure.
func TestApplySkipsATPGAttributeThisKernelLacks(t *testing.T) {
	const iqn = "iqn.2026-01.example:t"
	root := t.TempDir()
	base := filepath.Join(root, "iscsi", iqn, "tpgt_1")
	for _, d := range []string{"attrib", "np", "lun", "acls", "param"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "enable"), []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// This kernel exposes one attribute; the config names two.
	if err := os.WriteFile(filepath.Join(base, "attrib", "authentication"), []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{Targets: []Target{{IQN: iqn, TPGs: []TPG{{
		Tag:    1,
		Enable: false,
		Attributes: map[string]string{
			"authentication":        "1",
			"login_keys_workaround": "1", // absent from this kernel
		},
	}}}}}

	rep, err := New(configfs.New(root)).Apply(cfg)
	if err != nil {
		t.Fatalf("an attribute this kernel does not expose must be skipped, not fatal: %v", err)
	}
	// The supported one must still have been applied.
	got, err := os.ReadFile(filepath.Join(base, "attrib", "authentication"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "1" {
		t.Errorf("the supported attribute must still be applied, got %q", got)
	}
	// And the skip must be reported rather than passed over in silence.
	var noted bool
	for _, n := range rep.Changes {
		if strings.Contains(n, "login_keys_workaround") && strings.Contains(n, "not supported") {
			noted = true
		}
	}
	if !noted {
		t.Errorf("skipping an attribute must be recorded, or a configuration silently "+
			"does not take effect: %v", rep.Changes)
	}
}

// TestCacheDynamicACLsIsDiscovered names the specific attribute the project's
// own live test sets, so the regression that motivated this cannot come back
// unnoticed.
func TestCacheDynamicACLsIsDiscovered(t *testing.T) {
	if !slices.Contains(discoveredTPGAttrs, "cache_dynamic_acls") {
		t.Error("cache_dynamic_acls is set by lio/live_test.go and must round-trip; " +
			"without it the live test configures something that vanishes on reboot")
	}
}

// TestDiscoveredTPGAttrsMatchesTheKernel pins the measured set. If a kernel
// gains or renames an attribute this list does not silently disagree with it
// -- the live suite is what would catch that, and this records what was
// measured so the comparison is possible.
func TestDiscoveredTPGAttrsMatchesTheKernel(t *testing.T) {
	// MEASURED on Azure Linux 3.0, kernel 6.6.144.1-1.azl3, by listing
	// iscsi/<iqn>/tpgt_N/attrib/ on a freshly created TPG. All are mode 0644
	// and all were written successfully with the TPG both disabled and enabled.
	if !slices.Equal(slices.Sorted(slices.Values(discoveredTPGAttrs)), slices.Sorted(slices.Values(kernelTPGAttrs))) {
		t.Errorf("the managed set no longer matches what was measured on the kernel:\n"+
			"  managed:  %v\n  measured: %v", discoveredTPGAttrs, kernelTPGAttrs)
	}
}

// TestATPGAttributeThatDoesNotStickIsNotReportedAsApplied.
//
// Some iSCSI TPG setters accept a write and silently decline to apply it,
// returning 0 without changing the value: writing cache_dynamic_acls=0 while
// generate_node_acls=1 hits an early return at linux v6.6
// drivers/target/iscsi/iscsi_target_tpg.c:729-732, and setting
// generate_node_acls=1 forces cache_dynamic_acls=1 from the other direction
// (:683-687). The write reports success, so without a read-back the change
// note claims a value that never took effect.
//
// A plain tmpdir file cannot model that -- it keeps whatever is written. A
// symlink to /dev/null can: the write is accepted and discarded, and the read
// comes back empty, which is exactly "accepted, not applied".
func TestATPGAttributeThatDoesNotStickIsNotReportedAsApplied(t *testing.T) {
	const iqn = "iqn.2026-01.example:t"
	root := t.TempDir()
	base := filepath.Join(root, "iscsi", iqn, "tpgt_1")
	for _, d := range []string{"attrib", "np", "lun", "acls", "param"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "enable"), []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(base, "attrib", "cache_dynamic_acls")); err != nil {
		t.Skipf("cannot model a non-sticking attribute here: %v", err)
	}

	cfg := Config{Targets: []Target{{IQN: iqn, TPGs: []TPG{{
		Tag:        1,
		Attributes: map[string]string{"cache_dynamic_acls": "0"},
	}}}}}

	rep, err := New(configfs.New(root)).Apply(cfg)
	if err != nil {
		t.Fatalf("a silently-declined write must not be fatal: %v", err)
	}
	var claimed, reported bool
	for _, n := range rep.Changes {
		if !strings.Contains(n, "cache_dynamic_acls") {
			continue
		}
		if strings.Contains(n, "NOT APPLIED") {
			reported = true
		} else {
			claimed = true
		}
	}
	if claimed {
		t.Errorf("the change note claims a value the kernel did not keep: %v", rep.Changes)
	}
	if !reported {
		t.Errorf("a write that did not take effect must be reported, not passed over "+
			"in silence: %v", rep.Changes)
	}
}
