package lio

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwedgwood/glitr/lio/configfs"
)

// stageLiveBackstore builds an already-created, already-enabled fileio
// backstore whose info line reports the given backing mode, with
// emulate_write_cache staged at the value the kernel would have set on
// create. Reconcile therefore takes the already-enabled path.
func stageLiveBackstore(t *testing.T, mode string) (*configfs.FS, Backstore) {
	t.Helper()
	root := t.TempDir()
	b := testBackstore()
	stageBackstoreDir(t, root, b)
	fs := configfs.New(root)

	wce := "0"
	if mode == "Buffered-WCE" {
		wce = "1"
	}
	for _, kv := range [][2]string{
		{"1", "enable"},
		{b.Dev, "udev_path"},
		{"TCM FILEIO ID: 0  File: " + b.Dev + "  Size: 1048576  Mode: " + mode + " Async: 0", "info"},
	} {
		if err := fs.WriteAttr(kv[0], append(b.objPath(), kv[1])...); err != nil {
			t.Fatal(err)
		}
	}
	if err := fs.WriteAttr(wce, append(b.objPath(), "attrib", "emulate_write_cache")...); err != nil {
		t.Fatal(err)
	}
	return fs, b
}

func liveWCE(t *testing.T, fs *configfs.FS, b Backstore) string {
	t.Helper()
	v, err := fs.ReadAttr(append(b.objPath(), "attrib", "emulate_write_cache")...)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestWriteCacheNeverLiesAboutBufferedBacking is the regression test for the
// review's only unanimous finding, and the one that mattered most: reconcile
// could construct the exact state the design claims is unrepresentable.
//
// BufferedIO is create-time (it rides the control string); emulate_write_cache
// is a mutable attribute rewritten on every pass. configfs is kernel memory
// and survives a DAEMON restart -- only a reboot clears it. So:
//
//	applianced -write-back   ->  backstore opened without O_DSYNC, WCE=1
//	drop the flag, restart   ->  reconcile writes WCE=0 onto that same object
//
// The device now acknowledges writes out of volatile page cache while telling
// the initiator it has no cache to flush. A consumer that correctly issues
// SYNCHRONIZE CACHE before its journal commit gets a no-op, and loses
// acknowledged data on power loss with no way to have defended itself.
//
// MEASURED on Azure Linux 3.0, kernel 6.6.144.1: the kernel ACCEPTS that
// write. emulate_write_cache_store carries no export_count guard, and refuses
// only when transport->get_write_cache is defined -- which fileio does not
// define.
//
// Negative control: reverting constrainWriteCache to return b.Attributes
// unchanged fails this test on the "wrote 0" assertion.
func TestWriteCacheNeverLiesAboutBufferedBacking(t *testing.T) {
	fs, b := stageLiveBackstore(t, "Buffered-WCE")

	// Desired: write-through. This is the operator dropping -write-back and
	// restarting the daemon against a still-buffered configfs tree.
	b.BufferedIO = false
	b.Attributes = map[string]string{"emulate_write_cache": "0"}

	rep, err := New(fs).Apply(Config{Backstores: []Backstore{b}})
	if err != nil {
		t.Fatalf("a mode mismatch must not be fatal -- it would crash-loop the daemon "+
			"against a healthy tree, the failure mode four earlier fixes caused: %v", err)
	}
	if got := liveWCE(t, fs, b); got != "1" {
		t.Errorf("emulate_write_cache = %q, want \"1\": the backing file is still open "+
			"without O_DSYNC, so advertising no write cache tells the initiator a "+
			"lie it cannot detect and cannot defend against", got)
	}
	if len(rep.Drift) != 1 {
		t.Fatalf("the override must be REPORTED, not silent: an operator who asked for "+
			"write-through and did not get it has to be told. drift = %v", rep.Drift)
	}
	d := rep.Drift[0]
	if d.Attr != "emulate_write_cache" || d.Live != "1" || d.Desired != "0" {
		t.Errorf("drift must carry the applied value so the applied view records what the "+
			"engine DID, not what it asked for; got %+v", d)
	}
	if s := d.String(); !strings.Contains(s, "WRITE CACHE MODE MISMATCH") ||
		!strings.Contains(s, "next boot") {
		t.Errorf("operator message must name the fault and the remedy, got %q", s)
	}
}

// TestWriteCacheNeverClaimsAbsentCache is the other direction: adding
// -write-back and restarting against an O_DSYNC tree.
//
// It is not a data-loss bug -- the device really is write-through, which is
// the safe end -- but it is the same lie inverted. Advertising a volatile
// cache that does not exist invites the initiator to issue SYNCHRONIZE CACHE
// commands that can only be no-ops, and reports a durability posture the
// operator did not get. Both directions must be held to the live mode.
func TestWriteCacheNeverClaimsAbsentCache(t *testing.T) {
	fs, b := stageLiveBackstore(t, "O_DSYNC")

	b.BufferedIO = true
	b.Attributes = map[string]string{"emulate_write_cache": "1"}

	rep, err := New(fs).Apply(Config{Backstores: []Backstore{b}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := liveWCE(t, fs, b); got != "0" {
		t.Errorf("emulate_write_cache = %q, want \"0\": the file is opened O_DSYNC, so "+
			"there is no cache to flush", got)
	}
	if len(rep.Drift) != 1 {
		t.Fatalf("drift = %v, want the unhonoured -write-back reported", rep.Drift)
	}
}

// TestWriteCacheAgreeingModeIsNotDrift guards the over-correction: when the
// live mode already matches the request, this must be an ordinary converged
// reconcile with no drift and no churn.
func TestWriteCacheAgreeingModeIsNotDrift(t *testing.T) {
	for _, tc := range []struct{ mode, wce string }{
		{"O_DSYNC", "0"},
		{"Buffered-WCE", "1"},
	} {
		fs, b := stageLiveBackstore(t, tc.mode)
		b.BufferedIO = tc.mode == "Buffered-WCE"
		b.Attributes = map[string]string{"emulate_write_cache": tc.wce}

		rep, err := New(fs).Apply(Config{Backstores: []Backstore{b}})
		if err != nil {
			t.Fatalf("%s: %v", tc.mode, err)
		}
		if len(rep.Drift) != 0 {
			t.Errorf("%s: drift = %v, want none -- the live mode is what was asked for",
				tc.mode, rep.Drift)
		}
		if got := liveWCE(t, fs, b); got != tc.wce {
			t.Errorf("%s: emulate_write_cache = %q, want %q", tc.mode, got, tc.wce)
		}
	}
}

// TestParseInfoModeKeepsTheHyphen is the regression test for a false
// MEASUREMENT -- a class this project had not seen before.
//
// A probe extracted the mode with sed 's/.*Mode: \([A-Za-z_]*\).*/\1/p'. The
// character class stops at the hyphen, so "Buffered-WCE" came back as
// "Buffered". That artifact was then recorded in two code comments as an
// observed kernel behaviour ("giving Mode: Buffered with WCE=0"), which the
// kernel cannot in fact produce: fd_show_configfs_dev_params renders the field
// from fbd_flags alone and emits only the two literals.
//
// Seven false-pass assertions have been found in this project's tests; this
// was the first false measurement. The extraction is part of the measurement.
func TestParseInfoModeKeepsTheHyphen(t *testing.T) {
	const info = "Status: ACTIVATED  Max Queue Depth: 0  SectorSize: 512  " +
		"File: /var/lib/glitr/x.img  Size: 134217728  Mode: Buffered-WCE Async: 0"
	if got := parseInfoMode(info); got != "Buffered-WCE" {
		t.Errorf("parseInfoMode = %q, want %q -- truncating at the hyphen is the "+
			"mismeasurement that put a fiction in the source comments", got, "Buffered-WCE")
	}
	if got := parseInfoMode("File: /x  Size: 1  Mode: O_DSYNC Async: 0"); got != "O_DSYNC" {
		t.Errorf("parseInfoMode = %q, want O_DSYNC", got)
	}
	if got := parseInfoMode("File: /x  Size: 1"); got != "" {
		t.Errorf("parseInfoMode = %q, want empty for an absent mode", got)
	}
}

// TestDiscoverRoundTripsWriteCacheState is the regression test for a
// save/restore that silently changed a device's durability contract.
//
// discoveredBackstoreAttrs listed only {block_size, optimal_sectors}, and
// BufferedIO was never recovered at all. So `lish saveconfig` on a write-back
// appliance produced a config that restored every volume as write-through --
// and CAPABILITIES.md claimed the round trip was byte-identical.
//
// Both halves have to come back, and from different places: the attribute
// from attrib/, the backing mode from the info line, which is the only
// observable for a create-time setting with no attribute of its own.
func TestDiscoverRoundTripsWriteCacheState(t *testing.T) {
	fs, b := stageLiveBackstore(t, "Buffered-WCE")

	got, err := discoverBackstores(fs)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("discovered %d backstores, want 1", len(got))
	}
	d := got[0]
	if !d.BufferedIO {
		t.Error("BufferedIO must be recovered from the info line: it is create-time, " +
			"so a restore that loses it rebuilds the device with different durability " +
			"than the operator chose")
	}
	if d.Attributes["emulate_write_cache"] != "1" {
		t.Errorf("emulate_write_cache = %q, want \"1\" -- the advertised half of the "+
			"weld must round-trip with the backing half or the two restore inconsistent",
			d.Attributes["emulate_write_cache"])
	}
	_ = b

	// The write-through case must round-trip too, and must NOT acquire a
	// spurious BufferedIO.
	fs2, _ := stageLiveBackstore(t, "O_DSYNC")
	got2, err := discoverBackstores(fs2)
	if err != nil {
		t.Fatal(err)
	}
	if got2[0].BufferedIO {
		t.Error("an O_DSYNC device must not be discovered as buffered")
	}
	if got2[0].Attributes["emulate_write_cache"] != "0" {
		t.Errorf("emulate_write_cache = %q, want \"0\"", got2[0].Attributes["emulate_write_cache"])
	}
}

// TestUnknownModeIsNotReportedAsWriteThrough is the regression test for a
// fuzz finding, and the direction is what makes it matter.
//
// parseInfoMode returned whatever token followed "Mode: ". constrainWriteCache
// derives the live write-cache attribute as `"0" unless the mode is
// Buffered-WCE`, so ANY unrecognised token -- a value a later kernel might
// introduce -- was read as write-through. The library would then report that
// an acknowledged write is on stable storage while the backing file was
// opened without O_DSYNC.
//
// That is the one direction this must never fail in, and it is reachable
// without any bug on our side: it needs only the kernel to change a string.
func TestUnknownModeIsNotReportedAsWriteThrough(t *testing.T) {
	for _, tc := range []struct {
		name string
		info string
		want string
	}{
		{"the two the kernel emits", "TCM FILEIO ID: 0  File: /x  Size: 1  Mode: O_DSYNC  Async: 0", "O_DSYNC"},
		{"buffered, hyphen intact", "TCM FILEIO ID: 0  File: /x  Size: 1  Mode: Buffered-WCE  Async: 0", "Buffered-WCE"},
		{"a token a later kernel might use", "Mode: DirectIO  Async: 0", ""},
		{"the fuzz finding", "Mode: 0", ""},
		{"empty", "Mode: ", ""},
		{"absent", "TCM FILEIO ID: 0  File: /x", ""},
	} {
		if got := parseInfoMode(tc.info); got != tc.want {
			t.Errorf("%s: parseInfoMode(%q) = %q, want %q", tc.name, tc.info, got, tc.want)
		}
	}

	// The consequence, not just the parse: an unknown mode must leave the
	// managed attribute ALONE rather than asserting write-through.
	a := &applyCtx{}
	b := Backstore{Type: FileIO, Name: "v", Attributes: map[string]string{"emulate_write_cache": "1"}}
	got := a.constrainWriteCache(b, "Mode: DirectIO")
	if got["emulate_write_cache"] != "1" {
		t.Errorf("an unreadable mode must not rewrite the desired value to %q -- "+
			"that claims the device is write-through when it cannot be determined",
			got["emulate_write_cache"])
	}
	if len(a.drift) != 0 {
		t.Errorf("an unknown mode must not be reported as drift: %v", a.drift)
	}
}

// TestDiscoverRefusesAnUninterpretableInfoLine: the fileio info line is the
// ONLY place the backing mode can be recovered from, and it is kernel prose
// with no compatibility promise.
//
// Unknown used to resolve to BufferedIO=false, which means O_DSYNC -- a claim
// that every write reaches stable storage. Asserting that for a device whose
// mode could not be determined claims a durability it may not have, and the
// mode is create-time so no reconcile can correct it afterwards.
func TestDiscoverRefusesAnUninterpretableInfoLine(t *testing.T) {
	stage := func(t *testing.T, info string) *Manager {
		t.Helper()
		root := t.TempDir()
		dir := filepath.Join(root, "core", "fileio_0", "vol0")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "wwn"), 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range map[string]string{
			"udev_path":           "/var/lib/glitr/vol0.img\n",
			"wwn/vpd_unit_serial": "T10 VPD Unit Serial Number: aaaabbbbccccdddd\n",
			"info":                info + "\n",
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return New(configfs.New(root))
	}

	for name, info := range map[string]string{
		"unknown mode": "Status: ACTIVATED  Max Queue Depth: 128  SectorSize: 512  Size: 1048576  Mode: Something-New",
		"no mode":      "Status: ACTIVATED  SectorSize: 512  Size: 1048576",
		"no size":      "Status: ACTIVATED  SectorSize: 512  Mode: O_DSYNC",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := stage(t, info).Discover(); err == nil {
				t.Error("an uninterpretable info line was accepted; the backing mode " +
					"would have defaulted to a durability claim")
			}
		})
	}

	// Both real renderings must still work, or this would pass by refusing
	// everything.
	for name, info := range map[string]string{
		"o_dsync":  "Status: ACTIVATED  SectorSize: 512  Size: 1048576  Mode: O_DSYNC",
		"buffered": "Status: ACTIVATED  SectorSize: 512  Size: 1048576  Mode: Buffered-WCE",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := stage(t, info).Discover()
			if err != nil {
				t.Fatalf("a real info line was refused: %v", err)
			}
			if len(cfg.Backstores) != 1 {
				t.Fatalf("discovered %d backstores, want 1", len(cfg.Backstores))
			}
			if want := info == "Status: ACTIVATED  SectorSize: 512  Size: 1048576  Mode: Buffered-WCE"; cfg.Backstores[0].BufferedIO != want {
				t.Errorf("BufferedIO = %v, want %v", cfg.Backstores[0].BufferedIO, want)
			}
		})
	}
}
