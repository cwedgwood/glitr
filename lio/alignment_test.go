package lio

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwedgwood/glitr/lio/configfs"
)

// TestUnalignedSizeDoesNotFailWholeConfigValidation is the library half of a
// whole-appliance outage.
//
// Config.Validate runs over the ENTIRE desired config on every reconcile and
// returns on the first bad backstore, so a size rule enforced there rejects
// the whole tree -- every healthy export included -- because of one record.
// An unaligned size belongs to an already-existing volume that no reconcile
// can fix (block_size is immutable while exported), and the kernel has
// floored the block count for it all along, so failing here removes a working
// device to protect nobody.
func TestUnalignedSizeDoesNotFailWholeConfigValidation(t *testing.T) {
	bad := testBackstore()
	bad.Size = 1000001
	bad.Attributes = map[string]string{"block_size": "512"}

	if err := (Config{Backstores: []Backstore{bad}}).Validate(); err != nil {
		t.Fatalf("an unaligned size must not fail whole-config validation -- that is a "+
			"crash loop against an otherwise healthy tree: %v", err)
	}

	// The value itself is still validated: that is static, and a block size
	// the kernel would refuse is worth naming before the write fails.
	bad.Attributes["block_size"] = "777"
	if err := (Config{Backstores: []Backstore{bad}}).Validate(); err == nil {
		t.Error("an invalid block_size VALUE must still be rejected")
	}
}

// TestUnalignedSizeIsRefusedOnCreate: the check moves to where the size is
// actually being chosen. Bringing a short device into existence is a
// different act from declining to reconcile one that already exists.
func TestUnalignedSizeIsRefusedOnCreate(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	b.Size = 1000001
	b.Attributes = map[string]string{"block_size": "512"}
	stageBackstoreDir(t, root, b)

	_, err := New(configfs.New(root)).Apply(Config{Backstores: []Backstore{b}})
	if err == nil {
		t.Fatal("creating a backstore whose size is not a whole number of blocks must be " +
			"refused: the kernel silently floors it and the caller gets a short device")
	}
	if !strings.Contains(err.Error(), "multiple of block_size") {
		t.Errorf("error must explain the alignment problem, got %v", err)
	}
}

// TestUnalignedBackingFileIsRefusedWhenSizeOmitted closes the gap that the
// b.Size check alone left open: fileio derives the effective size from the
// backing file when Size is 0, so a check against b.Size passes
// unconditionally in exactly that case and the device is exported short.
func TestUnalignedBackingFileIsRefusedWhenSizeOmitted(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	b.Size = 0
	b.Attributes = map[string]string{"block_size": "4096"}
	b.Dev = filepath.Join(t.TempDir(), "unaligned.img")
	stageBackstoreDir(t, root, b)
	f, err := os.Create(b.Dev)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(1<<20 + 512); err != nil {
		t.Fatal(err)
	}
	f.Close()

	_, err = New(configfs.New(root)).Apply(Config{Backstores: []Backstore{b}})
	if err == nil {
		t.Fatal("an unaligned BACKING FILE must be refused even when Size is omitted")
	}
	if !strings.Contains(err.Error(), "multiple of block_size") {
		t.Errorf("error must explain the alignment problem, got %v", err)
	}
}

// TestFlooredSizeAgainstUnflooredLiveObjectIsNotAShrink is the regression test
// for a crash loop introduced by the FIX for an earlier crash loop.
//
// The kernel stores and reports fd_dev_size verbatim. MEASURED on Azure Linux
// 3.0, kernel 6.6.144.1: a backstore created with fd_dev_size=1000000 reports
// "Size: 1000000" in its info line, even though it serves only the 1953 whole
// 512-byte blocks it can address and drops the trailing 64 bytes.
//
// So a caller that correctly floors a legacy capacity before asking for it --
// which is what appliance.desiredLIO now does -- presents 999936 against a
// live object reporting 1000000. Comparing raw, that is a shrink, and the
// reconcile fails: applianced then crash-loops against a completely healthy
// tree, on the ordinary upgrade path of "new binary, systemctl restart, no
// reboot", for exactly the legacy volumes the alignment work was written for.
//
// The two figures describe the same device. Compare floored.
func TestFlooredSizeAgainstUnflooredLiveObjectIsNotAShrink(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	b.Attributes = map[string]string{"block_size": "512"}
	b.Size = 999936 // 1000001 floored to a whole block
	stageBackstoreDir(t, root, b)
	fs := configfs.New(root)

	// An existing, enabled object as an older build left it: the unfloored
	// figure, verbatim, exactly as the kernel renders it.
	for _, kv := range [][2]string{{"1", "enable"}, {b.Dev, "udev_path"}} {
		if err := fs.WriteAttr(kv[0], append(b.objPath(), kv[1])...); err != nil {
			t.Fatal(err)
		}
	}
	if err := fs.WriteAttr("TCM FILEIO ID: 0  File: "+b.Dev+"  Size: 1000001  Mode: O_DSYNC",
		append(b.objPath(), "info")...); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteAttr("512", append(b.objPath(), "attrib", "block_size")...); err != nil {
		t.Fatal(err)
	}

	if _, err := New(fs).Apply(Config{Backstores: []Backstore{b}}); err != nil {
		t.Fatalf("a floored size against a live object reporting the unfloored one must be "+
			"treated as converged -- both describe the same device, and failing here "+
			"crash-loops the daemon on upgrade: %v", err)
	}
}

// TestGenuineShrinkIsStillRefused: the floor tolerance must not swallow a real
// shrink, which would silently shorten a device an initiator has mounted.
func TestGenuineShrinkIsStillRefused(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	b.Attributes = map[string]string{"block_size": "512"}
	b.Size = 512 << 10
	stageBackstoreDir(t, root, b)
	fs := configfs.New(root)

	for _, kv := range [][2]string{{"1", "enable"}, {b.Dev, "udev_path"}} {
		if err := fs.WriteAttr(kv[0], append(b.objPath(), kv[1])...); err != nil {
			t.Fatal(err)
		}
	}
	if err := fs.WriteAttr("TCM FILEIO ID: 0  File: "+b.Dev+"  Size: 1048576  Mode: O_DSYNC",
		append(b.objPath(), "info")...); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteAttr("512", append(b.objPath(), "attrib", "block_size")...); err != nil {
		t.Fatal(err)
	}

	_, err := New(fs).Apply(Config{Backstores: []Backstore{b}})
	if err == nil {
		t.Fatal("a real shrink (512KiB requested against a live 1MiB) must still be refused")
	}
	if !strings.Contains(err.Error(), "shrink unsupported") {
		t.Errorf("want a shrink error, got %v", err)
	}
}

// TestUnalignedSizeRefusedWhenNoBlockSizeStated: the kernel uses 512 whether or
// not the attribute was set, so "no geometry stated" is not "no geometry" --
// reading the attribute and skipping the check when absent made this a check
// that quietly did nothing for any caller that did not set it.
func TestUnalignedSizeRefusedWhenNoBlockSizeStated(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	b.Size = 1000001
	b.Attributes = nil
	stageBackstoreDir(t, root, b)

	_, err := New(configfs.New(root)).Apply(Config{Backstores: []Backstore{b}})
	if err == nil {
		t.Fatal("an unaligned size must be refused even when no block_size is stated: " +
			"the kernel defaults to 512 and still truncates the tail")
	}
	if !strings.Contains(err.Error(), "multiple of block_size") {
		t.Errorf("error must explain the alignment problem, got %v", err)
	}
}
