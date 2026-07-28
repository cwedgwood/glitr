package lio

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwedgwood/glitr/lio/configfs"
)

// The kernel returns a bare EINVAL for two unrelated things: "immutable while
// exported" and "value out of range". Apply treats EINVAL on an exported
// backstore as immutability drift, so an out-of-range value on an exported
// device was reported as drift -- telling an operator the device is busy when
// the real problem is the number they supplied.
//
// Validating the value first makes a surviving EINVAL mean immutability and
// nothing else. The allowed sets are measured against the kernel; see
// validateAttr for the figures and for the probe that got optimal_sectors
// wrong by running against an unconfigured backstore.

func TestValidateAttrMatchesTheKernelsAllowedValues(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	stageBackstoreDir(t, root, b)
	// hw_max_sectors is what bounds optimal_sectors, and it is a per-device
	// runtime value rather than a constant.
	hw := filepath.Join(root, "core", "fileio_0", b.Name, "attrib", "hw_max_sectors")
	if err := os.MkdirAll(filepath.Dir(hw), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hw, []byte("16384\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &applyCtx{fs: configfs.New(root)}

	cases := []struct {
		key, val string
		ok       bool
		why      string
	}{
		{"block_size", "512", true, ""},
		{"block_size", "4096", true, ""},
		{"block_size", "256", false, "below the kernel's minimum"},
		{"block_size", "8192", false, "above the kernel's maximum"},
		{"block_size", "1000", false, "not a power of two in the allowed set"},
		{"emulate_write_cache", "0", true, ""},
		{"emulate_write_cache", "1", true, ""},
		{"emulate_write_cache", "2", false, "not a boolean"},
		{"optimal_sectors", "0", true, "0 means no preference"},
		{"optimal_sectors", "16384", true, "exactly hw_max_sectors is allowed"},
		{"optimal_sectors", "16385", false, "one past hw_max_sectors"},
		{"optimal_sectors", "-1", false, "negative"},
		{"optimal_sectors", "banana", false, "not a number"},
		// An attribute validateAttr does not model must pass through: inventing
		// a set would produce rejections the kernel would never make.
		{"emulate_tpu", "1", true, "unmodelled attribute is not second-guessed"},
	}
	for _, c := range cases {
		err := a.validateAttr(b, c.key, c.val)
		if c.ok && err != nil {
			t.Errorf("%s=%s must be accepted (%s), got %v", c.key, c.val, c.why, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s=%s must be rejected (%s), but passed -- the kernel would return "+
				"EINVAL and, on an exported device, it would be misreported as drift",
				c.key, c.val, c.why)
		}
	}
}

// TestOptimalSectorsBoundIsReadFromTheDevice: the ceiling is per-device
// (FD_MAX_BYTES/512 = 16384 for fileio here), so a hard-coded constant would
// be wrong on any device with a different limit.
func TestOptimalSectorsBoundIsReadFromTheDevice(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	stageBackstoreDir(t, root, b)
	hw := filepath.Join(root, "core", "fileio_0", b.Name, "attrib", "hw_max_sectors")
	if err := os.MkdirAll(filepath.Dir(hw), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hw, []byte("2048\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &applyCtx{fs: configfs.New(root)}

	if err := a.validateAttr(b, "optimal_sectors", "2048"); err != nil {
		t.Errorf("a value at this device's limit must be accepted: %v", err)
	}
	err := a.validateAttr(b, "optimal_sectors", "4096")
	if err == nil {
		t.Fatal("4096 exceeds this device's hw_max_sectors of 2048 and must be refused; " +
			"a constant limit would have let it through")
	}
	if !strings.Contains(err.Error(), "2048") {
		t.Errorf("the error must name the device's actual limit, got %v", err)
	}
}

// TestUnreadableBoundDoesNotInventARejection: an unreadable hw_max_sectors is
// not evidence the value is wrong. Rejecting there would turn a read failure
// into a bogus configuration error.
func TestUnreadableBoundDoesNotInventARejection(t *testing.T) {
	root := t.TempDir()
	b := testBackstore()
	stageBackstoreDir(t, root, b)
	a := &applyCtx{fs: configfs.New(root)}
	if err := a.validateAttr(b, "optimal_sectors", "999999"); err != nil {
		t.Errorf("with no hw_max_sectors to read, the value must pass through and let "+
			"the kernel decide: %v", err)
	}
}

// TestBadValueOnAnExportedDeviceIsNotReportedAsDrift is the point of the
// whole change.
//
// Both cases are EINVAL from the kernel, and the exported case was
// indistinguishable from immutability, so a bad value on an exported device
// was reported as drift: "the kernel would not change this because the device
// is in use", about a number it would have refused on an idle device too. The
// operator is sent to look at the export rather than at their input.
//
// This is reachable in a tmpdir precisely BECAUSE validation now happens
// before the write -- the neighbouring drift tests note that an end-to-end
// Apply cannot otherwise reach these paths off a real kernel, since a tmpdir
// never returns EINVAL.
func TestBadValueOnAnExportedDeviceIsNotReportedAsDrift(t *testing.T) {
	fs, b := stageDriftBackstore(t, true) // exported
	// The bound is per-device and read from the tree, so it has to be there.
	if err := fs.WriteAttr("16384", append(b.objPath(), "attrib", "hw_max_sectors")...); err != nil {
		t.Fatal(err)
	}
	b.Attributes = map[string]string{"optimal_sectors": "99999999"}

	rep, err := New(fs).Apply(Config{Backstores: []Backstore{b}})
	if err == nil {
		t.Fatal("an out-of-range value must be an error, not tolerated as drift: " +
			"tolerating it declares the config applied when it was not")
	}
	if len(rep.Drift) > 0 {
		t.Errorf("a bad value must not be reported as immutability drift; got %v", rep.Drift)
	}
	if !strings.Contains(err.Error(), "optimal_sectors") {
		t.Errorf("the error must name the attribute at fault, got %v", err)
	}
	if !strings.Contains(err.Error(), "hw_max_sectors") {
		t.Errorf("the error must explain WHY the value is bad rather than blaming the "+
			"export, got %v", err)
	}
}

// TestValidationDoesNotBlockTheToleratedImmutableCase is the counter-test.
//
// Validating values must not make a genuinely immutable attribute fatal again.
// That was a real crash loop: adding optimal_sectors to the managed set gave
// every pre-existing volume a desired value differing from its live one, and
// startup replay crash-looped through seven restarts against a healthy tree.
//
// It checks the gate rather than the outcome, because the tolerated path
// cannot be reached end-to-end in a tmpdir -- only a real kernel returns
// EINVAL for immutability, which is why the drift tests next door unit-test
// the predicate instead. What matters here is that a VALID value still reaches
// the write, where immutableWhileExported can tolerate it.
func TestValidationDoesNotBlockTheToleratedImmutableCase(t *testing.T) {
	fs, b := stageDriftBackstore(t, true)
	if err := fs.WriteAttr("16384", append(b.objPath(), "attrib", "hw_max_sectors")...); err != nil {
		t.Fatal(err)
	}
	a := &applyCtx{fs: fs}
	// The live value the crash loop was about, and the desired one, are both
	// legal -- so validation must let them through to the kernel.
	for _, v := range []string{"0", "8192", "16384"} {
		if err := a.validateAttr(b, "optimal_sectors", v); err != nil {
			t.Errorf("optimal_sectors=%s is a legal value and must reach the write, "+
				"where immutability can be tolerated; validation rejected it: %v", v, err)
		}
	}
}

// TestUnmodelledAttributeStillReachesTheImmutabilityFallback pins the KNOWN
// SCOPE LIMIT of validateAttr rather than pretending it does not exist.
//
// A cross-model review found that the commit adding validateAttr claimed
// "EINVAL means one thing" for the whole path. It does not:
// immutableWhileExported takes no key, so for an attribute validateAttr does
// not model, an out-of-range value on an exported device is still classified
// as immutability drift. Backstore.Attributes is a raw public map, so such a
// key is reachable from a hand-written config through lish.
//
// This is documented behaviour, not a bug to fix by guessing: narrowing the
// fallback to a hard-coded immutable-key list would classify a genuine
// immutability EINVAL as fatal on any kernel whose set differs, which is the
// crash loop the predicate exists to prevent. The safe direction is to extend
// validateAttr, and this test is what will notice when a key is added -- it
// fails, and the fix is to move the key into the modelled list.
func TestUnmodelledAttributeStillReachesTheImmutabilityFallback(t *testing.T) {
	a := &applyCtx{}
	// A key validateAttr models: a bad value is rejected before the write.
	if err := a.validateAttr(Backstore{}, "block_size", "8192"); err == nil {
		t.Error("block_size is modelled, so a bad value must be rejected up front")
	}
	// A key it does not model: passed through, so a kernel EINVAL for a BAD
	// VALUE is indistinguishable from one for immutability.
	if err := a.validateAttr(Backstore{}, "emulate_tpu", "2"); err != nil {
		t.Errorf("emulate_tpu is not modelled, so it must pass through unvalidated "+
			"rather than inventing a rejection the kernel would not make: %v", err)
	}
}
