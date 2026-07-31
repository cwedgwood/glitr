package storage

import (
	"strings"
	"testing"
)

// TestCheckGranularity: the rule is stated once, here, so the appliance can
// apply it without knowing the number.
func TestCheckGranularity(t *testing.T) {
	for _, size := range []int64{0, 4096, 8192, 1 << 20} {
		if err := CheckGranularity(size, 4096); err != nil {
			t.Errorf("size %d is a whole number of 4096 and must be accepted: %v", size, err)
		}
	}
	for _, size := range []int64{1, 512, 4095, 4097, (1 << 20) + 512} {
		err := CheckGranularity(size, 4096)
		if err == nil {
			t.Errorf("size %d is not a whole number of 4096 and must be refused", size)
			continue
		}
		// The message has to name both numbers: a caller told only that its
		// size is wrong cannot work out what to round to, and this error
		// reaches an external controller through the REST API.
		if !strings.Contains(err.Error(), "4096") {
			t.Errorf("the error must name the granularity, got %q", err)
		}
	}
	// A store reporting a smaller granularity accepts sizes a 4096-byte one
	// would refuse. This is the case the method exists for: a block-backed
	// store over a 512-byte device.
	if err := CheckGranularity(4096+512, 512); err != nil {
		t.Errorf("512 granularity must accept a whole number of 512: %v", err)
	}
}

// TestCheckGranularityRefusesNonPositive: size%0 panics, so a store that
// reported a broken value would take the appliance down rather than refuse a
// request. Taking it as "unconstrained" would be worse still -- silently
// accepting sizes the store cannot represent.
func TestCheckGranularityRefusesNonPositive(t *testing.T) {
	for _, gran := range []int64{0, -1, -4096} {
		if err := CheckGranularity(1<<20, gran); err == nil {
			t.Errorf("granularity %d is not usable and must be refused", gran)
		}
	}
}

// TestStoreSizeGranularity: a file-backed store reports the constant, and the
// constant is a power of two at least as large as a 512-byte sector. Asserted
// rather than assumed because every size on the appliance is a multiple of it.
func TestStoreSizeGranularity(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got := s.SizeGranularity()
	if got != SizeGranularity {
		t.Errorf("a file-backed store must report %d, got %d", int64(SizeGranularity), got)
	}
	if got < 512 || got&(got-1) != 0 {
		t.Errorf("granularity %d must be a power of two of at least 512", got)
	}
}
