package lio

import (
	"net/netip"
	"testing"
)

func TestParseInfoSize(t *testing.T) {
	// Real fileio info line: "Size: N" appears AFTER "SectorSize: 512".
	info := "Status: ACTIVATED  Max Queue Depth: 0  SectorSize: 512  " +
		"HwMaxSectors: 16384\n        TCM FILEIO ID: 0        " +
		"File: /var/lib/glitr/x.img  Size: 134217728  Mode: O_DSYNC Async: 0"
	if got := parseInfoSize(info); got != 134217728 {
		t.Fatalf("parseInfoSize = %d; want 134217728 (must not match SectorSize)", got)
	}
	if got := parseInfoSize("SectorSize: 4096  Size: 268435456 x"); got != 268435456 {
		t.Fatalf("parseInfoSize(4096 case) = %d; want 268435456", got)
	}
	if got := parseInfoSize("no size here"); got != -1 {
		t.Fatalf("parseInfoSize(absent) = %d; want -1", got)
	}
}

func TestIsHex16(t *testing.T) {
	ok := []string{"1234567890abcdef", "00112233445566aa", "ffffffffffffffff"}
	bad := []string{"", "1234", "1234567890ABCDEF", "1234567890abcdeg",
		"1234567890abcdef0", "deadbeef-cafe-0001"}
	for _, s := range ok {
		if !isHex16(s) {
			t.Errorf("isHex16(%q) = false; want true", s)
		}
	}
	for _, s := range bad {
		if isHex16(s) {
			t.Errorf("isHex16(%q) = true; want false", s)
		}
	}
}

func TestBackstoreWWNValidation(t *testing.T) {
	base := Backstore{Type: FileIO, Name: "d0", Dev: "/tmp/d0.img"}
	if err := base.validate(); err != nil {
		t.Fatalf("empty wwn should be valid: %v", err)
	}
	base.WWN = "1234567890abcdef"
	if err := base.validate(); err != nil {
		t.Fatalf("16-hex wwn should be valid: %v", err)
	}
	base.WWN = "NOThex"
	if err := base.validate(); err == nil {
		t.Fatalf("non-hex wwn should be rejected")
	}
}

// mustAddr parses a literal test address. Panics: a malformed constant in a
// test is a bug in the test, not a condition to handle.
func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
