package lish

import (
	"net/netip"
	"testing"

	"github.com/cwedgwood/glitr/lio"
)

func TestWwidOf(t *testing.T) {
	if got := wwidOf("0011223344556677"); got != "0x60014050011223344556677000000000" {
		t.Fatalf("wwidOf = %q", got)
	}
	if len("0x60014050011223344556677000000000") != 2+32 {
		t.Fatal("wwid not 32 hex")
	}
	if got := wwidOf("short"); got != "" {
		t.Fatalf("wwidOf(short) = %q; want empty", got)
	}
}

func TestFreeHBA(t *testing.T) {
	cfg := &lio.Config{Backstores: []lio.Backstore{{HBA: 0}, {HBA: 2}}}
	if got := freeHBA(cfg); got != 1 {
		t.Fatalf("freeHBA = %d; want 1 (lowest free)", got)
	}
	cfg = &lio.Config{Backstores: []lio.Backstore{{HBA: 0}, {HBA: 1}}}
	if got := freeHBA(cfg); got != 2 {
		t.Fatalf("freeHBA = %d; want 2", got)
	}
}

func TestTargetIdx(t *testing.T) {
	cfg := &lio.Config{Targets: []lio.Target{{IQN: "a"}, {IQN: "b"}}}
	if targetIdx(cfg, "b") != 1 || targetIdx(cfg, "x") != -1 {
		t.Fatal("targetIdx wrong")
	}
}

func TestParsePortalLabel(t *testing.T) {
	p, ok := parsePortalLabel("10.0.0.1:3261")
	if !ok || p.IP != mustAddr("10.0.0.1") || p.Port != 3261 {
		t.Fatalf("parsePortalLabel = %+v ok=%v", p, ok)
	}
	p, ok = parsePortalLabel("10.0.0.1")
	if !ok || p.Port != lio.DefaultPortalPort {
		t.Fatalf("bare ip should default port: %+v", p)
	}
	if _, ok := parsePortalLabel("10.0.0.1:notaport"); ok {
		t.Fatal("bad port should fail")
	}
}

// TestParentRoundTrip checks that parentOf/pathOf reconstruct a stable path
// for representative deep nodes (no kernel needed).
func TestParentPath(t *testing.T) {
	s := &Shell{cwd: rootNode()}
	ml := &Node{kind: kMappedLUN, name: "mapped_lun0", iqn: "iqn.x:t", tag: 1, initiator: "iqn.x:i", index: 0}
	got := s.pathOf(ml)
	want := "/iscsi/iqn.x:t/tpg1/acls/iqn.x:i/mapped_lun0"
	if got != want {
		t.Fatalf("pathOf = %q; want %q", got, want)
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
