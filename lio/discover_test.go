package lio

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cwedgwood/glitr/lio/configfs"
)

func TestValidate(t *testing.T) {
	base := Config{
		Backstores: []Backstore{{Type: FileIO, Name: "d0", Dev: "/tmp/d0.img"}},
		Targets: []Target{{IQN: "iqn.2026-01.dev.glitr:t", TPGs: []TPG{{
			Tag:  1,
			LUNs: []LUN{{Index: 0, Backstore: "d0"}},
			ACLs: []ACL{{InitiatorIQN: "iqn.2026-01.dev.glitr:i",
				MappedLUNs: []MappedLUN{{Index: 0, TPGLUN: 0}}}},
		}}}},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := []struct {
		name string
		mut  func(*Config)
		kind Kind
	}{
		{"bad-iqn", func(c *Config) { c.Targets[0].IQN = "bogus" }, KindInvalidSpec},
		{"lun-missing-backstore", func(c *Config) { c.Targets[0].TPGs[0].LUNs[0].Backstore = "nope" }, KindDependency},
		{"dup-backstore", func(c *Config) { c.Backstores = append(c.Backstores, c.Backstores[0]) }, KindInvalidSpec},
		{"mapped-missing-lun", func(c *Config) { c.Targets[0].TPGs[0].ACLs[0].MappedLUNs[0].TPGLUN = 9 }, KindDependency},
		{"bad-type", func(c *Config) { c.Backstores[0].Type = "bogus" }, KindInvalidSpec},
		{"bad-tag", func(c *Config) { c.Targets[0].TPGs[0].Tag = 0 }, KindInvalidSpec},
		{"dup-target-iqn", func(c *Config) { c.Targets = append(c.Targets, c.Targets[0]) }, KindInvalidSpec},
		{"dup-tpg-tag", func(c *Config) { c.Targets[0].TPGs = append(c.Targets[0].TPGs, c.Targets[0].TPGs[0]) }, KindInvalidSpec},
		{"dup-acl-iqn", func(c *Config) {
			c.Targets[0].TPGs[0].ACLs = append(c.Targets[0].TPGs[0].ACLs, c.Targets[0].TPGs[0].ACLs[0])
		}, KindInvalidSpec},
		{"dup-portal", func(c *Config) {
			c.Targets[0].TPGs[0].Portals = []Portal{{IP: mustAddr("10.0.0.1"), Port: 3260}, {IP: mustAddr("10.0.0.1"), Port: 3260}}
		}, KindInvalidSpec},
		{"dup-mapped-lun", func(c *Config) {
			c.Targets[0].TPGs[0].ACLs[0].MappedLUNs = append(c.Targets[0].TPGs[0].ACLs[0].MappedLUNs, MappedLUN{Index: 0, TPGLUN: 0})
		}, KindInvalidSpec},
		{"neg-mapped-lun", func(c *Config) { c.Targets[0].TPGs[0].ACLs[0].MappedLUNs[0].Index = -1 }, KindInvalidSpec},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := deepCopy(base)
			tc.mut(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected error")
			}
			if got := KindOf(err); got != tc.kind {
				t.Fatalf("KindOf = %s; want %s (%v)", got, tc.kind, err)
			}
		})
	}
}

func TestDiscoverFakeTree(t *testing.T) {
	root := t.TempDir()
	mk := func(parts ...string) string {
		p := filepath.Join(append([]string{root}, parts...)...)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	wr := func(val string, parts ...string) {
		p := filepath.Join(append([]string{root}, parts...)...)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(val+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	iqn := "iqn.2026-01.dev.glitr:target"
	ini := "iqn.2026-01.dev.glitr:initiator"

	// Backstore.
	mk("core", "fileio_0", "test0", "wwn")
	os.WriteFile(filepath.Join(root, "core", "fileio_0", "hba_info"), []byte("x"), 0o644)
	wr("/var/lib/glitr/test0.img", "core", "fileio_0", "test0", "udev_path")
	wr("T10 VPD Unit Serial Number: abc-123", "core", "fileio_0", "test0", "wwn", "vpd_unit_serial")
	wr("4096", "core", "fileio_0", "test0", "attrib", "block_size") // managed attr must round-trip (H2)

	// Target / TPG / portal.
	wr("1", "iscsi", iqn, "tpgt_1", "enable")
	wr("0", "iscsi", iqn, "tpgt_1", "attrib", "authentication") // managed TPG attr must round-trip (H2)
	mk("iscsi", iqn, "tpgt_1", "np", "10.10.0.1:3260")
	// discovery_auth is a real directory in configfs and must be skipped.
	mk("iscsi", "discovery_auth")
	os.WriteFile(filepath.Join(root, "iscsi", "lio_version"), []byte("x"), 0o644)

	// TPG LUN 0 -> backstore.
	lunDir := mk("iscsi", iqn, "tpgt_1", "lun", "lun_0")
	if err := os.Symlink(filepath.Join(root, "core", "fileio_0", "test0"), filepath.Join(lunDir, "aa11bb22cc")); err != nil {
		t.Fatal(err)
	}

	// ACL + mapped LUN 0 -> TPG LUN 0.
	mlunDir := mk("iscsi", iqn, "tpgt_1", "acls", ini, "lun_0")
	if err := os.Symlink(filepath.Join(root, "iscsi", iqn, "tpgt_1", "lun", "lun_0"), filepath.Join(mlunDir, "dd33ee44ff")); err != nil {
		t.Fatal(err)
	}
	wr("0", "iscsi", iqn, "tpgt_1", "acls", ini, "lun_0", "write_protect")

	m := New(configfs.New(root))
	cfg, err := m.Discover()
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if len(cfg.Backstores) != 1 {
		t.Fatalf("backstores = %d; want 1", len(cfg.Backstores))
	}
	b := cfg.Backstores[0]
	if b.Type != FileIO || b.Name != "test0" || b.Dev != "/var/lib/glitr/test0.img" || b.WWN != "abc-123" {
		t.Fatalf("backstore discovered wrong: %+v", b)
	}
	if b.Attributes["block_size"] != "4096" {
		t.Fatalf("backstore block_size not discovered: %+v", b.Attributes)
	}

	if len(cfg.Targets) != 1 {
		t.Fatalf("targets = %d; want 1 (discovery_auth must be skipped)", len(cfg.Targets))
	}
	tp := cfg.Targets[0].TPGs[0]
	if !tp.Enable || len(tp.Portals) != 1 || tp.Portals[0].IP != mustAddr("10.10.0.1") || tp.Portals[0].Port != 3260 {
		t.Fatalf("tpg/portal discovered wrong: %+v", tp)
	}
	if tp.Attributes["authentication"] != "0" {
		t.Fatalf("tpg authentication not discovered: %+v", tp.Attributes)
	}
	if len(tp.LUNs) != 1 || tp.LUNs[0].Backstore != "test0" {
		t.Fatalf("lun discovered wrong: %+v", tp.LUNs)
	}
	if len(tp.ACLs) != 1 || tp.ACLs[0].InitiatorIQN != ini {
		t.Fatalf("acl discovered wrong: %+v", tp.ACLs)
	}
	if len(tp.ACLs[0].MappedLUNs) != 1 || tp.ACLs[0].MappedLUNs[0].TPGLUN != 0 {
		t.Fatalf("mapped lun discovered wrong: %+v", tp.ACLs[0].MappedLUNs)
	}
}

// deepCopy makes an independent copy of a Config for mutation in tests.
func deepCopy(c Config) Config {
	out := c
	out.Backstores = append([]Backstore(nil), c.Backstores...)
	out.Targets = make([]Target, len(c.Targets))
	for i, t := range c.Targets {
		nt := t
		nt.TPGs = make([]TPG, len(t.TPGs))
		for j, g := range t.TPGs {
			ng := g
			ng.LUNs = append([]LUN(nil), g.LUNs...)
			ng.Portals = append([]Portal(nil), g.Portals...)
			ng.ACLs = make([]ACL, len(g.ACLs))
			for k, acl := range g.ACLs {
				na := acl
				na.MappedLUNs = append([]MappedLUN(nil), acl.MappedLUNs...)
				ng.ACLs[k] = na
			}
			nt.TPGs[j] = ng
		}
		out.Targets[i] = nt
	}
	return out
}

// TestDiscoverAbsentTreeIsNotEmptyConfig pins the distinction between "the
// LIO subsystem is not here" and "nothing is configured".
//
// Discovery treats an absent subdirectory as "none configured", which is
// correct inside a live tree. Applied to a host where configfs is not mounted
// or target_core_mod is not loaded, that rule reported an empty Config with
// no error -- and a caller that persists what it discovers then wrote {} over
// a good saved configuration and reported success, destroying the only record
// that survives a reboot.
func TestDiscoverAbsentTreeIsNotEmptyConfig(t *testing.T) {
	// A path that does not exist: the subsystem is absent.
	m := New(configfs.New(filepath.Join(t.TempDir(), "no-such-tree")))
	if _, err := m.Discover(); !errors.Is(err, ErrNoLIOTree) {
		t.Fatalf("Discover on an absent tree = %v, want ErrNoLIOTree", err)
	}

	// A path that exists but is a file, not a directory: also not a tree.
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(configfs.New(f)).Discover(); !errors.Is(err, ErrNoLIOTree) {
		t.Fatalf("Discover on a non-directory = %v, want ErrNoLIOTree", err)
	}

	// An empty tree that IS present is a legitimate empty Config, not an
	// error -- a host with the modules loaded and nothing exported yet.
	empty := t.TempDir()
	cfg, err := New(configfs.New(empty)).Discover()
	if err != nil {
		t.Fatalf("Discover on a present-but-empty tree: %v", err)
	}
	if len(cfg.Backstores) != 0 || len(cfg.Targets) != 0 {
		t.Fatalf("present-but-empty tree gave %+v, want an empty Config", cfg)
	}
}
