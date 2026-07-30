package lish

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/cwedgwood/glitr/lio"
	"github.com/cwedgwood/glitr/saveconfig"
)

// --- create ---------------------------------------------------------------

func (s *Shell) cmdCreate(args []string) error {
	switch s.cwd.kind {
	case kBSType:
		// create <name> <dev> [size-bytes]
		if len(args) < 2 {
			return fmt.Errorf("usage: create <name> <dev> [size-bytes]")
		}
		var size int64
		if len(args) >= 3 {
			n, err := strconv.ParseInt(args[2], 10, 64)
			if err != nil {
				return fmt.Errorf("bad size %q: %w", args[2], err)
			}
			size = n
		}
		name, dev := args[0], args[1]
		return s.mutate(func(cfg *lio.Config) error {
			for _, b := range cfg.Backstores {
				if b.Name == name {
					return fmt.Errorf("backstore %q already exists", name)
				}
			}
			cfg.Backstores = append(cfg.Backstores, lio.Backstore{
				Type: s.cwd.btype, HBA: freeHBA(cfg), Name: name, Dev: dev, Size: size,
			})
			return nil
		})
	case kISCSI:
		// create <iqn>  → target with an enabled tpg1
		if len(args) != 1 {
			return fmt.Errorf("usage: create <iqn>")
		}
		iqn := args[0]
		return s.mutate(func(cfg *lio.Config) error {
			if targetIdx(cfg, iqn) >= 0 {
				return fmt.Errorf("target %q already exists", iqn)
			}
			cfg.Targets = append(cfg.Targets, lio.Target{
				IQN:  iqn,
				TPGs: []lio.TPG{{Tag: 1, Enable: true}},
			})
			return nil
		})
	case kLUNs:
		// create <index> <backstore>
		if len(args) != 2 {
			return fmt.Errorf("usage: create <index> <backstore>")
		}
		idx, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("bad LUN index %q: %w", args[0], err)
		}
		bs := args[1]
		return s.editTPG(func(g *lio.TPG) error {
			for _, l := range g.LUNs {
				if l.Index == idx {
					return fmt.Errorf("lun%d already exists", idx)
				}
			}
			g.LUNs = append(g.LUNs, lio.LUN{Index: idx, Backstore: bs})
			return nil
		})
	case kACLs:
		// create <initiator-iqn>
		if len(args) != 1 {
			return fmt.Errorf("usage: create <initiator-iqn>")
		}
		iqn := args[0]
		return s.editTPG(func(g *lio.TPG) error {
			for _, a := range g.ACLs {
				if a.InitiatorIQN == iqn {
					return fmt.Errorf("acl %q already exists", iqn)
				}
			}
			g.ACLs = append(g.ACLs, lio.ACL{InitiatorIQN: iqn})
			return nil
		})
	case kPortals:
		// create <ip> [port]
		if len(args) < 1 {
			return fmt.Errorf("usage: create <ip> [port]")
		}
		port := lio.DefaultPortalPort
		if len(args) >= 2 {
			p, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("bad port %q: %w", args[1], err)
			}
			port = p
		}
		np, ok := lio.ParsePortal(args[0])
		if !ok {
			return fmt.Errorf("bad portal address %q", args[0])
		}
		np.Port = uint16(port)
		return s.editTPG(func(g *lio.TPG) error {
			for _, pt := range g.Portals {
				// Addr comparison, so two spellings of one IPv6 address are
				// caught here rather than by the kernel refusing the bind.
				if pt.IP == np.IP && pt.Port == np.Port {
					return fmt.Errorf("portal %s already exists", np)
				}
			}
			g.Portals = append(g.Portals, np)
			return nil
		})
	}
	return fmt.Errorf("cannot create under %s", s.pathOf(s.cwd))
}

// --- delete ---------------------------------------------------------------

func (s *Shell) cmdDelete(args []string) error {
	switch s.cwd.kind {
	case kBSType:
		if len(args) != 1 {
			return fmt.Errorf("usage: delete <name>")
		}
		return s.deleteBackstore(s.cwd.btype, args[0])
	case kBackstore:
		return s.deleteBackstore(s.cwd.btype, s.cwd.name)
	case kTarget:
		iqn := s.cwd.iqn
		if err := s.mutate(func(cfg *lio.Config) error {
			i := targetIdx(cfg, iqn)
			if i < 0 {
				return fmt.Errorf("no such target %q", iqn)
			}
			cfg.Targets = append(cfg.Targets[:i], cfg.Targets[i+1:]...)
			return nil
		}); err != nil {
			return err
		}
		s.cwd, _ = s.parentOf(s.cwd)
		return nil
	case kLUNs:
		if len(args) != 1 {
			return fmt.Errorf("usage: delete <index>")
		}
		idx, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("bad index %q: %w", args[0], err)
		}
		return s.editTPG(func(g *lio.TPG) error {
			for i, l := range g.LUNs {
				if l.Index == idx {
					g.LUNs = append(g.LUNs[:i], g.LUNs[i+1:]...)
					return nil
				}
			}
			return fmt.Errorf("no such lun%d", idx)
		})
	case kLUN:
		idx := s.cwd.index
		if err := s.editTPG(func(g *lio.TPG) error {
			for i, l := range g.LUNs {
				if l.Index == idx {
					g.LUNs = append(g.LUNs[:i], g.LUNs[i+1:]...)
					return nil
				}
			}
			return fmt.Errorf("no such lun%d", idx)
		}); err != nil {
			return err
		}
		s.cwd, _ = s.parentOf(s.cwd)
		return nil
	case kACLs:
		if len(args) != 1 {
			return fmt.Errorf("usage: delete <initiator-iqn>")
		}
		return s.deleteACL(args[0])
	case kACL:
		if err := s.deleteACL(s.cwd.initiator); err != nil {
			return err
		}
		s.cwd, _ = s.parentOf(s.cwd)
		return nil
	case kMappedLUN:
		return s.cmdUnmapIndex(s.cwd.initiator, s.cwd.index, true)
	case kPortals:
		if len(args) < 1 {
			return fmt.Errorf("usage: delete <ip> [port]")
		}
		p, ok := parsePortalLabel(strings.Join(args, ":"))
		if len(args) >= 2 {
			pt, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("bad port %q: %w", args[1], err)
			}
			p, ok = lio.ParsePortal(args[0])
			p.Port = uint16(pt)
		}
		if !ok {
			return fmt.Errorf("bad portal %v", args)
		}
		return s.deletePortal(p)
	case kPortal:
		if err := s.deletePortal(s.cwd.portal); err != nil {
			return err
		}
		s.cwd, _ = s.parentOf(s.cwd)
		return nil
	}
	return fmt.Errorf("cannot delete at %s", s.pathOf(s.cwd))
}

func (s *Shell) deleteBackstore(bt lio.BackstoreType, name string) error {
	return s.mutate(func(cfg *lio.Config) error {
		for i, b := range cfg.Backstores {
			if b.Type == bt && b.Name == name {
				cfg.Backstores = append(cfg.Backstores[:i], cfg.Backstores[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("no such %s backstore %q", bt, name)
	})
}

func (s *Shell) deleteACL(iqn string) error {
	return s.editTPG(func(g *lio.TPG) error {
		for i, a := range g.ACLs {
			if a.InitiatorIQN == iqn {
				g.ACLs = append(g.ACLs[:i], g.ACLs[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("no such acl %q", iqn)
	})
}

func (s *Shell) deletePortal(p lio.Portal) error {
	return s.editTPG(func(g *lio.TPG) error {
		for i, pt := range g.Portals {
			if pt.IP == p.IP && (pt.Port == p.Port || (pt.Port == 0 && p.Port == lio.DefaultPortalPort)) {
				g.Portals = append(g.Portals[:i], g.Portals[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("no such portal %s:%d", p.IP, p.Port)
	})
}

// --- set / enable / map ---------------------------------------------------

func (s *Shell) cmdSet(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: set <attr> <value>")
	}
	attr, val := args[0], args[1]
	switch s.cwd.kind {
	case kBackstore:
		name, bt := s.cwd.name, s.cwd.btype
		return s.mutate(func(cfg *lio.Config) error {
			b := findBackstore(cfg, bt, name)
			if b == nil {
				return fmt.Errorf("no such backstore %q", name)
			}
			switch attr {
			case "wwn":
				b.WWN = val
			case "vendor_id":
				b.VendorID = val
			case "product_id":
				b.ProductID = val
			case "revision":
				b.Revision = val
			case "block_size":
				if b.Attributes == nil {
					b.Attributes = map[string]string{}
				}
				b.Attributes[attr] = val
			default:
				return fmt.Errorf("unknown backstore attr %q (wwn|vendor_id|product_id|revision|block_size)", attr)
			}
			return nil
		})
	case kTPG:
		// Warn, do not refuse. An unmanaged attribute still applies to the
		// running kernel, so refusing would remove a capability the shell has
		// always had -- but Discover reads only the managed set, so `save`
		// omits it and it is gone at the next boot with nothing reporting it.
		// That silent loss is the whole reason the managed set was widened
		// from 3 keys to 13; a key outside it has the same problem.
		if !slices.Contains(lio.DiscoveredTPGAttrs(), attr) {
			s.printf("WARNING: %s is not in the set this appliance saves and restores, "+
				"so it applies now but `save` will omit it and it will be gone at the "+
				"next boot\n", attr)
		}
		return s.editTPG(func(g *lio.TPG) error {
			if g.Attributes == nil {
				g.Attributes = map[string]string{}
			}
			g.Attributes[attr] = val
			return nil
		})
	}
	return fmt.Errorf("cannot set at %s", s.pathOf(s.cwd))
}

func (s *Shell) cmdEnable(on bool) error {
	if s.cwd.kind != kTPG {
		return fmt.Errorf("enable/disable only apply to a tpg")
	}
	return s.editTPG(func(g *lio.TPG) error { g.Enable = on; return nil })
}

func (s *Shell) cmdMap(args []string) error {
	if s.cwd.kind != kACL {
		return fmt.Errorf("map only applies to an acl")
	}
	if len(args) < 2 {
		return fmt.Errorf("usage: map <mapped-lun> <tpg-lun> [ro]")
	}
	ml, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("bad mapped-lun %q: %w", args[0], err)
	}
	tl, err := strconv.Atoi(args[1])
	if err != nil {
		return fmt.Errorf("bad tpg-lun %q: %w", args[1], err)
	}
	ro := len(args) >= 3 && (args[2] == "ro" || args[2] == "1" || args[2] == "true")
	iqn := s.cwd.initiator
	return s.editACL(iqn, func(a *lio.ACL) error {
		for _, m := range a.MappedLUNs {
			if m.Index == ml {
				return fmt.Errorf("mapped_lun%d already exists", ml)
			}
		}
		a.MappedLUNs = append(a.MappedLUNs, lio.MappedLUN{Index: ml, TPGLUN: tl, WriteProtect: ro})
		return nil
	})
}

func (s *Shell) cmdUnmap(args []string) error {
	if s.cwd.kind != kACL {
		return fmt.Errorf("unmap only applies to an acl")
	}
	if len(args) != 1 {
		return fmt.Errorf("usage: unmap <mapped-lun>")
	}
	ml, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("bad mapped-lun %q: %w", args[0], err)
	}
	return s.cmdUnmapIndex(s.cwd.initiator, ml, false)
}

func (s *Shell) cmdUnmapIndex(iqn string, ml int, cdUp bool) error {
	if err := s.editACL(iqn, func(a *lio.ACL) error {
		for i, m := range a.MappedLUNs {
			if m.Index == ml {
				a.MappedLUNs = append(a.MappedLUNs[:i], a.MappedLUNs[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("no such mapped_lun%d", ml)
	}); err != nil {
		return err
	}
	if cdUp {
		s.cwd, _ = s.parentOf(s.cwd)
	}
	return nil
}

// --- info / get -----------------------------------------------------------

func (s *Shell) cmdInfo(args []string) error {
	n := s.cwd
	if len(args) > 0 {
		r, err := s.resolve(args[0])
		if err != nil {
			return err
		}
		n = r
	}
	cfg, err := s.config()
	if err != nil {
		return err
	}
	switch n.kind {
	case kBackstore:
		b := findBackstore(&cfg, n.btype, n.name)
		if b == nil {
			return fmt.Errorf("no such backstore %q", n.name)
		}
		s.printf("name:       %s\n", b.Name)
		s.printf("type:       %s\n", b.Type)
		s.printf("dev:        %s\n", b.Dev)
		s.printf("size:       %d\n", b.Size)
		s.printf("wwn:        %s\n", b.WWN)
		s.printf("wwid:       %s\n", wwidOf(b.WWN))
		if b.VendorID != "" {
			s.printf("vendor_id:  %s\n", b.VendorID)
		}
		if b.ProductID != "" {
			s.printf("product_id: %s\n", b.ProductID)
		}
		if b.Revision != "" {
			s.printf("revision:   %s\n", b.Revision)
		}
		for _, k := range sortedKeys(b.Attributes) {
			s.printf("attr %s: %s\n", k, b.Attributes[k])
		}
	case kTPG:
		for _, g := range tpgOf(cfg, n.iqn, n.tag) {
			s.printf("tpg:      %d\n", g.Tag)
			s.printf("enabled:  %t\n", g.Enable)
			s.printf("portals:  %d\n", len(g.Portals))
			s.printf("luns:     %d\n", len(g.LUNs))
			s.printf("acls:     %d\n", len(g.ACLs))
			for _, k := range sortedKeys(g.Attributes) {
				s.printf("attr %s: %s\n", k, g.Attributes[k])
			}
		}
	default:
		s.printf("%s%s\n", n.name, summarySuffix(n.summary(s)))
	}
	return nil
}

func (s *Shell) cmdGet(args []string) error {
	cfg, err := s.config()
	if err != nil {
		return err
	}
	switch s.cwd.kind {
	case kBackstore:
		b := findBackstore(&cfg, s.cwd.btype, s.cwd.name)
		if b == nil {
			return fmt.Errorf("no such backstore %q", s.cwd.name)
		}
		got := map[string]string{
			"wwn": b.WWN, "vendor_id": b.VendorID,
			"product_id": b.ProductID, "revision": b.Revision,
		}
		maps.Copy(got, b.Attributes)
		return s.printMap(got, args)
	case kTPG:
		for _, g := range tpgOf(cfg, s.cwd.iqn, s.cwd.tag) {
			return s.printMap(g.Attributes, args)
		}
	}
	return fmt.Errorf("cannot get at %s", s.pathOf(s.cwd))
}

func (s *Shell) printMap(m map[string]string, want []string) error {
	if len(want) > 0 {
		for _, k := range want {
			s.printf("%s=%s\n", k, m[k])
		}
		return nil
	}
	for _, k := range sortedKeys(m) {
		s.printf("%s=%s\n", k, m[k])
	}
	return nil
}

func (s *Shell) cmdHelp() error {
	s.printf(`navigation: ls [path]  tree [path]  cd [path]  pwd  info [path]  get [attr...]
globals:    saveconfig [file]  restoreconfig [file]  clearconfig  help  exit
  (tree = recursive dump from here; 'lish discover' dumps the whole config as JSON)
contextual verbs by location:
  /backstores/<type>   create <name> <dev> [size] | delete <name>
  <backstore>          set wwn|vendor_id|product_id|revision|block_size <v> | info
  /iscsi               create <iqn> | (cd <iqn>) delete
  <tpg>                enable | disable | set <attr> <v> | info
  <tpg>/luns           create <index> <backstore> | delete <index>
  <tpg>/acls           create <iqn> | delete <iqn>
  <acl>                map <mapped-lun> <tpg-lun> [ro] | unmap <mapped-lun>
  <tpg>/portals        create <ip> [port] | delete <ip> [port]
`)
	return nil
}

// --- persistence globals --------------------------------------------------

func (s *Shell) cmdSave(args []string) error {
	path := saveconfig.DefaultPath
	if len(args) > 0 {
		path = args[0]
	}
	if err := saveconfig.Save(s.m, path); err != nil {
		return err
	}
	s.printf("saved to %s\n", path)
	return nil
}

func (s *Shell) cmdRestore(args []string) error {
	path := saveconfig.DefaultPath
	if len(args) > 0 {
		path = args[0]
	}
	rep, err := saveconfig.Restore(s.m, path)
	if err != nil {
		return err
	}
	s.printf("restored from %s (%d changes)\n", path, len(rep.Changes))
	s.invalidate()
	return nil
}

func (s *Shell) cmdClear() error {
	rep, err := s.m.Clear()
	if err != nil {
		return err
	}
	s.printf("cleared (%d changes)\n", len(rep.Changes))
	s.cwd = rootNode()
	s.invalidate()
	return nil
}

// --- edit helpers ---------------------------------------------------------

// editTPG mutates the TPG identified by the current node's (iqn,tag).
func (s *Shell) editTPG(fn func(g *lio.TPG) error) error {
	iqn, tag := s.cwd.iqn, s.cwd.tag
	return s.mutate(func(cfg *lio.Config) error {
		ti := targetIdx(cfg, iqn)
		if ti < 0 {
			return fmt.Errorf("no such target %q", iqn)
		}
		for gi := range cfg.Targets[ti].TPGs {
			if cfg.Targets[ti].TPGs[gi].Tag == tag {
				return fn(&cfg.Targets[ti].TPGs[gi])
			}
		}
		return fmt.Errorf("no such tpg%d", tag)
	})
}

// editACL mutates the ACL identified by iqn within the current node's TPG.
func (s *Shell) editACL(initiator string, fn func(a *lio.ACL) error) error {
	return s.editTPG(func(g *lio.TPG) error {
		for i := range g.ACLs {
			if g.ACLs[i].InitiatorIQN == initiator {
				return fn(&g.ACLs[i])
			}
		}
		return fmt.Errorf("no such acl %q", initiator)
	})
}

// --- pure helpers ---------------------------------------------------------

func freeHBA(cfg *lio.Config) int {
	used := map[int]bool{}
	for _, b := range cfg.Backstores {
		used[b.HBA] = true
	}
	for i := 0; ; i++ {
		if !used[i] {
			return i
		}
	}
}

func targetIdx(cfg *lio.Config, iqn string) int {
	for i, t := range cfg.Targets {
		if t.IQN == iqn {
			return i
		}
	}
	return -1
}

func findBackstore(cfg *lio.Config, bt lio.BackstoreType, name string) *lio.Backstore {
	for i := range cfg.Backstores {
		if cfg.Backstores[i].Type == bt && cfg.Backstores[i].Name == name {
			return &cfg.Backstores[i]
		}
	}
	return nil
}

// wwidOf renders the initiator-visible NAA wwid for a 16-hex wwn, or "" if the
// wwn is not the expected width (kernel-assigned values are still 16 hex).
func wwidOf(wwn string) string {
	if len(wwn) != 16 {
		return ""
	}
	return "0x6001405" + wwn + "000000000"
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

func summarySuffix(s string) string {
	if s == "" {
		return ""
	}
	return " " + s
}
