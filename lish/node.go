package lish

import (
	"fmt"
	"strconv"

	"github.com/cwedgwood/glitr/lio"
)

// kind identifies the type of a node in the LIO object tree.
type kind int

const (
	kRoot kind = iota
	kBackstores
	kBSType    // /backstores/fileio, /backstores/iblock
	kBackstore // a storage object
	kISCSI     // /iscsi
	kTarget    // an iSCSI target
	kTPG       // a target portal group
	kLUNs      // .../luns
	kLUN       // a LUN
	kACLs      // .../acls
	kACL       // a node ACL
	kMappedLUN // a mapped LUN under an ACL
	kPortals   // .../portals
	kPortal    // a portal
)

// Node is a single element of the navigable LIO tree. One struct with a
// kind + context fields keeps the tree compact (vs a type per level).
type Node struct {
	kind      kind
	name      string // path segment / display name
	btype     lio.BackstoreType
	iqn       string
	tag       int
	initiator string
	index     int
	portal    lio.Portal
}

func rootNode() *Node { return &Node{kind: kRoot, name: ""} }

// children returns the child nodes derived from live LIO state.
func (n *Node) children(sh *Shell) ([]*Node, error) {
	cfg, err := sh.config()
	if err != nil {
		return nil, err
	}
	switch n.kind {
	case kRoot:
		return []*Node{
			{kind: kBackstores, name: "backstores"},
			{kind: kISCSI, name: "iscsi"},
		}, nil
	case kBackstores:
		return []*Node{
			{kind: kBSType, name: "fileio", btype: lio.FileIO},
			{kind: kBSType, name: "iblock", btype: lio.IBlock},
		}, nil
	case kBSType:
		var out []*Node
		for _, b := range cfg.Backstores {
			if b.Type == n.btype {
				out = append(out, &Node{kind: kBackstore, name: b.Name, btype: b.Type})
			}
		}
		return out, nil
	case kISCSI:
		var out []*Node
		for _, t := range cfg.Targets {
			out = append(out, &Node{kind: kTarget, name: t.IQN, iqn: t.IQN})
		}
		return out, nil
	case kTarget:
		var out []*Node
		for _, t := range cfg.Targets {
			if t.IQN == n.iqn {
				for _, g := range t.TPGs {
					out = append(out, &Node{kind: kTPG, name: "tpg" + strconv.Itoa(g.Tag), iqn: n.iqn, tag: g.Tag})
				}
			}
		}
		return out, nil
	case kTPG:
		return []*Node{
			{kind: kLUNs, name: "luns", iqn: n.iqn, tag: n.tag},
			{kind: kACLs, name: "acls", iqn: n.iqn, tag: n.tag},
			{kind: kPortals, name: "portals", iqn: n.iqn, tag: n.tag},
		}, nil
	case kLUNs:
		var out []*Node
		for _, g := range tpgOf(cfg, n.iqn, n.tag) {
			for _, l := range g.LUNs {
				out = append(out, &Node{kind: kLUN, name: "lun" + strconv.Itoa(l.Index), iqn: n.iqn, tag: n.tag, index: l.Index})
			}
		}
		return out, nil
	case kACLs:
		var out []*Node
		for _, g := range tpgOf(cfg, n.iqn, n.tag) {
			for _, a := range g.ACLs {
				out = append(out, &Node{kind: kACL, name: a.InitiatorIQN, iqn: n.iqn, tag: n.tag, initiator: a.InitiatorIQN})
			}
		}
		return out, nil
	case kACL:
		var out []*Node
		for _, g := range tpgOf(cfg, n.iqn, n.tag) {
			for _, a := range g.ACLs {
				if a.InitiatorIQN == n.initiator {
					for _, ml := range a.MappedLUNs {
						out = append(out, &Node{kind: kMappedLUN, name: "mapped_lun" + strconv.Itoa(ml.Index), iqn: n.iqn, tag: n.tag, initiator: n.initiator, index: ml.Index})
					}
				}
			}
		}
		return out, nil
	case kPortals:
		var out []*Node
		for _, g := range tpgOf(cfg, n.iqn, n.tag) {
			for _, p := range g.Portals {
				out = append(out, &Node{kind: kPortal, name: portalLabel(p), iqn: n.iqn, tag: n.tag, portal: p})
			}
		}
		return out, nil
	default:
		return nil, nil
	}
}

// summary is the short status ls shows next to the node.
func (n *Node) summary(sh *Shell) string {
	cfg, err := sh.config()
	if err != nil {
		return ""
	}
	switch n.kind {
	case kBackstore:
		for _, b := range cfg.Backstores {
			if b.Type == n.btype && b.Name == n.name {
				s := b.Dev
				if b.WWN != "" {
					s += " wwid=" + b.WWN
				}
				return "[" + s + "]"
			}
		}
	case kTarget:
		for _, t := range cfg.Targets {
			if t.IQN == n.iqn {
				return fmt.Sprintf("[TPGs: %d]", len(t.TPGs))
			}
		}
	case kTPG:
		// tpgOf returns the single matching TPG or nothing, so this is a
		// lookup, not an iteration. It used to be written as a range that
		// returned on the first element either way, which reads as a loop but
		// cannot run twice.
		if gs := tpgOf(cfg, n.iqn, n.tag); len(gs) > 0 {
			if gs[0].Enable {
				return "[enabled]"
			}
			return "[disabled]"
		}
	case kLUN:
		for _, g := range tpgOf(cfg, n.iqn, n.tag) {
			for _, l := range g.LUNs {
				if l.Index == n.index {
					return "[-> " + l.Backstore + "]"
				}
			}
		}
	case kACL:
		for _, g := range tpgOf(cfg, n.iqn, n.tag) {
			for _, a := range g.ACLs {
				if a.InitiatorIQN == n.initiator {
					return fmt.Sprintf("[Mapped LUNs: %d]", len(a.MappedLUNs))
				}
			}
		}
	case kMappedLUN:
		for _, g := range tpgOf(cfg, n.iqn, n.tag) {
			for _, a := range g.ACLs {
				if a.InitiatorIQN == n.initiator {
					for _, ml := range a.MappedLUNs {
						if ml.Index == n.index {
							wp := ""
							if ml.WriteProtect {
								wp = " ro"
							}
							return "[-> lun" + strconv.Itoa(ml.TPGLUN) + wp + "]"
						}
					}
				}
			}
		}
	}
	return ""
}

func tpgOf(cfg lio.Config, iqn string, tag int) []lio.TPG {
	for _, t := range cfg.Targets {
		if t.IQN == iqn {
			for _, g := range t.TPGs {
				if g.Tag == tag {
					return []lio.TPG{g}
				}
			}
		}
	}
	return nil
}

// Rendering and parsing a portal live in lio, where the configfs directory
// name is decided, so an operator types and reads exactly the name the kernel
// holds -- and so nobody has to decide about brackets twice.
func portalLabel(p lio.Portal) string { return p.String() }

// parsePortalLabel fills in the standard port when the operator typed only an
// address. lio.ParsePortal reports the absence as Port 0 so callers can apply
// their own default; lish has no other default to apply.
func parsePortalLabel(s string) (lio.Portal, bool) {
	p, ok := lio.ParsePortal(s)
	if ok && p.Port == 0 {
		p.Port = lio.DefaultPortalPort
	}
	return p, ok
}
