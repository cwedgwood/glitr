package lio

import (
	"net/netip"
	"strings"
)

// maxIQNLen is the maximum length of an iSCSI name (RFC 3720 section 3.2.6.1).
const maxIQNLen = 223

// validIQNSeg reports whether an IQN is usable as a configfs path segment
// (LIO stores target and initiator IQNs as directory names under iscsi/ and
// acls/). Rejecting an unsafe IQN here — before the appliance persists it —
// prevents a "poison record" that passes prefix validation but is rejected by
// configfs at reconcile time, which would fail every subsequent startup replay.
// iSCSI names are <= maxIQNLen bytes (RFC 3720).
func validIQNSeg(iqn string) bool {
	if iqn == "" || iqn == "." || iqn == ".." || len(iqn) > maxIQNLen {
		return false
	}
	for _, r := range iqn {
		if r == '/' || r == ' ' || r < 0x20 || r == 0x7f {
			return false
		}
		// A comma is legal in a configfs name but not here: an IQN is
		// embedded verbatim in SCSI-3 PR APTPL records, which the kernel
		// parses as a comma-separated k=v list. An IQN containing a comma
		// would inject extra fields (res_holder, sa_res_key, ...) into a
		// restored reservation. Rejected at the boundary rather than escaped
		// later. RFC 3720 iSCSI names do not contain commas.
		if r == ',' {
			return false
		}
	}
	return true
}

// ValidInitiatorIQN reports whether s is a well-formed, configfs-safe iSCSI
// initiator IQN: it starts with "iqn." and is a usable configfs path segment.
// Exposed so the appliance can reject a bad IQN at its API boundary with the
// same rule the reconcile layer enforces (avoiding a persisted poison record).
func ValidInitiatorIQN(s string) bool {
	return strings.HasPrefix(s, "iqn.") && validIQNSeg(s)
}

// ValidTargetIQN reports whether s is a well-formed, configfs-safe target
// name. Targets may also be named naa.<hex>, which initiators may not.
//
// Exposed for the same reason as ValidInitiatorIQN: a caller that takes this
// from configuration should be able to reject it AT ITS OWN BOUNDARY, with a
// message naming the setting, rather than have it surface later as a
// reconcile failure that reads like a kernel problem.
func ValidTargetIQN(s string) bool {
	return (strings.HasPrefix(s, "iqn.") || strings.HasPrefix(s, "naa.")) && validIQNSeg(s)
}

// Validate checks the desired Config for structural and naming errors
// before any configfs operation is attempted. It reports the first
// problem found as an *Error with Kind KindInvalidSpec.
func (c Config) Validate() error {
	names := map[string]bool{}
	for _, b := range c.Backstores {
		if err := b.validate(); err != nil {
			return errf(KindInvalidSpec, "validate", "backstore/"+b.Name, err)
		}
		if names[b.Name] {
			return errf(KindInvalidSpec, "validate", "backstore/"+b.Name,
				wrapf("duplicate backstore name"))
		}
		names[b.Name] = true
	}
	tgtIQNs := map[string]bool{}
	for _, t := range c.Targets {
		if tgtIQNs[t.IQN] {
			return errf(KindInvalidSpec, "validate", "target/"+t.IQN,
				wrapf("duplicate target IQN"))
		}
		tgtIQNs[t.IQN] = true
		if err := t.validate(names); err != nil {
			return err
		}
	}
	return nil
}

func (b Backstore) validate() error {
	switch b.Type {
	case FileIO, IBlock:
	default:
		return wrapf("unsupported backstore type %q", b.Type)
	}
	if b.Name == "" {
		return wrapf("backstore name is required")
	}
	if strings.ContainsAny(b.Name, "/ \t\n") {
		return wrapf("backstore name %q contains invalid characters", b.Name)
	}
	// "." and ".." pass the character check but are not names configfs will
	// ever accept, so a record carrying one is a POISON RECORD: it validates
	// when the appliance persists it and then fails at every reconcile
	// afterwards, including startup replay. Rejected here for the same reason
	// validIQNSeg rejects them, and for the one name a caller most often
	// derives from something a user typed.
	if b.Name == "." || b.Name == ".." {
		return wrapf("backstore name %q is not a name configfs accepts", b.Name)
	}
	if b.HBA < 0 {
		return wrapf("backstore HBA index must be >= 0")
	}
	if b.Dev == "" {
		return wrapf("backstore backing device/file path is required")
	}
	if b.WWN != "" && !isHex16(b.WWN) {
		return wrapf("wwn %q must be 16 lowercase hex digits", b.WWN)
	}
	if v, ok := b.Attributes["block_size"]; ok {
		if !validBlockSize(v) {
			return wrapf("block_size %q must be one of 512, 1024, 2048, 4096", v)
		}
		// NOTE: size-vs-block-size alignment is deliberately NOT checked here.
		//
		// Validate runs over the WHOLE desired config on every reconcile, and
		// returns on the first bad backstore, so a rule enforced here rejects
		// the entire tree -- including every healthy export -- because of one
		// record. An unaligned size is a property of an ALREADY EXISTING
		// volume that no reconcile can fix (block_size is immutable while
		// exported), and the kernel has silently floored the block count for
		// it all along, so failing here removes a working device to protect
		// nobody. Under Restart=on-failure that is a crash loop against a
		// healthy tree.
		//
		// The check therefore lives on the CREATE path, in controlString,
		// where the size is actually being chosen and where the effective
		// size (which may come from the backing file rather than b.Size) is
		// known. Callers that pick sizes -- storage.Store.Create/Resize and
		// the appliance -- enforce it at their own boundaries too.
	}
	return nil
}

// validBlockSize reports whether v is a block size the kernel will accept.
//
// The kernel validates this itself and returns a bare EINVAL
// (linux v6.6 drivers/target/target_core_configfs.c:1125-1129); checking here
// turns "write failed" into a message naming the legal values. The set is the
// KERNEL's, deliberately -- a narrower policy (the appliance allows only 512
// and 4096) belongs to the caller, not to this library.
func validBlockSize(v string) bool {
	switch v {
	case "512", "1024", "2048", "4096":
		return true
	}
	return false
}

func (t Target) validate(backstores map[string]bool) error {
	id := "target/" + t.IQN
	if !strings.HasPrefix(t.IQN, "iqn.") && !strings.HasPrefix(t.IQN, "naa.") {
		return errf(KindInvalidSpec, "validate", id,
			wrapf("target IQN %q must start with iqn. or naa.", t.IQN))
	}
	if !validIQNSeg(t.IQN) {
		return errf(KindInvalidSpec, "validate", id,
			wrapf("target IQN %q contains characters invalid for a configfs name", t.IQN))
	}
	tpgTags := map[int]bool{}
	for _, tpg := range t.TPGs {
		if tpg.Tag < 1 {
			return errf(KindInvalidSpec, "validate", id,
				wrapf("TPG tag must be >= 1, got %d", tpg.Tag))
		}
		if tpgTags[tpg.Tag] {
			return errf(KindInvalidSpec, "validate", id,
				wrapf("duplicate TPG tag %d", tpg.Tag))
		}
		tpgTags[tpg.Tag] = true
		lunIdx := map[int]bool{}
		for _, l := range tpg.LUNs {
			if l.Index < 0 {
				return errf(KindInvalidSpec, "validate", id,
					wrapf("LUN index must be >= 0"))
			}
			if lunIdx[l.Index] {
				return errf(KindInvalidSpec, "validate", id,
					wrapf("duplicate LUN index %d", l.Index))
			}
			lunIdx[l.Index] = true
			if !backstores[l.Backstore] {
				return errf(KindDependency, "validate", id,
					wrapf("LUN %d references unknown backstore %q", l.Index, l.Backstore))
			}
		}
		// netip.AddrPort is comparable and canonical, so it is the key
		// directly: two spellings of one address are one map entry, and a
		// character check for "/ \t\n" is unnecessary because an Addr cannot
		// hold them. Both used to be done by hand on a string, and the
		// duplicate check missed every alternative IPv6 spelling.
		portals := map[netip.AddrPort]bool{}
		for _, p := range tpg.Portals {
			if !p.IP.IsValid() {
				return errf(KindInvalidSpec, "validate", id, wrapf("portal IP is required"))
			}
			// No range check: Portal.Port is a uint16, so out of range is
			// not representable. It used to be an int and this guard was the
			// only thing standing between a caller's bad value and String
			// silently narrowing it to a plausible port.
			key := netip.AddrPortFrom(p.IP, p.port())
			if portals[key] {
				return errf(KindInvalidSpec, "validate", id, wrapf("duplicate portal %s", key))
			}
			portals[key] = true
		}
		aclIQNs := map[string]bool{}
		for _, acl := range tpg.ACLs {
			if !strings.HasPrefix(acl.InitiatorIQN, "iqn.") {
				return errf(KindInvalidSpec, "validate", id,
					wrapf("initiator IQN %q must start with iqn.", acl.InitiatorIQN))
			}
			if !validIQNSeg(acl.InitiatorIQN) {
				return errf(KindInvalidSpec, "validate", id,
					wrapf("initiator IQN %q contains characters invalid for a configfs name", acl.InitiatorIQN))
			}
			if aclIQNs[acl.InitiatorIQN] {
				return errf(KindInvalidSpec, "validate", id,
					wrapf("duplicate ACL initiator IQN %q", acl.InitiatorIQN))
			}
			aclIQNs[acl.InitiatorIQN] = true
			mlIdx := map[int]bool{}
			for _, m := range acl.MappedLUNs {
				if m.Index < 0 {
					return errf(KindInvalidSpec, "validate", id,
						wrapf("mapped LUN index must be >= 0 (initiator %q)", acl.InitiatorIQN))
				}
				if mlIdx[m.Index] {
					return errf(KindInvalidSpec, "validate", id,
						wrapf("duplicate mapped LUN index %d (initiator %q)", m.Index, acl.InitiatorIQN))
				}
				mlIdx[m.Index] = true
				if !lunIdx[m.TPGLUN] {
					return errf(KindDependency, "validate", id,
						wrapf("mapped LUN %d references unknown TPG LUN %d", m.Index, m.TPGLUN))
				}
			}
		}
	}
	return nil
}
