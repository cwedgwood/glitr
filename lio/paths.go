package lio

import (
	"net/netip"
	"strconv"
)

// Configfs path helpers. All are relative to the configfs FS root
// (default /sys/kernel/config/target).

func itoa(i int) string { return strconv.Itoa(i) }

// core segments -------------------------------------------------------

func (b Backstore) hbaPath() []string { return []string{"core", b.dirName()} }
func (b Backstore) objPath() []string { return []string{"core", b.dirName(), b.Name} }

// iscsi segments ------------------------------------------------------

func targetPath(iqn string) []string { return []string{"iscsi", iqn} }

func tpgPath(iqn string, tag int) []string {
	return []string{"iscsi", iqn, "tpgt_" + itoa(tag)}
}

func portalPath(iqn string, tag int, p Portal) []string {
	return append(tpgPath(iqn, tag), "np", p.String())
}

// String renders a portal as "<address>:<port>", bracketing the address when
// its family requires it. This is both the configfs directory name and the
// form an operator types, so there is one implementation rather than one per
// caller -- there used to be four, each deciding for itself whether to add
// brackets by looking for a colon.
//
// IPv6 addresses MUST be bracketed. They contain colons themselves, so
// "fd00::1:3260" is ambiguous, and the kernel refuses it -- MEASURED on Azure
// Linux 3.0, kernel 6.6.144.1:
//
//	mkdir np/fd00::1:3260    -> EINVAL (Invalid argument)
//	mkdir np/[fd00::1]:3260  -> accepted, reads back as [fd00::1]:3260
//
// netip.AddrPort.String() brackets exactly when the family requires it, so
// nothing here decides anything about families.
func (p Portal) String() string {
	return netip.AddrPortFrom(p.IP, p.port()).String()
}

// ParsePortal is the inverse of Portal.String: it turns "<address>[:<port>]"
// -- a configfs np/ directory name, or something an operator typed -- back
// into a Portal.
//
// A bare address yields Port 0, which the model already defines as
// DefaultPortalPort. Reporting the absence rather than filling it in lets a
// caller apply its own default (the appliance takes one from a flag) without
// having to guess whether 3260 was written or assumed.
//
// netip accepts exactly what String produces, brackets included, so the round
// trip needs no bracket-stripping or split-on-the-last-colon reasoning. Both
// used to be written by hand, and getting the strip wrong meant every
// reconcile saw the bracketed form as a portal it had not asked for alongside
// the bare one it had -- creating the second and pruning the first, forever.
func ParsePortal(name string) (Portal, bool) {
	if ap, err := netip.ParseAddrPort(name); err == nil {
		if ap.Addr().Zone() != "" {
			return Portal{}, false
		}
		return Portal{IP: ap.Addr().Unmap(), Port: ap.Port()}, true
	}
	// A bare address, optionally bracketed. The brackets must BALANCE:
	// trimming them off either end accepted "[fd00::1" as valid, and an
	// address that reaches configfs through a typo binds successfully --
	// IP_FREEBIND -- on something nobody can reach.
	bare := name
	if len(bare) >= 2 && bare[0] == '[' && bare[len(bare)-1] == ']' {
		bare = bare[1 : len(bare)-1]
	}
	addr, err := netip.ParseAddr(bare)
	if err != nil {
		return Portal{}, false
	}
	// A zone ("fe80::1%eth0") parses happily and then renders back into a
	// configfs directory name the kernel rejects. Refusing it here means the
	// failure is a parse error at the edge, with the offending text in hand,
	// rather than a mkdir EINVAL several layers in.
	if addr.Zone() != "" {
		return Portal{}, false
	}
	return Portal{IP: addr.Unmap()}, true
}

// key is the canonical comparable identity of a portal: the address AND the
// port with the default applied, so Port 0 and Port 3260 are one portal rather
// than two. Used for the sets that decide what to create and what to prune,
// where treating them as two meant creating one and pruning the other on every
// pass.
func (p Portal) key() netip.AddrPort {
	return netip.AddrPortFrom(p.IP, p.port())
}

func lunPath(iqn string, tag, index int) []string {
	return append(tpgPath(iqn, tag), "lun", "lun_"+itoa(index))
}

func aclPath(iqn string, tag int, initiator string) []string {
	return append(tpgPath(iqn, tag), "acls", initiator)
}

func mappedLunPath(iqn string, tag int, initiator string, index int) []string {
	return append(aclPath(iqn, tag, initiator), "lun_"+itoa(index))
}
