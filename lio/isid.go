package lio

import (
	"fmt"
	"regexp"
	"strings"
)

// The ISID (initiator session identifier) is the one piece of SCSI-3 PR
// identity the kernel exposes ONLY as prose. There is no numeric attribute for
// it, so unlike every other verdict in this library it has to be read out of a
// formatted line.
//
// ONE implementation, deliberately. This used to exist twice, in two
// packages, with byte-identical regexes and DIFFERENT failure policy: one copy
// validated the extracted shape and errored, the other returned
// whatever it matched. That divergence was the bug: a truncated capture became
// a live session identifier, which differs from the one the registration
// demands, which is a false "stranded reservation" report. Two copies of a
// parser are two policies waiting to disagree.
//
// The extraction is part of the measurement. A previous parser in this
// codebase truncated "Buffered-WCE" to "Buffered" through a too-narrow
// character class and the wrong value was recorded as a MEASURED kernel fact.

// sessionISIDRE finds the CURRENT session's ISID in an ACL's info attribute,
// where the kernel prints it byte-spaced:
//
//	LIO Session ID: 1   ISID: 0x00 02 3d 00 00 01  TSIH: 1  SessionType: Normal
//
// The capture stops at two spaces because that is the line's field separator,
// while the ISID's own bytes are separated by single spaces. The non-greedy
// "+?" is inert against today's format -- the class excludes ":" and the
// letters of "TSIH", so greedy backtracks to the same answer -- and becomes
// load-bearing only if a FOLLOWING field is itself hex and spaces and is also
// followed by two spaces.
var sessionISIDRE = regexp.MustCompile(`ISID:\s*0x([0-9a-fA-F ]+?)\s\s`)

// isidRE is the canonical form every kernel rendering reduces to: lower-case,
// no spaces, no 0x. Anything else is a failed parse rather than a value.
var isidRE = regexp.MustCompile(`^[0-9a-f]{12}$`)

// ParseSessionISID extracts an initiator's CURRENT session identifier from the
// ACL info attribute, in canonical form.
//
// Canonical because the two places the kernel renders an ISID disagree about
// spelling -- byte-spaced here, run together in the registration list -- and
// the whole point of reading it is to compare the two.
//
// Returns an error rather than a value when the line is absent (no live
// session) or does not parse. Both must be distinguishable from a successful
// read by the caller: a value that is not a 12-hex-digit ISID means the line
// format changed, and comparing it would manufacture a mismatch.
func ParseSessionISID(info string) (string, error) {
	m := sessionISIDRE.FindStringSubmatch(strings.ReplaceAll(info, "\x00", ""))
	if m == nil {
		return "", fmt.Errorf("no ISID found in ACL info; the session may be logged out")
	}
	got := strings.ToLower(strings.ReplaceAll(m[1], " ", ""))
	if !isidRE.MatchString(got) {
		return "", fmt.Errorf("extracted %q from the ACL info, which is not a 12-hex-digit "+
			"ISID -- the line format changed and this parse is no longer trustworthy", got)
	}
	return got, nil
}

// registeredISIDRE finds each registration's initiator and the ISID it
// DEMANDS, in res_pr_registered_i_pts:
//
//	iSCSI Node: iqn.1993-08.org.debian:01:x,i,0x00023d000004 Key: 0x...aaaa PRgen: 0x0
//
// The ",i,0x..." suffix appears only when isid_present_at_reg is set
// (linux v6.6 drivers/target/target_core_pr.c:43-54), so its presence is
// itself the fact that this registration will require an exact ISID match.
var registeredISIDRE = regexp.MustCompile(`iSCSI Node:\s*(\S+?),i,0x([0-9a-fA-F]+)`)

// ParseRegisteredISIDs maps initiator IQN to the ISID its registration
// demands.
//
// An initiator ABSENT from the result registered WITHOUT an ISID, which is a
// different state: the kernel will then accept its PR commands from any
// session. Callers must not read "absent" as "no registration".
func ParseRegisteredISIDs(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, m := range registeredISIDRE.FindAllStringSubmatch(strings.ReplaceAll(s, "\x00", ""), -1) {
		got := strings.ToLower(m[2])
		if !isidRE.MatchString(got) {
			return nil, fmt.Errorf("registration for %s carries %q, which is not a "+
				"12-hex-digit ISID -- the format changed and this parse is no longer "+
				"trustworthy", m[1], got)
		}
		out[m[1]] = got
	}
	return out, nil
}
