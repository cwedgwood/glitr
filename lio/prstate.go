package lio

import (
	"os"
	"strings"
)

// PRState is the live SCSI-3 Persistent Reservation state of one backstore.
//
// Read-only, and read straight from configfs: it is what the KERNEL currently
// holds, not what any saved file or database believes. That distinction is the
// point -- verifyAPTPL exists precisely because those two can disagree.
type PRState struct {
	// Registrations are the live registered I_T nexuses.
	Registrations []PRRegistration
	// Holder is the initiator IQN holding the reservation, empty if none.
	//
	// Empty is only meaningful when HolderKnown is true. Check that first.
	//
	// The kernel does not render the holder's key here, so this identifies
	// the holder by initiator only. See lio/aptplcheck.go for why that is a
	// property of the kernel's output rather than a shortcut.
	Holder string
	// HolderKnown reports whether res_holder could be interpreted at all.
	//
	// When false, Holder is empty because the attribute was not understood --
	// NOT because no reservation is held. The two must not be conflated: the
	// kernel's rendering is prose with no compatibility promise, and reading
	// an unrecognised one as "nobody holds this" reports a protected device as
	// unprotected. The zero value is false, so a PRState that was never
	// populated says "I cannot tell" rather than "nothing is held".
	HolderKnown bool
	// Type is the reservation type as the kernel words it, e.g.
	// "Write Exclusive Access, Registrants Only". Empty when nothing is
	// reserved. Kept as the kernel's own text rather than re-encoded: the
	// exclusion semantics differ per type and the kernel's phrasing is what
	// an operator will find in the spec.
	Type string
	// APTPLActive reports whether the Activate Persist Through Power Loss
	// bit is set, i.e. whether this state is being persisted at all.
	APTPLActive bool
	// Truncated is set when the kernel's registration list appears to have
	// been cut off. It renders into a single page and simply stops
	// (linux v6.6 drivers/target/target_core_configfs.c, the
	// "if (len + strlen(buf) >= PAGE_SIZE) break;" in the registrations
	// show handler) with no marker and no error, so past roughly 17
	// long-IQN registrations the tail is invisible. A caller must not read
	// "not in this list" as "not registered" when this is true.
	Truncated bool
}

// PRRegistration is one live registration.
type PRRegistration struct {
	Initiator string
	Key       uint64
}

// prPageSize is the kernel's render limit for the registration list. Used only
// to notice that output may have been truncated, never to parse.
//
// Read at run time rather than hardcoded to 4096: the kernel's limit is
// PAGE_SIZE, so on a 64K-page kernel a hardcoded 4096 would flag spurious
// truncation on any list over ~4KB -- a silent wrong answer rather than a
// failure.
var prPageSize = os.Getpagesize()

// prMaxRegLine is the kernel's own buffer for one rendered registration line
// (linux v6.6 drivers/target/target_core_configfs.c, "char buf[384]" in the
// registrations show handler). It bounds how much room the line that did NOT
// fit could have needed, which is what the truncation margin has to allow for.
const prMaxRegLine = 384

// PRState reads the live SCSI-3 PR state of a backstore.
//
// Fails only if the attributes cannot be read at all; a device with no
// registrations and no reservation is a successful empty result, not an error.
//
// This is the read counterpart to VerifyAPTPL, which answers "does the saved
// state match?" and returns warnings. This answers "what is actually in force
// right now?" and returns state, which is what an operator view (and a future
// reservations endpoint) needs.
func (m *Manager) PRState(b Backstore) (PRState, error) {
	var st PRState

	regs, err := m.fs.ReadAttr(append(b.objPath(), "pr", "res_pr_registered_i_pts")...)
	if err != nil {
		return st, errf(KindConfigfs, "read", "backstore/"+b.Name+" pr/res_pr_registered_i_pts", err)
	}
	parsed, unparsed := parseRegistrations(regs)
	for _, r := range parsed {
		st.Registrations = append(st.Registrations, PRRegistration(r))
	}
	// Unparsable lines and a full page both mean the list cannot be trusted
	// as complete. Treat them the same, because the consequence is the same:
	// absence from this list stops being evidence of anything.
	//
	// The margin is the kernel's own line buffer, not a guess. The kernel
	// breaks BEFORE appending a line that would not fit, so after a
	// truncation the returned length can be as low as PAGE_SIZE minus the
	// length of that line -- up to prMaxRegLine. A smaller margin leaves a
	// window in which the list was truncated and this reports it complete.
	st.Truncated = unparsed > 0 || len(regs) >= prPageSize-prMaxRegLine

	// A res_holder read failure must NOT be swallowed. An unreadable holder
	// leaves Holder empty, which every caller renders as "no reservation
	// held" -- asserting the absence of a reservation on the strength of a
	// failed read, in the tool used to check fencing. That is the fail-open
	// direction. verifyAPTPL already treats this attribute the same way.
	//
	// res_pr_type and res_aptpl_active stay best-effort: they qualify a
	// holder that has already been established, so a failure there loses
	// detail rather than inverting the answer.
	v, err := m.fs.ReadAttr(append(b.objPath(), "pr", "res_holder")...)
	if err != nil {
		return st, errf(KindConfigfs, "read", "backstore/"+b.Name+" pr/res_holder", err)
	}
	st.Holder, _, st.HolderKnown = parseHolder(v)
	if st.Holder != "" {
		if v, err := m.fs.ReadAttr(append(b.objPath(), "pr", "res_pr_type")...); err == nil {
			st.Type = prTypeText(v)
		}
	}
	if v, err := m.fs.ReadAttr(append(b.objPath(), "pr", "res_aptpl_active")...); err == nil {
		// "APTPL Bit Status: Activated" / "... Disabled"
		st.APTPLActive = strings.Contains(v, "Activated")
	}
	return st, nil
}

// prTypeText extracts the reservation type from the kernel's rendering,
// "SPC-3 Reservation Type: Write Exclusive Access, Registrants Only".
func prTypeText(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\x00", ""))
	if _, rest, ok := strings.Cut(s, "Reservation Type:"); ok {
		return strings.TrimSpace(rest)
	}
	return ""
}
