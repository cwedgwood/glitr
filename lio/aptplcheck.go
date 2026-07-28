package lio

import (
	"fmt"
	"strconv"
	"strings"
)

// This file decides whether a saved SCSI-3 PR registration OUGHT to be live,
// and whether it actually is. Both halves used to be a count: verifyAPTPL
// compared the number of saved records against the number of "Key:" lines in
// res_pr_registered_i_pts. Counting is wrong in both directions.
//
// It over-reports. A saved record's registration dies with the export it was
// made through: detach a host and the kernel drops that registration, but it
// does NOT rewrite db_root/pr/aptpl_<wwn> (only a PR OUT does that). The
// saved file keeps two records while one is live, forever. Measured on a
// live target: attach a volume to two hosts, register both, detach one, and
// /health reports pr_unbound permanently -- through an unrelated reconcile
// and across a restart -- for an action the operator took deliberately. An
// alarm nobody can clear is one people learn to ignore, which is worse than
// no alarm.
//
// It under-reports, and this is the dangerous half. Two live registrations
// satisfy a count of two saved records even when they belong to different
// initiators or carry different keys -- so the saved RESERVATION HOLDER can
// be dormant while the count says everything took effect. The holder is the
// fencing-critical part: it is the record that decides who is locked out.
//
// So match identities, and check the holder on its own terms.
//
// # Why identity is (initiator IQN, key) and NOT the iSCSI session ID
//
// The saved record carries an initiator_sid and the live view renders one
// (",i,0x00023d000004"), so it is tempting to match on it. That would be
// wrong, and the kernel says so directly.
//
// APTPL BINDING ignores the ISID entirely. When an ACL mapped LUN appears,
// __core_scsi3_check_aptpl_registration matches exactly five fields --
// initiator IQN, mapped LUN, target IQN, TPGT and target LUN --
// (linux v6.6 drivers/target/target_core_pr.c:949-953). That is precisely the
// tuple exported() below tests. A record binds regardless of which session
// turns up, so matching on the ISID here would report "not live" for
// registrations the kernel has already bound: a false alarm of exactly the
// kind this file exists to remove.
//
// The ISID is not irrelevant, though, and this is worth knowing. If a saved
// record carries one, core_scsi3_alloc_aptpl_registration sets
// isid_present_at_reg (target_core_pr.c:866-870), and every subsequent PR
// command from an initiator is resolved by __core_scsi3_locate_pr_reg, which
// matches the node ACL and then REQUIRES an exact ISID match when that flag is
// set (target_core_pr.c:1171-1184). So a registration can be live and
// enforcing while the initiator that owns it can no longer address it.
//
// Measured on the lab (Azure Linux 3, kernel 6.6.144.1, open-iscsi):
//
//   - a target reboot PRESERVES the ISID: the restored registration binds and
//     the owner can still release it. This is the case APTPL exists for, and
//     it is unaffected.
//   - an explicit `iscsiadm --logout` + `--login` ROTATES the ISID
//     (00023d000002 -> 00023d000003). The registration stays live and visible
//     in res_pr_registered_i_pts, but the owner's own RELEASE then fails and
//     the kernel logs "SPC-3 PR: Unable to locate PR_REGISTERED *pr_reg for
//     RELEASE". The reservation is live, still fencing everyone else, and
//     unmanageable by its holder.
//   - that state is RECOVERABLE: another registered initiator can still
//     preempt it (measured rc=0, reservation transferred), which is the
//     ordinary cluster recovery path.
//
// That condition IS detectable, and an earlier version of this comment wrongly
// claimed otherwise. core_pr_dump_initiator_port emits the ",i,0x<isid>"
// suffix only when isid_present_at_reg is set (target_core_pr.c:43-54), so the
// suffix in res_pr_registered_i_pts -- which parseRegistrations already reads
// and discards -- gives both the ISID the registration demands AND the fact
// that it will demand one. The current session's ISID is readable too, from
// the ACL's info attribute. Two reads would diagnose it.
//
// It is still deliberately not reported here, for a different reason: this
// check answers "did the saved state take effect", and a rotated ISID does not
// change that answer -- the registration IS live and IS enforcing. The failure
// is that its owner cannot address it, which over-fences rather than
// fails open, and which recovers by preemption from another node. Mixing it
// into the identity match would only produce false alarms; if it is ever worth
// surfacing it belongs in a separate, differently-worded diagnostic.

// aptplRecord is a saved registration parsed into the fields that decide
// whether it can still be in effect. The kernel writes considerably more
// (initiator_sid, port_rtpi, res_scope, ...); those are needed to REPLAY a
// record but not to reason about it, and are deliberately not modelled here.
type aptplRecord struct {
	Initiator string // initiator_node
	Target    string // target_node
	TPGT      int    // tpgt
	MappedLUN int    // mapped_lun -- the ACL-side index, not the TPG LUN
	TargetLUN int    // target_lun -- the TPG LUN the mapped LUN points at
	Key       uint64 // sa_res_key, written in DECIMAL
	Holder    bool   // res_holder=1
	// ResType is the SCSI-3 reservation type, written by the kernel ONLY on
	// the holder record (linux v6.6 drivers/target/target_core_pr.c:1894,
	// "res_holder=1\nres_type=%02x\n"). It decides who a reservation was
	// excluding, which is what a report about a lapsed one has to get right.
	ResType int
}

// parseAPTPLRecord parses one comma-joined record as produced by
// appliance.ParseAPTPL.
//
// A record that cannot be parsed is an error rather than a skip: these are
// the records that were about to be handed back to the kernel, and one this
// package cannot read is one it cannot reason about. Silently ignoring it
// would report "all saved registrations are live" about a file we did not
// understand.
func parseAPTPLRecord(rec string) (aptplRecord, error) {
	var r aptplRecord
	seen := map[string]bool{}
	for f := range strings.SplitSeq(rec, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(f), "=")
		if !ok {
			continue
		}
		seen[k] = true
		var err error
		switch k {
		case "initiator_node":
			r.Initiator = v
		case "target_node":
			r.Target = v
		case "tpgt":
			r.TPGT, err = strconv.Atoi(v)
		case "mapped_lun":
			r.MappedLUN, err = strconv.Atoi(v)
		case "target_lun":
			r.TargetLUN, err = strconv.Atoi(v)
		case "sa_res_key":
			// Decimal in the saved file, hex in res_pr_registered_i_pts.
			r.Key, err = strconv.ParseUint(v, 10, 64)
		case "res_type":
			// Hex, and holder-only. Absent on non-holder records, so it is
			// not in the required set below.
			var n uint64
			n, err = strconv.ParseUint(v, 16, 8)
			r.ResType = int(n)
		case "res_holder":
			// Anything other than 0/1 is a file we do not understand, not a
			// licence to assume "not the holder". Treating an unknown value
			// as false would silently drop the fencing-critical half of this
			// check -- the same fail-open polarity the saved-file parser goes
			// to some trouble to avoid.
			switch v {
			case "0":
				r.Holder = false
			case "1":
				r.Holder = true
			default:
				err = fmt.Errorf("expected 0 or 1")
			}
		}
		if err != nil {
			return aptplRecord{}, fmt.Errorf("field %s=%q: %w", k, v, err)
		}
	}
	// res_holder is required: the kernel always writes it, so its absence
	// means a file this code cannot reason about, and defaulting it to false
	// would hide a dormant reservation holder.
	for _, k := range []string{"initiator_node", "target_node", "tpgt", "mapped_lun", "target_lun", "sa_res_key", "res_holder"} {
		if !seen[k] {
			return aptplRecord{}, fmt.Errorf("missing field %q", k)
		}
	}
	return r, nil
}

// exported reports whether the export this registration was made through
// still exists in cfg: the same target, TPG, initiator ACL and mapped LUN
// index, AND that the mapped LUN still points at THIS backstore.
//
// The fields tested here are deliberately the same five the kernel uses to
// bind a saved record -- initiator IQN, mapped LUN, target IQN, TPGT and
// target LUN (linux v6.6 drivers/target/target_core_pr.c:949-953). If this
// predicate is true, the kernel would bind the record; if it is false, the
// kernel never will. Keeping the two in step is what makes "expected to be
// live" mean something rather than being this package's own opinion.
//
// This is the whole detach fix. A registration cannot outlive its mapped
// LUN, so once the operator removes that export the record is expected to be
// dormant -- it is a record of something that used to be true, not a fault.
//
// Three things it must NOT do, each of which was a real defect:
//
//   - It must not test only the ACL. A host detached from THIS volume while
//     it stays attached to others keeps its ACL, which is exactly the case
//     that was measured on the live target.
//   - It must not test only the mapped LUN INDEX. Indices are caller-chosen
//     and freely reused across volumes -- Lunmap rejects one only against
//     currently-attached attachments -- so detaching volume X from a host at
//     LUN 62 and then attaching volume Y to that host at LUN 62 would make
//     X's dormant record look "still exported" and resurrect the permanent
//     false alarm this whole check exists to remove. Hence the backstore
//     argument: the index must still resolve, through the TPG LUN, to the
//     backstore being verified.
//   - It must not accept a mapped LUN that has been re-pointed. ensureMappedLUN
//     re-points a reused index IN PLACE, so index survival proves nothing about
//     what it now addresses; the saved target_lun must still match.
//
// A record whose LUN was reassigned is therefore treated as no longer
// exported, because it isn't: the registration died with the old mapping, and
// re-registering is the initiator's job. In every one of these cases the
// topology changed because someone asked it to.
func (r aptplRecord) exported(cfg Config, b Backstore) bool {
	for _, t := range cfg.Targets {
		if t.IQN != r.Target {
			continue
		}
		for _, g := range t.TPGs {
			if g.Tag != r.TPGT {
				continue
			}
			for _, acl := range g.ACLs {
				if acl.InitiatorIQN != r.Initiator {
					continue
				}
				for _, ml := range acl.MappedLUNs {
					if ml.Index != r.MappedLUN || ml.TPGLUN != r.TargetLUN {
						continue
					}
					// The index and the TPG LUN both match; confirm that TPG
					// LUN still exposes the backstore under verification.
					// Without this the record could be satisfied by another
					// volume that merely reuses the numbers.
					for _, l := range g.LUNs {
						if l.Index == ml.TPGLUN && l.Backstore == b.Name {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// SCSI-3 persistent reservation types (SPC-3 6.11.3.4). Only the ones whose
// exclusion semantics differ in a way this package must describe are named.
const (
	prTypeWriteExclusive         = 0x01
	prTypeExclusiveAccess        = 0x03
	prTypeWriteExclusiveRegOnly  = 0x05
	prTypeExclusiveAccessRegOnly = 0x06
	prTypeWriteExclusiveAllReg   = 0x07
	prTypeExclusiveAccessAllReg  = 0x08
)

// excluded describes, in words, who a reservation of this type kept out. A
// report that a reservation lapsed is only meaningful if it names the right
// population -- and for the registrants-only types, which is what every
// fencing tool in practice uses, a REGISTERED initiator was never excluded by
// it in the first place.
func (r aptplRecord) excluded() string {
	switch r.ResType {
	case prTypeWriteExclusiveRegOnly, prTypeExclusiveAccessRegOnly,
		prTypeWriteExclusiveAllReg, prTypeExclusiveAccessAllReg:
		return "initiators that are not registered"
	case prTypeWriteExclusive, prTypeExclusiveAccess:
		return "every other initiator"
	default:
		return "other initiators"
	}
}

// exportedMappings counts the mapped LUNs in cfg that reach b, ignoring one
// initiator (the lapsed holder, whose own export is by definition gone).
//
// This is what "is the backstore still exported to anybody" actually means.
// It deliberately does NOT consult the saved records: an initiator that never
// registered a PR key has no saved record at all, and under the
// registrants-only reservation types it is precisely the population the
// reservation was excluding. Counting saved records instead would go silent
// exactly when the warning matters most.
func exportedMappings(cfg Config, b Backstore, ignoreInitiator string) int {
	n := 0
	for _, t := range cfg.Targets {
		for _, g := range t.TPGs {
			for _, acl := range g.ACLs {
				if acl.InitiatorIQN == ignoreInitiator {
					continue
				}
				for _, ml := range acl.MappedLUNs {
					for _, l := range g.LUNs {
						if l.Index == ml.TPGLUN && l.Backstore == b.Name {
							n++
						}
					}
				}
			}
		}
	}
	return n
}

// liveReg is one registration the kernel currently holds.
type liveReg struct {
	Initiator string
	Key       uint64
}

// parseRegistrations parses res_pr_registered_i_pts, whose body is one line
// per registration:
//
//	SPC-3 PR Registrations:
//	iSCSI Node: iqn.1993-08.org.debian:01:host,i,0x00023d000004 Key: 0x000000000000aaaa PRgen: 0x00000000
//
// or the single word "None". The fabric name varies ("iSCSI Node:"), so the
// split is on " Node: " rather than a fixed prefix.
//
// Unparsable lines are counted, not guessed at. A caller that finds none of
// its expected registrations must be able to tell "the kernel does not have
// them" from "this function did not understand the output" -- the first is a
// fencing fault, the second is a bug here, and they warrant opposite
// reactions.
func parseRegistrations(s string) (regs []liveReg, unparsed int) {
	for line := range strings.SplitSeq(s, "\n") {
		line = strings.TrimSpace(strings.ReplaceAll(line, "\x00", ""))
		if line == "" || line == "None" || strings.HasSuffix(line, "Registrations:") {
			continue
		}
		_, rest, ok := strings.Cut(line, " Node: ")
		if !ok {
			unparsed++
			continue
		}
		node, keyPart, ok := strings.Cut(rest, " Key: ")
		if !ok {
			unparsed++
			continue
		}
		iqn, _, _ := strings.Cut(node, ",")
		keyStr, _, _ := strings.Cut(strings.TrimSpace(keyPart), " ")
		key, err := strconv.ParseUint(strings.TrimPrefix(keyStr, "0x"), 16, 64)
		if err != nil {
			unparsed++
			continue
		}
		regs = append(regs, liveReg{Initiator: strings.TrimSpace(iqn), Key: key})
	}
	return regs, unparsed
}

// parseHolder returns the initiator IQN holding the reservation and the ISID
// its registration demands, or ("", "") if none is held. res_holder reads as
// either
//
//	SPC-3 Reservation: iSCSI Initiator: iqn...,i,0x00023d000004
//
// or "No SPC-3 Reservation holder".
//
// The kernel does NOT render the holder's key here, which is why the holder
// check below matches on initiator identity alone.
//
// The ",i,0x..." suffix is emitted only when isid_present_at_reg is set
// (linux v6.6 drivers/target/target_core_pr.c:43-54), so its presence IS the
// fact that this registration will demand an exact ISID match. An EMPTY isid
// therefore means "this registration accepts PR commands from any session",
// which is a different state from "no registration" -- callers must not
// conflate them.
//
// noHolder is the kernel's rendering when no SCSI-3 reservation is held
// (linux v6.6 drivers/target/target_core_configfs.c:1795). It is matched
// exactly: if the wording ever changes, parseHolder reports "I cannot tell"
// rather than "nothing is held", which is the over-fencing direction.
const noHolder = "No SPC-3 Reservation holder"

// parseHolder returns the holder IQN and, where the kernel rendered one, the
// session ISID. known reports whether the text was interpretable AT ALL.
//
// The third result exists because "" is an ANSWER -- it means no reservation
// is held -- and without it every unrecognised rendering became that answer.
// The kernel's res_holder is human-formatted prose with no compatibility
// promise, so a wording change would have silently reported "nobody holds
// this" for a device somebody does hold, which is the fail-open direction in
// the one place this project cannot afford it. Callers must treat
// known==false as "I cannot tell" and take the over-fencing branch.
//
// The ISID is validated rather than returned raw: a bad extraction here would
// manufacture a MISMATCH in the stranded check, which is a false report. A
// suffix that does not parse yields ("iqn", "", true) -- the holder is still
// known, the session claim is simply not made.
func parseHolder(s string) (iqn, isid string, known bool) {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\x00", ""))
	_, rest, ok := strings.Cut(s, " Initiator: ")
	if !ok {
		// Not a holder line. Only the kernel's own "no holder" rendering may
		// be read as "nothing is held"; anything else is uninterpretable.
		// linux v6.6 drivers/target/target_core_configfs.c:1795 renders
		// "No SPC-3 Reservation holder\n" when dev->dev_pr_res_holder is NULL.
		if s == noHolder {
			return "", "", true
		}
		return "", "", false
	}
	name, tail, hasTail := strings.Cut(strings.TrimSpace(rest), ",")
	name = strings.TrimSpace(name)
	if name == "" {
		// " Initiator: " with nothing after it is not a holder and not the
		// no-holder rendering either.
		return "", "", false
	}
	if !hasTail {
		return name, "", true
	}
	got, ok := strings.CutPrefix(strings.TrimSpace(tail), "i,0x")
	if !ok {
		return name, "", true
	}
	// Fields, not Fields()[0]: a value ending exactly at ",i,0x" leaves an
	// empty remainder, and strings.Fields("") is an EMPTY SLICE, so indexing
	// it panics. That panic was reachable from PRState, ReservationHolder and
	// the APTPL verification inside Sync -- so a malformed attribute, which is
	// precisely the case this function exists to survive, would have taken
	// down a caller's daemon rather than being reported as an unusable value.
	fields := strings.Fields(got)
	if len(fields) == 0 {
		return name, "", true
	}
	got = strings.ToLower(fields[0])
	if !isidRE.MatchString(got) {
		return name, "", true
	}
	return name, got, true
}

// Reservation describes the live reservation on a backstore.
type Reservation struct {
	// Holder is the initiator IQN holding it, "" if none is held.
	Holder string
	// ISID is the session identifier the holder's registration demands.
	//
	// EMPTY MEANS "any session", not "unknown": the kernel emits the
	// ",i,0x..." suffix only when isid_present_at_reg is set, so its absence
	// is the positive fact that this registration is not bound to a session.
	ISID string
	// Type is the kernel's rendering of the reservation type, e.g. "Write
	// Exclusive Access, Registrants Only". Empty when it could not be read.
	Type string
	// SPC2 marks a legacy RESERVE(6) reservation rather than a SCSI-3
	// persistent one. Removing a mapped LUN does NOT release one of these:
	// core_scsi3_free_pr_reg_from_nacl touches dev->dev_pr_res_holder and the
	// SPC-3 registration list, never dev->reservation_holder.
	SPC2 bool
}

// AllRegistrants reports whether every registrant holds this reservation, in
// which case losing the nominal holder does not release it.
//
// For PR_TYPE_WRITE_EXCLUSIVE_ALLREG and PR_TYPE_EXCLUSIVE_ACCESS_ALLREG,
// is_reservation_holder returns true for ANY registrant (linux v6.6
// drivers/target/target_core_pr.c:70-84), and removing the nominal holder
// enters __core_scsi3_complete_pro_release with unreg=1, which TRANSFERS the
// reservation to the next registration rather than dropping it (:2463-2478).
//
// Matched on the kernel's prose because there is no numeric attribute for the
// live type; the exact strings are core_scsi3_pr_dump_type's (:2237-2257).
func (r Reservation) AllRegistrants() bool {
	return strings.Contains(strings.ToLower(r.Type), "all registrants")
}

// ReservationHolder returns the live reservation on b, if any.
//
// Exported for one specific reason: detaching a host that holds a SCSI-3
// persistent reservation RELEASES it, and the appliance has to be able to say
// so before it happens.
//
// That release is the kernel's deliberate choice, not a side effect. Removing
// a mapped LUN runs core_disable_device_list_for_node (linux v6.6
// drivers/target/target_core_device.c:454), which calls
// core_scsi3_free_pr_reg_from_nacl (target_core_pr.c:1342), and that function
// carries the comment "If the passed se_node_acl matches the reservation
// holder, release the reservation" before doing exactly that.
//
// It is a choice because THE STANDARD DOES NOT COVER THIS. SPC models I_T
// nexus loss, logical unit reset and power loss -- transport and device events
// -- while "the administrator removed this logical unit from that initiator's
// view" is an array feature that SCSI has no concept of. So every
// implementation picks its own answer, and LIO picked release. Other arrays
// are reported to retain the registration and require an explicit clear, which
// is the opposite choice; that has NOT been verified here and is not relied on.
//
// The TYPE and the SPC-2 flag are read because that release is not universal:
// the ALL REGISTRANTS types transfer instead of releasing, and an SPC-2
// reservation is not touched by this path at all. A caller warning about lost
// fencing has to be able to tell those apart or it cries wolf.
func (m *Manager) ReservationHolder(b Backstore) (Reservation, error) {
	raw, err := m.fs.ReadAttr(append(b.objPath(), "pr", "res_holder")...)
	if err != nil {
		return Reservation{}, err
	}
	clean := strings.TrimSpace(strings.ReplaceAll(raw, "\x00", ""))
	holder, isid, known := parseHolder(raw)
	if !known {
		// Fail closed. "" means "no reservation is held", so returning it for
		// prose we did not recognise would tell a caller the device is
		// unprotected -- the fail-open direction, and the one this project
		// cannot afford. Report that we cannot tell instead.
		return Reservation{}, errf(KindConfigfs, "read",
			"backstore/"+b.Name+" pr/res_holder",
			fmt.Errorf("%w: %q", ErrHolderUnreadable, clean))
	}
	res := Reservation{
		Holder: holder,
		ISID:   isid,
		// res_holder renders SPC-2 reservations through the same " Initiator: "
		// shape (target_core_configfs.c:1804), so the prefix is what tells
		// them apart.
		SPC2: strings.HasPrefix(clean, "SPC-2 Reservation:"),
	}
	if res.Holder == "" {
		return res, nil
	}
	// Best-effort: the type qualifies a holder already established, so a
	// failure loses detail rather than inverting the answer.
	if v, err := m.fs.ReadAttr(append(b.objPath(), "pr", "res_pr_type")...); err == nil {
		res.Type = prTypeText(v)
	}
	return res, nil
}
