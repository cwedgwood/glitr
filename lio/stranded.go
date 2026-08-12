package lio

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// A STRANDED reservation is one that is live and enforcing, but whose holder
// can no longer address it.
//
// It arises from an asymmetry in how the kernel identifies an initiator, which
// aptplcheck.go documents in full and labtest's pr-isid suite proves against a
// live kernel: restoring a saved registration IGNORES the ISID
// (__core_scsi3_check_aptpl_registration matches five fields, linux v6.6
// drivers/target/target_core_pr.c:949-953), while every later PR command from
// that initiator is resolved by __core_scsi3_locate_pr_reg, which REQUIRES an
// exact ISID match once one was recorded (:866-870, :1171-1184).
//
// So when an initiator's session identifier rotates -- which an explicit
// iscsiadm logout/login does, though a target reboot does NOT -- its own
// RELEASE starts failing with NOT READY while the reservation keeps fencing
// everyone else.
//
// WHY THIS IS SEPARATE FROM VerifyAPTPL, and must stay separate. That check
// answers "did the saved state take effect", and for a stranded reservation
// the answer is YES: the registration is bound and enforcing. Mixing the ISID
// into its identity match would report a false alarm for every registration
// the kernel has correctly bound. This is a different question -- "can the
// holder still manage what it holds" -- and it gets its own answer.
//
// WHY NOTHING IS COLLECTED. A reservation is a fence, and from inside the
// appliance a stranded one is indistinguishable from a deliberate long-lived
// one: a correctly fenced node may be down for a week. Releasing it
// automatically would let a fenced initiator write again, which is the exact
// data loss this whole feature exists to prevent. The recovery paths belong to
// the cluster, not to us: another registered initiator can preempt it (proven
// in pr-isid), or the volume can be deleted. So this REPORTS and never acts.

// UndecidedStrand names a target where the strand question cannot be answered.
//
// The kernel renders exactly ONE session per ACL, so when an initiator holds
// several at once -- multipath, which is the normal way this product is
// deployed -- the holder's registration may name a session that is live and
// simply not the one rendered. A mismatch is then not evidence of anything.
//
// Reported rather than silently skipped: an operator who stops seeing strand
// reports is entitled to know the detector went blind, and why. This is a
// statement about what the appliance can SEE, not about the storage, so it is
// deliberately not a warning -- nothing is wrong with the reservation.
type UndecidedStrand struct {
	// TargetIQN is the target whose sessions could not be enumerated.
	TargetIQN string
	// LiveSessions is what the kernel reports for the whole target, and
	// VisibleSessions is how many of them the per-ACL attribute renders.
	// LiveSessions is -1 when the count itself could not be read.
	LiveSessions, VisibleSessions int
	// Backstores names the reservations left undecided by this.
	Backstores []string
}

func (u UndecidedStrand) String() string {
	if u.LiveSessions < 0 {
		return fmt.Sprintf("%s: cannot tell whether these reservations are stranded — "+
			"the target's live session count could not be read, so a session identifier "+
			"that does not match the one visible per ACL may still belong to a live "+
			"session. Affected: %s",
			u.TargetIQN, strings.Join(u.Backstores, ", "))
	}
	return fmt.Sprintf("%s: cannot tell whether these reservations are stranded — the "+
		"kernel reports %d live sessions but renders only %d of them (one per ACL, the "+
		"last active), so a holder's session identifier that does not match the visible "+
		"one may still be live. This is normal with multipath. Nothing is wrong with the "+
		"reservations; the DETECTOR is blind here. Affected: %s",
		u.TargetIQN, u.LiveSessions, u.VisibleSessions, strings.Join(u.Backstores, ", "))
}

// StrandReport is what the strand check found, and what it could not decide.
type StrandReport struct {
	// Stranded names reservations PROVEN unaddressable by their holder.
	Stranded []StrandedReservation
	// Undecided names targets where the kernel has sessions this cannot see,
	// so no strand claim about them would be evidence-backed.
	Undecided []UndecidedStrand
}

// StrandedReservation names a reservation whose holder cannot address it.
type StrandedReservation struct {
	// Backstore is the object holding the reservation.
	Backstore string
	// Initiator holds the reservation and cannot release it.
	Initiator string
	// WantISID is the session identifier the registration demands.
	WantISID string
	// LiveISID lists every session identifier the target can see for this
	// initiator, comma-separated. Never empty: a reservation is only reported
	// stranded while its holder is logged in. May hold more than one when the
	// initiator is logged in through several TPGs, and none of them matched.
	LiveISID string
	// ResType is the kernel's rendering of the reservation type, e.g. "Write
	// Exclusive Access, Registrants Only". Empty when it could not be read,
	// which does not suppress the report -- see StrandedReservations.
	ResType string
}

func (s StrandedReservation) String() string {
	// The remedy is spelled out because the obvious one is not always
	// available, which was MEASURED rather than assumed. On the lab a week-old
	// reservation had BOTH registrations stranded -- holder wanting
	// 00023d000004 against session 00023d00000d, the other wanting 00023d000002
	// against 00023d000001 -- so "preempt from another registered initiator"
	// was impossible: no registration could issue a PR command at all.
	//
	// What does work from any session is REGISTER AND IGNORE EXISTING KEY,
	// because it does not have to locate an existing registration. Registering
	// a fresh key and then preempting (or clearing) resets the device.
	// Confirmed on the lab: after that sequence the holder, the registrations
	// and the APTPL bit were all gone, and the kernel rewrote its saved file so
	// nothing returns on the next restart.
	return fmt.Sprintf("%s: reservation held by %s cannot be released by it — the "+
		"registration requires session id %s and the sessions this target can see "+
		"for it are %s (type: %s). It is STILL ENFORCING (this over-fences rather "+
		"than failing open), so nothing is at risk and nothing here will clear it: a "+
		"stranded reservation and a deliberate one are indistinguishable from this "+
		"side. To clear it, register a new key from a CURRENT session "+
		"(register-and-ignore-existing-key works from any session, unlike preempt, "+
		"which needs a registration the kernel can still locate) and then preempt or "+
		"clear. Detaching the holder frees its registrations, but that is NOT a "+
		"reliable clear on its own: if the detach removes the LAST attachment the "+
		"backstore is pruned, and re-attaching recreates it -- at which point a "+
		"SAVED APTPL record is replayed and the reservation comes back. MEASURED. "+
		"To make a detach stick, the saved record has to be discarded with it. "+
		"The appliance's clear-reservation operation does both and keeps the "+
		"volume, its data and its mappings; deleting the volume also does both. "+
		"All of these DROP the fence, so establish that this reservation is "+
		"genuinely stranded rather than deliberate before using any of them",
		s.Backstore, s.Initiator, s.WantISID, s.LiveISID, s.resTypeText())
}

// resTypeText renders the reservation type, saying so plainly when it could
// not be read rather than letting an empty string read as a type.
func (s StrandedReservation) resTypeText() string {
	if s.ResType == "" {
		return "could not be read"
	}
	return s.ResType
}

// StrandedReservations reports reservations whose holder can no longer address
// them.
//
// Read-only, and cheap: one pr/res_holder read per backstore, one pr/res_pr_type
// read per backstore that turns out to hold a reservation, plus one per ACL
// belonging to such a holder.
//
// Only reports a holder that is LOGGED IN RIGHT NOW with a different session
// id. An initiator with no session at all is NOT reported: it may return with
// the same identifier -- a target reboot preserves it, which is the case APTPL
// exists for -- so calling that stranded would be a false alarm of exactly the
// kind aptplcheck.go was written to remove.
//
// ALL REGISTRANTS types are not reported either. For PR_TYPE_*_ALLREG any
// registrant is a reservation holder (linux v6.6
// drivers/target/target_core_pr.c:70-84, is_reservation_holder), and
// core_scsi3_emulate_pro_release consults exactly that -- so a rotated ISID on
// the nominal holder does not strand such a reservation, because any other
// registrant can still release it. Reporting one would be a false alarm, and
// the remedy text would be wrong twice over.
//
// THE KERNEL RENDERS ONE SESSION PER ACL, and this refuses to guess past it.
//
// The ACL info attribute shows exactly one session, se_nacl->nacl_sess, which
// the kernel documents as "the last active I_T Nexus for each struct
// se_node_acl" (v6.6 drivers/target/target_core_transport.c:426-430). An
// initiator holding several at once -- multipath, which is how this product is
// normally deployed -- registers on ONE specific nexus, while the last-active
// one is whichever leg most recently carried I/O. Those routinely differ, and
// comparing them reported a strand for every multipathed volume holding a
// reservation: a false alarm whose remediation advice (preempt, clear, detach)
// would have disturbed healthy fencing. MEASURED on the lab, and reported from
// a real deployment.
//
// So the count is checked first. The target publishes how many sessions are
// live (fabric_statistics/iscsi_instance/sessions); if that exceeds the number
// the per-ACL attributes render, the kernel is holding sessions this cannot
// see, and a holder's session identifier that does not match the visible one
// may simply be one of them. That is not evidence, so no strand is claimed --
// it is reported as UNDECIDED instead, naming the affected backstores, because
// a detector that goes quiet without saying so is worse than one that reports
// nothing.
//
// Detection is unaffected where each initiator holds a single session: the
// count then matches, the attribute is complete, and a mismatch is proof. That
// is the case the pr-isid suite exercises against a live kernel.
//
// Two data sources were proposed in the report and both were tested and
// rejected. dynamic_sessions is empty here because this appliance uses
// explicit ACLs (generate_node_acls=0), so no session is dynamic. And the PR
// registration table cannot distinguish the two cases at all: the holder's own
// registration IS the thing being questioned, and it stays in that table after
// its session is gone -- MEASURED, by rotating an ISID and watching the dead
// one persist in res_pr_registered_i_pts. Testing membership there would
// suppress every genuine strand.
func (m *Manager) StrandedReservations(cfg Config) StrandReport {
	var out []StrandedReservation
	blind := m.blindTargets(cfg)
	undecided := map[string][]string{}
	for _, b := range cfg.Backstores {
		// ONE reader for pr/res_holder and pr/res_pr_type, shared with the
		// unmap fence-loss warning. This used to carry its own regex and its
		// own second read; they had already begun to diverge -- the shared one
		// grew the SPC-2 flag and the type, this one did not.
		res, err := m.ReservationHolder(b)
		if err != nil {
			// Absent is ordinary: not every plugin exposes pr/, and a
			// backstore may hold no reservation. Unreadable is not worth
			// failing a report channel for.
			continue
		}
		if res.Holder == "" || res.ISID == "" {
			// No holder, or a holder whose registration carries no ISID --
			// which means the kernel will accept its PR commands from any
			// session, so it cannot be stranded.
			continue
		}
		if res.SPC2 {
			// A legacy RESERVE(6) reservation is not bound to a session at
			// all, so the ISID comparison does not apply to it.
			continue
		}
		holder, want, resType := res.Holder, res.ISID, res.Type

		if res.AllRegistrants() {
			continue
		}

		live, ok := m.liveISIDs(cfg, holder)
		if !ok || slices.Contains(live, want) {
			continue
		}
		name := "backstore/" + string(b.Type) + "/" + b.Name
		// The mismatch is real, but it is only EVIDENCE where every live
		// session is accounted for. Where it is not, the holder's nexus may be
		// one of the sessions the kernel is not rendering.
		if t := m.blindTargetFor(cfg, holder, blind); t != "" {
			undecided[t] = append(undecided[t], name)
			continue
		}
		out = append(out, StrandedReservation{
			Backstore: name,
			Initiator: holder,
			WantISID:  want,
			LiveISID:  strings.Join(live, ", "),
			ResType:   resType,
		})
	}
	rep := StrandReport{Stranded: out}
	for iqn, names := range undecided {
		b := blind[iqn]
		slices.Sort(names)
		rep.Undecided = append(rep.Undecided, UndecidedStrand{
			TargetIQN: iqn, LiveSessions: b.live, VisibleSessions: b.visible,
			Backstores: names,
		})
	}
	slices.SortFunc(rep.Undecided, func(a, b UndecidedStrand) int {
		return strings.Compare(a.TargetIQN, b.TargetIQN)
	})
	return rep
}

// blindness records, per target, how many sessions the kernel says are live
// and how many the per-ACL attributes actually render.
type blindness struct{ live, visible int }

// blindTargets reports which targets have sessions the ACL attributes cannot
// enumerate.
//
// A target is blind when the kernel's live session count exceeds the number of
// ACLs rendering a session -- which means at least one ACL holds several, and
// nothing says WHICH. It is also treated as blind when the count cannot be
// read at all: not knowing whether the attribute is complete is not the same
// as knowing that it is, and claiming a strand on that basis would be the
// guess this check exists to avoid.
func (m *Manager) blindTargets(cfg Config) map[string]blindness {
	out := map[string]blindness{}
	for _, t := range cfg.Targets {
		// Counted from the KERNEL's ACL directories, not from cfg. The number
		// this is compared against is the kernel's, so the other side of the
		// comparison has to be too: an ACL the kernel has and the desired
		// config does not would otherwise make the target look blind, and one
		// the config has and the kernel does not would hide that it is.
		visible := 0
		for _, g := range t.TPGs {
			names, err := m.fs.ReadDir(append(tpgPath(t.IQN, g.Tag), "acls")...)
			if err != nil {
				continue
			}
			for _, n := range names {
				raw, err := m.fs.ReadAttr(append(aclPath(t.IQN, g.Tag, n), "info")...)
				if err != nil {
					continue
				}
				if _, perr := ParseSessionISID(raw); perr == nil {
					visible++
				}
			}
		}
		live, err := m.liveSessionCount(t.IQN)
		switch {
		case err != nil:
			out[t.IQN] = blindness{live: -1, visible: visible}
		case live > visible:
			out[t.IQN] = blindness{live: live, visible: visible}
		}
	}
	return out
}

// blindTargetFor returns the blind target this initiator has a session on, or
// "" when every target it is logged into can be fully enumerated.
func (m *Manager) blindTargetFor(cfg Config, initiator string, blind map[string]blindness) string {
	if len(blind) == 0 {
		return ""
	}
	for _, t := range cfg.Targets {
		if _, ok := blind[t.IQN]; !ok {
			continue
		}
		for _, g := range t.TPGs {
			raw, err := m.fs.ReadAttr(append(aclPath(t.IQN, g.Tag, initiator), "info")...)
			if err != nil {
				continue
			}
			if _, perr := ParseSessionISID(raw); perr == nil {
				return t.IQN
			}
		}
	}
	return ""
}

// liveSessionCount is how many iSCSI sessions the kernel currently holds for a
// target.
//
// Read from fabric_statistics/iscsi_instance/sessions, which is a LIVE count
// rather than a cumulative one -- MEASURED: four sessions read 4, and reading
// it again after logging them all out read 0. It is the only place the kernel
// publishes a number that can be compared against what the per-ACL attributes
// render.
func (m *Manager) liveSessionCount(iqn string) (int, error) {
	raw, err := m.fs.ReadAttr(append(targetPath(iqn), "fabric_statistics", "iscsi_instance", "sessions")...)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(strings.ReplaceAll(raw, "\x00", "")))
	if err != nil {
		return 0, fmt.Errorf("session count for %s is %q, which is not a number -- the "+
			"format changed and this comparison is no longer trustworthy", iqn, strings.TrimSpace(raw))
	}
	return n, nil
}

// liveISIDs returns every session identifier the target can see for this
// initiator, sorted, and whether it has any session at all.
//
// Read from the TARGET's ACLs rather than from anything the initiator reports
// about itself. Every TPG is searched rather than stopping at the first match,
// because the same initiator can be logged in through more than one and the
// registration belongs to a specific one of them: stopping early compares the
// wrong session and reports a strand that is not there.
//
// See the LIMITATION note on StrandedReservations for what this still cannot
// see -- a second session to the SAME ACL, which the kernel does not render.
func (m *Manager) liveISIDs(cfg Config, initiator string) ([]string, bool) {
	seen := map[string]bool{}
	var out []string
	for _, t := range cfg.Targets {
		for _, g := range t.TPGs {
			raw, err := m.fs.ReadAttr(append(aclPath(t.IQN, g.Tag, initiator), "info")...)
			if err != nil {
				// Not on this TPG, or unreadable. Either way there is nothing
				// to compare here; keep looking.
				continue
			}
			got, perr := ParseSessionISID(raw)
			if perr != nil {
				// No ISID line means no live session on this TPG; a shape
				// failure means the extraction is not trustworthy, and
				// comparing it would manufacture a mismatch and with it a
				// false stranded report. Either way keep looking -- the same
				// initiator may be logged in through another TPG.
				continue
			}
			if !seen[got] {
				seen[got] = true
				out = append(out, got)
			}
		}
	}
	slices.Sort(out)
	return out, len(out) > 0
}
