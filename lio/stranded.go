package lio

import (
	"fmt"
	"slices"
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
		"clear; or detach the holder, which also releases it; or delete the volume",
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
// LIMITATION, and it is the kernel's, not ours: the ACL info attribute renders
// exactly ONE session, se_nacl->nacl_sess, which the kernel documents as "the
// last active I_T Nexus for each struct se_node_acl" (v6.6
// drivers/target/target_core_transport.c:426-430). An initiator holding
// several simultaneous sessions -- multipath, which this project ships a suite
// for -- may therefore have made its registration on a session that is still
// live but is no longer the last active one. This searches every TPG and
// reports only when NO live session it can see matches, which removes the
// cross-TPG case, but it cannot see a second session to the SAME ACL. The
// report says what was compared so an operator can tell.
func (m *Manager) StrandedReservations(cfg Config) []StrandedReservation {
	var out []StrandedReservation
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
		out = append(out, StrandedReservation{
			Backstore: "backstore/" + string(b.Type) + "/" + b.Name,
			Initiator: holder,
			WantISID:  want,
			LiveISID:  strings.Join(live, ", "),
			ResType:   resType,
		})
	}
	return out
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
