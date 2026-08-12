package appliance

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"

	"github.com/cwedgwood/glitr/applog"
	"github.com/cwedgwood/glitr/lio"
)

// ClearedReservation describes what a clear dropped, so the operator has a
// record of the fence they broke rather than only the fact that they broke
// one.
//
// Captured BEFORE the tear-down, because afterwards there is nothing left to
// read: that is the whole point of the operation.
type ClearedReservation struct {
	// Object is the name of the volume or snapshot the reservation was on.
	Object string `json:"object"`
	// Held reports whether a SCSI-3 reservation was actually in effect. False
	// means the clear ran against a volume that only had registrations, or
	// nothing at all -- which is not an error (see ClearReservation).
	//
	// Only meaningful when HeldKnown is true. Check that first.
	Held bool `json:"held"`
	// HeldKnown reports whether the pre-clear state could be read at all.
	//
	// When false, Held is false because the reservation state was not
	// readable -- NOT because nothing was held. Conflating those tells a
	// machine "no fence was broken" at the exact moment one may have been,
	// which is the fail-open direction. The same distinction the kernel-facing
	// lio.PRState draws with HolderKnown, for the same reason.
	HeldKnown bool `json:"held_known"`
	// Holder is the IQN that held it, "" if none did.
	Holder string `json:"holder,omitempty"`
	// ISID is the session the holder's registration was bound to. Empty means
	// the registration was not session-bound, not that it is unknown.
	ISID string `json:"isid,omitempty"`
	// Type is the kernel's rendering of the reservation type.
	Type string `json:"type,omitempty"`
	// SavedRecordDiscarded reports whether a saved APTPL record was removed.
	// This is the step that makes the clear stick across the rebuild.
	SavedRecordDiscarded bool `json:"saved_record_discarded"`
	// Warning carries everything the operator must act on, most importantly
	// that initiators saw the device disappear and return.
	//
	// Accumulated, never overwritten -- see addWarning. An earlier version
	// assigned to it, so a failure to read the PR state SUPPRESSED the
	// disruption warning: on the one path where the operator knows least,
	// they were told least.
	Warning string `json:"warning,omitempty"`
}

// addWarning appends a warning, keeping every fact rather than the last one.
//
// Each of these is independently true and independently actionable: that the
// device disappeared, that the pre-clear state was unreadable, that a fence
// dropped despite an error. Assignment made them compete, and the
// most-important one lost precisely when an earlier step had already failed.
func (r *ClearedReservation) addWarning(s string) {
	if r.Warning == "" {
		r.Warning = s
		return
	}
	r.Warning += ". " + s
}

// errClearVerify reports that the tear-down completed but the reservation was
// still readable afterwards.
var errClearVerify = errors.New("reservation still held after clear")

// ClearReservation breaks a SCSI-3 persistent reservation on one object while
// keeping the object, its data, its WWN and its mappings.
//
// # Why this is a tear-down and not a write
//
// There is no kernel interface for releasing someone else's reservation from
// the target side. Every attribute in a backstore's pr/ group is read-only
// except res_aptpl_metadata (linux v6.6 drivers/target/target_core_configfs.c
// :2207-2215), and that write is refused while the device is exported --
// `if (dev->export_count) return -EINVAL` (:2042). Disabling emulate_pr frees
// nothing. The only path that frees registrations wholesale is
// core_scsi3_free_all_registrations, reached only from target_free_device
// (target_core_device.c:1002) -- i.e. destroying the backstore.
//
// So the operation is: withhold the object from the desired config, reconcile
// (the kernel prunes the backstore and frees the reservation), restore it, and
// reconcile again. The db is never modified, so the mappings, LUN numbers and
// WWN all come back exactly as they were.
//
// # Why the saved record is discarded in the middle
//
// A saved APTPL record is replayed whenever a backstore is CREATED, so a
// rebuild would faithfully restore the reservation we just tore down --
// measured: the same key and the same ISID came back. That restore is correct
// and must stay, since it is what stops a target reboot silently dropping a
// fence. The clear therefore has to discard the record.
//
// It is discarded AFTER the prune rather than before, to close a race: while
// the backstore still exists an initiator can issue a PR OUT, and a PR OUT is
// the one thing that rewrites the saved file. Once the backstore is gone no
// initiator can reach the device at all, so nothing can recreate the record
// between the discard and the rebuild.
//
// # This is a deliberate fence-dropping act
//
// The appliance never does this on its own, and never as a side effect of
// another operation. A stranded reservation and a perfectly healthy one look
// identical from the target side, so only an operator who knows which they are
// looking at can decide. Hence confirm, which must equal the object's name.
//
// Initiators WILL see the device disappear and come back. Anything with the
// LUN open sees I/O errors for the gap, and multipath will fail and reinstate
// the paths. That is inherent in the only mechanism the kernel offers, not an
// implementation shortcut.
//
// Not an error if no reservation is held: the useful guarantee is that the
// object has no reservation afterwards, and refusing would make the operation
// useless for clearing leftover REGISTRATIONS, which are torn down by the same
// path and are what a pr_unbound report is about.
func (c *Coordinator) ClearReservation(ctx context.Context, kind Kind, ref, confirm string) (res ClearedReservation, err error) {
	ev := c.beginOp(ctx, eventPRCleared, "resource_kind", string(kind), "ref", ref)
	defer func() { ev.finish(err) }()

	c.mu.Lock()
	defer c.mu.Unlock()

	v := c.resolveObject(kind, ref)
	if v == nil {
		return ClearedReservation{}, notFound(string(kind), ref)
	}
	if confirm != v.Name {
		return ClearedReservation{}, statusErrCode(http.StatusBadRequest, CodeInvalidInput,
			"clearing a reservation drops fencing and interrupts every initiator "+
				"using %s %q, so it must be confirmed by name: expected confirm=%q, got %q",
			kind, v.Name, v.Name, confirm)
	}
	if v.State != stateReady {
		return ClearedReservation{}, statusErrCode(http.StatusConflict, CodeUnsupportedState,
			"%s %q is %s, so it has no backstore to clear", kind, v.Name, v.State)
	}

	// Gate on the same heal every other kernel-touching mutation gates on.
	// The rule at healIfDegraded is stated for EVERY such mutation, not just
	// commit(), and this one tears a backstore down and builds it again -- if
	// the kernel does not currently match the db, the tree this operation
	// reasons about is not the tree it will act on. It is deliberately not
	// exempt: a clear is a recovery operation, but recovering onto a tree we
	// know is wrong is how a clear ends up destroying the wrong object's
	// fencing.
	if err := c.healIfDegraded(ctx); err != nil {
		return ClearedReservation{}, err
	}

	out := ClearedReservation{Object: v.Name}

	// Read what is about to be dropped. Best-effort: an unreadable holder is
	// not a reason to refuse, because the operator is most likely to reach
	// for this operation precisely when the PR state is in a shape we cannot
	// interpret. Record that we could not tell rather than pretending there
	// was nothing there.
	if bs := c.backstoreOf(v.UUID); bs == nil {
		// No backstore means the kernel has no device for this object, so
		// nothing can be holding a reservation on it. That is knowledge, not
		// ignorance -- reporting it as "could not tell" would be as wrong in
		// the other direction.
		out.HeldKnown = true
	} else {
		switch res, err := c.lio.ReservationHolder(*bs); {
		case err != nil:
			out.addWarning(fmt.Sprintf(
				"the reservation state could not be read before clearing (%v), "+
					"so what was dropped is not recorded", err))
		case res.SPC2:
			out.HeldKnown = true
			// An SPC-2 reservation lives in dev->reservation_holder and is
			// NOT what this operation is named for, but destroying the device
			// does clear it too. Say so rather than reporting it as a SCSI-3
			// holder.
			out.Held, out.Holder, out.Type = true, res.Holder, "SPC-2 reservation"
		case res.Holder != "":
			out.HeldKnown = true
			out.Held, out.Holder, out.ISID, out.Type = true, res.Holder, res.ISID, res.Type
		default:
			// Read cleanly, nothing held. That IS knowledge.
			out.HeldKnown = true
		}
	}

	ev.set("resource_name", v.Name, "resource_id", v.UUID, "wwn", v.WWN)
	applog.Warn(ctx, c.logger(), eventPRClearing,
		"clearing a SCSI-3 reservation; initiators will see the device disappear and return",
		"resource_kind", string(kind), "resource_name", v.Name, "resource_id", v.UUID,
		"wwn", v.WWN, "holder", out.Holder, "isid", out.ISID, "reservation_type", out.Type)

	// Say so on /health for the duration. Everything below runs under mu,
	// which /health does not take, so without this a monitor reads the
	// pre-operation signals paired with a fresh "ok" while the object is
	// deliberately absent. Deferred so no return path can leave it set.
	c.setClearing(v.Name)
	defer c.setClearing("")
	// Release only THIS object's hold, and only once its record is proven
	// gone -- which happens in phase 2, not here. Releasing on entry, or
	// releasing wholesale, is what let a clear of B resurrect a withheld A.

	uuid, wwn := v.UUID, v.WWN

	// Phase 1: withhold the object and reconcile. This prunes the backstore,
	// which is what frees the registrations.
	c.prClearing = uuid
	_, pruneErr := c.reconcile(ctx)
	if pruneErr != nil {
		return c.recoverFromFailedPrune(ctx, out, kind, v.Name, uuid, pruneErr)
	}

	// Phase 2: discard the saved record, now that no initiator can reach the
	// device to rewrite it. See the header for why the ordering matters.
	//
	// Failing here is FATAL to the operation, unlike the identically-named
	// step on the delete path. There the volume is gone and a leftover file
	// is inert; here the backstore is about to be recreated with that exact
	// WWN, so a surviving record is replayed and restores the reservation the
	// operator just asked to drop. Reporting success in that case would be
	// the whole failure this operation exists to prevent.
	//
	// The object is left withheld deliberately: rebuilding it now is what
	// would replay the record, silently restoring the fence the operator just
	// asked to drop. Absent (over-fenced) is the safe direction.
	//
	// It does NOT come back on its own, and an earlier comment here claiming
	// healIfDegraded would restore it was measured false: phase 1 SUCCEEDED,
	// so lastReconcileErr is nil and that gate is a no-op, while desiredLIO
	// keeps withholding. So the state is published instead -- /health carries
	// withheld_after_failed_clear until it is resolved -- and the recovery is
	// stated plainly below: delete the file and re-run the clear. A daemon
	// restart also clears it, but by rebuilding from the db WITH the saved
	// record still present, which restores the reservation.
	discarded, err := c.discardSavedPRChecked(wwn)
	out.SavedRecordDiscarded = discarded
	if err == nil {
		// Proven gone: a rebuild can no longer replay it, so any hold this
		// object was under is resolved. Only this object's, and only now --
		// not on entry, and never wholesale.
		c.releaseHold(uuid)
	}
	if err != nil {
		// Publish the standing condition BEFORE returning. The deferred
		// setClearing("") is about to remove the in-flight signal, and without
		// this nothing would report that a volume is deliberately gone.
		c.holdBack(uuid, v.Name)
		out.addWarning(fmt.Sprintf(
			"%s %q is deliberately NOT presented to its initiators and no "+
				"reconcile will restore it until the saved APTPL record is "+
				"removed; /health reports it as withheld_after_failed_clear",
			kind, v.Name))
		// Every verb is explicitly indexed. An earlier version mixed one
		// %[1]s into an otherwise implicit list, which silently re-based the
		// argument cursor: the trailing verb -- the one naming the FILE to
		// delete -- printed the object name instead, so the appliance told an
		// operator to "Remove <volume>". go vet does not catch it. MEASURED.
		return out, statusErrWrap(http.StatusConflict, CodeFenceDropped, err,
			"the reservation on %[1]s %[2]q was released, but its saved APTPL "+
				"record could NOT be discarded (%[3]v); rebuilding the %[1]s now "+
				"would replay that record and restore the reservation, so it has "+
				"been left unexported rather than silently re-fenced. Delete the "+
				"FILE %[4]s (NOT the %[1]s) and re-run the clear",
			kind, v.Name, err, APTPLPath(c.cfg.DBRoot, wwn))
	}

	// Phase 3: restore the object. From here on a failure means the volume is
	// missing, which is the loud direction and is what healIfDegraded exists
	// for -- it will retry on the next mutation.
	c.prClearing = ""
	if _, err := c.reconcile(ctx); err != nil {
		// Do not assert the object is absent: ApplyDelta is fail-stop and NOT
		// transactional, so a partial rebuild can leave it absent, partly
		// built, or present. Classify what can actually be established, and
		// let the code carry the fence consequence rather than only the
		// reconcile one.
		verdict, _, _, readErr := c.fenceStateOf(uuid)
		if verdict == fenceUnknown {
			out.addWarning(fmt.Sprintf(
				"%s %q may be partly presented after a failed rebuild, and whether "+
					"it is fenced could NOT be established -- verify before relying "+
					"on either", kind, v.Name))
			return out, statusErrWrap(http.StatusServiceUnavailable, CodeFenceUnknown, err,
				"the reservation on %[1]s %[2]q was cleared, but the %[1]s could NOT "+
					"be presented again afterwards (%[3]v) and its fence state could "+
					"not be read (%[4]v) -- see /health",
				kind, v.Name, err, readErr)
		}
		out.addWarning(fmt.Sprintf(
			"%s %q may be only partly presented after a failed rebuild; the "+
				"reconcile is fail-stop and not transactional, so do not assume it "+
				"is wholly absent", kind, v.Name))
		return out, statusErrWrap(http.StatusServiceUnavailable, CodeReconcileFailed, err,
			"the reservation on %[1]s %[2]q was cleared, but the %[1]s could NOT "+
				"be presented again afterwards (%[3]v) -- see /health",
			kind, v.Name, err)
	}

	// Verify rather than assume, and FAIL CLOSED. The whole operation is
	// indirect -- nothing here writes "release" anywhere -- so the only honest
	// report is one that re-reads the result, and "I could not read it" is not
	// a result. Reporting success on an unreadable holder would invert
	// lio.ReservationHolder's own deliberate fail-closed contract at the API
	// boundary, in the one operation whose entire promise is that a fence is
	// gone.
	if err := c.verifyCleared(uuid, kind, v.Name); err != nil {
		return out, err
	}

	out.addWarning("initiators saw this device disappear and return; anything " +
		"holding it open will have seen I/O errors, and any reservation they " +
		"relied on for fencing is gone. Every REGISTRATION on this device was " +
		"freed too, not just the holder's, so every node that had registered a " +
		"key must re-register before it can fence again")
	ev.set("saved_record_discarded", out.SavedRecordDiscarded,
		"held", out.Held, "held_known", out.HeldKnown, "holder", out.Holder)
	return out, nil
}

// backstoreOf returns the desired backstore for an object, or nil if it has
// none. Asking desiredLIO rather than constructing one by hand is deliberate:
// HBA is an allocated index, and building it by hand is exactly the bug
// fenceLossWarningFor documents. Caller must hold c.mu.
func (c *Coordinator) backstoreOf(objectUUID string) *lio.Backstore {
	name := backstoreName(objectUUID)
	desired := c.desiredLIO()
	for i := range desired.Backstores {
		if desired.Backstores[i].Name == name {
			return &desired.Backstores[i]
		}
	}
	return nil
}

// discardSavedPRChecked removes the saved APTPL record and PROVES it is gone.
//
// Deliberately not discardSavedPR. That one is best-effort because it runs
// after a volume is deleted, where a leftover file is inert -- the WWN never
// recurs, so nothing can ever replay it. Here the opposite is true: the
// backstore is about to be recreated with this exact WWN, and a surviving
// record is replayed onto it (lio.Manager.SetAPTPLRecords), restoring the
// reservation the operator asked to drop. A silent failure here is the one
// bug this operation cannot have.
//
// Reports whether a record was actually removed, so the caller can say "there
// was nothing to discard" without claiming to have done something. The final
// Stat is not paranoia about os.Remove: it also catches a record recreated
// between the removal and the rebuild, which is the case the ordering in
// ClearReservation exists to make impossible and which must therefore be
// loud if it ever happens.
func (c *Coordinator) discardSavedPRChecked(wwn string) (bool, error) {
	if c.cfg.DBRoot == "" || wwn == "" {
		// No db root means no saved records exist to replay at all.
		return false, nil
	}
	path := APTPLPath(c.cfg.DBRoot, wwn)
	removed := true
	if err := os.Remove(path); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return false, fmt.Errorf("removing %s: %w", path, err)
		}
		removed = false
	}
	// Prove it. An error here is not "probably fine": it means we cannot
	// establish that the record is gone, which for this operation is the same
	// as knowing it is present.
	switch _, err := os.Stat(path); {
	case err == nil:
		return removed, fmt.Errorf("%s still exists after removal", path)
	case !errors.Is(err, fs.ErrNotExist):
		return removed, fmt.Errorf("could not confirm %s is gone: %w", path, err)
	}
	return removed, nil
}

// fenceVerdict is what could be established about the fence itself, as
// distinct from whether the whole operation succeeded.
//
// These must not be conflated. "Is the fence down?" has three answers, and
// exactly one of them is safe to report as a plain failure; "did everything
// the operation promises hold?" is a conjunction. An earlier version answered
// the first question by asking the second, so a provably-released reservation
// with a surviving registration was reported as a generic "could not clear" --
// whose documented safe reading is "still fenced". That is the under-fence
// class this operation exists to avoid.
type fenceVerdict int

const (
	// fenceUnknown: the state could not be read or interpreted. Never report
	// this as either fenced or unfenced.
	fenceUnknown fenceVerdict = iota
	// fenceDown: read cleanly, no reservation holder. Writes are NOT blocked.
	fenceDown
	// fenceUp: a reservation holder is present.
	fenceUp
)

// fenceStateOf answers only "is a reservation in effect on this object", and
// returns the state it read so a caller can ask further questions of it.
//
// haveBackstore is false when the object has no LIO device at all, which is
// the normal condition for an object with no attachments -- not an error.
// Caller must hold c.mu.
func (c *Coordinator) fenceStateOf(objectUUID string) (v fenceVerdict, st lio.PRState, haveBackstore bool, err error) {
	bs := c.backstoreOf(objectUUID)
	if bs == nil {
		// No device means nothing can be reserving it. That is knowledge, not
		// ignorance.
		return fenceDown, lio.PRState{HolderKnown: true}, false, nil
	}
	st, err = c.lio.PRState(*bs)
	switch {
	case err != nil:
		return fenceUnknown, st, true, err
	case !st.HolderKnown:
		return fenceUnknown, st, true, nil
	case st.Holder != "":
		return fenceUp, st, true, nil
	}
	return fenceDown, st, true, nil
}

// verifyCleared proves the operation's whole promise -- no reservation AND no
// registrations on the rebuilt object -- and fails when it cannot prove it.
//
// Uses PRState rather than ReservationHolder because it carries HolderKnown,
// so "the kernel printed something we do not recognise" stays distinct from
// "nothing is held". Conflating those reports a protected device as
// unprotected.
//
// # Why registrations are checked, and why that is a FENCING control
//
// It is tempting to argue that a registration without a holder blocks nothing,
// so checking it is mere tidiness. That is true at the instant of the clear
// and false a moment later.
//
// For PR_TYPE_WRITE_EXCLUSIVE_REGISTRANTS_ONLY and
// PR_TYPE_EXCLUSIVE_ACCESS_REGISTRANTS_ONLY the kernel admits any registered
// nexus (linux v6.6 drivers/target/target_core_pr.c:528-540):
//
//	} else if ((reg_only) || (all_reg)) {
//	        if (registered_nexus) {
//	                return 0;
//	        }
//
// So the moment ANY node takes such a reservation, every surviving
// registration is write permission. A decommissioned node whose registration
// outlived this clear is not fenced by the new reservation, and the warning
// this operation prints -- that every node must re-register before it can
// fence again -- never reaches it, because it never lost its registration.
// WERO is what this project's own fencing suite reserves
// (cmd/labtest/suite_clearpr.go), so this is the common case, not a corner.
//
// Truncated is a failure for the same reason: the kernel's registration list
// stops at a page boundary with no marker, so a short list is not evidence of
// an empty one.
//
// Caller must hold c.mu.
func (c *Coordinator) verifyCleared(objectUUID string, kind Kind, name string) error {
	verdict, st, haveBackstore, err := c.fenceStateOf(objectUUID)
	switch {
	case err != nil:
		return statusErrWrap(http.StatusConflict, CodeClearUnverified, errClearVerify,
			"the reservation on %[1]s %[2]q was torn down, but the result could "+
				"NOT be read back (%[3]v), so it is not proven gone; verify "+
				"before relying on this %[1]s being unfenced", kind, name, err)
	case verdict == fenceUnknown:
		return statusErrWrap(http.StatusConflict, CodeClearUnverified, errClearVerify,
			"%s %q reports a reservation state that could not be interpreted, "+
				"so it is not proven unfenced", kind, name)
	case verdict == fenceUp:
		return statusErrWrap(http.StatusConflict, CodeClearUnverified, errClearVerify,
			"%s %q is still held by %q after the backstore was rebuilt; this "+
				"should not happen -- a saved APTPL record may have been "+
				"rewritten, or an initiator re-reserved in the gap",
			kind, name, st.Holder)
	}
	if !haveBackstore {
		// Nothing further to inspect, and nothing to prove. This is the normal
		// state of an object with no attachments, where the operation's real
		// work was discarding the saved APTPL record so a later attach cannot
		// replay it. Treating it as a failure made a legitimate clear
		// impossible -- MEASURED -- and that is the pr_unbound case this
		// operation is advertised for.
		return nil
	}
	if st.Truncated {
		// fence_dropped, for the same reason as the branch below: the holder
		// was read cleanly and is GONE. Truncation makes the registration set
		// unknown, not the reservation -- so reporting "not proven gone" would
		// tell a caller the volume may still be fenced when it provably is not.
		return statusErrWrap(http.StatusConflict, CodeFenceDropped, errClearVerify,
			"the reservation on %[1]s %[2]q is gone -- the fence is DOWN -- but the "+
				"kernel truncated its registration list, so the registrations "+
				"cannot be shown to have gone with it", kind, name)
	}
	if n := len(st.Registrations); n > 0 {
		// CodeFenceDropped, not CodeClearUnverified: this branch has PROVEN
		// the holder is gone. Reporting it as "unverified" tells automation the
		// clear failed and the node is still fenced, which is the reading that
		// gets writes allowed against unprotected storage.
		return statusErrWrap(http.StatusConflict, CodeFenceDropped, errClearVerify,
			"the reservation on %[1]s %[2]q is gone, but %[3]d registration(s) "+
				"survived the tear-down. The fence is DOWN. Those registrations "+
				"are not harmless: under a registrants-only reservation the "+
				"kernel admits any registered nexus, so whoever holds them keeps "+
				"write access the moment anyone reserves again",
			kind, name, n)
	}
	return nil
}

// recoverFromFailedPrune restores the export after a failed phase 1 and
// reports what ACTUALLY happened rather than what was attempted.
//
// This exists because a failed prune does not mean nothing happened. Reconcile
// is fail-stop and NOT transactional (lio.ApplyDelta), and it removes in
// reverse dependency order: mapped LUNs, then ACLs, then LUNs, then
// backstores. Removing the holder's mapped LUN is itself what releases its
// reservation -- core_disable_device_list_for_node calls
// core_scsi3_free_pr_reg_from_nacl, which releases when the ACL matches the
// holder (linux v6.6 drivers/target/target_core_device.c:454,
// target_core_pr.c:1342). So a failure partway through the removals can leave
// the fence already dropped.
//
// Returning a bare "could not clear the reservation" there would be the worst
// answer this operation can give: an operator or an automation reads it as
// "the fence is still up" and proceeds on that belief, which is the
// under-fencing direction the project forbids. So the state is re-read and the
// error says which of the two happened.
func (c *Coordinator) recoverFromFailedPrune(ctx context.Context, out ClearedReservation, kind Kind,
	name, objectUUID string, pruneErr error) (ClearedReservation, error) {

	// Put it back first. Losing the volume is far worse than failing to drop
	// a fence, and the re-read below is only meaningful against a rebuilt
	// tree anyway.
	c.prClearing = ""
	if _, err := c.reconcile(ctx); err != nil {
		out.addWarning(fmt.Sprintf(
			"%s %q is NOT presented to its initiators after a failed clear, and "+
				"whether its reservation survived could not be established; do "+
				"not assume either way -- see /health", kind, name))
		return out, statusErrWrap(http.StatusConflict, CodeFenceUnknown, pruneErr,
			"could not clear the reservation on %s %q (%v) AND could not "+
				"restore its export afterwards (%v); the %[1]s is not "+
				"presented to its initiators, and whether its reservation "+
				"survived is UNKNOWN -- see /health",
			kind, name, pruneErr, err)
	}

	// Ask ONLY about the fence. Not "did everything succeed" -- that is a
	// conjunction, and a provably-released reservation with a surviving
	// registration would fail it, sending the caller a generic "could not
	// clear" whose safe reading is "still fenced". Reachable: removals run
	// mapped LUNs first, and removing the holder's mapped LUN frees only THAT
	// nexus's registrations (linux v6.6 drivers/target/target_core_pr.c:1342),
	// so another initiator's registration survives the release.
	verdict, st, _, readErr := c.fenceStateOf(objectUUID)

	switch verdict {
	case fenceDown:
		extra := ""
		if n := len(st.Registrations); n > 0 {
			extra = fmt.Sprintf(" %d registration(s) also survived, and under a "+
				"registrants-only reservation those keep write access.", n)
		}
		out.addWarning(fmt.Sprintf(
			"the clear did not complete (%v), but the reservation on %s %q was "+
				"ALREADY released before it failed, because reconcile removes "+
				"mapped LUNs before backstores and that alone releases the "+
				"holder. The fence is DOWN.%s The saved APTPL record was not "+
				"discarded, so a later rebuild of this backstore may restore the "+
				"reservation. Re-run the clear to reach a defined state",
			pruneErr, kind, name, extra))
		return out, statusErrWrap(http.StatusConflict, CodeFenceDropped, pruneErr,
			"the clear of %[1]s %[2]q failed (%[3]v) AFTER its reservation had "+
				"already been released; the fence is DOWN despite this error -- "+
				"do not treat this failure as meaning the %[1]s is still fenced",
			kind, name, pruneErr)

	case fenceUp:
		// The only verdict that may be reported as an ordinary failure to
		// clear, because here the caller's safe reading -- "still fenced" --
		// is true.
		return out, statusErrWrap(http.StatusConflict, CodeClearUnverified, pruneErr,
			"could not clear the reservation on %s %q (%v); it is still held by "+
				"%q, so fencing is unchanged", kind, name, pruneErr, st.Holder)
	}

	// fenceUnknown. Neither reading is safe, and saying so is the point: this
	// used to fall through to a bare error that reached clients as "internal",
	// indistinguishable from a nil dereference.
	out.addWarning(fmt.Sprintf(
		"whether %s %q is still fenced could NOT be established after a failed "+
			"clear; do not assume either way -- verify on the initiator before "+
			"relying on it", kind, name))
	// readErr is nil when the state was READ but could not be INTERPRETED --
	// the kernel's res_holder prose is not a stable format. Printing "<nil>"
	// there told an operator nothing; say which of the two happened.
	why := "the kernel's reservation state could not be interpreted"
	if readErr != nil {
		why = readErr.Error()
	}
	return out, statusErrWrap(http.StatusConflict, CodeFenceUnknown, pruneErr,
		"could not clear the reservation on %[1]s %[2]q (%[3]v) AND the fence "+
			"state could not be established afterwards (%[4]s); it is UNKNOWN "+
			"whether this %[1]s is still fenced",
		kind, name, pruneErr, why)
}
