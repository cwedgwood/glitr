package appliance

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"slices"

	"github.com/cwedgwood/glitr/lio"
)

// maxLUN bounds a caller-supplied mapped LUN so an absurd value can't be
// persisted and then rejected by the kernel at startup replay.
const maxLUN = 16383

// StatusError carries an HTTP status for the REST layer. Ops return it for
// client errors (bad request, not found, conflict); any other
// error is treated as internal (http.StatusInternalServerError).
type StatusError struct {
	Code int // HTTP status
	Msg  string
	// Reason is the stable machine-readable code, sent as "code" on the wire.
	// Empty means "derive it from the status" -- see codeForStatus.
	Reason string
	// Err is an optional underlying error.
	//
	// Present so an error can carry an HTTP status AND remain matchable with
	// errors.Is against a package sentinel. Without it the two are exclusive:
	// attaching a status meant flattening the cause to a string, so a test or
	// a caller could no longer ask what KIND of failure it was.
	Err error
}

// Unwrap exposes the underlying cause to errors.Is/errors.As.
func (e *StatusError) Unwrap() error { return e.Err }

// ErrorCode returns the machine-readable code for this error, deriving one
// from the HTTP status when none was set explicitly. Never empty, so a caller
// can always branch on it.
func (e *StatusError) ErrorCode() string {
	if e.Reason != "" {
		return e.Reason
	}
	return codeForStatus(e.Code)
}

func (e *StatusError) Error() string { return e.Msg }

// statusErrWrap is statusErrCode that also keeps a cause, so the result
// carries a status and a machine code while still matching errors.Is.
func statusErrWrap(status int, reason string, cause error, format string, a ...any) error {
	e := statusErr(status, format, a...).(*StatusError)
	e.Reason = reason
	e.Err = cause
	return e
}

func statusErr(code int, format string, a ...any) error {
	return &StatusError{Code: code, Msg: fmt.Sprintf(format, a...)}
}

func validIQN(s string) bool { return lio.ValidInitiatorIQN(s) }

// ConnInfo is what a client needs to connect to a mapped volume.
type ConnInfo struct {
	TargetIQN string `json:"target_iqn"`
	// Portals carry their own ports -- see Config.Portals. A client needs the
	// endpoint, not an address plus a guess.
	Portals []lio.Portal `json:"portals"`
	LUN     int          `json:"lun"`
	Wwid    string       `json:"wwid"`
}

// --- volume operations (storage + reconcile) ---

// discardSavedPR removes the kernel's saved SCSI-3 PR metadata for a deleted
// volume. The kernel writes db_root/pr/aptpl_<wwn> but never removes it, so
// without this the files accumulate for the life of the appliance.
//
// Only ever called for a volume that has just been deleted while unattached,
// which is the one moment the saved reservations are certainly dead: the
// backstore has been pruned by the preceding reconcile, so nothing can
// rewrite the file, and no future volume can inherit it (a WWN is the first 8
// bytes of a CSPRNG UUID -- 60 random bits, since one nibble is the UUID
// version -- and is enforced unique across live volumes).
//
// Best-effort by design. The volume is already gone, and failing the delete
// because a metadata file could not be unlinked would turn a tidiness
// problem into an API error. A leftover file is inert: it is only ever read
// back for a backstore with that exact WWN.
//
// That argument is load-bearing and does NOT generalise. ClearReservation
// removes the same file for a volume that is about to come BACK with the same
// WWN, where a leftover is replayed and restores the reservation being
// dropped -- so it uses discardSavedPRChecked, which proves the removal.
// Do not repoint that caller here.
func (c *Coordinator) discardSavedPR(wwn string) {
	if c.cfg.DBRoot == "" || wwn == "" {
		return
	}
	path := APTPLPath(c.cfg.DBRoot, wwn)
	// A failure here leaves an orphan. It is not retried and not fatal: the
	// volume is already deleted, so there is nothing to roll back and no
	// correctness consequence (the file is only ever read back for a
	// backstore with this exact WWN, which no longer exists and cannot recur
	// -- see OrphanPRState). It is logged, and the leftover is reported at
	// the next startup and by `applianced inspect`.
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Printf("warning: could not remove saved SCSI-3 PR state %s: %v "+
			"(harmless leftover; `applianced inspect` will list it)", path, err)
	}
}

// --- host operations ---

// --- attachment operations (LUN is a caller input) ---

// connInfo is what an initiator needs to reach a mapped volume. Caller must
// hold c.mu.
func (c *Coordinator) connInfo(o *Object, lun int) ConnInfo {
	return ConnInfo{
		TargetIQN: c.cfg.TargetIQN,
		Portals:   c.portals(),
		LUN:       lun, Wwid: Wwid(o.WWN),
	}
}

// fenceLossWarning reports whether detaching this host will release a
// reservation it holds, and returns the text to hand back to the caller.
//
// Best-effort and never fatal: this is a report channel, and failing an unmap
// because the reservation state could not be read would trade a real operation
// for a diagnostic. An unreadable holder simply yields no warning, which is
// the same outcome as no reservation -- an acceptable loss for a signal, and
// the reason this is not the only place the condition is reported.
func (c *Coordinator) fenceLossWarning(objectUUID, hostUUID string) string {
	h := c.host(hostUUID)
	if h == nil {
		return ""
	}
	return c.fenceLossWarningFor(objectUUID, h.Bindings.IQNs, hostUUID,
		fmt.Sprintf("disconnecting host %q from object %s", h.Name, objectUUID))
}

// fenceLossWarningFor is the same report for any change that costs a set of
// initiators their access to a volume, not only a detach: losing names the
// IQNs that are about to lose it, and action describes what is doing so.
//
// Replacing a host's IQN list drops the ACLs of the removed ones, which is the
// same kernel path as a detach (core_scsi3_free_pr_reg_from_nacl), so it has
// to be reported the same way. Sharing the function rather than copying it
// keeps the kernel reasoning below in one place; the earlier duplicate-by-hand
// version of this logic is exactly what got the backstore lookup wrong.
func (c *Coordinator) fenceLossWarningFor(objectUUID string, losing []string, detachingHost, action string) string {
	v := c.object(objectUUID)
	if v == nil {
		return ""
	}
	// Find the backstore through desiredLIO rather than reconstructing one.
	//
	// An earlier version built lio.Backstore{Type: FileIO, Name: ..., HBA: 0}
	// by hand, and HBA is an allocated INDEX, not a constant -- so on any
	// volume that did not happen to land on fileio_0 it read a different
	// object's reservation state, or none, and warned about nothing. The unit
	// test did not catch it because the fixture staged the volume at fileio_0
	// too: the test agreed with the bug. Only the live run exposed it.
	//
	// Asking desiredLIO means the lookup is by construction the same object
	// the reconcile manages.
	name := backstoreName(v.UUID)
	var bs *lio.Backstore
	desired := c.desiredLIO()
	for i := range desired.Backstores {
		if desired.Backstores[i].Name == name {
			bs = &desired.Backstores[i]
			break
		}
	}
	if bs == nil {
		return ""
	}
	res, err := c.lio.ReservationHolder(*bs)
	if err != nil {
		// Not silence. This used to return "" on any error, so an
		// uninterpretable res_holder produced the same outcome as "no
		// reservation is held": the operator unmapped and was told nothing,
		// in the one moment where they most needed to know that fencing might
		// be dropping. Say that we cannot tell instead -- a warning that
		// turns out to be unnecessary costs an operator a second look, and
		// the silence costs them the fence.
		return fmt.Sprintf(
			"whether a SCSI-3 reservation protects this volume could NOT be determined (%v), "+
				"so it is unknown whether this unmap released one; verify fencing before "+
				"relying on it", err)
	}
	if res.Holder == "" {
		return ""
	}
	// An SPC-2 reservation lives in dev->reservation_holder, which
	// core_scsi3_free_pr_reg_from_nacl never touches (linux v6.6
	// drivers/target/target_core_pr.c:1342-1377). res_holder renders it
	// through the same " Initiator: " shape as a SCSI-3 one
	// (target_core_configfs.c:1804), so without this check the warning would
	// name a persistent reservation that is not one and claim a release that
	// does not happen.
	if res.SPC2 {
		return ""
	}
	if !slices.Contains(losing, res.Holder) {
		// Losing access for a NON-holder is safe: it removes that initiator's
		// access, which over-fences rather than under-fencing, and leaves the
		// reservation protecting whoever remains.
		return ""
	}
	// ALL REGISTRANTS types TRANSFER rather than release: removing the holder
	// enters __core_scsi3_complete_pro_release with unreg=1, which promotes
	// the next registration (linux v6.6
	// drivers/target/target_core_pr.c:2463-2478). The fence survives, so
	// warning here would be a false alarm -- and a warning that fires when
	// nothing was lost trains an operator to ignore the one that matters.
	// lio/aptpl_test.go's TestAPTPLLapsedHolderSilentWhenReservationTransferred
	// is the same reasoning applied to the sibling APTPL report.
	if res.AllRegistrants() {
		return ""
	}
	// Whether the release is permanent depends on whether the backstore
	// survives the detach, which it does only if some OTHER host is still
	// attached. If this is the last attachment, pruneExports drops the export,
	// reconcile removes the backstore, and creating it again replays the saved
	// APTPL records (loadAPTPL, before enable) -- so the reservation can come
	// back on a later attach. Both are fence loss NOW; they differ in whether
	// re-attaching undoes it, and saying the wrong one is a claim the code did
	// not establish.
	// detachingHost, if set, is the attachment about to disappear and so does
	// not count as a survivor. Removing an IQN leaves the attachment in place,
	// so nothing is excluded and the export always survives.
	others := 0
	for _, cn := range c.st.Connections {
		if cn.ObjectUUID == objectUUID && (detachingHost == "" || cn.HostUUID != detachingHost) {
			others++
		}
	}
	restores := "re-attaching does not restore it, because saved records are " +
		"replayed only when a backstore is CREATED and this one survives"
	if others == 0 {
		restores = "this was the last attachment, so the backstore is removed and a " +
			"later attach will recreate it and replay the saved records -- the " +
			"reservation may return, which is its own surprise"
	}
	return fmt.Sprintf("%s RELEASED the SCSI-3 "+
		"reservation it held (%s, type: %s). Initiators this reservation was fencing "+
		"can write to the volume NOW, and %s. The kernel releases a reservation whose "+
		"holder loses its mapped LUN (core_scsi3_free_pr_reg_from_nacl, linux v6.6 "+
		"drivers/target/target_core_device.c:454); it was not refused because "+
		"an operator must be able to detach a host that may itself be dead. Losing the "+
		"ACL also frees every OTHER registration that initiator held on the volume, so a "+
		"preempt-based recovery may have lost the registration it needed. If the "+
		"volume is still in use by a cluster, re-establish fencing before allowing "+
		"writes",
		action, res.Holder, resTypeOrUnknown(res.Type), restores)
}

func resTypeOrUnknown(t string) string {
	if t == "" {
		return "could not be read"
	}
	return t
}

// Target returns the appliance's target IQN and its portals.
//
// Portals carry their own ports. There is deliberately no separate port
// return value: one existed, and it asserted that every portal shared it.
func (c *Coordinator) Target() (string, []lio.Portal) {
	// portals() reads c.st.Portals and its contract says the caller must hold
	// c.mu. This did not, while SetPortals writes that same field under the
	// lock -- and net/http serves every request on its own goroutine, so a GET
	// racing a PUT read a slice header being replaced. Every sibling accessor
	// (ListHosts, Lunmap) locks; this was the outlier, and -race stayed green
	// only because no test drove the two concurrently.
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg.TargetIQN, c.portals()
}

// SetPortals replaces the target's portal list.
//
// Portals are the fabric's shape, and changing them is exactly what an
// orchestrator needs to do without editing a systemd unit and restarting. The
// new list becomes the durable record; the -portals flag is only a bootstrap
// default (see adoptPortals).
//
// Ordering is deliberately NOT this function's business. Everything else in
// this package adds before it removes so there is never a window with the
// object missing, but portals cannot work that way: a wildcard will not bind
// while any other address holds its port, so the wildcard cases are strictly
// prune-then-add. lio.Sync already encodes that, and re-implementing any of it
// here would give two orderings that can disagree.
func (c *Coordinator) SetPortals(ctx context.Context, portals []lio.Portal) (out []lio.Portal, err error) {
	ev := c.beginOp(ctx, eventTargetPortals, "portals", portalsText(portals))
	defer func() { ev.finish(err) }()

	c.mu.Lock()
	defer c.mu.Unlock()

	// An empty list is the one change that cannot be undone through this API:
	// it takes away every address the target answers on, and this endpoint is
	// reached over a DIFFERENT socket, so the caller would keep its connection
	// and still have bricked the fabric.
	if len(portals) == 0 {
		return nil, statusErr(http.StatusBadRequest,
			"refusing to remove every portal: the target would answer on no "+
				"address and could not be reached to fix it")
	}

	// Validate against the same rules startup uses, so a set that would fail
	// replay can never be persisted. Config.Validate rejects duplicates by
	// address+port and malformed entries.
	next := Config{TargetIQN: c.cfg.TargetIQN, Portals: portals}
	if err := next.Validate(); err != nil {
		return nil, statusErr(http.StatusBadRequest, "%v", err)
	}

	prev := slices.Clone(c.st.Portals)
	ev.set("previous_portals", portalsText(prev))
	if samePortalSet(prev, portals) {
		// Nothing to do. Returning early keeps a no-op request from bouncing
		// the fabric: the reconciler would prune and re-add nothing, but a
		// caller polling this endpoint should not be able to cause churn.
		return c.portals(), nil
	}

	if err := c.commit(ctx, ev, func() error {
		c.st.Portals = slices.Clone(portals)
		return nil
	}); err != nil {
		// commit rolls the db back for anything up to and including persist.
		// A reconcile failure is NOT rolled back -- the record is the source
		// of truth and startup replay re-reconciles -- so say which happened,
		// because the two need different operator responses.
		if samePortalSet(c.st.Portals, prev) {
			return nil, statusErr(http.StatusConflict,
				"portal change rejected, portals unchanged (%s): %v",
				portalsText(prev), err)
		}
		return nil, statusErr(http.StatusConflict,
			"portals are now recorded as %s but the kernel did not accept them "+
				"(%v). The record is authoritative and will be retried on "+
				"restart; set a working list to recover", portalsText(portals), err)
	}
	// Adopting a new list makes any disagreement with the boot flag moot: the
	// operator has just said what they want through the API.
	//
	// healthMu, not mu (which this already holds): the field is published to
	// /health and read under healthMu. Lock order is mu -> healthMu
	// throughout, so taking it here is consistent with publishReconcile.
	c.healthMu.Lock()
	c.portalFlagIgnored = ""
	c.healthMu.Unlock()
	// The prose line is gone: the operation event carries portals and
	// previous_portals as fields, which is the same information in a form a
	// consumer can filter on.
	return c.portals(), nil
}
