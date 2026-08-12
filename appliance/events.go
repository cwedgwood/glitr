package appliance

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"

	"github.com/cwedgwood/glitr/applog"
	"github.com/cwedgwood/glitr/lio"
)

// Operation, reconcile and posture events.
//
// Phase 1 (#8) made it possible to see what was ASKED of the appliance: one
// rest.access record per request, with a correlation id. This is the other
// half -- what the appliance then DID about it, and whether it worked.
//
// The distinction is not bookkeeping. A mutation commits before it reconciles,
// so a call can return an error over a change that IS durable and WILL be
// replayed at startup. From outside, rest.access shows a 500 and nothing else;
// a controller that reads that as "it did not happen" and recreates the object
// is wrong in a way the log gave it no chance to avoid. So every operation
// event carries the commit/reconcile split explicitly rather than leaving it
// to be inferred from a status code.

// Event names. Dotted, one string, matching applog's envelope.
//
// Object events are built from the Kind, so a snapshot reports
// snapshot.create rather than being flattened into a volume event: the two
// share an implementation but are different things to a consumer.
const (
	eventConnectionCreate = "connection.create"
	eventConnectionDelete = "connection.delete"
	eventHostCreate       = "host.create"
	eventHostDelete       = "host.delete"
	eventHostRename       = "host.rename"
	eventHostBindings     = "host.bindings"
	eventTargetPortals    = "target.portals"
	eventTargetReinit     = "target.reinit"

	eventPRClearing = "pr.clearing"
	eventPRCleared  = "pr.cleared"
	eventPRReleased = "pr.released"

	eventReconcileFailed    = "reconcile.failed"
	eventReconcileRecovered = "reconcile.recovered"
	eventReconcileApplied   = "reconcile.applied"
	eventCommitNotDurable   = "commit.persisted_not_durable"

	eventBackupFailed    = "storage.backup_failed"
	eventBackupRecovered = "storage.backup_recovered"

	eventHealthChanged = "health.status_changed"
)

// logger returns the coordinator's logger, falling back to the process
// default.
//
// A method rather than a bare field read because not every Coordinator comes
// from Open: reinit builds one directly to rewrite a database offline, and a
// nil logger there would turn a maintenance command into a panic. The
// fallback is the same one Open applies, so behaviour does not depend on how
// the coordinator was constructed.
func (c *Coordinator) logger() *slog.Logger {
	if c.log == nil {
		return slog.Default()
	}
	return c.log
}

// objectEvent names an event for a kind of object, e.g. "snapshot.resize".
func objectEvent(kind Kind, verb string) string { return string(kind) + "." + verb }

// Outcome values.
//
// partial is the one that earns its place: it means the appliance did part of
// what was asked and the caller still got an error. Without it, "failed" would
// have to cover both a rejected request that changed nothing and a durable
// change whose reconcile did not land -- which need opposite responses from a
// controller that is retrying.
const (
	outcomeSucceeded = "succeeded"
	outcomeFailed    = "failed"
	outcomePartial   = "partial"
)

// reconcile_outcome values. Separate from the reconciled boolean because
// false has two meanings that must not be conflated: a create never needs a
// reconcile, and that is a steady state, not a silent failure.
const (
	reconcileNotRequired = "not-required"
	reconcileSucceeded   = "succeeded"
	reconcileFailed      = "failed"
)

// opLog accumulates one operation's event while the operation runs.
//
// It is threaded through commit and persistOnly rather than reconstructed
// afterwards from the returned error, because only those two know how far a
// mutation actually got. Deriving "durable" by sniffing the error at the call
// site would be guessing at exactly the point where guessing wrong is the
// expensive direction.
type opLog struct {
	c     *Coordinator
	ctx   context.Context
	event string
	attrs []any

	// persisted records that the db change reached disk. proven records that
	// it was also fsynced. They differ only in the errPersistedNotDurable
	// case, where the change is on disk but its survival across a power cut
	// is unproven -- see [errPersistedNotDurable].
	persisted bool
	proven    bool
	// reconcile is one of the reconcile_outcome values above.
	reconcile string
}

// beginOp starts an operation event. Fields known up front go here; anything
// discovered later is added with set.
//
// Deliberately takes no lock and touches no coordinator state, so it can be
// called before c.mu is acquired and still cover the early validation
// failures. Those are real outcomes: "the appliance refused this" is
// something a controller needs, and it is the cheapest event to lose.
func (c *Coordinator) beginOp(ctx context.Context, event string, attrs ...any) *opLog {
	return &opLog{c: c, ctx: ctx, event: event, attrs: attrs, reconcile: reconcileNotRequired}
}

// set adds fields discovered while the operation ran -- the minted uuid, the
// wwn, a resolved name.
func (o *opLog) set(attrs ...any) *opLog {
	if o == nil {
		return o
	}
	o.attrs = append(o.attrs, attrs...)
	return o
}

// finish emits the event.
//
// Level is chosen by who is at fault, not by whether an error occurred. A 4xx
// is the caller's request being refused and is already visible in rest.access;
// logging it at error would flood the stream that an operator watches for the
// appliance's own problems. A 5xx, or an error carrying no status at all, is
// the appliance's problem and is logged at error. A partial outcome is a
// warning whatever its status: something is half-done.
func (o *opLog) finish(err error) {
	if o == nil {
		return
	}
	outcome, level := outcomeSucceeded, slog.LevelInfo
	switch {
	case err == nil:
	case o.persisted:
		// The record change is on disk. Whatever else failed, this is not a
		// no-op, and saying "failed" would invite a caller to undo or repeat
		// something that already happened.
		outcome, level = outcomePartial, slog.LevelWarn
	default:
		outcome = outcomeFailed
		if status(err) >= http.StatusInternalServerError {
			level = slog.LevelError
		}
	}

	attrs := append([]any{
		"outcome", outcome,
		"durable", o.persisted,
		"durable_proven", o.proven,
		"reconciled", o.reconcile == reconcileSucceeded,
		"reconcile_outcome", o.reconcile,
	}, o.attrs...)
	if err != nil {
		attrs = append(attrs, "error", err.Error(), "error_code", errorCode(err))
	}

	msg := o.event + " " + outcome
	switch level {
	case slog.LevelError:
		applog.Error(o.ctx, o.c.logger(), o.event, msg, attrs...)
	case slog.LevelWarn:
		applog.Warn(o.ctx, o.c.logger(), o.event, msg, attrs...)
	default:
		applog.Info(o.ctx, o.c.logger(), o.event, msg, attrs...)
	}
}

// status returns the HTTP status an error carries, or 500 for one that
// carries none -- an error nobody classified is the appliance's problem until
// shown otherwise.
func status(err error) int {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code
	}
	return http.StatusInternalServerError
}

// errorCode returns the stable machine-readable code for an error. Always
// non-empty, so a consumer can branch on it without a nil check.
func errorCode(err error) string {
	var se *StatusError
	if errors.As(err, &se) {
		return se.ErrorCode()
	}
	return CodeInternal
}

// noteCommit records how far a persist got. Called by persist's callers, which
// are the only code that knows.
func (o *opLog) noteCommit(persisted, proven bool) {
	if o == nil {
		return
	}
	o.persisted, o.proven = persisted, proven
}

// noteReconcile records the reconcile verdict for this operation.
func (o *opLog) noteReconcile(outcome string) {
	if o == nil {
		return
	}
	o.reconcile = outcome
}

// --- reconcile and commit outcome ---

// lioFields unwraps a *lio.Error into fields, so a kernel or configfs failure
// arrives as data rather than as prose inside a message.
//
// Unwrapped HERE, at the coordinator boundary, and deliberately not by adding
// logging inside lio: that package is silent by design, and a library that
// logs is a library that has opinions about somebody else's log stream.
func lioFields(err error) []any {
	var le *lio.Error
	if !errors.As(err, &le) {
		return nil
	}
	f := []any{"error_kind", le.Kind.String()}
	if le.Op != "" {
		f = append(f, "error_op", le.Op)
	}
	if le.Obj != "" {
		f = append(f, "error_object", le.Obj)
	}
	return f
}

// logReconcileOutcome reports the edges of the appliance's worst state.
//
// prev is the reconcile error before this attempt, so both edges are
// available: the rise, which is the failure, and the FALL, which is the
// recovery. Without the falling edge the log's last word on a resolved outage
// is still the failure, and an operator reading back has no way to see that it
// ended -- only /health knows, and only right now.
//
// Caller must hold c.mu.
func (c *Coordinator) logReconcileOutcome(ctx context.Context, prev, err error, kind string, rep lio.Report) {
	switch {
	case err != nil:
		if prev != nil {
			// Still broken. Logging every attempt would turn a wedged kernel
			// into a log flood, and the condition is already standing in
			// /health. The edge is the event.
			return
		}
		// changes_applied on a FAILURE is not a curiosity. ApplyDelta is
		// fail-stop and not transactional, so a failed reconcile has usually
		// applied some of its changes and stopped partway; the count says how
		// far it got, which is the difference between "nothing happened" and
		// "the tree is halfway between two configurations".
		attrs := append([]any{
			"kind", kind, "error", err.Error(), "changes_applied", len(rep.Changes),
		}, lioFields(err)...)
		applog.Error(ctx, c.logger(), eventReconcileFailed,
			"reconcile failed; the kernel may not match the durable database", attrs...)
	case prev != nil:
		applog.Info(ctx, c.logger(), eventReconcileRecovered,
			"reconcile succeeded; the kernel matches the durable database again",
			"kind", kind, "changes_applied", len(rep.Changes))
	}
}

// logReplayApplied reports what a startup reconcile had to change.
//
// The change count is already computed and was, until now, discarded. "Did it
// have to fix anything after that reboot" is the first question asked after an
// unplanned restart, and a count answers it: zero means the kernel came back
// as the database expected. The changes themselves stay out of the field --
// an unbounded list in one record is not something a log consumer can budget
// for -- and remain available in the slow-reconcile diagnostics.
func (c *Coordinator) logReplayApplied(ctx context.Context, rep lio.Report) {
	applog.Info(ctx, c.logger(), eventReconcileApplied,
		"startup replay reconciled the kernel to the durable database",
		"kind", "startup", "changes_applied", len(rep.Changes))
}

// logNotDurable reports a db write that landed but was not proven durable.
//
// Warn, not error: the change IS on disk and the appliance is not in a bad
// state -- only its survival across a power cut in the next moments is
// unproven. Its own event because it is not an operation outcome; the
// operation event says partial and this says why.
func (c *Coordinator) logNotDurable(ctx context.Context, err error) {
	applog.Warn(ctx, c.logger(), eventCommitNotDurable,
		"database written and in effect, but not proven durable", "error", err.Error())
}

// --- backup posture ---

// logBackupPosture reports the EDGES of the db-backup posture.
//
// Edge-triggered, and that is not an optimisation: a backup is attempted on
// every mutation, so a record per success would drown the stream in the case
// where nothing is wrong. Now that backupErr describes the current posture
// rather than latching, both edges are well defined.
//
// Caller must hold healthMu.
func (c *Coordinator) logBackupPosture(ctx context.Context, prev, now error) {
	switch {
	case now != nil && prev == nil:
		applog.Warn(ctx, c.logger(), eventBackupFailed,
			"cannot keep a backup of the appliance database", "error", now.Error())
	case now == nil && prev != nil:
		applog.Info(ctx, c.logger(), eventBackupRecovered,
			"database backups are being kept again")
	}
}

// logFenceReleased reports that an operation is about to release a SCSI-3
// reservation, as its own event carrying the request id.
//
// It is emitted BEFORE the mutation commits, which is why it cannot simply be
// a field on the operation event: the reservation state being reported is the
// one that exists while the ACLs are still in place, and asking afterwards
// would ask about a fence that is already gone. It was previously a bare
// "WARNING:" line with nothing tying it to the request that caused it -- so
// two operators detaching two hosts produced two warnings and no way to tell
// which was whose. The same text is also set on the operation event, so a
// consumer reading only outcomes still sees it.
func (c *Coordinator) logFenceReleased(ctx context.Context, warning, kind, name, uuid string) {
	applog.Warn(ctx, c.logger(), eventPRReleased, warning,
		"resource_kind", kind, "resource_name", name, "resource_id", uuid)
}

// Standing-condition and diagnostic events.
//
// These were prose lines routed through the stdlib bridge. Converting them is
// what makes the stream uniformly filterable: a consumer can select on event
// rather than matching on message text, and each one now carries its real
// severity instead of the bridge's blanket WARN.
const (
	eventConfigIgnored        = "config.flag_ignored"
	eventIdentityAdopted      = "identity.adopted"
	eventIdentityNoMachineID  = "identity.no_machine_id"
	eventStorageQuarantined   = "storage.quarantined"
	eventStorageMissing       = "storage.missing"
	eventPROrphans            = "pr.orphans"
	eventPROrphanCheckFailed  = "pr.orphan_check_failed"
	eventPRStranded           = "pr.stranded"
	eventPRStrandUndecided    = "pr.strand_undecided"
	eventPRUnbound            = "pr.unbound"
	eventPRDiscardFailed      = "pr.discard_failed"
	eventAttributeDrift       = "drift.attribute"
	eventCommitSlow           = "commit.slow"
	eventReconcileSlow        = "reconcile.slow"
	eventReconcileFallback    = "reconcile.fallback"
	eventLifecycleShutdown    = "lifecycle.shutdown"
	eventLifecycleDrainFailed = "lifecycle.drain_failed"
	eventConfigWriteBack      = "config.write_back_enabled"
	eventConfigPRCheckOff     = "config.pr_check_disabled"
	eventStartupFailed        = "lifecycle.startup_failed"
)

// --- health transitions ---

// Health verdicts, as served on /health.
const (
	healthOK       = "ok"
	healthWarning  = "warning"
	healthDegraded = "degraded"
)

// Status is the top-level verdict for a health snapshot.
//
// A method on Health rather than a switch inside the /health handler, which is
// where it used to live, because the transition event has to agree with what
// /health serves. Two copies of this rule would eventually disagree, and the
// disagreement would be invisible: the log would announce a recovery for an
// appliance still serving "warning", or the reverse.
//
// Still HTTP 200 for a warning at the handler -- the appliance IS alive and
// serving -- but that is the handler's business, not this rule's.
func (h Health) Status() string {
	switch {
	case h.Degraded:
		return healthDegraded
	case len(h.Withheld) > 0 || h.ClearInProgress != "" ||
		len(h.PRUnbound) > 0 || len(h.PRStranded) > 0:
		return healthWarning
	}
	return healthOK
}

// Conditions names the standing conditions currently reported, using the same
// keys /health serves so a consumer needs no mapping table.
//
// Includes conditions that do NOT raise the verdict -- attribute_drift,
// db_backup_failing, quarantined_volume_dirs and the rest. Their edges are
// exactly what a consumer cannot otherwise see: they never change status, so
// without this the only way to notice one arriving or clearing is to have been
// polling at the time.
func (h Health) Conditions() []string {
	var out []string
	add := func(name string, present bool) {
		if present {
			out = append(out, name)
		}
	}
	add("pr_unbound", len(h.PRUnbound) > 0)
	add("pr_stranded", len(h.PRStranded) > 0)
	add("pr_strand_undecided", len(h.PRStrandUndecided) > 0)
	add("clear_in_progress", h.ClearInProgress != "")
	add("withheld_after_failed_clear", len(h.Withheld) > 0)
	add("attribute_drift", len(h.Drift) > 0)
	add("db_backup_failing", h.BackupErr != "")
	add("quarantined_volume_dirs", len(h.Quarantined) > 0)
	add("portal_flag_ignored", h.PortalFlagIgnored != "")
	add("iqn_flag_ignored", h.IQNFlagIgnored != "")
	slices.Sort(out)
	return out
}

// noteHealth logs a change in the published health verdict or in the set of
// standing conditions.
//
// The FALLING edge is why this exists. A consumer that starts polling after a
// condition arose cannot tell "never happened" from "resolved before I
// looked", and every condition here is one an operator is expected to act on.
//
// Deliberately NOT rate-limited, though a flapping condition could in
// principle produce a record per reconcile. Rate limiting drops edges, and the
// edge that would be dropped is as likely to be the recovery as the failure --
// which would reintroduce the exact gap this closes. Flapping is bounded by
// how often a reconcile or a PR re-check runs, and a condition that really is
// flapping is itself worth seeing.
//
// Must NOT be called with healthMu held: it takes a snapshot, which takes that
// lock.
func (c *Coordinator) noteHealth(ctx context.Context) {
	h := c.HealthSnapshot()
	status, conds := h.Status(), h.Conditions()

	c.healthMu.Lock()
	prevStatus, prevConds := c.lastStatus, c.lastConditions
	first := prevStatus == ""
	c.lastStatus, c.lastConditions = status, conds
	c.healthMu.Unlock()

	if first {
		// Startup is not a transition. Announcing one would report every
		// condition an appliance came up with as newly arrived, which is the
		// opposite of what an edge means -- lifecycle.start already says what
		// it started as.
		return
	}
	added, cleared := diffConditions(prevConds, conds)
	if status == prevStatus && len(added) == 0 && len(cleared) == 0 {
		return
	}

	attrs := []any{"from", prevStatus, "to", status}
	if len(added) > 0 {
		attrs = append(attrs, "fields_added", added)
	}
	if len(cleared) > 0 {
		attrs = append(attrs, "fields_cleared", cleared)
	}
	msg := "health changed from " + prevStatus + " to " + status
	if status == prevStatus {
		msg = "health conditions changed, verdict still " + status
	}
	// Worse is a warning, better or sideways is not. A recovery logged at warn
	// would page somebody to tell them it stopped.
	if healthRank(status) > healthRank(prevStatus) {
		applog.Warn(ctx, c.logger(), eventHealthChanged, msg, attrs...)
		return
	}
	applog.Info(ctx, c.logger(), eventHealthChanged, msg, attrs...)
}

// healthRank orders the verdicts so a transition can be called better or worse.
func healthRank(s string) int {
	switch s {
	case healthDegraded:
		return 2
	case healthWarning:
		return 1
	}
	return 0
}

// diffConditions reports which conditions arrived and which cleared. Both
// inputs are sorted.
func diffConditions(prev, now []string) (added, cleared []string) {
	for _, n := range now {
		if !slices.Contains(prev, n) {
			added = append(added, n)
		}
	}
	for _, p := range prev {
		if !slices.Contains(now, p) {
			cleared = append(cleared, p)
		}
	}
	return added, cleared
}
