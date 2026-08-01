package appliance

import "net/http"

// Machine-readable error codes.
//
// The human-readable message stays, and stays first: it is what an operator
// reads. The code is what a program branches on, because branching on prose
// means a reworded message silently changes behaviour.
//
// These are NOT frozen. They are a compatibility surface for callers that want
// one, added while there are few enough callers to change them.
const (
	CodeNotFound              = "not_found"
	CodeAlreadyExists         = "already_exists"
	CodeConfigurationMismatch = "configuration_mismatch"
	CodeResourceConnected     = "resource_connected"
	CodeLUNConflict           = "lun_conflict"
	CodeInvalidInput          = "invalid_input"
	CodeUnsupportedState      = "unsupported_state"
	CodeReconcileFailed       = "reconcile_failed"
	CodeInternal              = "internal"
	CodeNameTaken             = "name_taken"
	CodeLUNRequired           = "lun_required"
)

// codeForStatus is the default code for an HTTP status, so every error carries
// one without every call site having to name it.
//
// A default rather than a requirement because the alternative is worse: if the
// code had to be supplied everywhere, the sites that were never updated would
// send no code at all, and a caller cannot tell "no code" from "a code I do
// not recognise". A slightly coarse code beats a missing one; the sites where
// the distinction matters override it.
func codeForStatus(status int) string {
	switch status {
	case http.StatusNotFound:
		return CodeNotFound
	case http.StatusBadRequest:
		return CodeInvalidInput
	case http.StatusConflict:
		return CodeUnsupportedState
	case http.StatusServiceUnavailable:
		return CodeReconcileFailed
	default:
		return CodeInternal
	}
}

// statusErrCode is statusErr with an explicit machine-readable code, for the
// cases a caller has to tell apart. The 409s are the reason this exists: a
// duplicate create, an occupied LUN and a still-connected resource are all
// conflicts, and a controller does something different for each.
func statusErrCode(status int, code, format string, a ...any) error {
	e := statusErr(status, format, a...).(*StatusError)
	e.Reason = code
	return e
}
