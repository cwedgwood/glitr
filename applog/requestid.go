package applog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

// requestIDKey is the context key for the correlation id.
type requestIDKey struct{}

// WithRequestID returns a context carrying id.
//
// # The invariant this must not break
//
// appliance/rest.go deliberately does NOT plumb r.Context() into operations,
// because configfs writes block uncancellably in the kernel: a context would
// advertise a cancellation that cannot happen, and a caller that believed it
// could abandon a reconcile would be wrong in the one place being wrong is
// expensive.
//
// So a context used only to carry a request id MUST be derived with
// context.WithoutCancel before it reaches anything that mutates. Values
// propagate; Done() never fires. The helper below does that, and it is the
// only supported way to hand a request-scoped context to the coordinator.
func WithRequestID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID returns the id a context carries, or "".
func RequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// Observability derives a context that carries the values of parent -- the
// request id among them -- but can never be cancelled.
//
// This is the boundary between "a request happened" and "an operation runs".
// Passing r.Context() itself across that boundary would reintroduce
// cancellation into Create/Connect/Delete, which is precisely what rest.go
// avoids. Naming it makes the intent reviewable at the call site.
func Observability(parent context.Context) context.Context {
	return context.WithoutCancel(parent)
}

// NewRequestID mints an id for a request that did not bring one.
//
// 16 hex characters: enough to be unique across any realistic log window,
// short enough to read on a console. Not a UUID, because nothing here needs
// the structure and the extra length costs a line's worth of readability on
// every record.
func NewRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not recoverable and not worth a second code
		// path in a logging helper. An empty id degrades correlation; it does
		// not affect the operation.
		return ""
	}
	return hex.EncodeToString(b[:])
}
