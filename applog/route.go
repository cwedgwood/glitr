package applog

import (
	"context"
	"net/http"
	"sync"
)

// routeHolder carries the routed pattern back out to the access log.
//
// It exists because the pattern is not readable from any request the access
// middleware holds. net/http records Pattern on the request the ROUTING mux
// serves, and this API is mounted behind http.StripPrefix, which clones the
// request -- so the leaf pattern is written on a clone the outer frame never
// sees. A pointer in the context is the one thing both frames share.
//
// Guarded by a mutex because a handler may route from another goroutine; the
// cost is one uncontended lock per request.
type routeHolder struct {
	mu  sync.Mutex
	pat string
}

func (h *routeHolder) set(p string) {
	if p == "" {
		return
	}
	h.mu.Lock()
	h.pat = p
	h.mu.Unlock()
}

func (h *routeHolder) pattern() string {
	if h == nil {
		return ""
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.pat
}

type routeHolderKey struct{}

func withRouteHolder(ctx context.Context, h *routeHolder) context.Context {
	return context.WithValue(ctx, routeHolderKey{}, h)
}

// CaptureRoute records the pattern the inner mux matched, for the access log
// wrapped around the outside.
//
// Place it INSIDE any http.StripPrefix, wrapping the mux that owns the leaf
// patterns. Outside it, the only pattern available is the mount ("/v1/"),
// which is the same for every request and therefore useless.
//
// A no-op when no access log is installed, so it is safe to leave in place in
// tests and in any embedding that does not log.
func CaptureRoute(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, _ := r.Context().Value(routeHolderKey{}).(*routeHolder)
		if h == nil {
			next.ServeHTTP(w, r)
			return
		}
		// Serve first: Pattern is only set once the mux has matched.
		inner := &patternRecorder{h: h, next: next}
		inner.ServeHTTP(w, r)
	})
}

// patternRecorder serves the request and then reads the pattern off the very
// request the mux routed.
type patternRecorder struct {
	h    *routeHolder
	next http.Handler
}

func (p *patternRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Deferred, so a panicking handler still yields its route. The access log
	// records a panicked request, and a record naming the concrete path
	// instead of the pattern would be the one place a caller-chosen volume
	// name leaks -- on the request most likely to be read closely.
	// A CLOSURE, not `defer p.h.set(r.Pattern)`: deferred arguments are
	// evaluated where the defer statement runs, which is BEFORE routing, so
	// the direct form captures the empty pattern every time. MEASURED -- the
	// panic test caught it reporting the mount pattern.
	defer func() { p.h.set(r.Pattern) }()
	p.next.ServeHTTP(w, r)
}
