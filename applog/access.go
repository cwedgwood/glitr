package applog

import (
	"log/slog"
	"net/http"
	"time"
)

// HeaderRequestID is the correlation header, honoured inbound and echoed back.
const HeaderRequestID = "X-Request-Id"

// AccessLog wraps a handler and emits one rest.access record per request.
//
// This is the appliance's only accountability record. The REST API is
// unauthenticated by design (authorization is a separate, unbuilt concern), so
// without this there is no trace of who asked for what -- including the
// requests that drop fencing.
//
// # Choices worth stating
//
// It logs the ROUTE PATTERN, not the concrete path. The pattern is
// low-cardinality, which keeps an index usable, and it avoids putting volume
// names -- caller-chosen strings -- into every log line.
//
// An inbound X-Request-Id is HONOURED rather than replaced. A CSI driver's own
// id is more useful for joining across systems than one minted here, and the
// value is echoed back so a caller can correlate even if it did not send one.
//
// GET /health is logged at DEBUG. A liveness prober every couple of seconds
// otherwise dominates the stream and buries the events that matter; the
// carve-out is by route, so a health probe that FAILS is still visible through
// the status field at debug and through whatever the handler itself logs.
func AccessLog(l *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		id := r.Header.Get(HeaderRequestID)
		if id == "" {
			id = NewRequestID()
		}
		if id != "" {
			w.Header().Set(HeaderRequestID, id)
		}

		// Values only. Never cancellation -- see WithRequestID.
		//
		// The route holder rides in the context because the pattern cannot be
		// read back from any request this middleware holds. net/http writes
		// Pattern on the request the ROUTING mux serves, and the API is
		// mounted behind http.StripPrefix, which CLONES the request -- so the
		// leaf pattern is written on a clone this frame never sees, and the
		// outer request keeps only the mount pattern "/v1/".
		//
		// MEASURED, twice, in opposite ways: the first version read the
		// original request and always got an empty pattern; the second read
		// its own copy and always got "/v1/" in production, while its test
		// used a bare mux with no StripPrefix and so never reproduced the
		// real topology. A context holder written by CaptureRoute, INSIDE the
		// strip, is the only place the leaf pattern actually exists.
		holder := &routeHolder{}
		ctx := withRouteHolder(WithRequestID(r.Context(), id), holder)
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		routed := r.WithContext(ctx)

		// Emit from a DEFER, so a panicking handler still produces a record.
		//
		// Without this the accountability record goes missing at exactly the
		// moment something went badly wrong: net/http recovers the panic and
		// writes its own line via ErrorLog, and the request that caused it --
		// its route, its caller, its id -- is never logged at all. For an
		// unauthenticated API whose only audit trail this is, that is the
		// worst possible place to have a hole.
		//
		// The panic is re-raised so net/http still handles it exactly as
		// before; this only adds a record on the way past.
		emit := func(panicked bool) {
			lvl := slog.LevelInfo
			switch {
			case panicked || rec.status >= 500:
				lvl = slog.LevelError
			case rec.status >= 400:
				lvl = slog.LevelWarn
			case r.Method == http.MethodGet && r.URL.Path == "/v1/health":
				lvl = slog.LevelDebug
			}
			attrs := []slog.Attr{
				slog.String(FieldEvent, "rest.access"),
				slog.String(FieldRequestID, id),
				slog.String("method", r.Method),
				slog.String("route", routeOf(holder, routed, r)),
				slog.Int("status", rec.status),
				// Float milliseconds, not integer: these are routinely sub-ms
				// and an integer field would log 0 for most requests.
				slog.Float64("duration_ms", float64(time.Since(start).Microseconds())/1000),
				slog.Int64("bytes_out", rec.written),
				slog.String("remote_addr", r.RemoteAddr),
			}
			if panicked {
				// The status is what the recorder saw, which for a panic
				// before any write is the assumed 200 -- misleading on its
				// own, so say plainly that the handler did not finish.
				attrs = append(attrs, slog.Bool("panicked", true))
			}
			l.LogAttrs(ctx, lvl, "request", attrs...)
		}
		defer func() {
			if p := recover(); p != nil {
				emit(true)
				panic(p)
			}
			emit(false)
		}()

		next.ServeHTTP(rec, routed)
	})
}

// routeOf prefers the captured leaf pattern, then the outer mount pattern,
// then the concrete path.
func routeOf(h *routeHolder, routed, orig *http.Request) string {
	if p := h.pattern(); p != "" {
		return p
	}
	// Nothing captured a leaf pattern: either the request never reached a
	// pattern-aware mux, or it was refused before routing. The outer mount
	// pattern is still better than the concrete path, which would carry
	// caller-chosen volume names.
	if routed.Pattern != "" {
		return routed.Pattern
	}
	return orig.URL.Path
}

// recorder captures the status and byte count without buffering the body.
type recorder struct {
	http.ResponseWriter
	status  int
	written int64
	wrote   bool
}

func (rc *recorder) WriteHeader(code int) {
	// A 1xx is INFORMATIONAL: net/http allows it before the real response, so
	// latching on it would record "100" for a request that went on to answer
	// 201 or 500. Pass it through without treating it as the final status.
	if code >= 100 && code < 200 {
		rc.ResponseWriter.WriteHeader(code)
		return
	}
	if rc.wrote {
		return
	}
	rc.wrote = true
	rc.status = code
	rc.ResponseWriter.WriteHeader(code)
}

func (rc *recorder) Write(b []byte) (int, error) {
	if !rc.wrote {
		// net/http implies 200 on a first Write with no explicit header.
		rc.wrote = true
	}
	n, err := rc.ResponseWriter.Write(b)
	rc.written += int64(n)
	return n, err
}

// Flush preserves streaming for any handler that relies on it.
func (rc *recorder) Flush() {
	if f, ok := rc.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the wrapped writer to http.ResponseController.
//
// Dropping the optional interfaces a ResponseWriter may implement is the
// classic wrapper bug. Rather than forwarding each of Hijacker, Pusher and
// ReadFrom by hand -- and silently omitting whichever is added next -- this
// lets ResponseController find them all, which is what it is for. Nothing here
// hijacks or pushes today; the point is that adding it later must not
// silently lose the capability.
func (rc *recorder) Unwrap() http.ResponseWriter { return rc.ResponseWriter }
