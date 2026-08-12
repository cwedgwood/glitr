// Package applog is the appliance's structured-logging foundation.
//
// It exists so a control-plane consumer -- a CSI driver, an operator's
// collector -- can work from the log stream instead of only by polling
// /health. The diagnostics this project already emits are carefully worded and
// genuinely useful; what was missing is that severity was a string prefix
// rather than a field, and several high-value events were not logged at all.
//
// # Design notes
//
// Text is the DEFAULT. This is an appliance whose logs are read by humans on a
// serial console and by journald at least as often as by a collector, and
// silently changing the output of a running deployment is not something a
// logging change should do. JSON is opt-in.
//
// Every record carries a common envelope: service, schema_version, and a
// single dotted event name (pr.unbound, rest.access). One dotted string rather
// than separate category and name fields, because it stays greppable in
// journald and a consumer that wants a facet can split on the prefix.
//
// schema_version is present from the start because the field set becomes an
// external integration surface the moment anything parses it.
package applog

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"runtime/debug"
	"strings"
)

// SchemaVersion is the version of the envelope and field names. Bump it when a
// field changes meaning or is removed -- not when one is added, since
// consumers must tolerate unknown fields.
const SchemaVersion = 1

// LevelNotice sits between Info and Warn.
//
// It exists because this project deliberately reports some conditions as
// NOTICE rather than WARNING: a stranded reservation is still ENFORCING, so it
// is doing its job, and an operator paged for it learns to ignore the channel.
// Collapsing NOTICE into Info buries it and into Warn raises a false alert --
// neither is acceptable, so it gets its own level.
const LevelNotice = slog.LevelInfo + 2

// Envelope and correlation field names, as constants so a rename is a compile
// error rather than a silently-renamed field in someone's dashboard.
const (
	FieldEvent     = "event"
	FieldRequestID = "request_id"
	FieldHint      = "hint"
)

// Options configure the handler. The zero value is the text default.
//
// KNOWN LIMITATION: attribute names are flat, so a payload attr sharing an
// envelope key ("level", "msg", "time", "event", "service") produces a
// duplicate key in JSON. Both are emitted and ReplaceAttr does not rewrite the
// payload one, but a decoder that keeps the last value will see the payload's.
// Callers should not reuse those names; if that becomes a real collision the
// fix is to nest payload attrs under a group rather than to rename them
// silently.
type Options struct {
	Format string    // "text" (default) or "json"
	Level  string    // "debug", "info", "notice", "warn", "error"; default info
	Out    io.Writer // nil means os.Stderr
}

// ParseLevel maps a flag value to a level, reporting an unknown one rather
// than defaulting silently -- a typo in -log-level must not quietly become
// info and hide the debug output someone is waiting for.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "notice":
		return LevelNotice, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q (want debug, info, notice, warn or error)", s)
}

// New builds the handler and returns a logger plus the handler.
//
// The handler comes back because http.Server needs a *log.Logger built from
// it: net/http writes its own errors -- including "http: panic serving" and a
// stack -- to the stdlib default logger, which under a JSON handler would
// interleave raw text into the stream at the worst possible moment.
func New(o Options) (*slog.Logger, slog.Handler, error) {
	lvl, err := ParseLevel(o.Level)
	if err != nil {
		return nil, nil, err
	}
	out := o.Out
	if out == nil {
		out = os.Stderr
	}
	hopts := &slog.HandlerOptions{Level: lvl, ReplaceAttr: replaceAttr}

	var h slog.Handler
	switch strings.ToLower(strings.TrimSpace(o.Format)) {
	case "", "text":
		h = slog.NewTextHandler(out, hopts)
	case "json":
		h = slog.NewJSONHandler(out, hopts)
	default:
		return nil, nil, fmt.Errorf("unknown log format %q (want text or json)", o.Format)
	}

	h = h.WithAttrs([]slog.Attr{
		slog.String("service", "applianced"),
		slog.Int("schema_version", SchemaVersion),
	})
	return slog.New(h), h, nil
}

// replaceAttr names the custom level, which slog otherwise renders as
// "INFO+2" -- an unreadable value in a field consumers filter on.
func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	// The len(groups) guard is correct but, in this package, inert: every attr
	// emitted here is flat, so a payload attr named "level" sits at depth 0
	// alongside the record's own and IS rewritten when its value is a
	// slog.Level. MEASURED. The guard is kept for any future grouped use, not
	// claimed as protection today.
	//
	// The real constraint is the naming one documented on Options: do not
	// reuse an envelope key. Nesting payload attrs under a group would fix
	// both that and this, but issue #8 asks for flat fields that match the
	// /health keys exactly so the two join with no mapping table -- so the
	// constraint is the deliberate trade, and it is written down rather than
	// quietly worked around.
	if len(groups) == 0 && a.Key == slog.LevelKey {
		if lv, ok := a.Value.Any().(slog.Level); ok && lv == LevelNotice {
			a.Value = slog.StringValue("NOTICE")
		}
	}
	return a
}

// Install makes the logger the process default and routes the stdlib log
// package through it.
//
// Routing the stdlib package still matters: a dependency, or a site added in
// a hurry, can call log.Printf and should land in the same stream rather than
// bypassing the handler and interleaving raw text with structured records.
func Install(l *slog.Logger) {
	slog.SetDefault(l)
	// The stdlib bridge runs at Info.
	//
	// It ran at WARN for the duration of the migration, deliberately: slog
	// drops a bridged record when the handler rejects its level, so at Info an
	// operator running -log-level=warn would have silently lost the ~45
	// log.Printf sites that existed then -- including the ones whose text said
	// WARNING. Over-severity is visible and annoying; silent loss of a warning
	// is not, and the loud failure is the acceptable one.
	//
	// That reasoning expired when the sites did. Every anomaly the appliance
	// reports now carries its own level and its own event name, so the blanket
	// WARN had become the inaccuracy rather than the safeguard: it promoted
	// anything still arriving through the bridge -- which is now only
	// unconverted or third-party output -- to a severity nobody chose.
	slog.SetLogLoggerLevel(slog.LevelInfo)
	// The stdlib logger's own flags would prepend a second timestamp to a
	// record that already carries one.
	log.SetFlags(0)
}

// ServerErrorLog adapts the handler for http.Server.ErrorLog, at Warn:
// net/http writes there only for genuine problems -- a panic in a handler, an
// accept failure, a malformed request -- and none of those are routine.
func ServerErrorLog(h slog.Handler) *log.Logger {
	return slog.NewLogLogger(h, slog.LevelWarn)
}

// Notice logs a condition an operator should see that is not a fault.
func Notice(ctx context.Context, l *slog.Logger, event, msg string, args ...any) {
	l.LogAttrs(ctx, LevelNotice, msg, attrs(ctx, event, args)...)
}

// Info, Warn and Error are the ordinary levels. Each takes an event name, so
// no record can be emitted without one.
func Info(ctx context.Context, l *slog.Logger, event, msg string, args ...any) {
	l.LogAttrs(ctx, slog.LevelInfo, msg, attrs(ctx, event, args)...)
}

func Warn(ctx context.Context, l *slog.Logger, event, msg string, args ...any) {
	l.LogAttrs(ctx, slog.LevelWarn, msg, attrs(ctx, event, args)...)
}

func Error(ctx context.Context, l *slog.Logger, event, msg string, args ...any) {
	l.LogAttrs(ctx, slog.LevelError, msg, attrs(ctx, event, args)...)
}

// attrs prefixes the event name and folds in any request id the context
// carries, so a caller cannot forget the correlation field.
func attrs(ctx context.Context, event string, args []any) []slog.Attr {
	out := make([]slog.Attr, 0, len(args)/2+2)
	out = append(out, slog.String(FieldEvent, event))
	if id := RequestID(ctx); id != "" {
		out = append(out, slog.String(FieldRequestID, id))
	}
	for i := 0; i+1 < len(args); i += 2 {
		k, ok := args[i].(string)
		if !ok {
			continue
		}
		out = append(out, slog.Any(k, args[i+1]))
	}
	return out
}

// BuildInfo returns version, commit and Go version for lifecycle.start.
//
// Logged because a journal spanning an upgrade otherwise cannot attribute a
// line to a build, which is exactly when attribution matters most.
func BuildInfo() (version, commit, goVersion string) {
	version, commit, goVersion = "unknown", "unknown", "unknown"
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	goVersion = bi.GoVersion
	if bi.Main.Version != "" {
		version = bi.Main.Version
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			commit = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				commit += "-dirty"
			}
		}
	}
	return
}
