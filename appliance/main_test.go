package appliance

import (
	"io"
	"log/slog"
	"os"
	"testing"
)

// TestMain silences the process-default logger for this package's tests.
//
// The coordinator emits an operation event per mutation, and these tests
// perform thousands of them. Left at the default handler they bury the output
// that actually says which assertion failed, which makes a failing run harder
// to read than a passing one is to ignore.
//
// Nothing that asserts on events relies on this: a test that wants to read
// them sets Config.Logger to its own handler and reads that, which is the same
// path a daemon uses. So this suppresses noise without suppressing coverage.
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}
