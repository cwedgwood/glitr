package applog_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoProseLoggingRemains is the guard that makes bridging at Info safe.
//
// The bridge deliberately ran at WARN while ~45 log.Printf sites still
// existed, because slog drops a bridged record the handler rejects, so an
// operator at -log-level=warn would have lost them all. Returning it to Info
// is correct only while nothing the appliance reports as an anomaly still
// arrives that way -- and "nothing does" is a property of the source, not of
// any single behaviour, so it is checked as one.
//
// A source scan rather than a runtime assertion because the failure it guards
// against is a line that is never executed in a test: someone adds a
// log.Printf in a hurry, it works locally at the default level, and it is
// invisible in production to exactly the operator who raised the floor because
// they were being careful.
//
// log.Fatal is exempt. Those sites remain in applianced's subcommand paths,
// which run before a logger is configured at all, where writing plainly to
// stderr is the right thing and the bridge is not involved.
func TestNoProseLoggingRemains(t *testing.T) {
	// The packages the daemon is built from. lish and the probes are separate
	// binaries that never install this handler, so the bridge level does not
	// apply to them.
	pkgs := []string{
		"appliance", "applog", "applianceclient", "cmd/applianced",
		"storage", "lio", "lio/configfs", "setup", "hostlock", "scsi", "saveconfig",
	}
	root := ".."
	for _, p := range pkgs {
		dir := filepath.Join(root, p)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			checkFile(t, filepath.Join(dir, name))
		}
	}
}

func checkFile(t *testing.T, path string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "log" {
			return true
		}
		// Fatal exits the process from a path that has no logger yet.
		if strings.HasPrefix(sel.Sel.Name, "Fatal") {
			return true
		}
		switch sel.Sel.Name {
		case "Print", "Printf", "Println":
			t.Errorf("%s: log.%s is prose with no event name, and now bridges at Info -- "+
				"an operator running -log-level=warn will never see it. Use applog.Warn, "+
				"applog.Notice or applog.Info with an event name.",
				fset.Position(call.Pos()), sel.Sel.Name)
		}
		return true
	})
}
