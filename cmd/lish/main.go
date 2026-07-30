// Command lish is an interactive shell and example program for the glitr/lio
// declarative library. It drives a live kernel LIO target -- create, map,
// save, restore, clear -- to show what building on that library looks like.
// It is a worked example, not a full administration tool.
//
// It has four modes:
//
//	lish                       interactive shell over the live LIO tree
//	lish <path> <verb> [args]  single-command mode (e.g. lish /backstores/fileio ls)
//	lish save|restore|clear    whole-config JSON persistence
//	lish apply|discover|validate  JSON in/out for scripting
//
// Mutating verbs take a host-wide advisory lock, so lish will refuse to write
// the kernel LIO tree while another writer holds it.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cwedgwood/glitr/lio"
	"github.com/cwedgwood/glitr/lio/configfs"
	"github.com/cwedgwood/glitr/lish"
	"github.com/cwedgwood/glitr/saveconfig"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "lish:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	m := lio.New(configfs.Default())
	lockPath := lish.DefaultLockPath
	if v := os.Getenv("GLITR_LOCK"); v != "" {
		lockPath = v
	}
	lock := lish.NewLock(lockPath)

	if len(args) == 0 {
		return repl(m, lock)
	}

	switch args[0] {
	case "save":
		// NO lock: save is Discover plus a write to a file OUTSIDE configfs,
		// so it changes nothing the lock protects. It used to take it, which
		// made backing up or inspecting the live configuration impossible
		// while applianced was running -- exactly when an operator wants to --
		// and reported "refusing to mutate" about an operation that mutates
		// nothing. The interactive shell already treated save as read-only;
		// only this dispatch disagreed.
		//
		// A shared lock is not the answer either: applianced holds the
		// exclusive lock for its whole LIFETIME rather than per reconcile, so
		// any shared acquisition would block until the daemon exited.
		//
		// The exposure this accepts is that a save concurrent with a reconcile
		// can capture a tree mid-change. That is the same exposure every other
		// read has -- discover, tree, ls, info, get and the appliance's own
		// /health all read unlocked -- and a save that cannot run is strictly
		// worse than one that might need repeating.
		return guard(lock, args[0], func() error { return saveJSON(m, args[1:]) })
	case "restore":
		return guard(lock, args[0], func() error { return restoreJSON(m, args[1:]) })
	case "clear":
		return guard(lock, args[0], func() error {
			rep, err := m.Clear()
			if err != nil {
				return err
			}
			fmt.Printf("cleared (%d changes)\n", len(rep.Changes))
			return nil
		})
	case "discover":
		cfg, err := m.Discover()
		if err != nil {
			return err
		}
		return emitJSON(cfg)
	case "tree", "ls", "info", "get":
		// Read-only eyeballing verbs: `lish tree [path]`, `lish ls [path]`, ...
		sh := lish.NewShell(m, os.Stdout, lock)
		return sh.Exec(strings.Join(args, " "))
	case "apply":
		return guard(lock, args[0], func() error { return applyJSON(m) })
	case "validate":
		var cfg lio.Config
		if err := json.NewDecoder(os.Stdin).Decode(&cfg); err != nil {
			return fmt.Errorf("decode stdin: %w", err)
		}
		if err := cfg.Validate(); err != nil {
			return err
		}
		fmt.Println("ok")
		return nil
	default:
		// single-command mode: lish <path> <verb> [args...]
		return oneShot(m, lock, args)
	}
}

// repl runs the interactive shell.
func repl(m *lio.Manager, lock *lish.Lock) error {
	sh := lish.NewShell(m, os.Stdout, lock)
	in := bufio.NewScanner(os.Stdin)
	fmt.Print(sh.Prompt())
	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line != "" {
			if err := sh.Exec(line); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
			}
		}
		if sh.Done() {
			return nil
		}
		fmt.Print(sh.Prompt())
	}
	fmt.Println()
	return in.Err()
}

// oneShot resolves a path, then runs one verb there: lish <path> <verb> ...
func oneShot(m *lio.Manager, lock *lish.Lock, args []string) error {
	sh := lish.NewShell(m, os.Stdout, lock)
	path := args[0]
	verb := "ls"
	var rest []string
	if len(args) > 1 {
		verb = args[1]
		rest = args[2:]
	}
	if err := sh.Exec("cd " + path); err != nil {
		return err
	}
	return sh.Exec(strings.Join(append([]string{verb}, rest...), " "))
}

func withLock(l *lish.Lock, fn func() error) error {
	if err := l.Acquire(); err != nil {
		return err
	}
	defer l.Release()
	return fn()
}

func saveJSON(m *lio.Manager, args []string) error {
	path := saveconfig.DefaultPath
	if len(args) > 0 {
		path = args[0]
	}
	if err := saveconfig.Save(m, path); err != nil {
		return err
	}
	fmt.Printf("saved to %s\n", path)
	return nil
}

func restoreJSON(m *lio.Manager, args []string) error {
	path := saveconfig.DefaultPath
	if len(args) > 0 {
		path = args[0]
	}
	rep, err := saveconfig.Restore(m, path)
	if err != nil {
		return err
	}
	fmt.Printf("restored from %s (%d changes)\n", path, len(rep.Changes))
	return nil
}

func applyJSON(m *lio.Manager) error {
	var cfg lio.Config
	if err := json.NewDecoder(os.Stdin).Decode(&cfg); err != nil {
		return fmt.Errorf("decode stdin: %w", err)
	}
	rep, err := m.Sync(cfg)
	if err != nil {
		return err
	}
	fmt.Printf("applied (%d changes)\n", len(rep.Changes))
	return nil
}

func emitJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// guard runs fn, holding the writer lock only if the verb mutates.
func guard(lock *lish.Lock, verb string, fn func() error) error {
	if lish.VerbMutates(verb) {
		return withLock(lock, fn)
	}
	return fn()
}
