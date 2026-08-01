package main

import (
	"flag"
	"io"
	"strings"
	"testing"
)

// TestExtraArgsAreRefused: flag.Parse stops at the first non-flag argument and
// leaves the rest in Args(), which every subcommand used to discard.
//
// MEASURED on the lab before this existed: `-portals 10.10.0.1:3260
// 10.10.0.11:3260` -- a space where a comma belongs -- started the daemon
// "active" serving exactly ONE portal, with the second dropped silently.
// Multipath needs both, so the operator gets half a fabric and no signal.
// Config.Validate cannot catch it: the second address never reaches Config.
func TestExtraArgsAreRefused(t *testing.T) {
	newFS := func() (*flag.FlagSet, *string) {
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		portals := fs.String("portals", "0.0.0.0", "")
		return fs, portals
	}

	t.Run("space-instead-of-comma", func(t *testing.T) {
		fs, portals := newFS()
		if err := fs.Parse([]string{"-portals", "10.10.0.1:3260", "10.10.0.11:3260"}); err != nil {
			t.Fatal(err)
		}
		// Demonstrate the silent loss the check exists to catch.
		if *portals != "10.10.0.1:3260" {
			t.Fatalf("setup: expected the second portal to be split off, got %q", *portals)
		}
		err := extraArgsError(fs)
		if err == nil {
			t.Fatal("a portal dropped by a stray space must be refused, not ignored: " +
				"the appliance would serve half the fabric with no signal")
		}
		if !strings.Contains(err.Error(), "10.10.0.11:3260") {
			t.Errorf("the error must name the argument that was dropped, got %v", err)
		}
	})

	t.Run("valid-comma-form-accepted", func(t *testing.T) {
		fs, portals := newFS()
		if err := fs.Parse([]string{"-portals", "10.10.0.1:3260,10.10.0.11:3260"}); err != nil {
			t.Fatal(err)
		}
		if err := extraArgsError(fs); err != nil {
			t.Errorf("the correct comma-separated form must be accepted, got %v", err)
		}
		if *portals != "10.10.0.1:3260,10.10.0.11:3260" {
			t.Errorf("both portals must survive, got %q", *portals)
		}
	})

	t.Run("no-args-at-all", func(t *testing.T) {
		fs, _ := newFS()
		if err := fs.Parse(nil); err != nil {
			t.Fatal(err)
		}
		if err := extraArgsError(fs); err != nil {
			t.Errorf("no arguments is not an error, got %v", err)
		}
	})
}
