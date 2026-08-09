package lish

import "testing"

// TestVerbMutatesClassification pins which verbs need the writer lock.
//
// `lish save` used to take it, so backing up or inspecting the live
// configuration was impossible while applianced was running -- exactly when an
// operator wants to -- and the refusal said "refusing to mutate" about an
// operation that only reads configfs and writes a file somewhere else.
func TestVerbMutatesClassification(t *testing.T) {
	readOnly := []string{
		"save", "saveconfig", "discover", "tree", "ls", "info", "get", "validate",
		"cd", "pwd", "help", "?", "exit", "quit",
	}
	for _, v := range readOnly {
		if VerbMutates(v) {
			t.Errorf("%q is read-only and must not need the writer lock: requiring it "+
				"denies the operator this command whenever the appliance is running", v)
		}
	}
	mutating := []string{"restore", "restoreconfig", "clear", "clearconfig", "apply"}
	for _, v := range mutating {
		if !VerbMutates(v) {
			t.Errorf("%q changes kernel state and MUST take the writer lock, or it can "+
				"race a running appliance", v)
		}
	}
}

// TestUnknownVerbsAreAssumedToMutate documents the direction this is wrong in,
// which the earlier version of this test had BACKWARDS.
//
// The classifier used to live in cmd/lish with a read-only default, on the
// reasoning that an over-locked read is worse than an unlocked write. That
// held only because the CLI's guard is called with four literal verbs, so its
// default was unreachable. Shared with the interactive shell, the default IS
// reachable -- every contextual verb (create, delete, set, ...) falls through
// it -- and a read-only default would silently leave a new mutating verb
// racing a live appliance.
func TestUnknownVerbsAreAssumedToMutate(t *testing.T) {
	if !VerbMutates("some-verb-invented-later") {
		t.Error("an unrecognised verb reaches the shell's contextual dispatch, which " +
			"mutates; assuming read-only would leave it unlocked against a running " +
			"appliance")
	}
}

// TestContextualVerbsStillLock is the regression guard for the unification.
//
// Routing the shell through the shared classifier is only safe if the verbs
// that used to reach its locking `default` branch still classify as mutating.
// Getting this wrong would silently unlock every node-editing verb -- a much
// worse bug than the one the unification fixed.
func TestContextualVerbsStillLock(t *testing.T) {
	for _, v := range []string{"create", "delete", "set", "enable", "disable", "map", "unmap"} {
		if !VerbMutates(v) {
			t.Errorf("%q is a contextual mutating verb and must still take the lock", v)
		}
	}
}

// TestParsePortRefusesOutOfRange is the regression test for a truncation
// CodeQL found on its first run against the public repository.
//
// strconv.Atoi returns an int, and narrowing it with uint16(...) silently
// wraps: "70000" became 4464, so the shell created a portal on a port nobody
// asked for. lio.Portal.Port was made a uint16 so that value could not be
// represented -- and a mechanical conversion at the parse boundary put the bug
// back at the one place untrusted input arrives.
func TestParsePortRefusesOutOfRange(t *testing.T) {
	for _, bad := range []string{"70000", "65536", "-1", "4294967296", "", "http", "3260x"} {
		if got, err := parsePort(bad); err == nil {
			t.Errorf("parsePort(%q) = %d, want an error", bad, got)
		}
	}
	for in, want := range map[string]uint16{"0": 0, "1": 1, "3260": 3260, "65535": 65535} {
		got, err := parsePort(in)
		if err != nil {
			t.Errorf("parsePort(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("parsePort(%q) = %d, want %d", in, got, want)
		}
	}
}
