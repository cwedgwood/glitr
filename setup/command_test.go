package setup

import "testing"

// TestCommandForcesCLocale: the appliance must not inherit the operator's
// language for anything it execs. unitActive compares systemctl's output to
// the literal "active", and setup's failures quote a tool's own diagnostic --
// both would vary by host otherwise.
//
// LANGUAGE is the subtle half: it is a gettext extension that OVERRIDES
// LC_ALL for message translation, so clearing LC_ALL alone leaves a host with
// LANGUAGE exported still translating.
func TestCommandForcesCLocale(t *testing.T) {
	t.Setenv("LC_ALL", "fr_FR.UTF-8")
	t.Setenv("LANG", "fr_FR.UTF-8")
	t.Setenv("LANGUAGE", "fr")

	out, err := command("sh", "-c", "printf '%s|%s' \"$LC_ALL\" \"$LANGUAGE\"").Output()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out), "C|"; got != want {
		t.Errorf("command ran with LC_ALL|LANGUAGE = %q, want %q", got, want)
	}
}

// TestCommandKeepsTheRestOfTheEnvironment: pinning the locale must not discard
// PATH, or every tool lookup in setup breaks.
func TestCommandKeepsTheRestOfTheEnvironment(t *testing.T) {
	t.Setenv("GLITR_SETUP_PROBE", "kept")
	out, err := command("sh", "-c", "printf '%s' \"$GLITR_SETUP_PROBE\"").Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "kept" {
		t.Errorf("command must inherit the ambient environment, got %q", out)
	}
}
