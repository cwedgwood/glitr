package appliance

import (
	"fmt"
	"net/http"
	"strings"
	"unicode"
)

// Names.
//
// A name is what callers use. It is unique within its kind, chosen by the
// caller, and can be changed -- nothing keys off it, because identity is the
// UUID and device identity is the WWN. That is the whole reason a rename is
// safe: an initiator with the device mounted is looking at a WWN, and renaming
// does not touch it.
//
// The rules below are deliberately narrow. A name ends up in a URL path, in
// log lines, in an operator's shell, and in whatever the caller's own system
// uses to correlate -- so the interesting question is not "what can we store"
// but "what can we store that nothing downstream will misread".

// maxNameLen bounds a name. Long enough for a Kubernetes PVC name with a
// prefix (Trident and friends generate pvc-<uuid>, 40 characters), short
// enough that a listing stays readable.
const maxNameLen = 128

// validName rejects a name the appliance will not store.
//
// Rejected rather than sanitised: a caller that sends a name it cannot get
// back byte for byte will look up something that is not there, and will
// conclude the object was lost. Silence is the failure mode to avoid here.
func validName(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if len(name) > maxNameLen {
		return fmt.Errorf("name is %d bytes, over the %d-byte limit", len(name), maxNameLen)
	}
	// No leading or trailing space: it does not survive a round trip through
	// a shell or a URL, and two names differing only by it are indistinguishable
	// to the operator who has to tell them apart.
	if strings.TrimSpace(name) != name {
		return fmt.Errorf("name %q has leading or trailing whitespace", name)
	}
	// "." and ".." are refused because a name appears in a URL path, and a
	// caller that builds one by concatenation should not be able to walk out
	// of the collection it meant to address.
	if name == "." || name == ".." {
		return fmt.Errorf("name %q is reserved", name)
	}
	for _, r := range name {
		switch {
		case r == '/':
			return fmt.Errorf("name %q contains a path separator", name)
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("name %q contains a control character (%#U)", name, r)
		case unicode.IsSpace(r) && r != ' ':
			return fmt.Errorf("name %q contains whitespace other than a space (%#U)", name, r)
		}
	}
	return nil
}

// checkName validates a name and reports it as a client error.
func checkName(name string) error {
	if err := validName(name); err != nil {
		return statusErrCode(http.StatusBadRequest, CodeInvalidInput, "%s", err.Error())
	}
	return nil
}

// nameTaken reports that a name is already in use within its kind.
func nameTaken(what, name string) error {
	return statusErrCode(http.StatusConflict, CodeNameTaken,
		"a %s named %q already exists", what, name)
}

// notFound reports that nothing answers to this name or uuid.
func notFound(what, ref string) error {
	return statusErrCode(http.StatusNotFound, CodeNotFound, "%s %q not found", what, ref)
}
