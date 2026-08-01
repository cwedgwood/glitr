package appliance

import (
	"errors"
	"fmt"
	"testing"
)

// When the record write fails, Create either removes the bytes it just
// allocated or keeps them. Getting that backwards is unrecoverable in one
// direction, so the decision is its own function and is tested directly: the
// trigger (a rename that succeeded followed by a directory fsync that did not)
// cannot be forced portably.
func TestDropBytesKeepsAnObjectWhoseRecordIsAlreadyOnDisk(t *testing.T) {
	// The record is on disk; the bytes must stay, or the db names an object
	// that does not exist.
	notDurable := fmt.Errorf("writing %s: %w", "appliance.json", errPersistedNotDurable)
	if dropBytes(notDurable) {
		t.Error("bytes must be KEPT when the record is already on disk: deleting them " +
			"leaves a record naming an object that no longer exists")
	}
	// Everything else rolled the record back, so the bytes are orphaned and
	// nothing else knows the identifier yet.
	for name, err := range map[string]error{
		"disk full":   errors.New("no space left on device"),
		"read-only":   errors.New("read-only file system"),
		"marshalling": errors.New("json: unsupported value"),
	} {
		t.Run(name, func(t *testing.T) {
			if !dropBytes(err) {
				t.Errorf("bytes must be removed when the record was rolled back (%v)", err)
			}
		})
	}
}
