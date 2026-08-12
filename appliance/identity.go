package appliance

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
)

// Appliance identity: which target this is, and which machine it is.
//
// One appliance is one target with one IQN. Two targets means two appliances,
// which in practice means two machines, and the thing that goes wrong when you
// make the second by cloning the first is that both then claim the same name
// on the same fabric. An initiator offered two targets with one IQN, or two
// devices with one WWN, does not report a conflict -- it merges them, and
// writes land somewhere nobody chose.
//
// So identity is recorded, not recomputed: what this appliance is called, and
// which machine it was called that on. The second half is what makes a clone
// detectable at all.

// IQNPrefix is the naming authority half of a generated target IQN.
//
// RFC 3720 iqn. names are <date>.<reversed domain>:<unique within it>. The
// date and domain are ours; only the suffix has to be unique, and that is what
// the machine ID supplies.
const IQNPrefix = "iqn.2026-01.dev.glitr:"

// DefaultMachineIDPath is where systemd records this installation's ID.
//
// Chosen over a hostname because a hostname is neither unique (two fresh
// clones are both "localhost") nor stable, and over the DMI product UUID
// because that needs root to read and is absent in some hypervisors. It is
// also the one identifier a careful clone procedure already resets: systemd
// regenerates it when the file is empty at boot, so "this file changed" is a
// reliable statement that the disk is not on the machine it was.
const DefaultMachineIDPath = "/etc/machine-id"

// readMachineID returns the machine ID, or "" when the host does not have one.
//
// Absent is NOT an error. A non-systemd host, or a container without the file
// bind-mounted, still has to be able to run an appliance -- it just cannot
// have its clones detected, which is said out loud rather than papered over.
// A malformed one IS an error, because a file that exists and is not an ID
// means something is wrong that guessing would hide.
func readMachineID(path string) (string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		// systemd writes an empty file to mean "regenerate me at next boot",
		// which is exactly the state a cloned image is left in. Treated as
		// absent rather than as an identity, so nothing is ever recorded
		// against a value that is about to change.
		return "", nil
	}
	if !validMachineID(id) {
		return "", fmt.Errorf("%s does not contain a machine ID (%q)", path, id)
	}
	return id, nil
}

// validMachineID reports whether id is systemd's format: 32 lowercase hex
// digits. Checked because it becomes part of an IQN, where the character set
// is not arbitrary.
func validMachineID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// DeriveTargetIQN builds the target IQN for a machine.
//
// The machine ID goes in unaltered: it is 32 lowercase hex digits, which is
// already inside the character set an IQN allows, so there is no sanitising
// step here that could collide two different machines onto one name.
func DeriveTargetIQN(machineID string) string { return IQNPrefix + machineID }

// identityConflictError says the recorded machine is not this machine.
//
// A distinct type because the remedy is an operator decision, not a retry:
// whatever is on this disk was set up somewhere else, and only a human knows
// whether that means "this is a clone, give it a new name" or "this disk was
// moved to new hardware, keep everything".
type identityConflictError struct {
	Recorded string
	Actual   string
	DBPath   string
}

func (e *identityConflictError) Error() string {
	return fmt.Sprintf(
		"appliance: this database was created on machine %s but this machine is %s.\n"+
			"The disk has been cloned, or the OS reinstalled. Refusing to start: "+
			"serving with the recorded identity would put a second target with the same "+
			"IQN -- and volumes with the same WWNs -- on the fabric beside the original, "+
			"and an initiator merges those rather than reporting them.\n"+
			"Resolve it explicitly with one of:\n"+
			"  applianced reinit -root <root> -adopt   keep the volumes, take a new identity\n"+
			"                                          (every volume gets a new WWN, so this\n"+
			"                                          appliance cannot collide with the one\n"+
			"                                          it was cloned from)\n"+
			"  applianced reinit -root <root> -wipe    set the volumes aside and start empty\n"+
			"(database: %s)",
		e.Recorded, e.Actual, e.DBPath)
}

// adoptIdentity settles what this appliance is called, once, at startup.
//
// Three questions in a fixed order, because the answer to each depends on the
// one before:
//
//  1. Is this the machine the database was made on? If not, stop -- see
//     [identityConflictError]. Everything below assumes the answer is yes.
//  2. Is an IQN recorded? If not, this is a first start: take the one the
//     operator gave, or derive one, and record it.
//  3. Does the flag disagree with the record? Then the RECORD wins, and the
//     disagreement is reported. Applying the flag instead would rename the
//     target, and renaming a target destroys it: the reconciler removes the
//     one the kernel has and builds another, taking every session and every
//     APTPL reservation record with it (they are bound to the target IQN --
//     linux v6.6 drivers/target/target_core_pr.c:949-953).
//
// Caller must hold c.mu.
func (c *Coordinator) adoptIdentity() error {
	actual, err := readMachineID(c.machineIDPath())
	if err != nil {
		return fmt.Errorf("appliance: %w", err)
	}

	if c.st.MachineID != "" && actual != "" && c.st.MachineID != actual {
		return &identityConflictError{Recorded: c.st.MachineID, Actual: actual, DBPath: c.dbPath}
	}

	iqn := c.st.TargetIQN
	switch {
	case iqn != "":
		if c.cfg.TargetIQN != "" && c.cfg.TargetIQN != iqn {
			c.healthMu.Lock()
			c.iqnFlagIgnored = fmt.Sprintf(
				"the -iqn flag says %s but the recorded target IQN is %s; the record wins. "+
					"The IQN is set once, when the appliance is initialised: renaming a target "+
					"destroys it and every reservation bound to it, so it is not something a "+
					"restart is allowed to do",
				c.cfg.TargetIQN, iqn)
			msg := c.iqnFlagIgnored
			c.healthMu.Unlock()
			log.Printf("appliance: %s", msg)
		}
	case c.cfg.TargetIQN != "":
		iqn = c.cfg.TargetIQN
	case c.liveTargetIQN() != "":
		// An appliance that predates this field, restarting. It already has a
		// name -- initiators are logged in to it -- and deriving a fresh one
		// here would rename the target, which means destroying it and every
		// session on it during what the operator experienced as an upgrade.
		// So the kernel is the record of last resort: whatever this host is
		// already serving is what it is called.
		iqn = c.liveTargetIQN()
		log.Printf("appliance: adopting the target already live in the kernel (%s) as this "+
			"appliance's recorded identity", iqn)
	case actual != "":
		iqn = DeriveTargetIQN(actual)
	default:
		// Nothing to derive from and nothing given. Refusing beats inventing
		// a name that a second appliance would invent identically.
		return fmt.Errorf("appliance: no target IQN was given and none can be derived: "+
			"%s is absent or empty, so there is nothing unique to this machine to build "+
			"one from. Pass -iqn explicitly", c.machineIDPath())
	}

	if c.st.TargetIQN == iqn && c.st.MachineID == actual {
		c.cfg.TargetIQN = iqn
		return nil
	}
	c.st.TargetIQN, c.st.MachineID = iqn, actual
	// The effective identity, so every reader below sees what was decided here
	// rather than what the flag said.
	c.cfg.TargetIQN = iqn
	if err := c.persist(context.Background(), nil); err != nil {
		return fmt.Errorf("appliance: recording the target identity: %w", err)
	}
	if actual == "" {
		log.Printf("appliance: no machine ID at %s, so a cloned copy of this database "+
			"cannot be detected; target IQN is %s", c.machineIDPath(), iqn)
	}
	return nil
}

// liveTargetIQN is the IQN of the target this host is already serving, or "".
//
// Consulted ONLY when nothing is recorded and nothing was stated, to keep an
// upgrade from renaming a live target. Exactly one target qualifies: none means
// a fresh host, and more than one means something other than this appliance is
// managing LIO, in which case picking one of them would be a guess.
func (c *Coordinator) liveTargetIQN() string {
	if c.lio == nil {
		return ""
	}
	live, err := c.lio.Discover()
	if err != nil || len(live.Targets) != 1 {
		return ""
	}
	return live.Targets[0].IQN
}

// machineIDPath is where to look for the machine ID, overridable so tests can
// exercise a changed one without touching the host.
func (c *Coordinator) machineIDPath() string {
	if c.cfg.MachineIDPath != "" {
		return c.cfg.MachineIDPath
	}
	return DefaultMachineIDPath
}
