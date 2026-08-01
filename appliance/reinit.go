package appliance

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/cwedgwood/glitr/lio"
	"github.com/cwedgwood/glitr/storage"
)

// Re-initialising a copied appliance.
//
// [Coordinator.adoptIdentity] refuses to start a database that was created on
// another machine, because the appliance it was copied from is probably still
// running under that name. This is how an operator resolves it, and it is a
// subcommand rather than a REST endpoint on purpose: identity is not something
// the network gets to change, and the daemon this would be talking to is the
// one refusing to start.

// ReinitOptions describes a re-initialisation.
type ReinitOptions struct {
	// Root is the data root, the directory holding appliance.json.
	Root string
	// TargetIQN is the new name. Empty derives one from this machine, which
	// is the normal case -- a name given by hand is one more thing that has
	// to be unique by hand.
	TargetIQN string
	// Wipe sets every volume and snapshot aside instead of keeping them, for
	// a clone meant to be a fresh appliance rather than a second copy of the
	// original's contents.
	Wipe bool
	// MachineIDPath overrides where the machine ID is read from. For tests.
	MachineIDPath string
	// Out receives a description of what was done. Not optional in practice:
	// this rewrites identity, and an operator needs to see what it decided.
	Out io.Writer
}

// Reinit gives a copied appliance an identity of its own.
//
// Two things have to change for a clone to be safe on the same fabric as its
// original, and only one of them is the target IQN. The other is every
// volume's WWN: an initiator identifies a device by its WWN, so two appliances
// serving devices with the same one are not two devices to it -- multipath
// gathers them into a single path set and writes go to both. That is silent
// corruption, and it is the reason -adopt re-mints every WWN rather than only
// renaming the target.
//
// UUIDs are deliberately NOT re-minted. They name directories and backstores,
// never appear on the wire, and are meaningful only within one appliance, so
// changing them would rewrite the layout to fix a collision that cannot
// happen.
//
// The daemon must not be running: this rewrites the database underneath it.
// The caller holds the host lock -- see cmd/applianced.
func Reinit(opts ReinitOptions) error {
	if opts.Root == "" {
		return errors.New("appliance: reinit needs a data root (-root)")
	}
	if opts.TargetIQN != "" && !lio.ValidTargetIQN(opts.TargetIQN) {
		return fmt.Errorf("appliance: target IQN %q is not usable (-iqn)", opts.TargetIQN)
	}
	out := opts.Out
	if out == nil {
		out = io.Discard
	}

	machineIDPath := opts.MachineIDPath
	if machineIDPath == "" {
		machineIDPath = DefaultMachineIDPath
	}
	machineID, err := readMachineID(machineIDPath)
	if err != nil {
		return fmt.Errorf("appliance: %w", err)
	}

	iqn := opts.TargetIQN
	if iqn == "" {
		if machineID == "" {
			return fmt.Errorf("appliance: no target IQN was given and none can be derived: "+
				"%s is absent or empty. Pass -iqn", machineIDPath)
		}
		iqn = DeriveTargetIQN(machineID)
	}

	store, err := storage.Open(opts.Root)
	if err != nil {
		return err
	}
	c := &Coordinator{
		store:  store,
		st:     db{Version: dbVersion, Exports: map[string]int{}},
		dbPath: filepath.Join(opts.Root, "appliance.json"),
	}
	if _, err := c.load(); err != nil {
		return err
	}
	if c.st.Exports == nil {
		c.st.Exports = map[string]int{}
	}

	was := c.st.MachineID
	if was == "" {
		was = "(none recorded)"
	}
	fmt.Fprintf(out, "re-initialising %s\n", c.dbPath)
	fmt.Fprintf(out, "  machine   %s -> %s\n", was, orNone(machineID))
	fmt.Fprintf(out, "  target    %s -> %s\n", orNone(c.st.TargetIQN), iqn)

	if opts.Wipe {
		if err := wipeObjects(c, out); err != nil {
			return err
		}
	} else if err := remintWWNs(c, out); err != nil {
		return err
	}

	// Portals belong to the machine, not to the database: a clone is on
	// different hardware with different addresses. Cleared so the next start
	// adopts what it is told, which is the same rule as an appliance that
	// never recorded any.
	if len(c.st.Portals) > 0 {
		fmt.Fprintf(out, "  portals   cleared (%d); the next start adopts -portals\n",
			len(c.st.Portals))
		c.st.Portals = nil
	}

	c.st.TargetIQN, c.st.MachineID = iqn, machineID
	if err := c.persist(); err != nil && !errors.Is(err, errPersistedNotDurable) {
		return fmt.Errorf("appliance: writing the re-initialised database: %w", err)
	}
	fmt.Fprintf(out, "done. Start the appliance normally.\n")
	return nil
}

// remintWWNs gives every object a device identity of its own.
func remintWWNs(c *Coordinator, out io.Writer) error {
	if len(c.st.Objects) == 0 {
		fmt.Fprintf(out, "  volumes   none to re-mint\n")
		return nil
	}
	for _, o := range c.st.Objects {
		_, wwn, err := newIdentity()
		if err != nil {
			return err
		}
		o.WWN = wwn
	}
	fmt.Fprintf(out, "  volumes   %d kept, each with a NEW wwn -- an initiator sees them as\n"+
		"            different devices from the ones on the appliance this was copied from\n",
		len(c.st.Objects))
	return nil
}

// wipeObjects sets the contents aside rather than deleting them.
//
// Quarantine, not remove: the bytes are somebody's data even when the records
// are not wanted, and "start empty" should not be a synonym for "destroy the
// copy". Startup already knows how to report quarantined directories.
func wipeObjects(c *Coordinator, out io.Writer) error {
	n := 0
	for _, o := range c.st.Objects {
		if !c.store.Exists(o.UUID) {
			continue
		}
		if _, err := c.store.Quarantine(o.UUID); err != nil {
			return fmt.Errorf("appliance: setting %s aside: %w", o.Name, err)
		}
		n++
	}
	fmt.Fprintf(out, "  volumes   %d record(s) dropped, %d directory(ies) set aside\n",
		len(c.st.Objects), n)
	c.st.Objects = nil
	c.st.Connections = nil
	c.st.Exports = map[string]int{}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
