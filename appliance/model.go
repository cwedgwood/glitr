package appliance

import (
	"time"

	"github.com/cwedgwood/glitr/lio"
)

// The appliance's object model.
//
// The appliance exists to absorb the gap between what external code expects
// of a storage array and what SCSI and LIO actually provide. External code
// creates and addresses things BY NAME; LIO has no names at all, only WWNs,
// initiator IQNs, ACLs and LUN indexes. Everything in this file is the
// array-shaped side of that translation.
//
// Identity is a UUID, minted here and never reused. A name is what callers
// use, is unique within its kind, and can be changed -- nothing keys off it.

// Kind separates the namespaces a stored object lives in.
//
// A volume and a snapshot may hold the SAME name: they are different kinds
// of thing, and a caller asking for "the snapshot called db-1" is not asking
// for "the volume called db-1". CSI requires exactly this separation, since
// it treats snapshot ids and volume ids as distinct namespaces and will
// happily hand back both.
type Kind string

const (
	KindVolume   Kind = "volume"
	KindSnapshot Kind = "snapshot"
)

// Object is a block device the appliance can present: a volume or a snapshot.
//
// One type rather than two, because almost nothing discriminates. Both can be
// exported to a host, resized, snapshotted and deleted -- the live suites
// snapshot a snapshot and export one directly -- so separate Go types would
// duplicate every operation to buy type safety at the two points where kind
// actually matters: which namespace the name lives in, and which collection
// the REST layer lists it under.
type Object struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
	Kind Kind   `json:"kind"`
	// WWN is derived from the UUID and is what an initiator identifies the
	// device by. It outlives the name deliberately: renaming must not change
	// what a mounted filesystem is sitting on.
	WWN       string    `json:"wwn"`
	Capacity  int64     `json:"capacity"`
	BlockSize int       `json:"block_size"`
	Created   time.Time `json:"created"`
	State     string    `json:"state"`
	// Source is the UUID this was made from, if anything: the volume a
	// snapshot was taken of, or the object a clone was copied from.
	//
	// It records provenance, not kind. A snapshot has a source and so does a
	// clone -- the difference between them is Kind, which is precisely the
	// distinction the old model could not express, because it had only this
	// field and called it Parent.
	Source string `json:"source,omitempty"`
}

// Bindings are the fabric-level identities that let an initiator log in as a
// host.
//
// A struct rather than a bare []string because an IQN is an iSCSI concept and
// a host is not: Pure's host object carries iqns, nqns AND wwns together, and
// modelling the iSCSI case as though it were the only one is how a second
// fabric turns into a second host type. Only IQNs are implemented.
type Bindings struct {
	IQNs []string `json:"iqns,omitempty"`
}

// Host is an initiator, as the appliance models it.
//
// Its identity is the UUID and its handle is the Name. The bindings are how a
// particular initiator proves it is this host; there may be none, which is a
// host registered before its initiator's identity is known. desiredLIO emits
// one ACL per binding, so a host with none exports nothing.
//
// Host groups are the natural next object -- arrays map a volume to a group
// rather than to each member -- and are deliberately absent. Connection is
// shaped so they can be added without moving anything.
type Host struct {
	UUID     string   `json:"uuid"`
	Name     string   `json:"name"`
	Bindings Bindings `json:"bindings"`
}

// Connection exports one object to one host at one LUN.
//
// The LUN is always the caller's. The appliance does NOT assign one, unlike
// an array that hands out the first free number: in a cluster the same volume
// usually has to appear at the same LUN on every node, and a number chosen
// per-connection cannot promise that. An absent or conflicting LUN is an
// error, which is a decision the caller has to make rather than a detail the
// appliance can hide.
type Connection struct {
	ObjectUUID string `json:"object_uuid"`
	HostUUID   string `json:"host_uuid"`
	LUN        int    `json:"lun"`
}

// db is the appliance's entire durable state: one document, one writer,
// replaced atomically.
//
// It holds the object records too. Those used to live in storage's own file,
// which meant a name and the thing it named were committed separately and a
// crash between the two writes left an object nothing could find. One
// document removes that failure rather than mitigating it -- and it is what
// lets storage be what it should be, which is bytes behind a UUID.
type db struct {
	// Version is the on-disk schema version, so a future change can migrate
	// rather than guess.
	//
	// A version this build does not recognise is REFUSED rather than adopted
	// -- in both directions. Older means the pre-name layout, whose conversion
	// has been removed; newer means a build that knows fields this one would
	// drop on the next write. See [Coordinator.checkVersion].
	Version     int            `json:"version"`
	Objects     []*Object      `json:"objects"`
	Hosts       []*Host        `json:"hosts"`
	Connections []*Connection  `json:"connections"`
	Exports     map[string]int `json:"exports"` // object uuid -> TPG LUN index
	// Portals is the DURABLE record of what the target listens on. Empty
	// means "not recorded", and is read as "adopt the flag" rather than as
	// "no portals".
	Portals []lio.Portal `json:"portals"`
	// TargetIQN is the DURABLE record of what this appliance is called on the
	// fabric. Empty means "not recorded", exactly as for Portals, so an
	// appliance made before this field existed adopts on its next start
	// instead of needing a schema migration.
	//
	// Recorded rather than taken from a flag on every start because the IQN
	// is identity: two appliances built from one unit file would otherwise
	// both answer to the same name, and renaming a live target destroys it.
	TargetIQN string `json:"target_iqn,omitempty"`
	// MachineID is the machine this database was initialised on, and exists
	// only so that "this disk is somewhere else now" is answerable. Empty
	// means the host had none to record, in which case a clone cannot be
	// detected -- which is said out loud at startup rather than assumed away.
	MachineID string `json:"machine_id,omitempty"`
}

// dbVersion is the current on-disk schema version.
const dbVersion = 1

// object returns the record with this UUID, or nil. Caller must hold c.mu.
func (c *Coordinator) object(uuid string) *Object {
	for _, o := range c.st.Objects {
		if o.UUID == uuid {
			return o
		}
	}
	return nil
}

// objectByName returns the record with this name in this kind, or nil.
// Caller must hold c.mu.
func (c *Coordinator) objectByName(kind Kind, name string) *Object {
	for _, o := range c.st.Objects {
		if o.Kind == kind && o.Name == name {
			return o
		}
	}
	return nil
}

// resolveObject finds an object by name within a kind, falling back to a UUID
// match in that kind.
//
// Both, because a caller that stored a UUID must not be broken by the API
// becoming name-first, and a name is what everything else uses. The kind is
// always known from the route, so a volume named "x" and a snapshot named "x"
// never collide here. Caller must hold c.mu.
func (c *Coordinator) resolveObject(kind Kind, ref string) *Object {
	if o := c.objectByName(kind, ref); o != nil {
		return o
	}
	if o := c.object(ref); o != nil && o.Kind == kind {
		return o
	}
	return nil
}

// hostByName returns the host with this name, or nil. Caller must hold c.mu.
func (c *Coordinator) hostByName(name string) *Host {
	for _, h := range c.st.Hosts {
		if h.Name == name {
			return h
		}
	}
	return nil
}

// resolveHost finds a host by name, falling back to a UUID match. Caller must
// hold c.mu.
func (c *Coordinator) resolveHost(ref string) *Host {
	if h := c.hostByName(ref); h != nil {
		return h
	}
	return c.host(ref)
}

// connectionsOf returns every connection for an object. Caller must hold c.mu.
func (c *Coordinator) connectionsOf(objectUUID string) []*Connection {
	var out []*Connection
	for _, cn := range c.st.Connections {
		if cn.ObjectUUID == objectUUID {
			out = append(out, cn)
		}
	}
	return out
}

func copyHost(h Host) Host {
	cp := h
	cp.Bindings.IQNs = append([]string(nil), h.Bindings.IQNs...)
	return cp
}
