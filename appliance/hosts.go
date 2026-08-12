package appliance

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// Host and connection operations.
//
// A host is an initiator as the appliance models it: a UUID for identity, a
// name for callers, and a set of fabric bindings that let a particular
// initiator prove it is this host. LIO has no such object -- it has ACLs keyed
// by initiator IQN -- so every host here becomes one ACL per binding, and a
// host with no bindings becomes nothing at all.

// CreateHost registers a host, or returns the existing one when the name is
// taken by a host with the same bindings.
//
// created reports whether this call is what registered it; false means the
// name was already taken by a matching host. See [Coordinator.Create] for why
// the distinction is reported rather than hidden.
func (c *Coordinator) CreateHost(ctx context.Context, name string, iqns []string) (h Host, created bool, err error) {
	ev := c.beginOp(ctx, eventHostCreate, "resource_name", name, "iqn_count", len(iqns))
	defer func() { ev.set("created", created).finish(err) }()

	if err := checkName(name); err != nil {
		return Host{}, false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if existing := c.hostByName(name); existing != nil {
		// Compared as a SET: a caller replaying a create must not be punished
		// for a different ordering.
		want := append([]string(nil), iqns...)
		got := append([]string(nil), existing.Bindings.IQNs...)
		slices.Sort(want)
		slices.Sort(got)
		if !slices.Equal(want, got) {
			return Host{}, false, statusErrCode(http.StatusConflict, CodeConfigurationMismatch,
				"host %q already exists with bindings %v, not %v", name, existing.Bindings.IQNs, iqns)
		}
		ev.set("resource_id", existing.UUID)
		return copyHost(*existing), false, nil
	}
	if err := c.checkIQNs(iqns, ""); err != nil {
		return Host{}, false, err
	}
	uuid, err := newHostUUID()
	if err != nil {
		return Host{}, false, err
	}
	ev.set("resource_id", uuid)
	var newHost Host
	if err := c.commit(ctx, ev, func() error {
		h := &Host{UUID: uuid, Name: name,
			Bindings: Bindings{IQNs: append([]string(nil), iqns...)}}
		c.st.Hosts = append(c.st.Hosts, h)
		newHost = *h
		return nil
	}); err != nil {
		return Host{}, false, err
	}
	return copyHost(newHost), true, nil
}

// checkIQNs validates a proposed binding set, ignoring ownership by exceptHost
// so a host keeping a binding it already holds is not a conflict with itself.
// Caller must hold c.mu.
func (c *Coordinator) checkIQNs(iqns []string, exceptHost string) error {
	seen := map[string]bool{}
	for _, q := range iqns {
		if !validIQN(q) {
			return statusErrCode(http.StatusBadRequest, CodeInvalidInput,
				"invalid initiator IQN %q (must start with iqn.)", q)
		}
		if seen[q] {
			return statusErrCode(http.StatusBadRequest, CodeInvalidInput,
				"duplicate initiator IQN %q in request", q)
		}
		seen[q] = true
		if owner := c.iqnOwner(q, exceptHost); owner != "" {
			return statusErrCode(http.StatusConflict, CodeAlreadyExists,
				"iqn %s is already bound to host %s", q, owner)
		}
	}
	return nil
}

// ListHosts returns every host.
func (c *Coordinator) ListHosts() []Host {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []Host{}
	for _, h := range c.st.Hosts {
		out = append(out, copyHost(*h))
	}
	return out
}

// GetHost returns one host by name, or by uuid.
func (c *Coordinator) GetHost(ref string) (Host, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	h := c.resolveHost(ref)
	if h == nil {
		return Host{}, false
	}
	return copyHost(*h), true
}

// RenameHost changes a host's name, keeping its uuid, bindings and connections.
func (c *Coordinator) RenameHost(ctx context.Context, ref, newName string) (h Host, err error) {
	ev := c.beginOp(ctx, eventHostRename, "new_name", newName, "ref", ref)
	defer func() { ev.finish(err) }()

	if err := checkName(newName); err != nil {
		return Host{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	target := c.resolveHost(ref)
	if target == nil {
		return Host{}, notFound("host", ref)
	}
	ev.set("resource_id", target.UUID, "old_name", target.Name)
	if target.Name == newName {
		return copyHost(*target), nil
	}
	if c.hostByName(newName) != nil {
		return Host{}, nameTaken("host", newName)
	}
	old := target.Name
	if err := c.persistOnly(ctx, ev, func() error {
		if t := c.hostByName(old); t != nil {
			t.Name = newName
		}
		return nil
	}); err != nil {
		return Host{}, err
	}
	return copyHost(*c.hostByName(newName)), nil
}

// SetBindings replaces, adds to, or removes from a host's binding set.
//
// One entry point for all three because they share every hazard. Whatever the
// shape of the request, what matters is which bindings are LOST: an initiator
// that loses its ACL loses its access, and the kernel releases any reservation
// whose holder loses its mapped LUN. Returns a warning when that happens.
func (c *Coordinator) SetBindings(ctx context.Context, ref string, replace, add, remove []string) (h Host, warning string, err error) {
	ev := c.beginOp(ctx, eventHostBindings, "ref", ref)
	defer func() { ev.finish(err) }()

	c.mu.Lock()
	defer c.mu.Unlock()

	host := c.resolveHost(ref)
	if host == nil {
		return Host{}, "", notFound("host", ref)
	}

	ev.set("resource_name", host.Name, "resource_id", host.UUID)

	next := append([]string(nil), host.Bindings.IQNs...)
	if replace != nil {
		next = append([]string(nil), replace...)
	}
	for _, q := range add {
		if !slices.Contains(next, q) {
			next = append(next, q)
		}
	}
	if len(remove) > 0 {
		kept := next[:0]
		for _, q := range next {
			if !slices.Contains(remove, q) {
				kept = append(kept, q)
			}
		}
		next = kept
	}
	if err := c.checkIQNs(next, host.UUID); err != nil {
		return Host{}, "", err
	}

	var dropped []string
	for _, q := range host.Bindings.IQNs {
		if !slices.Contains(next, q) {
			dropped = append(dropped, q)
		}
	}

	// Ask BEFORE mutating: the reservation state being reported is the one
	// that exists while these bindings still have their ACLs.
	var warnings []string
	if len(dropped) > 0 {
		for _, cn := range c.st.Connections {
			if cn.HostUUID != host.UUID {
				continue
			}
			if w := c.fenceLossWarningFor(cn.ObjectUUID, dropped, "",
				fmt.Sprintf("removing %s from host %q (object %s)",
					strings.Join(dropped, ", "), host.Name, cn.ObjectUUID)); w != "" {
				warnings = append(warnings, w)
			}
		}
	}
	// Logged before the commit, and returned on BOTH paths, for the reason
	// Disconnect does the same: a reconcile failure inside commit arrives
	// after the mutation is durable, so the ACLs are gone and the fence with
	// them. An early return carrying only the error would drop the one signal
	// this produces, on the path an operator is least likely to read closely
	// because something else already failed.
	warning = strings.Join(warnings, " | ")
	if warning != "" {
		// Attributed to this operation rather than emitted as a free-floating
		// line. It is still logged BEFORE the commit, for the reason given
		// above -- but as its own event carrying the request id, so a reader
		// can join it to the operation that caused it even though the
		// operation's own event has not been emitted yet.
		c.logFenceReleased(ctx, warning, "host", host.Name, host.UUID)
		ev.set("warning", warning)
	}

	uuid := host.UUID
	var updated Host
	if err := c.commit(ctx, ev, func() error {
		t := c.host(uuid)
		t.Bindings.IQNs = next
		updated = *t
		return nil
	}); err != nil {
		return Host{}, warning, err
	}
	return copyHost(updated), warning, nil
}

// DeleteHost removes a host. Refused while it has connections.
func (c *Coordinator) DeleteHost(ctx context.Context, ref string) (err error) {
	ev := c.beginOp(ctx, eventHostDelete, "ref", ref)
	defer func() { ev.finish(err) }()

	c.mu.Lock()
	defer c.mu.Unlock()

	h := c.resolveHost(ref)
	if h == nil {
		return notFound("host", ref)
	}
	ev.set("resource_name", h.Name, "resource_id", h.UUID)
	if len(c.connectionsOfHost(h.UUID)) > 0 {
		return statusErrCode(http.StatusConflict, CodeResourceConnected,
			"host %q has connections; disconnect first", h.Name)
	}
	uuid := h.UUID
	return c.commit(ctx, ev, func() error {
		kept := c.st.Hosts[:0]
		for _, x := range c.st.Hosts {
			if x.UUID != uuid {
				kept = append(kept, x)
			}
		}
		c.st.Hosts = kept
		return nil
	})
}

// connectionsOfHost returns every connection for a host. Caller must hold c.mu.
func (c *Coordinator) connectionsOfHost(hostUUID string) []*Connection {
	var out []*Connection
	for _, cn := range c.st.Connections {
		if cn.HostUUID == hostUUID {
			out = append(out, cn)
		}
	}
	return out
}

// Connect exports an object to a host at a LUN.
//
// The LUN is required. The appliance does not assign one, unlike an array that
// hands out the first free number: in a cluster the same object usually has to
// appear at the same LUN on every node, and a number chosen per-connection
// cannot promise that. Making the caller say which LUN it wants is the honest
// version of a decision it has to make anyway.
//
// Safe to retry: connecting something already connected at that LUN returns
// the same details rather than a conflict. created reports which of those
// happened -- see [Coordinator.Create].
func (c *Coordinator) Connect(ctx context.Context, kind Kind, objectRef, hostRef string, lun int, lunGiven bool) (info ConnInfo, created bool, err error) {
	ev := c.beginOp(ctx, eventConnectionCreate,
		"object_name", objectRef, "object_kind", string(kind), "host_name", hostRef)
	if lunGiven {
		ev.set("lun", lun)
	}
	defer func() { ev.set("created", created).finish(err) }()

	c.mu.Lock()
	defer c.mu.Unlock()

	o := c.resolveObject(kind, objectRef)
	if o == nil {
		return ConnInfo{}, false, notFound(string(kind), objectRef)
	}
	if o.State != stateReady {
		return ConnInfo{}, false, statusErrCode(http.StatusConflict, CodeUnsupportedState,
			"%s %q is %s", o.Kind, o.Name, o.State)
	}
	ev.set("object_id", o.UUID, "wwn", o.WWN)
	h := c.resolveHost(hostRef)
	if h == nil {
		return ConnInfo{}, false, notFound("host", hostRef)
	}
	ev.set("host_id", h.UUID)
	if !lunGiven {
		return ConnInfo{}, false, statusErrCode(http.StatusBadRequest, CodeLUNRequired,
			"a lun is required: the appliance does not assign one, because in a "+
				"cluster the same object usually has to appear at the same lun on every node")
	}
	if lun < 0 || lun > maxLUN {
		return ConnInfo{}, false, statusErrCode(http.StatusBadRequest, CodeInvalidInput,
			"invalid lun %d (must be 0..%d)", lun, maxLUN)
	}

	for _, cn := range c.st.Connections {
		if cn.ObjectUUID == o.UUID && cn.HostUUID == h.UUID {
			if cn.LUN == lun {
				return c.connInfo(o, cn.LUN), false, nil
			}
			// Already connected at a different LUN is not a retry. Remapping
			// in place would change the device a live initiator is using, so
			// it is refused, and the message names the LUN it actually has so
			// the caller can reconcile without another round trip.
			return ConnInfo{}, false, statusErrCode(http.StatusConflict, CodeConfigurationMismatch,
				"%s %q is already connected to host %q at lun %d, not %d",
				o.Kind, o.Name, h.Name, cn.LUN, lun)
		}
		if cn.HostUUID == h.UUID && cn.LUN == lun {
			return ConnInfo{}, false, statusErrCode(http.StatusConflict, CodeLUNConflict,
				"lun %d is already in use on host %q", lun, h.Name)
		}
	}

	objUUID, hostUUID := o.UUID, h.UUID
	if err := c.commit(ctx, ev, func() error {
		c.exportIndex(objUUID)
		c.st.Connections = append(c.st.Connections,
			&Connection{ObjectUUID: objUUID, HostUUID: hostUUID, LUN: lun})
		return nil
	}); err != nil {
		return ConnInfo{}, false, err
	}
	return c.connInfo(o, lun), true, nil
}

// Disconnect withdraws an object from a host.
//
// Returns a warning when this releases a SCSI-3 reservation the host held. It
// is not refused: an operator must be able to detach a host that may itself be
// dead, which is the whole reason the warning exists rather than a refusal.
func (c *Coordinator) Disconnect(ctx context.Context, kind Kind, objectRef, hostRef string) (warning string, err error) {
	ev := c.beginOp(ctx, eventConnectionDelete,
		"object_name", objectRef, "object_kind", string(kind), "host_name", hostRef)
	defer func() { ev.finish(err) }()

	c.mu.Lock()
	defer c.mu.Unlock()

	o := c.resolveObject(kind, objectRef)
	if o == nil {
		return "", notFound(string(kind), objectRef)
	}
	h := c.resolveHost(hostRef)
	if h == nil {
		return "", notFound("host", hostRef)
	}
	found := false
	for _, cn := range c.st.Connections {
		if cn.ObjectUUID == o.UUID && cn.HostUUID == h.UUID {
			found = true
			break
		}
	}
	if !found {
		// Already disconnected is a success: a caller retrying a disconnect it
		// is not sure landed must not have to tell "it worked" apart from "it
		// had already worked".
		return "", nil
	}
	if err := c.healIfDegraded(ctx); err != nil {
		return "", err
	}

	warning = c.fenceLossWarning(o.UUID, h.UUID)
	if warning != "" {
		c.logFenceReleased(ctx, warning, string(o.Kind), o.Name, o.UUID)
		ev.set("warning", warning)
	}
	objUUID, hostUUID := o.UUID, h.UUID
	if err := c.commit(ctx, ev, func() error {
		kept := c.st.Connections[:0]
		for _, cn := range c.st.Connections {
			if cn.ObjectUUID == objUUID && cn.HostUUID == hostUUID {
				continue
			}
			kept = append(kept, cn)
		}
		c.st.Connections = kept
		c.pruneExports()
		return nil
	}); err != nil {
		return warning, err
	}
	return warning, nil
}

// ConnectionView is one connection as a caller sees it: names, not just UUIDs.
type ConnectionView struct {
	Object     string `json:"object"`
	ObjectKind Kind   `json:"object_kind"`
	ObjectUUID string `json:"object_uuid"`
	Host       string `json:"host"`
	HostUUID   string `json:"host_uuid"`
	LUN        int    `json:"lun"`
	TargetIQN  string `json:"target_iqn"`
	Wwid       string `json:"wwid"`
}

// ListConnections returns current connections, optionally filtered by object
// or host (empty means no filter on that field).
//
// objectKind narrows which namespace objectRef is looked up in. Empty means
// either, which is a convenience and not a guess: volumes and snapshots have
// separate namespaces, so one name can identify two different objects, and
// this REFUSES an ambiguous reference rather than picking one. It used to try
// volumes first and answer with that object's connections, which reported the
// snapshot as having none -- a wrong answer that looked like a right one, and
// the caller had no way to tell.
//
// Derived from the persisted desired state rather than from configfs: the db
// is what the appliance intends, and a caller reconciling against the kernel
// instead would read a transient mid-reconcile disagreement as a real one.
func (c *Coordinator) ListConnections(objectRef string, objectKind Kind, hostRef string) ([]ConnectionView, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var wantObj, wantHost string
	if objectRef != "" {
		switch objectKind {
		case KindVolume, KindSnapshot:
			o := c.resolveObject(objectKind, objectRef)
			if o == nil {
				return []ConnectionView{}, nil
			}
			wantObj = o.UUID
		case "":
			vol := c.resolveObject(KindVolume, objectRef)
			snap := c.resolveObject(KindSnapshot, objectRef)
			switch {
			case vol != nil && snap != nil:
				// Only reachable by NAME: a uuid resolves in at most one
				// namespace, so it never lands here.
				return nil, statusErrCode(http.StatusBadRequest, CodeInvalidInput,
					"%q names both a volume and a snapshot; say which with object_kind", objectRef)
			case vol != nil:
				wantObj = vol.UUID
			case snap != nil:
				wantObj = snap.UUID
			default:
				return []ConnectionView{}, nil
			}
		default:
			return nil, statusErrCode(http.StatusBadRequest, CodeInvalidInput,
				"unknown object_kind %q (use %q or %q)", objectKind, KindVolume, KindSnapshot)
		}
	}
	if hostRef != "" {
		h := c.resolveHost(hostRef)
		if h == nil {
			return []ConnectionView{}, nil
		}
		wantHost = h.UUID
	}

	out := []ConnectionView{}
	for _, cn := range c.st.Connections {
		if wantObj != "" && cn.ObjectUUID != wantObj {
			continue
		}
		if wantHost != "" && cn.HostUUID != wantHost {
			continue
		}
		v := ConnectionView{
			ObjectUUID: cn.ObjectUUID,
			HostUUID:   cn.HostUUID,
			LUN:        cn.LUN,
			TargetIQN:  c.cfg.TargetIQN,
		}
		// A connection whose object or host is missing is still reported: it
		// is real, it is in the db, and hiding it would make an inconsistency
		// invisible to the one call that could show it.
		if o := c.object(cn.ObjectUUID); o != nil {
			v.Object, v.ObjectKind, v.Wwid = o.Name, o.Kind, Wwid(o.WWN)
		}
		if h := c.host(cn.HostUUID); h != nil {
			v.Host = h.Name
		}
		out = append(out, v)
	}
	return out, nil
}
