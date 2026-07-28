package lio

import (
	"net/netip"
	"time"
)

// Sync reconciles the kernel to EXACTLY match desired: it applies
// everything in desired (create/update, exactly like Apply) and then
// prunes any live object not present in desired. It is the full
// declarative reconcile — the basis for save/restore and clear — and
// keeps the library's surface declarative (no imperative per-object
// mutators).
//
// Sync is NOT transactional. It applies then prunes, each step fail-stop
// on the first hard error, returning a partial Report of what it managed
// to change. A failure therefore leaves a partially-reconciled tree; the
// design relies on re-reconcile (the next Sync, or startup replay of the
// desired state) to converge. This is safe under the single-writer rule
// (the appliance holds the host writer-lock across a reconcile, so no
// other writer perturbs the tree between apply and prune). The guiding
// principle is forward progress: Sync should always be able to make the
// tree more correct, even if that is disruptive to consumers (e.g. a LUN
// whose backstore changed is torn down and rebuilt — see ensureLUN).
func (m *Manager) Sync(desired Config) (Report, error) {
	var tm SyncTimings

	// Validate BEFORE anything is removed. Apply validates too, but the
	// conflicting-portal prune below runs first, so a caller passing an
	// invalid config used to have a working portal torn down and then be told
	// the config was rejected -- a target left less reachable than it was by
	// a call that changed nothing it asked for. Cheap and pure, so running it
	// twice costs nothing worth saving.
	if err := desired.Validate(); err != nil {
		return Report{}, err
	}

	// Portals that CONFLICT with the desired set are removed before the apply
	// phase, not after it with everything else.
	//
	// Everything in this package adds before it removes, so there is never a
	// window in which a LUN is missing. Portals are the one object where that
	// order cannot work: a wildcard and a specific address cannot share a
	// port -- the socket sets SO_REUSEADDR but not SO_REUSEPORT (linux v6.6
	// drivers/target/iscsi/iscsi_target_login.c, iscsit_setup_np), so the
	// kernel refuses the second bind with EADDRINUSE. Adding first therefore
	// fails against the very object the prune was about to remove, and since
	// applianced runs under Restart=on-failure, changing a target from a
	// wildcard to explicit addresses crash-looped it. Both configurations are
	// individually valid, so validation cannot catch it; only the ordering
	// can.
	//
	// Safe for portals specifically, and measured rather than assumed: a
	// portal is only the accept socket. Removing one on a live target left
	// existing sessions established and serving I/O (256KiB read O_DIRECT
	// straight after), and cost only new logins for the width of the window,
	// which SendTargets reported as a timeout.
	t0 := time.Now()
	if err := m.pruneConflictingPortals(desired); err != nil {
		tm.Prune = time.Since(t0)
		return Report{Timings: tm}, err
	}
	tm.Prune = time.Since(t0)

	t0 = time.Now()
	rep, err := m.Apply(desired)
	tm.Apply = time.Since(t0)
	if err != nil {
		rep.Timings = tm
		return rep, err
	}

	t0 = time.Now()
	actual, err := m.Discover()
	tm.Discover = time.Since(t0)
	if err != nil {
		rep.Timings = tm
		return rep, err
	}

	a := &applyCtx{fs: m.fs, changes: rep.Changes, drift: rep.Drift, aptplRecords: m.aptplRecords}
	t0 = time.Now()
	err = a.prune(desired, actual)
	tm.Prune += time.Since(t0)
	if err != nil {
		return Report{Changes: a.changes, Drift: a.drift, APTPLUnbound: rep.APTPLUnbound, Timings: tm}, err
	}
	// Re-verify AFTER pruning, so the report describes the tree as it stands.
	//
	// This used to be load-bearing: the count-based check compared ALL saved
	// records against the live registration count, so a registration made
	// dormant by the prune counted as live and the report said nothing.
	// Identity matching removed that by construction — prune only removes
	// objects ABSENT from the desired config, and a record whose coordinates
	// are absent from desired is not expected to be live at all, so prune
	// cannot make an EXPECTED record dormant. Pre- and post-prune now yield
	// the same answer.
	//
	// It is kept because it costs one file read and one or two attribute
	// reads per backstore, and because re-verifying the tree we actually
	// ended up with is the honest thing to report. Do not "simplify" it away
	// on the old rationale: that rationale is gone, this one is not.
	t0 = time.Now()
	unbound := a.verifyAPTPL(desired)
	tm.Verify = time.Since(t0)
	return Report{Changes: a.changes, Drift: a.drift, APTPLUnbound: unbound, Timings: tm}, nil
}

// Clear removes every LIO object — reconcile to the empty configuration.
func (m *Manager) Clear() (Report, error) { return m.Sync(Config{}) }

// prune removes every live object in actual that is absent from desired,
// in reverse dependency order (mapped LUNs → ACLs / LUNs / portals → TPGs
// → targets, then backstores once their LUNs are unlinked).
func (a *applyCtx) prune(desired, actual Config) error {
	dTargets := map[string]Target{}
	for _, t := range desired.Targets {
		dTargets[t.IQN] = t
	}
	dBackstores := map[string]bool{}
	for _, b := range desired.Backstores {
		dBackstores[backstoreKey(b)] = true
	}

	for _, t := range actual.Targets {
		dt, ok := dTargets[t.IQN]
		if !ok {
			if err := a.removeTarget(t.IQN); err != nil {
				return err
			}
			continue
		}
		dTPGs := map[int]TPG{}
		for _, g := range dt.TPGs {
			dTPGs[g.Tag] = g
		}
		for _, g := range t.TPGs {
			dg, ok := dTPGs[g.Tag]
			if !ok {
				if err := a.removeTPG(t.IQN, g.Tag); err != nil {
					return err
				}
				continue
			}
			if err := a.prunePortals(t.IQN, g, dg); err != nil {
				return err
			}
			// Reverse dependency order: prune ACLs (and their mapped LUNs,
			// which are symlinks INTO the TPG LUNs) BEFORE the TPG LUNs they
			// reference — otherwise removing a still-referenced TPG LUN fails
			// EBUSY. (removeTPG already tears down in this order for a whole
			// TPG; the incremental prune must match it.)
			if err := a.pruneACLs(t.IQN, g, dg); err != nil {
				return err
			}
			if err := a.pruneLUNs(t.IQN, g, dg); err != nil {
				return err
			}
		}
	}

	for _, b := range actual.Backstores {
		if !dBackstores[backstoreKey(b)] {
			if err := a.removeBackstore(b); err != nil {
				return err
			}
		}
	}
	return nil
}

// backstoreKey identifies a backstore by its full configfs identity
// (plugin + HBA + name) — NOT just type/name. Two objects with the same
// name under different HBAs are distinct kernel objects, so prune must
// distinguish them or it would leave a stale duplicate that Discover then
// reports as a duplicate name (which Validate rejects).
func backstoreKey(b Backstore) string {
	return string(b.Type) + "_" + itoa(b.HBA) + "/" + b.Name
}

func (a *applyCtx) prunePortals(iqn string, actual, desired TPG) error {
	want := map[netip.AddrPort]bool{}
	for _, p := range desired.Portals {
		want[p.key()] = true
	}
	for _, p := range actual.Portals {
		if !want[p.key()] {
			if err := a.fs.Rmdir(portalPath(iqn, actual.Tag, p)...); err != nil {
				return errf(classifyRemove(err, KindBusy), "prune", "portal/"+iqn+"/"+p.String(), err)
			}
			a.note("pruned portal/" + iqn + "/" + p.String())
		}
	}
	return nil
}

func (a *applyCtx) pruneLUNs(iqn string, actual, desired TPG) error {
	want := map[int]bool{}
	for _, l := range desired.LUNs {
		want[l.Index] = true
	}
	for _, l := range actual.LUNs {
		if !want[l.Index] {
			if err := a.removeLUN(iqn, actual.Tag, l.Index); err != nil {
				return err
			}
			a.note("pruned lun/" + iqn + "/lun_" + itoa(l.Index))
		}
	}
	return nil
}

func (a *applyCtx) pruneACLs(iqn string, actual, desired TPG) error {
	want := map[string]ACL{}
	for _, acl := range desired.ACLs {
		want[acl.InitiatorIQN] = acl
	}
	for _, acl := range actual.ACLs {
		da, ok := want[acl.InitiatorIQN]
		if !ok {
			if err := a.removeACL(iqn, actual.Tag, acl.InitiatorIQN); err != nil {
				return err
			}
			a.note("pruned acl/" + iqn + "/" + acl.InitiatorIQN)
			continue
		}
		wantML := map[int]bool{}
		for _, ml := range da.MappedLUNs {
			wantML[ml.Index] = true
		}
		for _, ml := range acl.MappedLUNs {
			if !wantML[ml.Index] {
				if err := a.removeMappedLUN(iqn, actual.Tag, acl.InitiatorIQN, ml.Index); err != nil {
					return err
				}
				a.note("pruned mappedlun/" + acl.InitiatorIQN + "/lun_" + itoa(ml.Index))
			}
		}
	}
	return nil
}

// pruneConflictingPortals removes live portals that would prevent a desired
// portal from binding. See the note at its call site in Sync.
//
// Only genuine conflicts are removed. A live portal absent from the desired
// config but not contending for any desired address is left to the ordinary
// prune, so this does not become a second, differently-ordered removal path.
func (m *Manager) pruneConflictingPortals(desired Config) error {
	actual, err := m.Discover()
	if err != nil {
		return err
	}
	for _, at := range actual.Targets {
		for _, ag := range at.TPGs {
			dg, ok := desiredTPG(desired, at.IQN, ag.Tag)
			if !ok {
				continue // the whole TPG is going away; ordinary prune handles it
			}
			for _, live := range ag.Portals {
				if !portalConflictsWithAny(live, dg.Portals, ag.Portals) {
					continue
				}
				if err := m.fs.Rmdir(portalPath(at.IQN, ag.Tag, live)...); err != nil {
					return errf(classifyRemove(err, KindBusy), "prune", "portal/"+at.IQN+"/"+live.String(), err)
				}
			}
		}
	}
	return nil
}

func desiredTPG(cfg Config, iqn string, tag int) (TPG, bool) {
	for _, t := range cfg.Targets {
		if t.IQN != iqn {
			continue
		}
		for _, g := range t.TPGs {
			if g.Tag == tag {
				return g, true
			}
		}
	}
	return TPG{}, false
}

// portalConflictsWithAny reports whether live must go before any of desired
// can bind.
//
// A portal identical to a desired one usually does not conflict -- it IS the
// desired one, already in place -- but there is one exception, and missing it
// left this whole mechanism unable to perform the transition it exists for.
//
// If the desired set adds a WILDCARD on a port where live already holds a
// specific address, the wildcard cannot bind until that address is gone (see
// wildcardPrecludes). "It is already desired, so leave it" then declines to
// prune the one portal that is in the way, the wildcard's add fails, and
// applianced crash-loops -- REPRODUCED with a live [fd00:10:10::1]:3260 and a
// desired set of {[fd00:10:10::1]:3260, 0.0.0.0:3260}: state=activating, the
// wildcard never created, "mkdir .../np/0.0.0.0:3260: invalid argument" on
// every restart.
//
// So a desired portal is pruned anyway when a desired wildcard on its port is
// NOT yet live. It comes straight back in the apply phase, which adds
// wildcards first (portalApplyOrder), so the end state is the full desired set
// and the only cost is that the address is unbound for the width of the apply
// -- which is measured safe: existing sessions survive a portal removal, only
// new logins are refused.
func portalConflictsWithAny(live Portal, desired, alive []Portal) bool {
	for _, d := range desired {
		if live.key() != d.key() {
			continue
		}
		// live is itself desired. It still has to go if a desired wildcard on
		// this port has yet to appear.
		return blockedWildcardOnPort(live, desired, alive)
	}
	for _, d := range desired {
		if live.port() != d.port() {
			continue
		}
		if wildcardPrecludes(live.IP, d.IP) || wildcardPrecludes(d.IP, live.IP) {
			return true
		}
	}
	return false
}

// blockedWildcardOnPort reports whether desired wants a wildcard on live's port
// that has NOT bound yet, and that live is therefore standing in the way of.
//
// The "not bound yet" half is load-bearing. Without it, a steady state of
// {0.0.0.0:3260, [fd00::1]:3260} -- both live, both desired, nothing to do --
// would prune and re-add the specific portal on EVERY reconcile, because a
// desired wildcard on its port would always be present. Reconcile is called on
// every volume operation, so that is a portal flapping under normal use, and
// the flap is invisible: the end state is correct every time.
func blockedWildcardOnPort(live Portal, desired, alive []Portal) bool {
	if live.IP.IsUnspecified() {
		return false // live IS the wildcard; nothing to clear for it
	}
	for _, d := range desired {
		if d.port() != live.port() || !d.IP.IsUnspecified() {
			continue
		}
		// A desired wildcard on this port. Only in the way if it is absent.
		bound := false
		for _, a := range alive {
			if a.key() == d.key() {
				bound = true
				break
			}
		}
		if !bound {
			return true
		}
	}
	return false
}

// wildcardPrecludes reports whether binding w (if it is a wildcard) stops
// other from binding on the same port. Measured: 0.0.0.0 covers IPv4 only,
// while :: covers both families on a default Linux (net.ipv6.bindv6only=0).
//
// The family question is asked once, of the address itself. It used to be a
// ParseIP plus a To4() nil-check on each side, which is the same test written
// so that it looks like something else.
// A wildcard of EITHER family precludes every other address on its port.
//
// For "::" that is simply what a dual-stack wildcard means. For "0.0.0.0" it is
// a WORKAROUND for a bug in the LIO iSCSI TARGET DRIVER -- drivers/target/iscsi,
// the SCSI target subsystem -- and NOT in the kernel network stack. The rule is
// therefore wider than the traffic 0.0.0.0 actually serves (IPv4 only).
//
// Not reported upstream yet. The evidence is a disassembly of
// iscsit_check_np_match confirming the cast, an offsetof proof that
// sin6_flowinfo occupies the same bytes as sin_addr, and a reproduction that
// binds the two portals in the permitted order and serves both.
//
// The socket layer behaves correctly throughout: it is what returns the honest
// EADDRINUSE for a genuine conflict, and it binds both sockets happily when LIO
// lets the request through. The fault is entirely in LIO's own duplicate-portal
// check, which runs BEFORE any socket call -- a consumer mishandling a
// sockaddr_storage, not a defect in the API it consumes.
//
// iscsit_check_np_match (linux v6.6 drivers/target/iscsi/iscsi_target.c:265)
// casts BOTH the new sockaddr and the existing np->np_sockaddr using the NEW
// address's family. Adding an IPv4 portal therefore reads an existing IPv6
// portal as a struct sockaddr_in and compares four bytes at sin_addr's offset
// -- which in sockaddr_in6 is sin6_flowinfo, normally zero. 0.0.0.0's s_addr is
// also zero, so it FALSE-MATCHES every IPv6 portal on the same port and the add
// fails with EEXIST ("Network Portal: 0.0.0.0 already exists on a different
// TPG" in dmesg).
//
// The aliasing is not inferred, it is proven: offsetof on glibc gives
// sockaddr_in.sin_addr @4 and sockaddr_in6.sin6_flowinfo @4 -- the same offset.
// (sin_port and sin6_port are both @2, which is the only reason the PORT half
// of the same comparison is not equally broken.)
//
// MEASURED on Azure Linux 3 / kernel 6.6, one TPG, separate ports:
//
//	[fd00:10:10::1]:9270  first      -> ACCEPTED
//	0.0.0.0:9270    (s_addr == 0)    -> REJECTED   <- aliases flowinfo == 0
//	10.10.0.99:9270 (s_addr != 0)    -> ACCEPTED   <- no false match
//	fd00:10:10::9 vs live IPv4       -> ACCEPTED   <- non-zero, no false match
//
// which is why our explicit IPv4 portals coexist with IPv6 ones perfectly well:
// only the all-zero address of either family collides. It also falsifies the
// note this project used to carry, that "0.0.0.0 and explicit IPv6 coexist" --
// they do, but ONLY if 0.0.0.0 is added first (measured both ways, ports 9260
// and 9261).
//
// It is a genuine kernel defect rather than a policy we are tripping over, and
// the two are distinguishable by WHICH failure the kernel reports:
//
//	0.0.0.0 + live IPv4 specific -> "kernel_bind() failed: -98"  (EADDRINUSE,
//	                                a real socket conflict, correct)
//	0.0.0.0 + live IPv6 specific -> "Network Portal: 0.0.0.0 already exists
//	                                on a different TPG"          (EEXIST, from
//	                                the match check, BEFORE any bind)
//
// The second never reaches the network stack. And the configuration it refuses
// WORKS: with {0.0.0.0:3260, [fd00:10:10::1]:3260} bound -- reachable by adding
// the wildcard first -- both portals served real iSCSI discovery sessions from
// an initiator, over IPv4 and over IPv6.
//
// Present in torvalds/linux master as of 2026-08, byte-identical to v6.6, so
// this workaround is not waiting on a kernel we already have. The upstream fix
// is one comparison: reject when np->np_sockaddr.ss_family differs from
// sockaddr->ss_family.
//
// Being too eager here is cheap and the other direction is not: pruning a
// portal that did not strictly need pruning costs new logins for the width of
// the apply window, while missing a conflict fails the add, and applianced runs
// under Restart=on-failure -- reproduced as a crash loop when switching a
// target from explicit portals to the wildcard.
func wildcardPrecludes(w, other netip.Addr) bool {
	if !w.IsValid() || !other.IsValid() || !w.IsUnspecified() {
		return false
	}
	return true
}
