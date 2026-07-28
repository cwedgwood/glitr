package lio

import (
	"os"
	"slices"

	"github.com/cwedgwood/glitr/lio/configfs"
)

// ensureTarget creates iscsi/<iqn> if absent.
func (a *applyCtx) ensureTarget(t Target) error {
	id := "target/" + t.IQN
	// The iSCSI fabric group (<root>/iscsi) is a "makable" configfs group
	// that is NOT auto-created when iscsi_target_mod loads, and configfs is
	// volatile (empty after every boot). Ensure it exists so a target can be
	// created on a freshly-booted host without external host-prep — this is
	// what lets applianced/lish come up after a reboot. Idempotent.
	if err := a.fs.Mkdir("iscsi"); err != nil {
		return errf(classifyCreate(err, KindConfigfs), "apply", id, err)
	}
	if ok, err := a.fs.Exists(targetPath(t.IQN)...); err != nil {
		return errf(KindConfigfs, "apply", id, err)
	} else if !ok {
		if err := a.fs.Mkdir(targetPath(t.IQN)...); err != nil {
			return errf(classifyCreate(err, KindKernelRejected), "apply", id, err)
		}
		a.note("created " + id)
	}
	for i := range t.TPGs {
		if err := a.ensureTPG(t.IQN, t.TPGs[i]); err != nil {
			return err
		}
	}
	return nil
}

// ensureTPG reconciles a TPG and its children in dependency order:
// portals, LUNs, ACLs, then the enable flag last.
func (a *applyCtx) ensureTPG(iqn string, tpg TPG) error {
	id := "tpg/" + iqn + "/tpgt_" + itoa(tpg.Tag)
	if ok, err := a.fs.Exists(tpgPath(iqn, tpg.Tag)...); err != nil {
		return errf(KindConfigfs, "apply", id, err)
	} else if !ok {
		if err := a.fs.Mkdir(tpgPath(iqn, tpg.Tag)...); err != nil {
			return errf(classifyCreate(err, KindKernelRejected), "apply", id, err)
		}
		a.note("created " + id)
	}

	// Attributes (attrib/*) — only manage listed keys.
	//
	// An attribute this kernel does not expose is SKIPPED, not fatal, mirroring
	// discoverTPG. The two have to agree: discover tolerates ENOENT because a
	// key may be absent on an older kernel, so a config discovered on one
	// kernel can legitimately name a key another does not have. Since the
	// managed set went from 3 keys to 13, a `lish save` taken on 6.6 and
	// restored onto a kernel missing any ONE of them failed the entire
	// reconcile -- under Restart=on-failure, that is a crash loop over a
	// setting the appliance does not depend on.
	//
	// Skipping is the over-fence direction: the key keeps whatever value the
	// kernel defaults it to, and the note records that it was not applied, so
	// nothing silently claims a setting took effect.
	for _, k := range sortedKeys(tpg.Attributes) {
		want := tpg.Attributes[k]
		p := append(tpgPath(iqn, tpg.Tag), "attrib", k)
		cur, err := a.fs.ReadAttr(p...)
		if err != nil {
			if os.IsNotExist(err) {
				a.note(id + " attrib/" + k + " not supported by this kernel, skipped")
				continue
			}
			return errf(KindConfigfs, "apply", id+" attrib/"+k, err)
		}
		if cur != want {
			if err := a.fs.WriteAttr(want, p...); err != nil {
				return errf(KindKernelRejected, "apply", id+" attrib/"+k, err)
			}
			// READ BACK, because some iSCSI TPG setters accept a write and
			// silently decline to apply it -- they return 0 without changing
			// the value, so the write cannot be distinguished from a
			// successful one by its error alone.
			//
			// cache_dynamic_acls is the case in hand: writing 0 while
			// generate_node_acls is 1 hits an early "Skipping
			// cache_dynamic_acls=0 when generate_node_acls=1" return
			// (linux v6.6 drivers/target/iscsi/iscsi_target_tpg.c:729-732), and
			// setting generate_node_acls=1 forces cache_dynamic_acls=1 from
			// the other direction (:683-687). Without this read-back the change
			// note claimed a value that never took effect, which is the
			// project's own "do not claim more than was established" rule
			// applied to a report the operator reads.
			if after, rerr := a.fs.ReadAttr(p...); rerr == nil && after != want {
				a.note(id + " attrib/" + k + "=" + want +
					" NOT APPLIED (kernel kept " + after + ")")
				continue
			}
			a.note(id + " attrib/" + k + "=" + want)
		}
	}

	// Wildcards first, then everything else -- see portalApplyOrder.
	for _, p := range portalApplyOrder(tpg.Portals) {
		if err := a.ensurePortal(iqn, tpg.Tag, p); err != nil {
			return err
		}
	}
	for _, l := range tpg.LUNs {
		if err := a.ensureLUN(iqn, tpg.Tag, l); err != nil {
			return err
		}
	}
	for _, acl := range tpg.ACLs {
		if err := a.ensureACL(iqn, tpg.Tag, acl); err != nil {
			return err
		}
	}

	// enable flag last.
	want := "0"
	if tpg.Enable {
		want = "1"
	}
	ep := append(tpgPath(iqn, tpg.Tag), "enable")
	cur, err := a.fs.ReadAttr(ep...)
	if err != nil {
		return errf(KindConfigfs, "apply", id+" enable", err)
	}
	if cur != want {
		if err := a.fs.WriteAttr(want, ep...); err != nil {
			return errf(KindKernelRejected, "apply", id+" enable", err)
		}
		a.note(id + " enable=" + want)
	}
	return nil
}

// ensurePortal creates np/<ip>:<port> if absent.
func (a *applyCtx) ensurePortal(iqn string, tag int, p Portal) error {
	id := "portal/" + iqn + "/" + p.String()
	if ok, err := a.fs.Exists(portalPath(iqn, tag, p)...); err != nil {
		return errf(KindConfigfs, "apply", id, err)
	} else if ok {
		return nil
	}
	if err := a.fs.Mkdir(portalPath(iqn, tag, p)...); err != nil {
		return errf(classifyCreate(err, KindKernelRejected), "apply", id, err)
	}
	a.note("created " + id)
	return nil
}

// ensureLUN creates lun/lun_<index> and symlinks it to its backstore.
func (a *applyCtx) ensureLUN(iqn string, tag int, l LUN) error {
	id := "lun/" + iqn + "/lun_" + itoa(l.Index)
	bs, ok := a.backstoreByName(l.Backstore)
	if !ok {
		return errf(KindDependency, "apply", id,
			wrapf("references unknown backstore %q", l.Backstore))
	}
	want := a.fs.Path(bs.objPath()...)

	if ok, err := a.fs.Exists(lunPath(iqn, tag, l.Index)...); err != nil {
		return errf(KindConfigfs, "apply", id, err)
	} else if ok {
		_, cur, err := a.fs.FindSymlink(lunPath(iqn, tag, l.Index)...)
		if err != nil {
			return errf(KindConfigfs, "apply", id, err)
		}
		if cur == want {
			return nil // present and correctly wired
		}
		if cur != "" {
			// Conflict: this LUN index is wired to a DIFFERENT backstore.
			// Re-point IN PLACE — unlink the old backstore symlink and link
			// the new one inside the existing lun_<index> dir. Do NOT rmdir
			// the LUN: incoming mapped-LUN references (acls/.../lun_N -> this
			// LUN) hold a configfs refcount on it, so rmdir would EBUSY-wedge
			// the reconcile. Unlink+relink works even while the LUN is
			// exported/mapped (kernel-verified) and keeps the reconcile
			// converging.
			//
			// CAVEAT (kernel-verified): if an initiator is actively logged in
			// and using this LUN, swapping the backing store underneath it is
			// disruptive to that initiator — the live SCSI device sees errors
			// (LBA out of range, a capacity change) and reads garbage until it
			// re-logs in. Storage is being swapped under a live device; that
			// is inherent, not a bug here. The appliance never triggers this
			// (its TPG LUN index is bound 1:1 and stably to a volume's
			// backstore — see exportIndex/backstoreName — so a mapped LUN's
			// backstore is never changed in place; unmap+remap creates a fresh
			// LUN instead). Only lish or a hand-crafted lio.Config can reach
			// this path, i.e. by deliberately reusing a LUN index for a
			// different backstore.
			if err := a.unlinkAll(lunPath(iqn, tag, l.Index)); err != nil {
				return errf(KindKernelRejected, "apply", id, err)
			}
			a.note("re-pointing " + id + " (was -> " + backstoreNameFromPath(cur) + ")")
		}
		// cur == "" : dir exists without a symlink — fall through to link it.
	} else if err := a.fs.Mkdir(lunPath(iqn, tag, l.Index)...); err != nil {
		return errf(classifyCreate(err, KindKernelRejected), "apply", id, err)
	}

	link := append(lunPath(iqn, tag, l.Index), alias())
	if err := a.fs.Symlink(want, link...); err != nil {
		return errf(KindKernelRejected, "apply", id, err)
	}
	a.note("created " + id + " -> " + l.Backstore)
	return nil
}

// ensureACL creates acls/<iqn> and its mapped LUNs.
func (a *applyCtx) ensureACL(iqn string, tag int, acl ACL) error {
	id := "acl/" + iqn + "/" + acl.InitiatorIQN
	if ok, err := a.fs.Exists(aclPath(iqn, tag, acl.InitiatorIQN)...); err != nil {
		return errf(KindConfigfs, "apply", id, err)
	} else if !ok {
		if err := a.fs.Mkdir(aclPath(iqn, tag, acl.InitiatorIQN)...); err != nil {
			return errf(classifyCreate(err, KindKernelRejected), "apply", id, err)
		}
		a.note("created " + id)
	}
	for _, m := range acl.MappedLUNs {
		if err := a.ensureMappedLUN(iqn, tag, acl.InitiatorIQN, m); err != nil {
			return err
		}
	}
	return nil
}

// ensureMappedLUN creates acls/<iqn>/lun_<index> -> the TPG LUN.
func (a *applyCtx) ensureMappedLUN(iqn string, tag int, initiator string, m MappedLUN) error {
	id := "mappedlun/" + initiator + "/lun_" + itoa(m.Index)
	want := a.fs.Path(lunPath(iqn, tag, m.TPGLUN)...)

	if ok, err := a.fs.Exists(mappedLunPath(iqn, tag, initiator, m.Index)...); err != nil {
		return errf(KindConfigfs, "apply", id, err)
	} else if ok {
		_, cur, err := a.fs.FindSymlink(mappedLunPath(iqn, tag, initiator, m.Index)...)
		if err != nil {
			return errf(KindConfigfs, "apply", id, err)
		}
		if cur == want {
			return a.ensureWriteProtect(iqn, tag, initiator, m, id)
		}
		if cur != "" {
			// Conflict: this mapped LUN index points at a different TPG LUN.
			// Re-point IN PLACE (unlink old symlink, link new one in the
			// existing dir), consistent with ensureLUN and least disruptive
			// to the initiator's view.
			if err := a.unlinkAll(mappedLunPath(iqn, tag, initiator, m.Index)); err != nil {
				return errf(KindKernelRejected, "apply", id, err)
			}
			a.note("re-pointing " + id)
		}
		// cur == "" : dir exists without a symlink — fall through to link it.
	} else if err := a.fs.Mkdir(mappedLunPath(iqn, tag, initiator, m.Index)...); err != nil {
		return errf(classifyCreate(err, KindKernelRejected), "apply", id, err)
	}

	link := append(mappedLunPath(iqn, tag, initiator, m.Index), alias())
	if err := a.fs.Symlink(want, link...); err != nil {
		return errf(KindKernelRejected, "apply", id, err)
	}
	a.note("created " + id + " -> lun_" + itoa(m.TPGLUN))
	return a.ensureWriteProtect(iqn, tag, initiator, m, id)
}

func (a *applyCtx) ensureWriteProtect(iqn string, tag int, initiator string, m MappedLUN, id string) error {
	want := "0"
	if m.WriteProtect {
		want = "1"
	}
	p := append(mappedLunPath(iqn, tag, initiator, m.Index), "write_protect")
	cur, err := a.fs.ReadAttr(p...)
	if err != nil {
		return errf(KindConfigfs, "apply", id+" write_protect", err)
	}
	if cur != want {
		if err := a.fs.WriteAttr(want, p...); err != nil {
			return errf(KindKernelRejected, "apply", id+" write_protect", err)
		}
		a.note(id + " write_protect=" + want)
	}
	return nil
}

// removeTarget tears an iSCSI target down in reverse dependency order,
// as configfs requires (a directory can only be rmdir'd once its
// user-created children — symlinks, LUNs, portals, ACLs — are gone).
func (a *applyCtx) removeTarget(iqn string) error {
	id := "target/" + iqn
	if ok, err := a.fs.Exists(targetPath(iqn)...); err != nil {
		return errf(KindConfigfs, "remove", "target/"+iqn, err)
	} else if !ok {
		return nil
	}
	tpgs, err := a.fs.ReadDir(targetPath(iqn)...)
	if err != nil {
		return errf(KindConfigfs, "remove", "target/"+iqn, err)
	}
	for _, td := range tpgs {
		tag, ok := parseTPGT(td)
		if !ok {
			continue
		}
		if err := a.removeTPG(iqn, tag); err != nil {
			return err
		}
	}
	if err := a.fs.Rmdir(targetPath(iqn)...); err != nil {
		return errf(classifyRemove(err, KindBusy), "remove", id, err)
	}
	a.note("removed " + id)
	return nil
}

// unlinkAll removes every symlink child of a LUN/mapped-LUN directory.
// A missing directory is not an error (nothing to unlink); any real
// removal failure propagates so callers do not mistake a stuck unlink
// for success.
func (a *applyCtx) unlinkAll(dirParts []string) error {
	links, err := a.fs.ListSymlinks(dirParts...)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, l := range links {
		// Unlink, not Rmdir: these are symlinks, and removing one unmaps a
		// LUN's backstore rather than destroying an object.
		if err := a.fs.Unlink(append(append([]string{}, dirParts...), l)...); err != nil {
			return err
		}
	}
	return nil
}

// discoverTargets reconstructs the iscsi/* hierarchy.
func discoverTargets(fs *configfs.FS) ([]Target, error) {
	iqns, err := fs.ReadDir("iscsi")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, errf(KindConfigfs, "discover", "iscsi", err)
	}
	var out []Target
	for _, iqn := range iqns {
		// Skip iscsi fabric control entries that are not targets.
		if iqn == "discovery_auth" || iqn == "lio_version" {
			continue
		}
		if isDir, err := fs.IsDir("iscsi", iqn); err != nil {
			return nil, errf(KindConfigfs, "discover", "iscsi/"+iqn, err)
		} else if !isDir {
			continue // e.g. a stray file
		}
		t := Target{IQN: iqn}
		tpgDirs, err := fs.ReadDir("iscsi", iqn)
		if err != nil {
			return nil, errf(KindConfigfs, "discover", "iscsi/"+iqn, err)
		}
		for _, td := range tpgDirs {
			tag, ok := parseTPGT(td)
			if !ok {
				continue
			}
			tpg, err := discoverTPG(fs, iqn, tag)
			if err != nil {
				return nil, err
			}
			t.TPGs = append(t.TPGs, tpg)
		}
		out = append(out, t)
	}
	return out, nil
}

// discoveredTPGAttrs are the TPG attrib/* keys Discover reads back so
// save/restore round-trips them.
//
// This is the COMPLETE set the kernel exposes, not a selection, and that is
// the point. It used to hold three keys while lish would set ANY key the user
// named, so anything outside those three was written to the kernel and never
// read back -- present until the next reboot, then silently gone. A
// configuration that disappears on restart is worse than one that is refused,
// because nothing reports it. The gap was self-demonstrating: lio/live_test.go
// sets cache_dynamic_acls, which was one of the lost ones.
//
// MEASURED on Azure Linux 3.0, kernel 6.6.144.1-1.azl3, by enumerating
// iscsi/<iqn>/tpgt_N/attrib/ on a freshly created TPG. All thirteen are mode
// 0644, and each was written to a different value successfully with the TPG
// both DISABLED and ENABLED -- so widening this list cannot reintroduce the
// failure that adding optimal_sectors to the backstore set caused, where a
// managed attribute the kernel refused to change made startup replay
// crash-loop. Both states matter because ensureTPG writes attributes before
// the enable flag on create, but a reconcile of a running TPG writes them
// while it is enabled.
//
// Kept as an explicit list rather than "read every attrib/*": the set is a
// property of the kernel, so discovering it dynamically would silently change
// what this appliance manages when the kernel gains a key, and a value read
// from a newer kernel would then be written back to an older one.
var discoveredTPGAttrs = []string{
	"authentication",
	"cache_dynamic_acls",
	"default_cmdsn_depth",
	"default_erl",
	"demo_mode_discovery",
	"demo_mode_write_protect",
	"fabric_prot_type",
	"generate_node_acls",
	"login_keys_workaround",
	"login_timeout",
	"prod_mode_write_protect",
	"t10_pi",
	"tpg_enabled_sendtargets",
}

func discoverTPG(fs *configfs.FS, iqn string, tag int) (TPG, error) {
	tpg := TPG{Tag: tag, Attributes: map[string]string{}}
	id := "iscsi/" + iqn + "/tpgt_" + itoa(tag)
	// enable always exists for a live TPG: an UNREADABLE value must not be
	// reported as "disabled", or a save/restore round-trip would disable a
	// live target. A genuinely absent attribute (ENOENT) is tolerated.
	en, err := fs.ReadAttr(append(tpgPath(iqn, tag), "enable")...)
	if err != nil && !os.IsNotExist(err) {
		return TPG{}, errf(KindConfigfs, "discover", id+" enable", err)
	}
	tpg.Enable = en == "1"
	for _, k := range discoveredTPGAttrs {
		v, err := fs.ReadAttr(append(tpgPath(iqn, tag), "attrib", k)...)
		if err != nil {
			if os.IsNotExist(err) {
				continue // not supported by this kernel — genuinely absent
			}
			return TPG{}, errf(KindConfigfs, "discover", id+" attrib/"+k, err)
		}
		tpg.Attributes[k] = v
	}

	// Portals.
	nps, err := fs.ReadDir(append(tpgPath(iqn, tag), "np")...)
	if err != nil {
		return TPG{}, errf(KindConfigfs, "discover", "iscsi/"+iqn+" np", err)
	}
	for _, np := range nps {
		if p, ok := ParsePortal(np); ok {
			tpg.Portals = append(tpg.Portals, p)
		}
	}

	// LUNs.
	luns, err := fs.ReadDir(append(tpgPath(iqn, tag), "lun")...)
	if err != nil {
		return TPG{}, errf(KindConfigfs, "discover", "iscsi/"+iqn+" lun", err)
	}
	for _, ld := range luns {
		idx, ok := parseLUN(ld)
		if !ok {
			continue
		}
		l := LUN{Index: idx}
		// The backstore symlink identifies what this LUN exposes; an
		// unreadable link must not silently yield an empty backstore name
		// (which Sync would treat as a mismatch and re-point in place).
		_, target, err := fs.FindSymlink(lunPath(iqn, tag, idx)...)
		if err != nil {
			return TPG{}, errf(KindConfigfs, "discover", id+" lun_"+itoa(idx), err)
		}
		if target != "" {
			l.Backstore = backstoreNameFromPath(target)
		}
		tpg.LUNs = append(tpg.LUNs, l)
	}

	// ACLs.
	acls, err := fs.ReadDir(append(tpgPath(iqn, tag), "acls")...)
	if err != nil {
		return TPG{}, errf(KindConfigfs, "discover", "iscsi/"+iqn+" acls", err)
	}
	for _, aclName := range acls {
		if isDir, err := fs.IsDir(aclPath(iqn, tag, aclName)...); err != nil {
			return TPG{}, errf(KindConfigfs, "discover", id+" acls/"+aclName, err)
		} else if !isDir {
			continue
		}
		acl := ACL{InitiatorIQN: aclName}
		children, err := fs.ReadDir(aclPath(iqn, tag, aclName)...)
		if err != nil {
			return TPG{}, errf(KindConfigfs, "discover", "acls/"+aclName, err)
		}
		for _, c := range children {
			idx, ok := parseLUN(c)
			if !ok {
				continue
			}
			m := MappedLUN{Index: idx}
			// An unreadable mapped-LUN link must not default to TPGLUN 0:
			// Sync would then re-point this initiator's mapping at LUN 0.
			_, target, err := fs.FindSymlink(mappedLunPath(iqn, tag, aclName, idx)...)
			if err != nil {
				return TPG{}, errf(KindConfigfs, "discover", "acls/"+aclName+" lun_"+itoa(idx), err)
			}
			if target != "" {
				m.TPGLUN = lunIndexFromPath(target)
			}
			wp, err := fs.ReadAttr(append(mappedLunPath(iqn, tag, aclName, idx), "write_protect")...)
			if err != nil && !os.IsNotExist(err) {
				return TPG{}, errf(KindConfigfs, "discover", "acls/"+aclName+" write_protect", err)
			}
			m.WriteProtect = wp == "1"
			acl.MappedLUNs = append(acl.MappedLUNs, m)
		}
		tpg.ACLs = append(tpg.ACLs, acl)
	}
	return tpg, nil
}

// portalApplyOrder returns portals with the unspecified addresses first.
//
// The kernel will accept "0.0.0.0:3260" alongside "[fd00::1]:3260" only if the
// wildcard is added FIRST; the other order is refused (see wildcardPrecludes
// for the mechanism and the measurements). Applying in the order the operator
// happened to write them therefore made the SAME desired state succeed or fail
// on the spelling of a comma-separated flag:
//
//	-portals 0.0.0.0:3260,[fd00::1]:3260   worked
//	-portals [fd00::1]:3260,0.0.0.0:3260   failed, and crash-looped the daemon
//
// Sorting makes the outcome a property of the SET rather than of its notation.
// It returns a new slice: the caller's Config is the desired state and reusing
// it as scratch space is how a reconciler starts disagreeing with itself.
//
// Note this is a total order, not a stable partition: two wildcards cannot
// coexist on one port anyway (Validate rejects duplicates), so the only thing
// that matters is that every unspecified address precedes every specific one.
func portalApplyOrder(portals []Portal) []Portal {
	if len(portals) < 2 {
		return portals
	}
	out := make([]Portal, len(portals))
	copy(out, portals)
	slices.SortStableFunc(out, func(a, b Portal) int {
		// Wildcards first: a wildcard cannot bind after a specific address on
		// the same port. Only that one relation matters, so everything else
		// compares equal and the stable sort preserves the caller's order.
		switch {
		case a.IP.IsUnspecified() && !b.IP.IsUnspecified():
			return -1
		case !a.IP.IsUnspecified() && b.IP.IsUnspecified():
			return 1
		}
		return 0
	})
	return out
}

// DiscoveredTPGAttrs returns the TPG attributes this appliance reads back, and
// therefore the ones that survive a save/restore.
//
// Exported so a caller setting an attribute can tell the operator when it will
// NOT survive a reboot. A copy, so a caller cannot narrow what is managed.
func DiscoveredTPGAttrs() []string { return slices.Clone(discoveredTPGAttrs) }
