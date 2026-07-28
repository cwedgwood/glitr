package lio

import "os"

// Unexported removal helpers shared by removeTarget (iscsi.go), the
// declarative prune (sync.go) and the replace-in-place path in the ensure*
// functions. The library exposes no imperative per-object mutators — all
// mutation goes through Apply / Sync / Remove.
//
// Every helper returns an error. Removal failures MUST propagate (not be
// swallowed): a LUN or mapped LUN that silently fails to unmap would leave
// an initiator seeing storage the control plane believes is gone. Callers
// need to know so they can retry, escalate, or clean up.

// removeLUN unlinks a LUN's backstore symlink and removes the LUN dir.
func (a *applyCtx) removeLUN(iqn string, tag, index int) error {
	if err := a.unlinkAll(lunPath(iqn, tag, index)); err != nil {
		return errf(classifyRemove(err, KindConfigfs), "remove", "lun/"+iqn+"/lun_"+itoa(index), err)
	}
	if err := a.fs.Rmdir(lunPath(iqn, tag, index)...); err != nil {
		return errf(classifyRemove(err, KindBusy), "remove", "lun/"+iqn+"/lun_"+itoa(index), err)
	}
	return nil
}

// removeMappedLUN unlinks a mapped LUN's symlink and removes its dir.
func (a *applyCtx) removeMappedLUN(iqn string, tag int, initiator string, index int) error {
	if err := a.unlinkAll(mappedLunPath(iqn, tag, initiator, index)); err != nil {
		return errf(classifyRemove(err, KindConfigfs), "remove", "mappedlun/"+initiator+"/lun_"+itoa(index), err)
	}
	if err := a.fs.Rmdir(mappedLunPath(iqn, tag, initiator, index)...); err != nil {
		return errf(classifyRemove(err, KindBusy), "remove", "mappedlun/"+initiator+"/lun_"+itoa(index), err)
	}
	return nil
}

// removeACL removes an ACL's mapped LUNs then the ACL dir.
func (a *applyCtx) removeACL(iqn string, tag int, initiator string) error {
	// Absent is fine -- there is nothing to remove. UNREADABLE is not: the
	// error used to be discarded, so the subsequent rmdir failed on the
	// SYMPTOM (children present) with the CAUSE (the directory could not be
	// listed) already thrown away. removeTPG's comment thirty lines below
	// condemns exactly this and was fixed; this path was missed.
	children, err := a.fs.ReadDir(aclPath(iqn, tag, initiator)...)
	if err != nil && !os.IsNotExist(err) {
		return errf(KindConfigfs, "list", "acl/"+initiator, err)
	}
	for _, c := range children {
		if idx, ok := parseLUN(c); ok {
			if err := a.removeMappedLUN(iqn, tag, initiator, idx); err != nil {
				return err
			}
		}
	}
	if err := a.fs.Rmdir(aclPath(iqn, tag, initiator)...); err != nil {
		return errf(classifyRemove(err, KindBusy), "remove", "acl/"+iqn+"/"+initiator, err)
	}
	return nil
}

// removeTPG removes a TPG's portals, LUNs and ACLs then the TPG dir.
//
// It deliberately does NOT write enable=0 first. That was raised as a possible
// omission, on the theory that an enabled TPG would refuse to be torn down.
// MEASURED on Azure Linux 3.0, kernel 6.6.144.1-1.azl3: with enable reading
// back 1, rmdir of the portal, the TPG and then the target all succeed, with
// nothing logged. Adding the write would be a configfs round-trip per teardown
// bought by nothing, so the absence is intentional rather than overlooked.
//
// Listing each child group used to be `if names, err := ReadDir(...); err ==
// nil`, which skipped the whole group on ANY error. The kernel creates acls/,
// lun/ and np/ with the TPG, so a read failure there is never routine -- it
// means the group could not be enumerated, and silently declining to remove
// children leaves the final rmdir to fail on a symptom (children present)
// with the cause (the group was unreadable) already discarded.
func (a *applyCtx) removeTPG(iqn string, tag int) error {
	id := "tpg/" + iqn + "/tpgt_" + itoa(tag)
	// children lists one of the TPG's child groups. Absent is ordinary and
	// means "nothing to remove"; unreadable is reported.
	children := func(group string) ([]string, error) {
		names, err := a.fs.ReadDir(append(tpgPath(iqn, tag), group)...)
		if err != nil {
			if notADir(err) {
				return nil, nil
			}
			return nil, errf(KindConfigfs, "remove", id+"/"+group, err)
		}
		return names, nil
	}

	acls, err := children("acls")
	if err != nil {
		return err
	}
	for _, aclName := range acls {
		isDir, err := a.fs.IsDir(aclPath(iqn, tag, aclName)...)
		if err != nil && !notADir(err) {
			return errf(KindConfigfs, "remove", "acl/"+iqn+"/"+aclName, err)
		}
		if isDir {
			if err := a.removeACL(iqn, tag, aclName); err != nil {
				return err
			}
		}
	}
	luns, err := children("lun")
	if err != nil {
		return err
	}
	for _, ln := range luns {
		if idx, ok := parseLUN(ln); ok {
			if err := a.removeLUN(iqn, tag, idx); err != nil {
				return err
			}
		}
	}
	nps, err := children("np")
	if err != nil {
		return err
	}
	for _, np := range nps {
		if err := a.fs.Rmdir(append(tpgPath(iqn, tag), "np", np)...); err != nil {
			return errf(classifyRemove(err, KindBusy), "remove", "portal/"+iqn+"/"+np, err)
		}
	}
	if err := a.fs.Rmdir(tpgPath(iqn, tag)...); err != nil {
		return errf(classifyRemove(err, KindBusy), "remove", "tpg/"+iqn+"/tpgt_"+itoa(tag), err)
	}
	return nil
}
