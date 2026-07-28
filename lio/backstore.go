package lio

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/cwedgwood/glitr/lio/configfs"
)

// applyCtx threads the configfs handle and a running change log through
// an apply pass so callers can see whether reapplication was a no-op.
// stateBackstores indexes the desired backstores by name for LUN wiring.
type applyCtx struct {
	fs              *configfs.FS
	changes         []string
	drift           []AttrDrift
	stateBackstores map[string]Backstore

	// aptplRecords supplies saved SCSI-3 PR registrations for a backstore
	// being created. See Manager.SetAPTPLRecords.
	aptplRecords func(Backstore) ([]string, error)
}

func (a *applyCtx) note(s string) { a.changes = append(a.changes, s) }

// immutableWhileExported reports whether a failed attribute write is the one
// failure a reconcile must tolerate: the kernel refusing to change a
// create-time property while the device is exported.
//
// It is deliberately narrow. Skipping a write means declaring convergence
// while the live object disagrees with the desired config, so the only
// defensible reason to do it is that NO reconcile could ever succeed --
// which is true precisely when the kernel's own precondition says so. Both
// halves are checked:
//
//   - the error must be EINVAL, which is what that guard returns (linux v6.6
//     drivers/target/target_core_configfs.c:1118-1123 for block_size,
//     :1088-1092 for optimal_sectors). EACCES, EIO, ENOENT from a mistyped
//     attribute key, or an attribute the running kernel does not expose are
//     all different bugs, and narrating them as "immutable while exported"
//     makes them permanently invisible.
//   - the device must actually be exported. On an UNEXPORTED object the write
//     should have worked, so a failure there is a real fault and must stay
//     fatal -- notably on the create-then-retry path, where an object left
//     enabled-but-unexported by an earlier failure would otherwise have its
//     attribute write silently skipped and then be LUN-mapped with the wrong
//     geometry.
//
// The kernel's own condition is dev->export_count, and that is NOT readable:
// MEASURED on a live target (Azure Linux 3.0, kernel 6.6.144.1), a backstore
// object dir contains only action, alias, alua, alua_lu_gp, attrib, control,
// enable, info, lba_map, pr, statistics, udev_path and wwn. There is no
// export_count attribute. Reading one would fail on every real kernel, making
// this predicate always false and reinstating the crash loop it exists to
// prevent -- so the count is derived from what increments it instead: a TPG
// LUN symlink referencing this backstore. That is the same fact, observable.
//
// KEY-AGNOSTIC ON PURPOSE, and this is the limit of what validateAttr buys.
// This answers "EINVAL while exported" for any attribute, so it can only
// distinguish immutability from a bad value for keys validateAttr models
// (block_size, emulate_write_cache, optimal_sectors -- rejected before the
// write, so a surviving EINVAL is immutability). For any OTHER key an
// out-of-range value on an exported device still lands here and is reported as
// drift. Narrowing this to a known-immutable key list is the obvious fix and
// is wrong: the kernel's immutable set is per-attribute and per-version, so a
// stale list would classify a genuine immutability EINVAL as a hard failure
// and crash-loop the daemon, which is the failure this predicate was written
// to stop. Extending validateAttr is the safe direction.
func (a *applyCtx) immutableWhileExported(b Backstore, err error) bool {
	if !errors.Is(err, syscall.EINVAL) {
		return false
	}
	n, cerr := a.countLUNRefs(b)
	return cerr == nil && n > 0
}

// lunRefCounts walks the iSCSI fabric ONCE and tallies, per backstore object
// path, how many TPG LUN symlinks resolve to it -- the observable form of the
// kernel's dev->export_count.
//
// SCOPE: the iSCSI fabric only. dev->export_count is incremented by
// core_dev_export() from core_tpg_add_lun() for ANY fabric module (loopback,
// vhost, srpt, ...), so a backstore also exported through one of those counts
// 0 here. That is a deliberate, bounded inaccuracy: this appliance owns an
// iSCSI target and nothing else, and the error direction is the safe one --
// a LUN symlink existing strictly implies export_count > 0, so this can
// never claim "exported" about an object that is not. Under-counting only
// makes an EINVAL fatal that could have been tolerated, which is loud.
//
// Walked rather than cached because a stale answer here decides whether a
// real fault is reported or swallowed.
//
// The walk is O(total LUNs), so running it per backstore makes any caller with
// a backstore loop O(N * total LUNs) -- at appliance scale that is the whole
// benefit of the incremental path spent on a read-only check. Callers needing
// the answer for more than one backstore must call this once and index it.
func (a *applyCtx) lunRefCounts() (map[string]int, error) {
	iqns, err := a.fs.ReadDir("iscsi")
	if err != nil {
		if os.IsNotExist(err) {
			// No iSCSI fabric at all means nothing can be exported. That is a
			// definite answer of zero, not a failure to determine one.
			return map[string]int{}, nil
		}
		return nil, err
	}
	counts := map[string]int{}
	for _, iqn := range iqns {
		tpgs, err := a.fs.ReadDir("iscsi", iqn)
		if err != nil {
			// "iscsi" also holds non-target entries (discovery_auth,
			// lio_version), so a not-a-directory or gone-away error is
			// expected and skipped. Anything else is a real read failure and
			// must NOT be quietly treated as "no LUNs here": an undercount
			// turns a tolerable EINVAL back into a fatal one.
			if notADir(err) {
				continue
			}
			return nil, err
		}
		for _, tpg := range tpgs {
			if !strings.HasPrefix(tpg, "tpgt_") {
				continue
			}
			luns, err := a.fs.ReadDir("iscsi", iqn, tpg, "lun")
			if err != nil {
				if notADir(err) {
					continue
				}
				return nil, err
			}
			for _, lun := range luns {
				_, target, err := a.fs.FindSymlink("iscsi", iqn, tpg, "lun", lun)
				if err != nil {
					if notADir(err) {
						continue
					}
					return nil, err
				}
				if target != "" {
					counts[target]++
				}
			}
		}
	}
	return counts, nil
}

// countLUNRefs returns the LUN-symlink count for a single backstore. Callers
// with more than one backstore must use lunRefCounts directly.
func (a *applyCtx) countLUNRefs(b Backstore) (int, error) {
	counts, err := a.lunRefCounts()
	if err != nil {
		return 0, err
	}
	return counts[a.fs.Path(b.objPath()...)], nil
}

// notADir reports whether err means "this path is not a directory we can list"
// -- either absent or not a directory at all. Both are ordinary while walking
// a configfs tree that mixes object dirs with plain attribute files.
func notADir(err error) bool {
	return os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR)
}

// AttrDrift is one managed attribute whose desired value the kernel would not
// accept because the backstore is exported.
//
// It carries the LIVE value, not just a description of the problem, because
// two different callers need it. An operator needs the sentence; the reconcile
// engine needs the value, so it can record what it ACTUALLY applied rather
// than what it asked for -- see appliance's applied view. A pre-rendered
// string served the first and silently failed the second.
type AttrDrift struct {
	// Backstore is the object name, matching Backstore.Name.
	Backstore string
	Type      BackstoreType
	// Attr is the attrib/ key, e.g. "block_size".
	Attr string
	// Live is what the kernel currently holds; Desired is what was asked for.
	Live, Desired string
	// Err, when set, means the live value could NOT be determined -- the
	// object or attribute was unreadable. Live is then meaningless and must
	// not be treated as an applied value. Reported rather than skipped:
	// silence would render an unreadable device as a converged one, which is
	// the fail-open this check exists to prevent. Attr is empty when the
	// failure was about the object rather than one attribute.
	Err error
}

// String renders the drift for an operator. block_size is escalated over the
// other managed attributes because the consequences are not comparable:
// optimal_sectors drift costs an alignment hint that consumers already have a
// convention for, whereas block_size drift means the REST API reports one
// geometry while the initiator sees another -- the exact lie the block-size
// work exists to prevent -- so it is named as such rather than filed
// alongside routine tuning drift.
func (d AttrDrift) String() string {
	id := "backstore/" + string(d.Type) + "/" + d.Backstore
	if d.Err != nil {
		what := "the backstore"
		if d.Attr != "" {
			what = "attrib/" + d.Attr
		}
		return fmt.Sprintf(
			"%s: %s could not be read (%v) -- whether the live device matches the "+
				"desired configuration is UNKNOWN", id, what, d.Err)
	}
	if d.Attr == "block_size" {
		return fmt.Sprintf(
			"%s: GEOMETRY MISMATCH -- the live device has block_size %s but %s is the desired "+
				"value; initiators see %s while the desired configuration says %s. It cannot be changed "+
				"while the volume is exported; unexport it (an operator decision about a device "+
				"an initiator may have mounted) to converge",
			id, d.Live, d.Desired, d.Live, d.Desired)
	}
	if d.Attr == "emulate_write_cache" {
		mode, claim := "write-through (O_DSYNC)", "no cache"
		if d.Live == "1" {
			mode, claim = "buffered (page cache)", "a volatile cache"
		}
		return fmt.Sprintf(
			"%s: WRITE CACHE MODE MISMATCH -- the live backing mode is %s, which is fixed when "+
				"the object is created and cannot be changed on a live device. "+
				"emulate_write_cache is held at %s so the initiator is honestly told there is %s; "+
				"the requested value %s would make the device lie about its durability. "+
				"The mode converges on the next boot, when the backstore is rebuilt from the "+
				"desired config",
			id, mode, d.Live, claim, d.Desired)
	}
	return fmt.Sprintf(
		"%s: attrib/%s is %s, wanted %s -- immutable while the volume is exported, left alone",
		id, d.Attr, d.Live, d.Desired)
}

// driftUnknown records that the live value could not be read. Deliberately
// the same channel as driftNote: an operator asking "does the kernel match?"
// must not get "yes" when the answer is "could not tell".
func (a *applyCtx) driftUnknown(b Backstore, key string, err error) {
	a.drift = append(a.drift, AttrDrift{
		Backstore: b.Name, Type: b.Type, Attr: key, Err: err,
	})
}

func (a *applyCtx) driftNote(b Backstore, key, cur, want string) {
	a.drift = append(a.drift, AttrDrift{
		Backstore: b.Name, Type: b.Type, Attr: key, Live: cur, Desired: want,
	})
}

// ensureBackstore reconciles a single core backstore.
//
// fileio create sequence, in the order the kernel requires:
//
//	mkdir core/<plugin>_<hba>            # HBA
//	mkdir core/<plugin>_<hba>/<name>     # storage object
//	control  <- fd_dev_name=<dev>,fd_dev_size=<bytes>
//	udev_path<- <dev>
//	enable   <- 1
func (a *applyCtx) ensureBackstore(b Backstore) error {
	id := "backstore/" + string(b.Type) + "/" + b.Name
	if err := b.validate(); err != nil {
		return errf(KindInvalidSpec, "apply", id, err)
	}

	// Already configured?
	if ok, err := a.fs.Exists(b.objPath()...); err != nil {
		return errf(KindConfigfs, "apply", id, err)
	} else if ok {
		// The read error is NOT discarded, but ABSENT and UNREADABLE are
		// different answers and only one of them is fatal.
		//
		// ENOENT means the object directory carries no enable attribute, so
		// nothing is enabled and the create path below is correct. Any other
		// error -- EACCES, EIO -- means the state could not be determined,
		// and falling through then runs the create path against an object
		// that may be ENABLED AND EXPORTED, where the control write sets
		// fd_dev_size on a live device before the pass fail-stops.
		//
		// "Could not tell" is not "not enabled". Refusing is the over-fence
		// direction: it leaves the tree as it was, while guessing wrong
		// mutates a device an initiator is using.
		enabled, err := a.fs.ReadAttr(append(b.objPath(), "enable")...)
		if err != nil && !os.IsNotExist(err) {
			return errf(KindConfigfs, "apply", id,
				wrapf("the object exists but its enable state could not be read: %v", err))
		}
		if enabled == "1" {
			cur, err := a.fs.ReadAttr(append(b.objPath(), "udev_path")...)
			if err != nil {
				return errf(KindConfigfs, "apply", id, err)
			}
			if cur != b.Dev {
				return errf(KindIncompatible, "apply", id,
					wrapf("backing path is %q, want %q", cur, b.Dev))
			}
			// Reconcile mutable identity/attributes on the live object.
			return a.reconcileBackstoreMutable(b, id)
		}
	}

	// Create + configure.
	if err := a.fs.Mkdir(b.hbaPath()...); err != nil {
		return errf(classifyCreate(err, KindConfigfs), "apply", id, err)
	}
	if err := a.fs.Mkdir(b.objPath()...); err != nil {
		return errf(classifyCreate(err, KindConfigfs), "apply", id, err)
	}

	control, err := b.controlString()
	if err != nil {
		return errf(KindInvalidSpec, "apply", id, err)
	}
	if err := a.fs.WriteAttr(control, append(b.objPath(), "control")...); err != nil {
		return errf(KindKernelRejected, "apply", id, err)
	}
	if err := a.fs.WriteAttr(b.Dev, append(b.objPath(), "udev_path")...); err != nil {
		return errf(KindKernelRejected, "apply", id, err)
	}
	// Restore saved SCSI-3 PR state, if any, BEFORE enabling the object.
	//
	// Ordering here is a safety property, not a preference. The kernel
	// accepts this write until the device is exported, so it would also
	// succeed just after enable — but then a FAILED restore would leave an
	// enabled backstore behind, the next pass would take the already-enabled
	// early return above, never re-run the provider, and export a LUN whose
	// reservations were never restored. That is the exact split-brain this
	// feature exists to prevent, and because applianced runs under
	// Restart=on-failure it would be reached automatically and come up green.
	//
	// Writing first makes the failure residue safe: enable is never reached,
	// so the next Apply falls through to this create path and genuinely
	// retries. Fail-stop is only sound when re-reconvergence retries the step
	// that failed.
	//
	// Verified on a live target that a record written pre-enable survives
	// enable and still binds when the ACL mapped LUN appears.
	if err := a.loadAPTPL(b, id); err != nil {
		return err
	}
	if err := a.fs.WriteAttr("1", append(b.objPath(), "enable")...); err != nil {
		return errf(KindKernelRejected, "apply", id, err)
	}
	// Everything below is set AFTER enable but BEFORE the backstore is
	// LUN-mapped (all are immutable once exported). block_size in
	// particular is RESET to the backing-device default if written
	// before enable, so it must be written here.
	for _, k := range sortedKeys(b.Attributes) {
		if err := a.fs.WriteAttr(b.Attributes[k], append(b.objPath(), "attrib", k)...); err != nil {
			return errf(KindKernelRejected, "apply", id+" attrib/"+k, err)
		}
	}
	for _, f := range b.wwnDirFields() {
		if f.val == "" {
			continue
		}
		if err := a.fs.WriteAttr(f.val, append(b.objPath(), "wwn", f.key)...); err != nil {
			return errf(KindKernelRejected, "apply", id+" wwn/"+f.key, err)
		}
	}
	if b.WWN != "" {
		if err := a.fs.WriteAttr(b.WWN, append(b.objPath(), "wwn", "vpd_unit_serial")...); err != nil {
			return errf(KindKernelRejected, "apply", id, err)
		}
	}
	a.note("created " + id)
	return nil
}

// loadAPTPL restores saved SCSI-3 Persistent Reservation registrations onto
// a just-created backstore, via the provider installed by
// Manager.SetAPTPLRecords. It is a no-op when no provider is set or the
// provider returns no records.
//
// Records are written one per write: the kernel parses a single
// registration per store and rejects anything it cannot tokenise with
// EINVAL. Note this is NOT the format the kernel itself writes to
// db_root/pr/aptpl_<wwn> — that file frames records with PR_REG_START /
// PR_REG_END marker lines, which are not valid input here and must be
// stripped by the caller.
func (a *applyCtx) loadAPTPL(b Backstore, id string) error {
	if a.aptplRecords == nil {
		return nil
	}
	recs, err := a.aptplRecords(b)
	if err != nil {
		return errf(KindInvalidSpec, "apply", id+" pr/res_aptpl_metadata", err)
	}
	for _, rec := range recs {
		if strings.TrimSpace(rec) == "" {
			continue
		}
		if err := a.fs.WriteAttr(rec, append(b.objPath(), "pr", "res_aptpl_metadata")...); err != nil {
			return errf(KindKernelRejected, "apply", id+" pr/res_aptpl_metadata", err)
		}
		a.note("restored PR registration on " + id)
	}
	return nil
}

// verifyAPTPL compares the SCSI-3 PR registrations saved on disk against the
// ones actually live in the kernel, for every backstore in the config.
//
// It must run AFTER the targets are applied: loading a record does not
// activate it, the kernel holds it dormant and binds it when the matching
// ACL mapped LUN is created. Anything still unbound at that point never
// will be, because its saved coordinates no longer match the topology.
//
// It checks EVERY backstore rather than only the ones replayed on this pass.
// Records are replayed only at creation, so a steady-state reconcile replays
// nothing — and if this only reported what it had just replayed, the very
// next reconcile would silently erase the warning while the reservation was
// still missing. The condition is a property of the tree, not of one pass.
//
// The provider is a pure data source, so consulting it here is a cheap file
// read and safe to repeat; only the WRITE is restricted to creation.
//
// Only pr/res_aptpl_metadata is write-only; the live registrations and the
// reservation holder are readable, which is what makes this check possible.
//
// Matching is by IDENTITY, not by count — see aptplcheck.go for why counting
// both over- and under-reports. Records whose export no longer exists are
// deliberately silent here: they are the residue of an operator detaching a
// host, and reporting them produces a permanent alarm for a routine action.
func (a *applyCtx) verifyAPTPL(cfg Config) []string {
	if a.aptplRecords == nil {
		return nil
	}
	var out []string
	for _, b := range cfg.Backstores {
		out = append(out, a.verifyBackstoreAPTPL(cfg, b)...)
	}
	return out
}

func (a *applyCtx) verifyBackstoreAPTPL(cfg Config, b Backstore) []string {
	id := "backstore/" + string(b.Type) + "/" + b.Name
	recs, err := a.aptplRecords(b)
	if err != nil {
		// Not fatal here -- this is a report channel, not a failure
		// channel, and a steady-state reconcile should not be brought
		// down by it. But it must be SAID: a file that becomes damaged
		// or unreadable AFTER its backstore was created is otherwise
		// reported by nothing at all, and the first symptom would be the
		// appliance failing to start at the next restart. Staying silent
		// here would re-introduce the absent/unreadable/damaged
		// conflation this package went to some trouble to remove.
		return []string{fmt.Sprintf(
			"%s: saved SCSI-3 PR state could not be read: %v — "+
				"whether any reservation is in effect is UNKNOWN, and this check will "+
				"refuse to start if this backstore is recreated", id, err)}
	}

	// Parse the saved side first, and keep only the records whose export
	// still exists. A record we cannot parse is reported rather than
	// dropped: claiming everything is bound on the strength of a file we
	// could not read would be exactly the fail-open this check exists to
	// prevent.
	var want []aptplRecord
	var lapsedHolder string
	var lapsedType aptplRecord
	var out []string
	for i, rec := range recs {
		if strings.TrimSpace(rec) == "" {
			continue
		}
		r, err := parseAPTPLRecord(rec)
		if err != nil {
			out = append(out, fmt.Sprintf(
				"%s: saved SCSI-3 PR record %d is unparsable (%v) — "+
					"whether the reservation it describes is in effect is UNKNOWN", id, i, err))
			continue
		}
		switch {
		case r.exported(cfg, b):
			want = append(want, r)
		case r.Holder:
			// A saved RESERVATION HOLDER whose own export is gone is not
			// simply stale, unlike a plain registration. A registration is
			// the registering initiator's own claim and dies with it. A
			// reservation is a restriction imposed on EVERYONE ELSE, so
			// losing it changes what the remaining initiators may do: detach
			// the holder and a previously-fenced node can write again.
			//
			// Remembered rather than reported here, because whether it
			// matters depends on the rest of the tree -- see below.
			lapsedHolder, lapsedType = r.Initiator, r
		}
	}
	if len(want) == 0 && len(out) == 0 && lapsedHolder == "" {
		return nil
	}

	live, err := a.fs.ReadAttr(append(b.objPath(), "pr", "res_pr_registered_i_pts")...)
	if err != nil {
		return append(out, fmt.Sprintf(
			"%s: %d SCSI-3 PR registration(s) are saved and still exported but could not be read back: %v",
			id, len(want), err))
	}
	regs, unparsed := parseRegistrations(live)
	if unparsed > 0 {
		// Distinguished from "not registered" on purpose: this one is a bug
		// in the parser or a kernel format change, and answering it by
		// declaring the reservation missing would send an operator chasing
		// a fencing fault that is not there.
		out = append(out, fmt.Sprintf(
			"%s: %d line(s) of the kernel's live SCSI-3 PR registrations could not be parsed — "+
				"treat any registration conclusion for this backstore as UNRELIABLE", id, unparsed))
	}
	haveReg := make(map[liveReg]bool, len(regs))
	for _, g := range regs {
		haveReg[g] = true
	}

	for _, r := range want {
		if !haveReg[liveReg{Initiator: r.Initiator, Key: r.Key}] {
			out = append(out, fmt.Sprintf(
				"%s: saved SCSI-3 PR registration for initiator %s (key 0x%x) is still exported "+
					"at mapped LUN %d but is NOT live — any reservation relied on for fencing is NOT in effect",
				id, r.Initiator, r.Key, r.MappedLUN))
		}
	}

	// The holder gets its own check. It is the record that decides who is
	// locked out, and it is precisely what a count cannot see: two live
	// registrations satisfy two saved records while the saved holder sits
	// dormant. res_holder does not render the key, so this matches on
	// initiator identity.
	holder := ""
	for _, r := range want {
		if r.Holder {
			holder = r.Initiator
			break
		}
	}
	if holder == "" && lapsedHolder != "" {
		out = append(out, a.reportLapsedHolder(cfg, b, id, lapsedHolder, lapsedType)...)
	}
	if holder != "" {
		got, err := a.fs.ReadAttr(append(b.objPath(), "pr", "res_holder")...)
		switch {
		case err != nil:
			out = append(out, fmt.Sprintf(
				"%s: a saved SCSI-3 RESERVATION HOLDER (%s) is still exported but the live holder "+
					"could not be read back: %v", id, holder, err))
		default:
			// An uninterpretable rendering yields "" here, which will not equal
			// the saved holder and so reports the reservation as unbound. That
			// is the over-reporting direction and is deliberate.
			if liveHolder, _, _ := parseHolder(got); liveHolder != holder {
				out = append(out, fmt.Sprintf(
					"%s: the saved SCSI-3 RESERVATION HOLDER is %s but the live holder is %q — "+
						"the reservation that fences every other initiator is NOT in effect",
					id, holder, liveHolder))
			}
		}
	}
	return out
}

// reportLapsedHolder describes a saved reservation HOLDER whose own export is
// gone, when that matters.
//
// It is separated out because it is the one place in this file that makes a
// claim about FENCING CONSEQUENCES rather than about kernel binding, and three
// separate defects lived here. Each guard below exists because of one.
//
// The live holder is read FIRST, and silence is the answer whenever one
// exists. That is not defensive coding, it is required: removing a mapped LUN
// calls __core_scsi3_complete_pro_release(..., unreg=1), and for the
// ALL_REGISTRANTS types that path does not release the reservation at all --
// it TRANSFERS it to the next registrant
// (linux v6.6 drivers/target/target_core_pr.c:2471-2480). Reporting without
// looking would therefore announce that a reservation is not in effect while
// it demonstrably is; and because promotion is not a PR OUT the kernel never
// rewrites the saved file, so that false alarm would be PERMANENT -- the exact
// unclearable-alarm class this whole check exists to remove.
//
// The survivor count comes from the config topology, never from the saved
// records. An initiator that never registered has no saved record, and under
// the registrants-only types it is exactly the population the reservation was
// excluding, so counting saved records would go silent precisely when this
// matters most.
func (a *applyCtx) reportLapsedHolder(cfg Config, b Backstore, id, lapsed string, rec aptplRecord) []string {
	survivors := exportedMappings(cfg, b, lapsed)
	if survivors == 0 {
		// Nothing else can reach the device, so nothing is newly permitted.
		return nil
	}

	live, err := a.fs.ReadAttr(append(b.objPath(), "pr", "res_holder")...)
	if err != nil {
		return []string{fmt.Sprintf(
			"%s: the saved SCSI-3 RESERVATION HOLDER (%s) is no longer exported and the live "+
				"holder could not be read back (%v) — whether a reservation still protects the "+
				"%d remaining initiator mapping(s) is UNKNOWN", id, lapsed, err, survivors)}
	}
	// known is deliberately ignored: an unreadable rendering gives h == "",
	// which falls through to REPORT a possible loss of protection rather than
	// returning nil. Over-reporting is the safe direction here.
	if h, _, _ := parseHolder(live); h != "" {
		// Somebody still holds it: either the kernel promoted a surviving
		// registrant (ALL_REG), or another initiator reserved in the
		// meantime. Either way the device is still protected.
		return nil
	}

	return []string{fmt.Sprintf(
		"%s: the saved SCSI-3 RESERVATION HOLDER (%s) is no longer exported and no reservation "+
			"is held — %d initiator mapping(s) remain exported here and %s are no longer "+
			"excluded; a surviving initiator that reserves clears this",
		id, lapsed, survivors, rec.excluded())}
}

// wwnDirFields are the plain writable identity strings under the wwn/
// directory (vpd_unit_serial is handled separately — it is written
// post-enable and reads back with a "T10 ...:" prefix).
//
// These are compared to the live value with a plain string equality, which is
// safe because the kernel does NOT space-pad them on readback. That was
// questioned on the reasoning that INQUIRY data is fixed-width (vendor 8,
// product 16) and target_core_dev.c pads the in-memory field, which would
// have made every reconcile rewrite an identity that never changed and left
// Apply permanently non-idempotent.
//
// MEASURED instead of reasoned, on Azure Linux 3.0, kernel 6.6.144.1-1.azl3:
// writing "LIO-ORG", "AB" and "EXACTLY8" to wwn/vendor_id, and "SHORT" and
// "IIVM" to wwn/product_id, each reads back byte-exact with only the trailing
// newline that ReadAttr already strips — no padding at any length, including
// one exactly filling the field. The padding lives in the INQUIRY response the
// initiator sees, not in the configfs attribute. If a future kernel changes
// that, this comparison is where it will show up, as a change note repeated on
// every reconcile.
func (b Backstore) wwnDirFields() []struct{ key, val string } {
	return []struct{ key, val string }{
		{"vendor_id", b.VendorID},
		{"product_id", b.ProductID},
		{"revision", b.Revision},
	}
}

// constrainWriteCache returns the managed attributes to apply, with
// emulate_write_cache forced to agree with the LIVE backing mode whenever the
// two have diverged, recording drift when it overrides.
//
// This closes a hole the create path cannot see. BufferedIO reaches the kernel
// through the control string and is create-time only, but emulate_write_cache
// is an ordinary mutable attribute that this function rewrites on every
// reconcile. configfs is kernel memory and survives a daemon restart, so
// running with buffered IO, changing the desired setting and restarting used
// to write WCE=0 onto a backstore that is still open without O_DSYNC: writes
// acknowledged from volatile page cache while the initiator is told there is
// no cache to flush. MEASURED on Azure Linux 3.0, kernel 6.6.144.1 -- the
// write is accepted, because emulate_write_cache_store has no export_count
// guard and refuses only when transport->get_write_cache is defined, which
// fileio does not define (linux v6.6 drivers/target/target_core_device.c,
// target_core_file.c).
//
// Deriving both halves from one setting makes the combination unrepresentable
// only for a NEW object; this makes it unreachable for a live one too.
//
// The override is deliberately toward the live mode in BOTH directions,
// because in both the live mode is the truth and the attribute is the claim:
//
//	live buffered, write-through wanted -> hold WCE=1: honestly advertise the
//	    volatile cache, so the initiator keeps flushing it.
//	live O_DSYNC, write-back wanted     -> hold WCE=0: the device really has
//	    no cache to flush; claiming one would invite pointless flushes.
//
// Neither is what the operator asked for, so both are reported as drift. The
// mode itself converges on the next boot, when configfs is empty and the
// backstore is rebuilt from the desired config -- the same self-healing path
// as optimal_sectors drift.
func (a *applyCtx) constrainWriteCache(b Backstore, info string) map[string]string {
	const key = "emulate_write_cache"
	want, managed := b.Attributes[key]
	if !managed || b.Type != FileIO || info == "" {
		return b.Attributes
	}
	mode := parseInfoMode(info)
	if mode == "" {
		return b.Attributes
	}
	live := "0"
	if mode == "Buffered-WCE" {
		live = "1"
	}
	if live == want {
		return b.Attributes
	}
	a.driftNote(b, key, live, want)
	out := make(map[string]string, len(b.Attributes))
	maps.Copy(out, b.Attributes)
	out[key] = live

	return out
}

// reconcileBackstoreMutable updates the identity, managed attributes and
// (growable) size on an already-enabled backstore, noting only actual
// changes. wwn/vendor/product/revision/block_size are immutable once the
// backstore is LUN-mapped (a mismatch there returns kernel-rejected);
// fd_dev_size is live-growable even while exported.
func (a *applyCtx) reconcileBackstoreMutable(b Backstore, id string) error {
	if b.WWN != "" {
		raw, err := a.fs.ReadAttr(append(b.objPath(), "wwn", "vpd_unit_serial")...)
		if err != nil {
			return errf(KindConfigfs, "apply", id, err)
		}
		if lastField(raw, ':') != b.WWN {
			if err := a.fs.WriteAttr(b.WWN, append(b.objPath(), "wwn", "vpd_unit_serial")...); err != nil {
				return errf(KindKernelRejected, "apply", id+" wwn", err)
			}
			a.note(id + " wwn=" + b.WWN)
		}
	}
	for _, f := range b.wwnDirFields() {
		if f.val == "" {
			continue
		}
		cur, err := a.fs.ReadAttr(append(b.objPath(), "wwn", f.key)...)
		if err != nil {
			return errf(KindConfigfs, "apply", id+" wwn/"+f.key, err)
		}
		if cur != f.val {
			if err := a.fs.WriteAttr(f.val, append(b.objPath(), "wwn", f.key)...); err != nil {
				return errf(KindKernelRejected, "apply", id+" wwn/"+f.key, err)
			}
			a.note(id + " wwn/" + f.key + "=" + f.val)
		}
	}
	// The fileio info line carries two things this function needs -- the
	// backing mode and the served size -- and is read once for both.
	var info string
	if b.Type == FileIO {
		raw, err := a.fs.ReadAttr(append(b.objPath(), "info")...)
		if err != nil {
			return errf(KindConfigfs, "apply", id+" info", err)
		}
		info = raw
	}
	attrs := a.constrainWriteCache(b, info)
	for _, k := range sortedKeys(attrs) {
		want := attrs[k]
		p := append(b.objPath(), "attrib", k)
		cur, err := a.fs.ReadAttr(p...)
		if err != nil {
			return errf(KindConfigfs, "apply", id+" attrib/"+k, err)
		}
		if cur == want {
			continue
		}
		// Check the VALUE before the write, so that a surviving EINVAL means
		// immutability and nothing else. Without this an out-of-range value on
		// an exported device was reported as drift -- "the kernel would not
		// change this because the device is in use" -- about a number the
		// kernel would have refused on an idle device too.
		if verr := a.validateAttr(b, k, want); verr != nil {
			return errf(KindKernelRejected, "apply", id+" attrib/"+k, verr)
		}
		if err := a.fs.WriteAttr(want, p...); err != nil {
			if !a.immutableWhileExported(b, err) {
				return errf(KindKernelRejected, "apply", id+" attrib/"+k, err)
			}
			a.driftNote(b, k, cur, want)
			continue
		}
		a.note(id + " attrib/" + k + "=" + want)
	}
	// Size: grow-only, live (fd_dev_size is writable even when exported).
	if b.Size > 0 && b.Type == FileIO {
		cur := parseInfoSize(info)
		if cur < 0 {
			// An unparsable current size must not be reported as converged:
			// the caller would be told the resize succeeded while the
			// initiator still sees the old capacity.
			return errf(KindConfigfs, "apply", id+" size",
				wrapf("cannot parse size from fileio info %q", info))
		}
		bs := b.blockSize()
		switch {
		case b.Size-b.Size%bs == cur-cur%bs:
			// Already the desired size. Compared FLOORED on both sides
			// because that is the device the kernel actually serves: it
			// derives the last LBA as (size - block_size)/block_size (linux
			// v6.6 drivers/target/target_core_file.c:804-822) and drops any
			// partial trailing block.
			//
			// This matters on upgrade. The kernel stores and reports
			// fd_dev_size verbatim -- MEASURED on Azure Linux 3.0, kernel
			// 6.6.144.1: a backstore created with fd_dev_size=1000000 reports
			// "Size: 1000000", not the floored 999936 it actually serves. So
			// a caller that (correctly) floors a legacy capacity before
			// asking for it would look like it was requesting a SHRINK, and
			// the arm below would fail the reconcile -- crash-looping the
			// daemon against a healthy tree over two numbers describing the
			// same device.
		case b.Size < cur:
			return errf(KindIncompatible, "apply", id,
				wrapf("size %d < current %d (shrink unsupported)", b.Size, cur))
		default:
			if b.Size%bs != 0 {
				return errf(KindInvalidSpec, "apply", id,
					wrapf("size %d is not a multiple of block_size %d; the kernel "+
						"would truncate the trailing partial block", b.Size, bs))
			}
			ctl := "fd_dev_name=" + b.Dev + ",fd_dev_size=" + itoa64(b.Size)
			if err := a.fs.WriteAttr(ctl, append(b.objPath(), "control")...); err != nil {
				return errf(KindKernelRejected, "apply", id+" resize", err)
			}
			a.note(id + " size=" + itoa64(b.Size))
		}
	}
	return nil
}

// blockSize is the logical block size this backstore is configured for, or
// the kernel's fileio default when the caller stated none.
//
// Defaulting rather than skipping matters: the kernel uses 512 whether or not
// the attribute was set, so "no block_size stated" is not "no geometry" and an
// unaligned size still loses its tail. A check that silently does nothing for
// an absent attribute is not a check.
func (b Backstore) blockSize() int64 {
	if v, ok := b.Attributes["block_size"]; ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return defaultBlockSize
}

// defaultBlockSize is the kernel's fileio default (linux v6.6
// drivers/target/target_core_file.c: fd_block_size is 512 for a regular file).
const defaultBlockSize = 512

// controlString builds the fileio/iblock control-attribute payload.
func (b Backstore) controlString() (string, error) {
	switch b.Type {
	case FileIO:
		size := b.Size
		if size == 0 {
			fi, err := os.Stat(b.Dev)
			if err != nil {
				return "", wrapf("cannot stat backing file %q: %v", b.Dev, err)
			}
			if fi.Mode().IsRegular() {
				size = fi.Size()
			}
		}
		// The kernel derives the last LBA as (size - block_size)/block_size
		// (linux v6.6 drivers/target/target_core_file.c:804-822), so a size
		// that is not a whole multiple of the block size silently loses its
		// tail. Check the EFFECTIVE size -- b.Size may be 0 with the real
		// figure coming from the backing file above, and a check against
		// b.Size alone would pass unconditionally in exactly that case.
		//
		// b.blockSize() DEFAULTS to 512 when no attribute was stated, because
		// that is what the kernel uses either way: reading the attribute
		// directly and skipping the check when it is absent made this a check
		// that quietly did nothing for any caller that did not state a
		// geometry, while the kernel still truncated.
		//
		// This is on the create path on purpose: it refuses to bring a short
		// device into existence, without giving a pre-existing unaligned
		// volume the power to fail a whole-tree reconcile (see validate.go).
		if size > 0 {
			if bs := b.blockSize(); size%bs != 0 {
				return "", wrapf("size %d is not a multiple of block_size %d; the kernel "+
					"would truncate the trailing partial block", size, bs)
			}
			return "fd_dev_name=" + b.Dev + ",fd_dev_size=" + itoa64(size) + b.bufferedOpt(), nil
		}
		return "fd_dev_name=" + b.Dev + b.bufferedOpt(), nil
	case IBlock:
		return "udev_path=" + b.Dev, nil
	default:
		return "", wrapf("unsupported backstore type %q", b.Type)
	}
}

// bufferedOpt is the control-string fragment selecting the fileio backend's
// buffered mode. Empty means the default, which opens the backing file
// O_DSYNC so an acknowledged write is on stable storage.
func (b Backstore) bufferedOpt() string {
	if b.BufferedIO {
		return ",fd_buffered_io=1"
	}
	return ""
}

// removeBackstore deletes a backstore (object dir then its HBA dir).
func (a *applyCtx) removeBackstore(b Backstore) error {
	id := "backstore/" + string(b.Type) + "/" + b.Name
	if err := a.fs.Rmdir(b.objPath()...); err != nil {
		return errf(classifyRemove(err, KindBusy), "remove", id, err)
	}
	// Best-effort HBA removal; it may be shared or already gone.
	_ = a.fs.Rmdir(b.hbaPath()...)
	a.note("removed " + id)
	return nil
}

// discoveredBackstoreAttrs are the managed attrib/* keys Discover reads back
// so save/restore round-trips them (Apply re-enforces them post-enable). An
// explicit list — not "read every attrib/*" — because most attributes are
// read-only or noise; only the ones we manage need faithful replay.
//
// block_size and optimal_sectors are immutable once the backstore is exported,
// so both are written in the same post-enable, pre-LUN-map window.
// emulate_write_cache is not immutable, but it must be discovered anyway: it
// is half of the write-cache weld, and a saved config that omitted it restored
// a write-back device as write-through. See discoverBackstores for the other
// half, which is not an attribute at all.
var discoveredBackstoreAttrs = []string{"block_size", "emulate_write_cache", "optimal_sectors"}

// discoverBackstores enumerates core/*_*/<name> storage objects.
func discoverBackstores(fs *configfs.FS) ([]Backstore, error) {
	hbas, err := fs.ReadDir("core")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, errf(KindConfigfs, "discover", "core", err)
	}
	var out []Backstore
	for _, hba := range hbas {
		plugin, idx, ok := splitLast(hba, '_')
		if !ok {
			continue
		}
		hbaIdx, ok := atoi(idx)
		if !ok {
			continue
		}
		objs, err := fs.ReadDir("core", hba)
		if err != nil {
			return nil, errf(KindConfigfs, "discover", "core/"+hba, err)
		}
		for _, name := range objs {
			if isDir, err := fs.IsDir("core", hba, name); err != nil {
				return nil, errf(KindConfigfs, "discover", "core/"+hba+"/"+name, err)
			} else if !isDir {
				continue // hba_info, hba_mode files
			}
			b := Backstore{Type: BackstoreType(plugin), HBA: hbaIdx, Name: name}
			id := "core/" + hba + "/" + name
			// udev_path and vpd_unit_serial carry device identity: an
			// unreadable value must not become an empty Dev/WWN, which a
			// save/restore round-trip would then write to the kernel. A
			// genuinely ABSENT attribute (ENOENT — not exposed by this
			// plugin/kernel) is different and is tolerated.
			dev, err := fs.ReadAttr("core", hba, name, "udev_path")
			if err != nil && !os.IsNotExist(err) {
				return nil, errf(KindConfigfs, "discover", id+" udev_path", err)
			}
			b.Dev = dev
			serial, err := fs.ReadAttr("core", hba, name, "wwn", "vpd_unit_serial")
			if err != nil && !os.IsNotExist(err) {
				return nil, errf(KindConfigfs, "discover", id+" vpd_unit_serial", err)
			}
			if err == nil {
				b.WWN = lastField(serial, ':')
			}
			// Same rule as udev_path/vpd_unit_serial above: absent is
			// tolerated, unreadable is reported. These three are the SCSI
			// inquiry identity, so swallowing a read error turns them into
			// empty strings that a save/restore round-trip writes back to the
			// kernel -- silently re-identifying the device to initiators that
			// key on it.
			optIdent := func(attr string, dst *string) error {
				v, err := fs.ReadAttr("core", hba, name, "wwn", attr)
				if err != nil {
					if os.IsNotExist(err) {
						return nil
					}
					return errf(KindConfigfs, "discover", id+" "+attr, err)
				}
				*dst = v
				return nil
			}
			if err := optIdent("vendor_id", &b.VendorID); err != nil {
				return nil, err
			}
			if err := optIdent("product_id", &b.ProductID); err != nil {
				return nil, err
			}
			if err := optIdent("revision", &b.Revision); err != nil {
				return nil, err
			}
			// info carries BOTH the size and the backing mode. An unreadable
			// info therefore produces exactly the harm the comment below
			// warns about -- a buffered device restored as O_DSYNC -- so it
			// cannot be swallowed either.
			info, err := fs.ReadAttr("core", hba, name, "info")
			if err != nil && !os.IsNotExist(err) {
				return nil, errf(KindConfigfs, "discover", id+" info", err)
			}
			if err == nil {
				// An info line that is PRESENT but not interpretable is the
				// same problem as one that could not be read, and is refused
				// for the same reason. The kernel formats it as prose with no
				// compatibility promise, so a wording change makes both
				// values below unrecoverable -- and both then default to
				// something plausible rather than something true.
				sz := parseInfoSize(info)
				if sz < 0 {
					return nil, errf(KindConfigfs, "discover", id+" info", fmt.Errorf(
						"cannot read the size out of %q", strings.TrimSpace(info)))
				}
				if sz > 0 {
					b.Size = sz
				}
				// The backing mode is create-time and has no attribute, so
				// the info line is the ONLY place it can be recovered from
				// (linux v6.6 drivers/target/target_core_file.c:963-966).
				// Without this a saved config restored a buffered device as
				// O_DSYNC: a silent change of the durability contract the
				// operator chose, which reconcile would then be unable to
				// correct because the mode is fixed at create time.
				//
				// Unknown is refused rather than resolved to false. false
				// means O_DSYNC, which is a claim that every write reaches
				// stable storage -- so guessing it for a device whose mode we
				// could not determine asserts a durability the device may not
				// have, which is the wrong direction to be wrong in.
				switch mode := parseInfoMode(info); mode {
				case "Buffered-WCE":
					b.BufferedIO = true
				case "O_DSYNC":
					b.BufferedIO = false
				default:
					return nil, errf(KindConfigfs, "discover", id+" info", fmt.Errorf(
						"cannot read the backing mode out of %q", strings.TrimSpace(info)))
				}
			}
			// A managed attribute that cannot be READ must not be discovered
			// as absent: reconcile would see drift against desired and try to
			// write a value the kernel may refuse once exported, or a
			// save/restore would drop it. Not every attribute is exposed by
			// every plugin or kernel, so absent stays ordinary.
			for _, k := range discoveredBackstoreAttrs {
				v, err := fs.ReadAttr("core", hba, name, "attrib", k)
				if err != nil {
					if os.IsNotExist(err) {
						continue
					}
					return nil, errf(KindConfigfs, "discover", id+" attrib/"+k, err)
				}
				if b.Attributes == nil {
					b.Attributes = map[string]string{}
				}
				b.Attributes[k] = v
			}
			out = append(out, b)
		}
	}
	return out, nil
}

// VerifyDrift reports managed attributes that differ from the desired config
// on backstores the kernel will not let us change, without writing anything.
//
// This is the read-only counterpart to the drift that Apply/Sync report as a
// side effect of trying, and it exists because the incremental path does not
// try. ApplyDelta only visits backstores whose desired config CHANGED, so its
// Report.Drift describes that subset -- and drift is a standing condition
// covering the whole tree. Publishing the delta's view would erase the
// standing one: a fleet with forty drifted volumes would show them at startup,
// then have them silently vanish from /health the moment an unrelated host was
// attached, because that delta touched nothing drifted.
//
// The sibling signal already learned this. See the comment at the VerifyAPTPL
// call in appliance: "the incremental path must do it explicitly or the
// pr_unbound signal goes stale."
//
// An ABSENT object is skipped: this answers "what is knowably wrong", and a
// backstore that does not exist yet is the reconcile's job, not a standing
// condition. An UNREADABLE one is reported, not skipped. The two used to be
// conflated by `err != nil || !ok`, which rendered EACCES/EIO as "converged"
// -- a fail-open in the one signal whose entire job is to say the live device
// disagrees with what this appliance claims about it. countLUNRefs was
// hardened against exactly this conflation and its new caller reintroduced it
// at the call site.
func (m *Manager) VerifyDrift(cfg Config) []AttrDrift {
	a := &applyCtx{fs: m.fs}
	// One fabric walk for the whole config. Per-backstore it was O(N * total
	// LUNs) of configfs syscalls under the caller's lock.
	counts, cerr := a.lunRefCounts()
	for _, b := range cfg.Backstores {
		if cerr != nil {
			a.driftUnknown(b, "", fmt.Errorf("cannot determine whether the backstore is exported: %w", cerr))
			continue
		}
		ok, err := m.fs.Exists(b.objPath()...)
		if err != nil {
			a.driftUnknown(b, "", err)
			continue
		}
		if !ok {
			continue
		}
		// Only an EXPORTED backstore can hold drift: on an unexported one the
		// kernel would accept the write, so any difference is simply not
		// reconciled yet.
		if counts[m.fs.Path(b.objPath()...)] == 0 {
			continue
		}
		for _, k := range sortedKeys(b.Attributes) {
			cur, err := m.fs.ReadAttr(append(b.objPath(), "attrib", k)...)
			if err != nil {
				a.driftUnknown(b, k, err)
				continue
			}
			if cur == b.Attributes[k] {
				continue
			}
			a.driftNote(b, k, cur, b.Attributes[k])
		}
	}
	return a.drift
}

// validateAttr rejects a value the kernel would refuse for a REASON OTHER THAN
// immutability, before the write is attempted.
//
// It exists because the kernel returns a bare EINVAL for two unrelated things:
// "this attribute is immutable while the device is exported" and "this value
// is out of range". Apply treats EINVAL on an exported backstore as
// immutability drift, so an out-of-range value on an exported device was
// reported as drift -- an operator told the device is busy when the real
// problem is the number they supplied. Checking the value first means a
// surviving EINVAL genuinely is immutability -- FOR THE KEYS BELOW. That scope
// limit is real and worth stating plainly: immutableWhileExported takes no key
// (see its definition), so it answers "EINVAL on an exported object" for ANY
// attribute. For a key this function does not model, an out-of-range value on
// an exported device is therefore STILL reported as immutability drift,
// exactly as before. Backstore.Attributes is a raw public map, so such keys
// are reachable from a hand-written config through lish.
//
// The allowed sets are MEASURED, not assumed, on Azure Linux 3.0 kernel
// 6.6.144.1-1.azl3 against an enabled, unexported fileio backstore:
//
//	block_size          512, 1024, 2048, 4096 accepted; 256 and 8192 rejected
//	emulate_write_cache 0 and 1 accepted; 2 rejected
//	optimal_sectors     0..hw_max_sectors accepted; hw_max_sectors+1 rejected
//
// Those measurements match the kernel's own parsers, which is why they are
// trusted beyond the one machine they were taken on: block_size is checked
// against the same four values at linux v6.6
// drivers/target/target_core_configfs.c:1119-1129, and optimal_sectors against
// da->hw_max_sectors at :1088-1094.
//
// emulate_write_cache is DELIBERATELY STRICTER THAN THE KERNEL. The kernel
// parses it with kstrtobool (v6.6 target_core_configfs.c:692), which also
// accepts y/n/t/f/on/off/true/false; this takes 0 and 1 only. That is a
// narrowing of a raw library API and it is not free -- it refuses input the
// kernel would accept. Kept because every producer here emits 0/1
// (callers emit a canonical 0/1; discovery reads back 0/1), because the
// cur != want comparison that guards the write is a string equality only 0/1
// can satisfy, and because the failure is a refusal rather than a wrong write.
// A caller needing the kernel's full spelling set should send 0/1.
//
// The first probe of this got optimal_sectors wrong -- every value but 0 was
// refused -- because it ran against a backstore that had been created but not
// ENABLED, and the limit derives from hw_max_sectors, which is not set until
// configure. That is why the bound is read from the device rather than written
// down: it is a runtime property (16384 for fileio here, being FD_MAX_BYTES /
// 512), so a constant would be wrong on any device with a different limit.
//
// An attribute this does not know is passed through unvalidated. Guessing at a
// set for it would invent rejections the kernel would not make, which is worse
// than the ambiguity being fixed -- but see the scope note above for what that
// choice costs.
func (a *applyCtx) validateAttr(b Backstore, key, val string) error {
	switch key {
	case "block_size":
		switch val {
		case "512", "1024", "2048", "4096":
			return nil
		}
		return fmt.Errorf("block_size %q is not one of 512, 1024, 2048, 4096", val)
	case "emulate_write_cache":
		if val == "0" || val == "1" {
			return nil
		}
		return fmt.Errorf("emulate_write_cache %q is not 0 or 1", val)
	case "optimal_sectors":
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 {
			return fmt.Errorf("optimal_sectors %q is not a non-negative integer", val)
		}
		// The ceiling is per-device. If it cannot be read, do NOT invent a
		// limit: an unreadable bound is not evidence the value is wrong, and
		// rejecting here would turn a read failure into a bogus config error.
		raw, rerr := a.fs.ReadAttr(append(b.objPath(), "attrib", "hw_max_sectors")...)
		if rerr != nil {
			return nil
		}
		maxSectors, cerr := strconv.Atoi(raw)
		if cerr != nil || maxSectors <= 0 {
			return nil
		}
		if n > maxSectors {
			return fmt.Errorf("optimal_sectors %d exceeds this device's hw_max_sectors (%d)", n, maxSectors)
		}
		return nil
	}
	return nil
}
