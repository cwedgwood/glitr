package appliance

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/cwedgwood/glitr/lio"
)

// SCSI-3 Persistent Reservation state (APTPL — Activate Persist Through
// Power Loss) is persisted by the kernel itself, as db_root/pr/aptpl_<wwn>,
// but the kernel never reads those files back. Reloading them is a
// userspace job, and this file is that job.
//
// The split of responsibility is deliberate:
//
//   - the kernel saves (we get durability across a reboot for free, and
//     could not reconstruct the records ourselves anyway — they are
//     authored by initiators at runtime);
//   - this package locates and parses the saved file (it knows db_root);
//   - lio writes the records to configfs at the one instant the kernel
//     accepts them (see lio.Manager.SetAPTPLRecords).
//
// The file's framing is NOT the format the kernel accepts back. It writes
// records delimited by "PR_REG_START: N" / "PR_REG_END: N" marker lines,
// which are not valid input — feeding the file back verbatim is rejected
// with EINVAL. Each record must be stripped of its markers and supplied as
// one comma-joined key=value list.

// APTPLProvider returns a provider suitable for
// lio.Manager.SetAPTPLRecords, reading saved PR registrations from
// dbRoot/pr/aptpl_<wwn>.
//
// A backstore with no WWN, or with no saved file, yields no records: both
// are normal (a volume that never had a reservation has no file). Every
// other outcome fails the apply rather than silently dropping reservations
// — absent is not the same as unreadable, and neither is the same as
// damaged. A truncated or malformed file is a realistic consequence of the
// very crash this feature exists to survive, so it must not be mistaken for
// "there was nothing reserved".
func APTPLProvider(dbRoot string) func(lio.Backstore) ([]string, error) {
	return func(b lio.Backstore) ([]string, error) {
		if b.WWN == "" {
			return nil, nil
		}
		// Defence in depth: Apply validates the WWN (16 lowercase hex) before
		// reaching here, but this function is exported, takes an arbitrary
		// Backstore, and uses the value as a path component.
		if !isHex16(b.WWN) {
			return nil, fmt.Errorf("refusing to read saved PR state: malformed WWN %q", b.WWN)
		}
		path := APTPLPath(dbRoot, b.WWN)
		data, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read saved PR state %s: %w", path, err)
		}
		recs, err := ParseAPTPL(string(data))
		if err != nil {
			return nil, fmt.Errorf("saved PR state %s: %w", path, err)
		}
		return recs, nil
	}
}

func isHex16(s string) bool {
	if len(s) != 16 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// APTPLPath is where the kernel persists APTPL metadata for a backstore
// with the given WWN (its vpd_unit_serial).
func APTPLPath(dbRoot, wwn string) string {
	return filepath.Join(dbRoot, "pr", "aptpl_"+wwn)
}

// ParseAPTPL converts the kernel's saved APTPL metadata into records the
// kernel will accept back via pr/res_aptpl_metadata.
//
// Input is a sequence of blocks:
//
//	PR_REG_START: 1
//	initiator_fabric=iSCSI
//	initiator_node=iqn.1993-08.org.debian:01:host
//	sa_res_key=43690
//	res_holder=1
//	...
//	PR_REG_END: 1
//
// Output is one comma-joined "k=v,k=v,..." string per block. Marker lines
// are dropped (the kernel's parser tokenises on "," and "\n" and rejects
// anything it does not recognise with EINVAL, so they must not survive).
//
// Structural damage is an ERROR, not an empty result. This file is the sole
// input to a fencing decision, and a truncated or corrupt one is a likely
// consequence of the crash this feature exists to survive; quietly returning
// "no records" would export the volume unreserved and hand a fenced node its
// access back. Only the kernel's own "no registrations" placeholder — a file
// with no blocks at all — legitimately yields zero records.
func ParseAPTPL(s string) ([]string, error) {
	var out []string
	var cur []string
	inBlock := false
	startLine := 0
	sawStray := false

	for n, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "PR_REG_START:"):
			if inBlock {
				return nil, fmt.Errorf("line %d: PR_REG_START inside an unterminated block opened at line %d", n+1, startLine)
			}
			inBlock, cur, startLine = true, nil, n+1
		case strings.HasPrefix(line, "PR_REG_END:"):
			if !inBlock {
				return nil, fmt.Errorf("line %d: PR_REG_END without a matching PR_REG_START", n+1)
			}
			rec, err := joinRecord(cur, startLine)
			if err != nil {
				return nil, err
			}
			out = append(out, rec)
			inBlock, cur = false, nil
		case line == "":
			// blank padding, ignore
		case !inBlock:
			// Content outside any block. Tracked rather than ignored so a
			// file whose framing was lost cannot masquerade as "nothing was
			// reserved" (see the zero-record check below).
			sawStray = true
		case inBlock:
			if !strings.Contains(line, "=") {
				return nil, fmt.Errorf("line %d: unparsable line inside a registration block: %q", n+1, line)
			}
			// Values are re-joined with commas for the kernel parser, which
			// tokenises on "," -- an embedded comma would inject extra fields.
			if strings.Contains(line, ",") {
				return nil, fmt.Errorf("line %d: illegal comma in saved PR field: %q", n+1, line)
			}
			cur = append(cur, line)
		}
	}
	if inBlock {
		return nil, fmt.Errorf("truncated saved PR state: block opened at line %d is never terminated", startLine)
	}
	if len(out) == 0 && !isNoRegistrations(s) {
		// Zero records is only legitimate for the kernel's own placeholder.
		//
		// Anything else claiming to have no reservations is a damaged file,
		// and the most likely damage is the emptiest: the kernel rewrites
		// this file with O_TRUNC followed by a write, so there is a window
		// on EVERY PR OUT in which it exists and is zero bytes. A crash in
		// that window is precisely the crash this feature exists to survive.
		// Treating it as "nothing was reserved" would export the volume
		// unreserved and hand a fenced node its access back — silently, and
		// with the file still sitting there looking plausible.
		//
		// Truncation INSIDE a block already failed closed; this is the same
		// crash truncated a little further, and it must not fail open.
		if strings.TrimSpace(strings.ReplaceAll(s, "\x00", "")) == "" {
			return nil, errors.New("saved PR state is empty; expected either registration blocks " +
				"or the kernel's no-registrations placeholder (a zero-length file is what a crash " +
				"during the kernel's O_TRUNC rewrite leaves behind)")
		}
		if sawStray {
			return nil, errors.New("saved PR state contains no registration blocks and does not " +
				"match the kernel's no-registrations placeholder; treating it as unreserved would " +
				"be unsafe")
		}
	}
	return out, nil
}

// isNoRegistrations reports whether s is the kernel's placeholder for a
// device with no PR state. The kernel writes strlen(buf)+1 bytes, so a
// trailing NUL is expected and must not defeat the comparison.
func isNoRegistrations(s string) bool {
	return strings.TrimSpace(strings.ReplaceAll(s, "\x00", "")) == "No Registrations or Reservations"
}

// aptplRequired are the fields without which a restored registration is
// meaningless. Their absence means the file is damaged, not that the
// registration is somehow optional.
var aptplRequired = []string{"initiator_node", "sa_res_key", "mapped_lun", "target_node"}

func joinRecord(lines []string, startLine int) (string, error) {
	if len(lines) == 0 {
		return "", fmt.Errorf("empty registration block at line %d", startLine)
	}
	have := make(map[string]bool, len(lines))
	for _, l := range lines {
		have[l[:strings.Index(l, "=")]] = true
	}
	for _, k := range aptplRequired {
		if !have[k] {
			return "", fmt.Errorf("registration block at line %d is missing %q", startLine, k)
		}
	}
	return strings.Join(lines, ","), nil
}

// OrphanPRState returns saved SCSI-3 PR metadata files under dbRoot that do
// not correspond to any of liveWWNs, newest-last by name.
//
// KNOWN, DELIBERATELY UNFIXED EDGE CASE — read before "tidying" this up.
//
// The kernel writes db_root/pr/aptpl_<wwn> and never removes it. applianced
// discards a volume's file when the volume is deleted (see
// Coordinator.discardSavedPR), which covers the normal path, but files can
// still be left behind:
//
//   - volumes deleted before that cleanup existed;
//   - a delete whose unlink failed (logged at the time, but not retried);
//   - state removed out of band, e.g. the storage db replaced or rolled back.
//
// These are REPORTED and never reaped automatically. Reaping would mean
// concluding, from a single view of the tree, that a reservation is dead —
// and a volume can be absent for reasons that are temporary or recoverable:
// a partially restored db, a backstore not yet replayed, an operator
// mid-migration. Being wrong in that direction silently destroys live
// fencing state, which is the precise failure this whole feature exists to
// prevent; being wrong in the other direction wastes a few hundred bytes.
// An unmatched file is inert — it is only ever read back for a backstore
// with that exact WWN — so the safe default is to leave it and say so.
//
// The consequence of leaving them is bounded but real: if a WWN ever did
// recur, the new volume would inherit the old reservations. That cannot
// happen through the normal path (a WWN is the first 8 bytes of a CSPRNG UUID
// -- 60 random bits, one nibble being the UUID version -- and is enforced
// unique across live volumes) but could through a hand-edited or restored db,
// which is
// exactly the situation where the operator, not this code, should decide.
func OrphanPRState(dbRoot string, liveWWNs []string) ([]string, error) {
	if dbRoot == "" {
		return nil, nil
	}
	dir := filepath.Join(dbRoot, "pr")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	live := make(map[string]bool, len(liveWWNs))
	for _, w := range liveWWNs {
		live[w] = true
	}
	var orphans []string
	for _, e := range entries {
		wwn, ok := strings.CutPrefix(e.Name(), "aptpl_")
		if !ok || live[wwn] {
			continue
		}
		orphans = append(orphans, filepath.Join(dir, e.Name()))
	}
	return orphans, nil
}
