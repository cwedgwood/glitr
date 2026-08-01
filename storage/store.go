package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Store manages volumes under a single storage root (one XFS filesystem
// in production). It is safe for concurrent use.
//
// Layout:
//
//	<root>/volumes.json          # record db (authoritative)
//	<root>/volumes/<uuid>/disk   # sparse raw backing file
//	<root>/volumes/<uuid>/metadata.json  # advisory (human/debug), db wins
type Store struct {
	root string
	mu   sync.Mutex
	vols map[string]*Volume
	// backupErr records the last failure to maintain the record-db backups.
	// Sticky: it is not cleared by a later success, because the gap it
	// reports -- a window with no restorable copy -- does not un-happen.
	//
	// Guarded by its OWN mutex, not mu. mu is held across volume I/O --
	// allocation, truncate, RemoveAll -- and this value is read by /health,
	// which must stay answerable exactly when a slow operation is in flight.
	// Sharing mu would put disk latency on the health path.
	bakMu     sync.Mutex
	backupErr error
	// quarantined names volume dirs set aside by repair because the db had
	// no record of them. Written once during Open, read-only afterwards.
	quarantined []string
	// rejected holds db records load could not accept, kept out of vols so
	// nothing can act on their values, and kept VERBATIM so persist can write
	// them back byte-for-byte. Written once during Open, read-only afterwards.
	rejected []RejectedRecord
}

// RejectedRecord is one db entry that failed validation and was excluded from
// the live volume set.
//
// Raw is the record's ORIGINAL bytes. Keeping them is not a nicety: persist
// serialises the live volume map, so a record merely dropped from that map
// would be erased from volumes.json by the next ordinary create or delete --
// turning a loud startup failure into the silent loss of the operator's only
// copy. Every persist writes these back unchanged.
type RejectedRecord struct {
	// UUID is best-effort and may be empty or itself invalid: it is reported
	// so an operator can find the entry, never used to build a path.
	UUID   string          `json:"uuid,omitempty"`
	Reason string          `json:"reason"`
	Raw    json.RawMessage `json:"-"`
}

// RejectedRecords returns the db records load refused, in file order.
//
// These are excluded from the live set on purpose. The values that fail
// validation are exactly the dangerous ones -- UUID becomes a filesystem path
// and WWN becomes the SCSI identity an initiator keys on -- so a rejected
// record is held outside the volume map entirely rather than carried inside it
// in a Failed state, where any code path that forgot to check State could
// reach it.
func (s *Store) RejectedRecords() []RejectedRecord {
	return append([]RejectedRecord(nil), s.rejected...)
}

// quarantinePrefix marks a volume dir that repair set aside. The leading dot
// keeps it out of the volume scan for the same reason ".staging-" is skipped.
const quarantinePrefix = ".orphan-"

// Quarantined returns the volume dirs repair set aside because the db had no
// record of them, newest-sorted, relative to <root>/volumes. Their data is
// intact. Each is either a Delete that crashed before removing the dir (dead,
// reclaimable) or a volume that a restored db predates (LIVE data whose
// record must be rebuilt) — see repair. Reported so an operator is told
// rather than left to find them.
func (s *Store) Quarantined() []string {
	return append([]string(nil), s.quarantined...)
}

func (s *Store) dbPath() string         { return filepath.Join(s.root, "volumes.json") }
func (s *Store) volsDir() string        { return filepath.Join(s.root, "volumes") }
func (s *Store) volDir(u string) string { return filepath.Join(s.volsDir(), u) }

// DiskPath returns the backing-file path for a volume — what a caller points
// a LIO fileio backstore at.
func (s *Store) DiskPath(uuid string) string {
	return filepath.Join(s.volDir(uuid), "disk")
}

// Open loads (or initialises) the store at root and runs startup repair.
func Open(root string) (*Store, error) {
	s := &Store{root: root, vols: map[string]*Volume{}}
	if err := os.MkdirAll(s.volsDir(), 0o755); err != nil {
		return nil, err
	}
	dbExisted, err := s.load()
	if err != nil {
		return nil, err
	}
	if err := s.repair(dbExisted); err != nil {
		return nil, err
	}
	return s, nil
}

// load reads the record db, returning whether the db FILE existed. A
// missing file is a valid empty store (first boot) but the caller must
// know it was absent — repair treats "db absent but volume dirs present"
// as a lost db, not an empty one (see repair).
//
// Validation failures are split by BLAST RADIUS, because "the db is not what
// we wrote" and "one row is unusable" are different problems:
//
//   - A record that is individually malformed is REJECTED and the store keeps
//     serving every other volume. Refusing to export healthy volumes because
//     a sibling record is bad is a self-inflicted outage, and a total one
//     after a reboot: MEASURED on the lab, one bad record of three left the
//     kernel with zero targets and zero backstores, while applianced restarted
//     every 2s with no REST left to explain why. (Before a reboot the data
//     path is untouched -- configfs is kernel memory the daemon does not own,
//     so reads, writes and SCSI PR all keep working while the control plane
//     loops.)
//
//   - A CROSS-RECORD conflict still fails closed. A duplicate UUID or WWN is
//     an ambiguity BETWEEN records, so there is no "the bad one" to drop: the
//     WWN becomes the SCSI WWID, and two volumes sharing one present a single
//     device identity that multipath can coalesce, so writes could land on the
//     wrong volume. Guessing which record to honour risks exactly the data
//     corruption the check exists to prevent.
//
//   - A file that does not parse as JSON fails closed too. There are no
//     records to salvage, so there is nothing to be partial about.
//
// Rejected records are held OUT of the live map (see RejectedRecord): the
// values that fail validation are the ones that are dangerous if touched --
// UUID builds a filesystem path, WWN becomes a SCSI identity.
func (s *Store) load() (dbExisted bool, err error) {
	data, err := os.ReadFile(s.dbPath())
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	// Decode to raw elements first so every record's ORIGINAL bytes survive.
	// persist writes rejected records back verbatim; without the raw form, a
	// rejected record would be erased by the next mutation.
	var raws []json.RawMessage
	if err := json.Unmarshal(data, &raws); err != nil {
		return true, fmt.Errorf("storage: parsing %s: %w", s.dbPath(), err)
	}

	reject := func(raw json.RawMessage, uuid, format string, args ...any) {
		s.rejected = append(s.rejected, RejectedRecord{
			UUID:   uuid,
			Reason: fmt.Sprintf(format, args...),
			Raw:    append(json.RawMessage(nil), raw...),
		})
	}

	type accepted struct {
		v   *Volume
		raw json.RawMessage
	}
	var ok []accepted
	for _, raw := range raws {
		var v *Volume
		if err := json.Unmarshal(raw, &v); err != nil {
			reject(raw, "", "record is not a volume object: %v", err)
			continue
		}
		if v == nil {
			reject(raw, "", "null volume record")
			continue
		}
		if bad := validateRecord(v); bad != "" {
			reject(raw, v.UUID, "%s", bad)
			continue
		}
		ok = append(ok, accepted{v, raw})
	}

	// Cross-record conflicts are checked only among records that are
	// individually sound, so one malformed row cannot manufacture a false
	// duplicate and take the store down.
	seenWWN := map[string]string{}
	for _, a := range ok {
		v := a.v
		if _, dup := s.vols[v.UUID]; dup {
			return true, fmt.Errorf("storage: %s contains duplicate volume uuid %q", s.dbPath(), v.UUID)
		}
		if prev, dup := seenWWN[v.WWN]; dup {
			return true, fmt.Errorf("storage: %s: volumes %s and %s share wwn %q",
				s.dbPath(), prev, v.UUID, v.WWN)
		}
		seenWWN[v.WWN] = v.UUID
		s.vols[v.UUID] = v
	}
	return true, nil
}

// validateRecord reports why a single record is unusable, or "" if it is
// sound. Every case here is a property of ONE record, which is what makes it
// safe to reject that record alone; conflicts BETWEEN records are handled by
// load and still fail closed.
func validateRecord(v *Volume) string {
	switch {
	case !validUUID(v.UUID):
		// The UUID is used to build directory paths, so a non-canonical one
		// is a path-traversal risk, not just untidy.
		return fmt.Sprintf("invalid volume uuid %q", v.UUID)
	case v.Capacity <= 0:
		return fmt.Sprintf("non-positive capacity %d", v.Capacity)
	case !validWWN(v.WWN):
		return fmt.Sprintf("invalid wwn %q", v.WWN)
	case v.State != Ready && v.State != Failed:
		return fmt.Sprintf("unknown state %q", v.State)
	case v.Parent != "" && !validUUID(v.Parent):
		return fmt.Sprintf("invalid parent uuid %q", v.Parent)
	// A block size is persisted geometry: it describes bytes an initiator has
	// already formatted against. Validate it exactly as strictly as the WWN,
	// for the same reason. 0 is the one legal absence (a record written before
	// the field existed) and repair backfills it.
	case v.BlockSize != 0 && !ValidBlockSize(v.BlockSize):
		return fmt.Sprintf("invalid block size %d (must be %d or %d)",
			v.BlockSize, DefaultBlockSize, MaxBlockSize)
	// A volume smaller than one logical block is not a volume. The kernel
	// derives the last LBA as (size - block_size)/block_size (linux v6.6
	// drivers/target/target_core_file.c:804-822), so it would present a
	// zero-length device: there is no valid geometry to give it and nothing an
	// initiator could do with it.
	//
	// This is the one case here that a PRE-EXISTING record can trip -- the
	// others reject values the API never produced, but Create used to accept
	// any size > 0. It used to exit the daemon at startup, so an upgrade with
	// one such record crash-looped forever; now it costs that volume only.
	case v.Capacity < int64(v.BlockSizeOrDefault()):
		return fmt.Sprintf("capacity %d is smaller than its logical block size %d, "+
			"so it cannot be presented as a block device (records this small predate "+
			"the minimum volume size and hold no usable data)",
			v.Capacity, v.BlockSizeOrDefault())
	}
	return ""
}

// repair reconciles the db against the filesystem: staging dirs are
// removed; a record whose file is missing/short is marked Failed; a file
// larger than the recorded capacity reconciles the capacity up (a crashed
// grow committed the file but not the db).
//
// SAFETY: if the db file was ABSENT while real (non-staging) volume dirs
// exist, the authoritative record was lost (deleted, partial restore, fs
// repair) — repair refuses to start rather than treat every backing file
// as an orphan and delete it.
//
// SAFETY: a volume dir with no record is QUARANTINED, never deleted. Two
// situations produce one and they are indistinguishable on disk:
//
//	a Delete that committed the db and crashed before RemoveAll — the data
//	    is genuinely dead, and quarantining it merely holds space;
//	a db restored from a backup — every backup is written BEFORE the
//	    mutation it protects, so the newest one is always at least one
//	    volume behind the directories, and every volume created since looks
//	    exactly like the case above.
//
// The second is the documented lost-db recovery. Deleting on that path
// destroyed the newest volumes' backing data at the moment an operator was
// already recovering from losing the db — the worst possible time to be
// wrong. Since the two cannot be told apart, the only safe reading is the
// non-destructive one; reclaiming a quarantine dir is a decision for an
// operator who can see both, not for startup.
func (s *Store) repair(dbExisted bool) error {
	entries, err := os.ReadDir(s.volsDir())
	if err != nil {
		return err
	}
	var finalDirs []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".staging-") {
			_ = os.RemoveAll(filepath.Join(s.volsDir(), name)) // uncommitted, always safe
			continue
		}
		if strings.HasPrefix(name, quarantinePrefix) {
			// Already set aside by an earlier pass. Not a volume, and must
			// not be re-quarantined into an ever-lengthening name.
			s.quarantined = append(s.quarantined, name)
			continue
		}
		finalDirs = append(finalDirs, name)
	}
	if !dbExisted && len(finalDirs) > 0 {
		// Name the backups explicitly. The recovery is "restore the db", and
		// an operator meeting this message for the first time -- at the worst
		// possible moment -- should not have to discover where a backup might
		// be, or guess whether one exists.
		hint := "no backups were found in " + s.root + ", so the record db must be rebuilt by hand"
		if bak, err := latestBackup(s.dbPath()); err == nil && bak != "" {
			hint = "the most recent backup is " + bak + " -- copy it to " + s.dbPath() +
				" to recover. Volumes created after that backup was taken have no record in " +
				"it; they will be set aside under " + s.volsDir() + "/" + quarantinePrefix +
				"* with their data intact, not deleted"
		}
		return fmt.Errorf("storage: %s is missing but %d volume director(ies) are present; "+
			"refusing to start to avoid deleting live data. %s",
			s.dbPath(), len(finalDirs), hint)
	}
	for _, name := range finalDirs {
		if _, ok := s.vols[name]; ok {
			continue
		}
		// A rejected record's directory is NOT orphaned: its record is still
		// in the db, just not in the live set. Renaming it would break the
		// recovery it exists to allow -- an operator fixes the record,
		// restarts, and finds the data under a quarantine name with the
		// volume marked Failed, i.e. the fix undone by the fix.
		if s.recordRejected(name) {
			continue
		}
		q := quarantinePrefix + time.Now().UTC().Format("20060102T150405Z") + "-" + name
		if err := os.Rename(filepath.Join(s.volsDir(), name), filepath.Join(s.volsDir(), q)); err != nil {
			return fmt.Errorf("storage: cannot quarantine unrecorded volume dir %s: %w", name, err)
		}
		s.quarantined = append(s.quarantined, q)
	}
	if len(s.quarantined) > 0 {
		slices.Sort(s.quarantined)
	}
	dirty := false
	for _, v := range s.vols {
		// Backfill the block size onto records written before the field
		// existed. Those volumes were created at the kernel's fileio default,
		// so 512 is what their initiators have always seen -- recording it
		// makes the pin explicit rather than reinterpreting an absent field
		// at every call site, and makes the REST API able to say so.
		if v.BlockSize == 0 {
			v.BlockSize = DefaultBlockSize
			dirty = true
		}
		// NOTE: an unaligned legacy capacity is deliberately NOT rewritten
		// here, and this is the second attempt at that problem.
		//
		// The first attempt floored the record to a whole block, reasoning
		// that the kernel truncates the tail anyway so the figure was already
		// a lie. Both halves of that went wrong, because a durable migration
		// has to be correct against every legacy input AND against a live
		// kernel object that predates it:
		//
		//   - For 0 < capacity < block_size the floor yields 0, which `load`
		//     rejects as non-positive -- repair persisted a record that
		//     bricked the next Open, having marked it ready on the way.
		//   - Worse, on an upgrade WITHOUT a reboot the kernel object is
		//     still live and still reports the UNFLOORED size (measured on
		//     Azure Linux 3.0, kernel 6.6.144.1: a backstore created with
		//     fd_dev_size=1000000 reports "Size: 1000000" verbatim). The
		//     floored record then looked like a shrink to the reconcile, and
		//     "shrink unsupported" crash-looped the daemon -- the exact
		//     failure the floor was written to prevent.
		//
		// The alignment concern belongs where the size is USED, not where it
		// is stored: appliance.desiredLIO floors what it hands to lio, and
		// lio compares sizes floored, so both describe the device the kernel
		// actually serves. The durable record keeps what the caller asked
		// for.
		fi, err := os.Stat(s.DiskPath(v.UUID))
		switch {
		case err != nil && !os.IsNotExist(err):
			// Unreadable is NOT the same as missing: marking a volume Failed
			// here would exclude it from the desired state and make the next
			// reconcile prune a live export because of a transient I/O error.
			return fmt.Errorf("storage: cannot stat backing file for volume %s: %w", v.UUID, err)
		case err != nil:
			if v.State != Failed {
				v.State = Failed
				dirty = true
			}
		case fi.Size() >= v.Capacity:
			if fi.Size() > v.Capacity { // crashed grow: reconcile up
				v.Capacity = fi.Size()
				dirty = true
			}
			if v.State != Ready {
				v.State = Ready
				dirty = true
			}
		default: // file shorter than recorded capacity
			if v.State != Failed {
				v.State = Failed
				dirty = true
			}
		}
	}
	if dirty {
		return s.persist()
	}
	return nil
}

// Create allocates a new sparse volume of the given size (bytes).
func (s *Store) Create(size int64, blockSize int) (*Volume, error) {
	if size <= 0 {
		return nil, fmt.Errorf("storage: volume size must be > 0")
	}
	if blockSize == 0 {
		blockSize = DefaultBlockSize
	}
	if !ValidBlockSize(blockSize) {
		return nil, fmt.Errorf("storage: block size %d must be %d or %d",
			blockSize, DefaultBlockSize, MaxBlockSize)
	}
	// The kernel derives the last LBA as (size - block_size)/block_size, so a
	// size that is not a whole multiple loses its tail silently: the caller
	// would ask for N bytes and the initiator would see fewer. Refuse instead.
	if size%int64(blockSize) != 0 {
		return nil, fmt.Errorf("storage: size %d is not a multiple of block size %d",
			size, blockSize)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	uuid, wwn, err := newIdentity()
	if err != nil {
		return nil, err
	}
	v := &Volume{UUID: uuid, WWN: wwn, Capacity: size, Created: time.Now().UTC(),
		State: Ready, BlockSize: blockSize}
	if err := s.stage(v, func(disk string) error {
		f, err := os.OpenFile(disk, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := f.Truncate(v.Capacity); err != nil {
			return err
		}
		return f.Sync()
	}); err != nil {
		return nil, err
	}
	s.vols[uuid] = v
	if err := s.persist(); err != nil {
		if errors.Is(err, ErrPersistedNotDurable) {
			return copyVol(v), err // db already names it: keep memory in step
		}
		// Roll back so in-memory state matches the (unchanged) db, and the
		// on-disk dir doesn't linger as an orphan a later persist would
		// resurrect or repair would delete.
		delete(s.vols, uuid)
		_ = os.RemoveAll(s.volDir(uuid))
		return nil, err
	}
	return copyVol(v), nil
}

// stage builds the volume dir + metadata under a staging name, invokes
// fill to create the "disk" backing file, fsyncs, then renames to the
// final path. The db commit is the caller's final step.
func (s *Store) stage(v *Volume, fill func(diskPath string) error) error {
	staging := filepath.Join(s.volsDir(), ".staging-"+v.UUID)
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return err
	}
	defer os.RemoveAll(staging) // no-op after a successful rename

	if err := fill(filepath.Join(staging, "disk")); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(staging, "metadata.json"), v); err != nil {
		return err
	}
	if err := syncDir(staging); err != nil {
		return err
	}
	if err := os.Rename(staging, s.volDir(v.UUID)); err != nil {
		return err
	}
	return syncDir(s.volsDir())
}

// Delete removes a volume (db record first, then on-disk artifacts).
func (s *Store) Delete(uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.vols[uuid]
	if !ok {
		return fmt.Errorf("storage: volume %s not found", uuid)
	}
	delete(s.vols, uuid)
	if err := s.persist(); err != nil {
		if errors.Is(err, ErrPersistedNotDurable) {
			return err // db already dropped it: keep memory in step
		}
		s.vols[uuid] = v // roll back: db still has it, so must memory
		return err
	}
	return os.RemoveAll(s.volDir(uuid))
}

// Resize grows a volume to newSize bytes (grow-only).
func (s *Store) Resize(uuid string, newSize int64) (*Volume, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.vols[uuid]
	if !ok {
		return nil, fmt.Errorf("storage: volume %s not found", uuid)
	}
	if newSize == v.Capacity {
		return copyVol(v), nil
	}
	if newSize < v.Capacity {
		return nil, fmt.Errorf("storage: shrink unsupported (%d < %d)", newSize, v.Capacity)
	}
	// The same invariant Create enforces, enforced here too rather than only
	// one layer up in the appliance: a grow that is not a whole number of
	// blocks silently loses its tail exactly as an unaligned create does, and
	// storage is a real API boundary -- a caller that is not the appliance
	// must not be able to reintroduce a short disk.
	if bs := int64(v.BlockSizeOrDefault()); newSize%bs != 0 {
		return nil, fmt.Errorf("storage: size %d is not a multiple of block size %d", newSize, bs)
	}
	f, err := os.OpenFile(s.DiskPath(uuid), os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	if err := f.Truncate(newSize); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	f.Close()
	v.Capacity = newSize
	_ = writeJSON(filepath.Join(s.volDir(uuid), "metadata.json"), v)
	if err := s.persist(); err != nil {
		// The file grow is already durable; leave v.Capacity at newSize so
		// memory matches the file (and the db repair reconciles up on the
		// next Open). Report the persist error to the caller.
		return nil, err
	}
	return copyVol(v), nil
}

// copyVol returns a heap copy of v so callers never receive a pointer into
// the mutex-protected map (which they could mutate without the lock).
func copyVol(v *Volume) *Volume {
	cp := *v
	return &cp
}

// Get returns a copy of a volume record.
func (s *Store) Get(uuid string) (Volume, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.vols[uuid]
	if !ok {
		return Volume{}, false
	}
	return *v, true
}

// List returns all volume records, sorted by creation time.
func (s *Store) List() []Volume {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Volume, 0, len(s.vols))
	for _, v := range s.vols {
		out = append(out, *v)
	}
	slices.SortFunc(out, func(a, b Volume) int { return a.Created.Compare(b.Created) })
	return out
}

// persist atomically rewrites the record db.
// ErrPersistedNotDurable reports that the db was successfully renamed into
// place — so the ON-DISK state is already the NEW state — but the containing
// directory could not be fsynced, leaving durability across a power loss
// unproven. Callers must NOT roll back in-memory state on this error: doing so
// would make memory disagree with what a restart would load.
//
// Exported because it is RETURNED to external callers. Create, Resize, Delete
// and Snapshot can all produce it, and while unexported a caller could not
// distinguish "the operation succeeded, on disk, durability unproven" from
// "the operation failed" -- it saw a non-nil error next to a non-nil *Volume,
// which most Go code discards. The instruction above is addressed to callers,
// so they need to be able to identify it. Test with errors.Is.
var ErrPersistedNotDurable = errors.New("storage: db written but not proven durable")

func (s *Store) persist() error {
	list := make([]*Volume, 0, len(s.vols))
	for _, v := range s.vols {
		list = append(list, v)
	}
	slices.SortFunc(list, func(a, b *Volume) int { return a.Created.Compare(b.Created) })

	// Re-emit records load rejected, byte-for-byte.
	//
	// Without this the feature would be a worse bug than the one it fixes.
	// persist serialises the LIVE map, so a record excluded from that map is
	// erased from volumes.json by the very next create or delete -- silently,
	// and from the operator's only copy. Rejecting a record must cost the
	// volume's availability, never the record itself, so the file keeps
	// everything and only the live set is filtered.
	//
	// They are written unchanged rather than re-marshalled: the record is
	// invalid by definition, so there is no struct that round-trips it
	// faithfully, and a "helpful" rewrite would destroy the evidence an
	// operator needs to see what was actually on disk.
	payload := make([]json.RawMessage, 0, len(list)+len(s.rejected))
	for _, v := range list {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		payload = append(payload, b)
	}
	for _, r := range s.rejected {
		payload = append(payload, r.Raw)
	}

	// Preserve the current contents before replacing them.
	//
	// This is the other half of a promise the store already makes: repair
	// REFUSES to start when the db is absent while volume directories exist,
	// on the grounds that the authoritative record was lost and deleting live
	// data would be worse. That refusal is only humane if there is something
	// to restore FROM, and until now there was not -- the fail-closed half had
	// shipped and the recoverable half had not.
	//
	// A failed backup does NOT fail the mutation. Refusing to create a volume
	// because a recovery convenience could not be linked would trade a real
	// operation for a hypothetical one. But it is recorded rather than
	// swallowed: silent loss of the backups would put us back where we
	// started, with a documented recovery path pointing at nothing.
	backupErr := func() error {
		if _, err := linkBackup(s.dbPath(), time.Now()); err != nil {
			return err
		}
		return pruneBackups(s.dbPath(), dbBackupsKept)
	}()

	if err := writeJSON(s.dbPath(), payload); err != nil {
		return err
	}
	if err := syncDir(s.root); err != nil {
		return fmt.Errorf("%w: %v", ErrPersistedNotDurable, err)
	}
	if backupErr != nil {
		s.bakMu.Lock()
		s.backupErr = backupErr
		s.bakMu.Unlock()
	}
	return nil
}

// dbBackupsKept is how many previous versions of the record db are retained.
//
// Enough to survive a bad change that is noticed a few mutations late, few
// enough that the directory stays readable by a human under stress -- which is
// the only situation in which anyone reads it. Each is a hard link to an inode
// that already existed, so the cost is a directory entry, not a copy; the
// space held is the old db content, and only until the last link to it goes.
const dbBackupsKept = 10

// BackupErr reports a failure to maintain the record-db backups, or nil.
//
// Separate from the mutation path on purpose: a backup failure must not fail a
// volume operation, but it must not be invisible either. The recovery
// procedure for a lost db is "restore from a backup", so backups that have
// quietly stopped being written turn a documented recovery into no recovery.
func (s *Store) BackupErr() error {
	s.bakMu.Lock()
	defer s.bakMu.Unlock()
	return s.backupErr
}

// recordRejected reports whether a volume dir belongs to a record that load
// rejected. Matched on the record's own uuid STRING, which may be malformed --
// that is the point: the directory on disk was named by whatever the record
// says, so the comparison has to be against the same untrusted text. It is
// only ever compared, never used to build a path.
func (s *Store) recordRejected(dir string) bool {
	for _, r := range s.rejected {
		if r.UUID != "" && r.UUID == dir {
			return true
		}
	}
	return false
}
