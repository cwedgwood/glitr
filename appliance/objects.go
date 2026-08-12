package appliance

import (
	"errors"
	"net/http"
	"time"

	"github.com/cwedgwood/glitr/storage"
)

// Object operations.
//
// Everything here is name-first. A caller names what it wants; the appliance
// mints the UUID, allocates the bytes, and commits both in one record. Repeating
// a create with a name that already exists returns what is there, so a caller
// that cannot tell whether its request landed can simply ask again -- which is
// the single most important thing an external controller needs and the reason
// this layer exists at all.

// Block sizes the appliance will present to an initiator. These live here, not
// in storage: a backing file has no block size, only a length. The number
// matters to what the initiator sees and to what LIO is told.
//
// Deliberately narrower than the kernel's set, which is 512, 1024, 2048 and
// 4096 (linux v6.6 drivers/target/target_core_configfs.c:1125-1129). The two
// in between exist but nothing makes them, and offering a choice we do not
// test is offering a way to get stuck: block_size is fixed once an object is
// exported.
//
// MaxBlockSize is 4096 and so is the storage layer's size granularity. They
// are unrelated numbers that happen to agree: one is what the initiator is
// told a sector is, the other is what the filesystem underneath can share.
// A block-backed store could report 512 granularity while we still present
// 4096 here. Do not merge them.
const (
	DefaultBlockSize = 512
	MaxBlockSize     = 4096
)

// ValidBlockSize reports whether n is a block size the appliance will present.
func ValidBlockSize(n int) bool { return n == DefaultBlockSize || n == MaxBlockSize }

// MinVolumeSize is the smallest object the appliance will create.
//
// Policy, not a limit of the kernel or of storage: an object smaller than this
// costs the same records, LUN and reconcile work as a useful one. 1MiB is a
// whole number of every granularity a backing store could plausibly report
// (it is 256 * 4096 and 2048 * 512), so the floor never lands off-boundary.
const MinVolumeSize = 1 << 20

// checkSize applies both size rules: at least [MinVolumeSize], and a whole
// number of the backing store's granularity.
//
// A method, not a function, because the second rule is the store's to state
// rather than ours -- see [github.com/cwedgwood/glitr/storage.Store.SizeGranularity].
func (c *Coordinator) checkSize(size int64) error {
	if size < MinVolumeSize {
		return statusErrCode(http.StatusBadRequest, CodeInvalidInput,
			"size %d is below the %d-byte minimum", size, MinVolumeSize)
	}
	if err := storage.CheckGranularity(size, c.store.SizeGranularity()); err != nil {
		// The kernel derives the last LBA as (size - block_size)/block_size,
		// so a size that is not a whole number of blocks silently loses its
		// tail: the caller asks for N bytes and the initiator sees fewer.
		return statusErrCode(http.StatusBadRequest, CodeInvalidInput, "%s", err)
	}
	return nil
}

// CreateRequest is a request to create a volume or a snapshot.
type CreateRequest struct {
	Name string
	// Size in bytes. Ignored when Source is set and Size is zero, in which
	// case the source's size is inherited.
	Size int64
	// BlockSize is fixed for the life of the object. Zero means the default.
	// Ignored when Source is set: a copy shares the source's geometry, because
	// the filesystem inside it was written for that geometry and would be
	// misread at another.
	BlockSize int
	// Source is the object to copy, by name or uuid, within SourceKind.
	Source     string
	SourceKind Kind
}

// Create makes a volume or a snapshot.
//
// One function for both because they differ in exactly two ways: which
// namespace the name is taken from, and whether the result is presented as a
// snapshot. The bytes are the same operation either way.
//
// created reports whether this call is what made the object. False means the
// name was already taken by something matching the request, which is a success
// -- it is what makes a create safe to replay -- but it is not the same event,
// and a caller reconciling against its own records needs to tell them apart.
// The shape is [sync.Map.LoadOrStore]'s, for the same reason.
//
// The returned object is authoritative when created is false: its capacity is
// whatever the object actually is now, which need not be the size requested,
// because an object can be resized after it is made. Compare there if that
// matters to you -- see [Coordinator.matchExisting] for why the appliance will
// not compare it for you.
func (c *Coordinator) Create(kind Kind, req CreateRequest) (o Object, created bool, err error) {
	if err := checkName(req.Name); err != nil {
		return Object{}, false, err
	}
	if req.BlockSize == 0 {
		req.BlockSize = DefaultBlockSize
	}
	if !ValidBlockSize(req.BlockSize) {
		return Object{}, false, statusErrCode(http.StatusBadRequest, CodeInvalidInput,
			"block_size must be %d or %d", DefaultBlockSize, MaxBlockSize)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Held across the duplicate check, the allocation and the commit, so two
	// callers racing one name cannot both get past the check.
	if existing := c.objectByName(kind, req.Name); existing != nil {
		o, err := c.matchExisting(existing, req)
		return o, false, err
	}

	var source *Object
	if req.Source != "" {
		source = c.resolveObject(req.SourceKind, req.Source)
		if source == nil {
			return Object{}, false, notFound(string(req.SourceKind), req.Source)
		}
		if source.State != stateReady {
			return Object{}, false, statusErrCode(http.StatusConflict, CodeUnsupportedState,
				"%s %q is %s", source.Kind, source.Name, source.State)
		}
		// A copy inherits geometry and, unless grown, size.
		req.BlockSize = source.BlockSize
		if req.Size == 0 {
			req.Size = source.Capacity
		}
		if req.Size < source.Capacity {
			return Object{}, false, statusErrCode(http.StatusBadRequest, CodeInvalidInput,
				"size %d is smaller than %s %q (%d); a copy cannot shrink",
				req.Size, source.Kind, source.Name, source.Capacity)
		}
	}

	if err := c.checkSize(req.Size); err != nil {
		return Object{}, false, err
	}

	uuid, wwn, err := newIdentity()
	if err != nil {
		return Object{}, false, err
	}

	// Bytes first, record second. A crash between them leaks a directory that
	// startup quarantines with its data intact; the other order would put an
	// object in the db that has no bytes, which every later operation would
	// then trip over.
	if source != nil {
		if err := c.store.Clone(source.UUID, uuid); err != nil {
			return Object{}, false, err
		}
		if req.Size > source.Capacity {
			if err := c.store.Resize(uuid, req.Size); err != nil {
				_ = c.store.Delete(uuid)
				return Object{}, false, err
			}
		}
	} else if err := c.store.Create(uuid, req.Size); err != nil {
		return Object{}, false, err
	}

	obj := &Object{
		UUID: uuid, Name: req.Name, Kind: kind, WWN: wwn,
		Capacity: req.Size, BlockSize: req.BlockSize,
		Created: time.Now().UTC(), State: stateReady,
	}
	if source != nil {
		obj.Source = source.UUID
	}
	// No reconcile: a new object is unexported, and desiredLIO only emits a
	// backstore for objects with a connection. Routing this through commit()
	// would make creating an object acquire reconcile latency and share a
	// failure domain with every export on the appliance, for a mutation that
	// touches no kernel state.
	if err := c.persistOnly(func() error {
		c.st.Objects = append(c.st.Objects, obj)
		return nil
	}); err != nil {
		if dropBytes(err) {
			_ = c.store.Delete(uuid)
			return Object{}, false, err
		}
		return *obj, true, err
	}
	return *obj, true, nil
}

// dropBytes reports whether a failed record write leaves the bytes orphaned.
//
// It does, except for one case. errPersistedNotDurable means persist renamed
// the db into place and only THEN failed to fsync the directory: the record is
// on disk and persistOnly keeps memory in step with it, so deleting the bytes
// would leave a record naming an object that no longer exists -- worse than
// the leak the cleanup avoids, and unrecoverable rather than merely untidy.
// Every other failure rolled the record back, so the bytes are all that is
// left and nothing else knows the identifier yet.
func dropBytes(err error) bool { return !errors.Is(err, errPersistedNotDurable) }

// matchExisting implements the repeat-create rule.
//
// Returns the existing object when the request describes it, and a conflict
// when it describes something else -- because handing back an object that is
// not what was asked for is worse than refusing.
//
// Capacity is deliberately NOT compared: an object can be resized after it is
// made, so a size difference is not evidence of a different object, and
// refusing on it would wedge a caller that grew something and then replayed
// its create. The source is compared for the opposite reason -- provenance is
// fixed at creation -- but by UUID first, so that a source which has since
// been deleted does not wedge the replay in the same way. Caller must hold
// c.mu.
func (c *Coordinator) matchExisting(existing *Object, req CreateRequest) (Object, error) {
	if req.BlockSize != 0 && existing.BlockSize != req.BlockSize {
		return Object{}, statusErrCode(http.StatusConflict, CodeConfigurationMismatch,
			"%s %q already exists with block_size %d, not %d",
			existing.Kind, existing.Name, existing.BlockSize, req.BlockSize)
	}
	if req.Source != "" && req.Source != existing.Source {
		// The UUID is compared FIRST, and on its own. It is what the record
		// stores, so a caller that holds it needs nothing resolved -- which
		// matters because the source may have been DELETED. Deleting the
		// thing a snapshot came from is allowed (the snapshot's bytes are its
		// own; see validateLoaded), and resolving unconditionally made the
		// replay fail from then on: a create that is safe to retry stopped
		// being safe, permanently, the moment its source went away. Absent
		// was being read as different.
		src := c.resolveObject(req.SourceKind, req.Source)
		switch {
		case src == nil:
			// A NAME that resolves to nothing cannot be matched, and must not
			// be assumed to be the source. Names are reusable: the source was
			// deleted and something else may hold that name now, or may later,
			// so "it was probably this" would be a claim the appliance cannot
			// support. Say what is recorded and let the caller decide.
			return Object{}, statusErrCode(http.StatusConflict, CodeConfigurationMismatch,
				"%s %q already exists and was made from %s, which no longer exists; "+
					"%q resolves to nothing now, so it cannot be matched -- repeat the "+
					"create with that uuid as the source, or use a different name",
				existing.Kind, existing.Name, existing.Source, req.Source)
		case existing.Source != src.UUID:
			// Resolves, but to something else. A reused name lands here, and
			// refusing is right: the object wearing that name today is not
			// what this was made from.
			return Object{}, statusErrCode(http.StatusConflict, CodeConfigurationMismatch,
				"%s %q already exists and was not made from %q",
				existing.Kind, existing.Name, req.Source)
		}
	}
	return *existing, nil
}

// Object states. Ready is the only one an object is created in; Missing is
// what a record wears when its backing file is gone, which is a report rather
// than a lifecycle step.
const (
	stateReady   = "ready"
	stateMissing = "missing"
)

// List returns every object of a kind.
func (c *Coordinator) List(kind Kind) []Object {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []Object{}
	for _, o := range c.st.Objects {
		if o.Kind == kind {
			out = append(out, *o)
		}
	}
	return out
}

// Get returns one object by name, or by uuid.
func (c *Coordinator) Get(kind Kind, ref string) (Object, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	o := c.resolveObject(kind, ref)
	if o == nil {
		return Object{}, false
	}
	return *o, true
}

// Rename changes an object's name.
//
// Safe while the object is exported and mounted: an initiator identifies the
// device by its WWN, which is derived from the UUID and does not move. Nothing
// keys off the name, which is what separates a name from an identifier.
func (c *Coordinator) Rename(kind Kind, ref, newName string) (Object, error) {
	if err := checkName(newName); err != nil {
		return Object{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	o := c.resolveObject(kind, ref)
	if o == nil {
		return Object{}, notFound(string(kind), ref)
	}
	if o.Name == newName {
		return *o, nil
	}
	if other := c.objectByName(kind, newName); other != nil {
		return Object{}, nameTaken(string(kind), newName)
	}
	old := o.Name
	if err := c.persistOnly(func() error {
		// Re-resolve: persistOnly snapshots and restores state on failure, so
		// the pointer above may not be the record that ends up committed.
		if t := c.objectByName(kind, old); t != nil {
			t.Name = newName
		}
		return nil
	}); err != nil {
		return Object{}, err
	}
	return *c.objectByName(kind, newName), nil
}

// Delete removes an object and its bytes. Refused while it is connected.
func (c *Coordinator) Delete(kind Kind, ref string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	o := c.resolveObject(kind, ref)
	if o == nil {
		return notFound(string(kind), ref)
	}
	if len(c.connectionsOf(o.UUID)) > 0 {
		return statusErrCode(http.StatusConflict, CodeResourceConnected,
			"%s %q is connected; disconnect it first", o.Kind, o.Name)
	}
	// The db says this is unconnected -- but if a previous reconcile failed,
	// the kernel may still hold a live LUN with an open fd on the backing
	// file. Converge first; never unlink storage the kernel is serving.
	if err := c.healIfDegraded(); err != nil {
		return err
	}
	uuid, wwn := o.UUID, o.WWN

	// Record first, bytes second. A crash between them leaves bytes with no
	// record, which startup quarantines with the data intact. The other order
	// would leave a record pointing at nothing, which every later operation
	// would trip over and which no operator could clean up safely.
	if err := c.persistOnly(func() error {
		c.st.Objects = deleteObject(c.st.Objects, uuid)
		delete(c.st.Exports, uuid)
		return nil
	}); err != nil {
		return err
	}
	c.discardSavedPR(wwn)
	// A deleted object cannot still be withheld. Leaving the hold would keep
	// /health reporting a standing condition for something that no longer
	// exists, and would leave a UUID in the set that desiredLIO excludes
	// forever.
	c.releaseHold(uuid)
	return c.store.Delete(uuid)
}

func deleteObject(objs []*Object, uuid string) []*Object {
	kept := objs[:0]
	for _, o := range objs {
		if o.UUID != uuid {
			kept = append(kept, o)
		}
	}
	return kept
}

// Resize grows an object. Reports whether initiators must rescan to see it.
func (c *Coordinator) Resize(kind Kind, ref string, newSize int64) (rescanRequired bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	o := c.resolveObject(kind, ref)
	if o == nil {
		return false, notFound(string(kind), ref)
	}
	if newSize == o.Capacity {
		return len(c.connectionsOf(o.UUID)) > 0, nil
	}
	if newSize < o.Capacity {
		return false, statusErrCode(http.StatusBadRequest, CodeInvalidInput,
			"shrink unsupported (%d < %d)", newSize, o.Capacity)
	}
	// A grow obeys the same rules as a create; the kernel floors the block
	// count either way.
	if err := c.checkSize(newSize); err != nil {
		return false, err
	}
	if err := c.healIfDegraded(); err != nil {
		return false, err
	}
	if err := c.store.Resize(o.UUID, newSize); err != nil {
		return false, err
	}
	uuid := o.UUID
	exported := len(c.connectionsOf(uuid)) > 0
	if err := c.persistOnly(func() error {
		if t := c.object(uuid); t != nil {
			t.Capacity = newSize
		}
		return nil
	}); err != nil {
		return exported, err
	}
	// The backing file is bigger; the kernel has to be told, which is a
	// reconcile and not a persist.
	if _, err := c.reconcile(); err != nil {
		return exported, err
	}
	return exported, nil
}
