package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBlockSizeDefaultsAndValidation: the appliance offers 512 and 4096 only.
// The kernel would also take 1024 and 2048, but those correspond to no real
// disk geometry and only add ways for a consumer to be surprised.
func TestBlockSizeDefaultsAndValidation(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	v, err := s.Create(1<<20, 0)
	if err != nil {
		t.Fatalf("create with 0 (meaning default): %v", err)
	}
	if v.BlockSize != DefaultBlockSize {
		t.Errorf("block size = %d, want the default %d", v.BlockSize, DefaultBlockSize)
	}

	if v, err := s.Create(1<<20, 4096); err != nil {
		t.Errorf("4096 must be accepted: %v", err)
	} else if v.BlockSize != 4096 {
		t.Errorf("block size = %d, want 4096", v.BlockSize)
	}

	for _, bad := range []int{1024, 2048, 511, 8192, -512} {
		if _, err := s.Create(1<<20, bad); err == nil {
			t.Errorf("block size %d must be rejected", bad)
		}
	}
}

// TestBlockSizeMustDivideCapacity: the kernel derives the last LBA as
// (size - block_size)/block_size (linux v6.6
// drivers/target/target_core_file.c:804-822), so an unaligned size silently
// loses its trailing partial block -- the caller asks for N bytes and the
// initiator sees fewer. Refusing is better than quietly shipping a short disk.
func TestBlockSizeMustDivideCapacity(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// 1 MiB + 512: fine at 512, not a multiple of 4096.
	const unaligned = (1 << 20) + 512
	if _, err := s.Create(unaligned, DefaultBlockSize); err != nil {
		t.Errorf("size %d is a whole number of 512-byte blocks: %v", unaligned, err)
	}
	_, err = s.Create(unaligned, 4096)
	if err == nil {
		t.Fatalf("size %d is not a multiple of 4096 and must be refused", unaligned)
	}
	if !strings.Contains(err.Error(), "multiple") {
		t.Errorf("error should explain the alignment rule, got %q", err)
	}
}

// TestSnapshotInheritsBlockSize: a snapshot shares the parent's extents byte
// for byte, so presenting it at a different block size would describe
// identical bytes as a differently-shaped device -- the partition table and
// filesystem inside were written for the parent's geometry.
func TestSnapshotInheritsBlockSize(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := s.Create(1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot(parent.UUID)
	if err != nil {
		t.Skipf("snapshot needs reflink support: %v", err)
	}
	if snap.BlockSize != parent.BlockSize {
		t.Errorf("snapshot block size = %d, want the parent's %d",
			snap.BlockSize, parent.BlockSize)
	}
}

// TestUnrecordedBlockSizeReadsAsDefault is the upgrade path. A volume created
// before this field existed has no block_size in its metadata, and it was made
// at the kernel default -- an initiator may have it mounted right now. It must
// therefore keep reporting 512 forever, so absent has to mean 512 rather than
// "unmanaged".
func TestUnrecordedBlockSizeReadsAsDefault(t *testing.T) {
	if got := (Volume{}).BlockSizeOrDefault(); got != DefaultBlockSize {
		t.Errorf("an unrecorded block size reads as %d, want %d", got, DefaultBlockSize)
	}
	if got := (Volume{BlockSize: 4096}).BlockSizeOrDefault(); got != 4096 {
		t.Errorf("a recorded block size must be preserved, got %d", got)
	}
}

// TestBlockSizePersists: the value has to survive a restart, because the
// device geometry an initiator already saw cannot be re-derived from anything
// else on disk.
func TestBlockSizePersists(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Create(1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}

	// Reopened store: the value must come back.
	s2, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Get(v.UUID)
	if !ok {
		t.Fatal("volume vanished across reopen")
	}
	if got.BlockSize != 4096 {
		t.Errorf("after reopen block size = %d, want 4096", got.BlockSize)
	}

	// And it must be in the per-volume metadata, which is what a rebuild
	// would have to read.
	meta, err := os.ReadFile(filepath.Join(root, "volumes", v.UUID, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(meta), `"block_size": 4096`) &&
		!strings.Contains(string(meta), `"block_size":4096`) {
		t.Errorf("metadata.json does not record the block size:\n%s", meta)
	}
}

// editDB rewrites the record db through a real JSON round-trip and reopens
// the store over it. Field-level string surgery on the file is too fragile to
// trust for a regression test -- a formatting change would silently turn the
// test into a no-op that still passes.
func editDB(t *testing.T, root string, edit func(rec map[string]any)) (*Store, error) {
	t.Helper()
	path := filepath.Join(root, "volumes.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recs []map[string]any
	if err := json.Unmarshal(raw, &recs); err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		edit(r)
	}
	out, err := json.Marshal(recs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return Open(root)
}

// legacyStore stages a store holding one volume, then rewrites its record into
// the shape an older build wrote: no block_size key at all.
func legacyStore(t *testing.T, edit func(rec map[string]any)) (*Store, string) {
	t.Helper()
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Create(1<<20, 0)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := editDB(t, root, func(rec map[string]any) {
		delete(rec, "block_size")
		if edit != nil {
			edit(rec)
		}
	})
	if err != nil {
		t.Fatalf("a record written by an older build must still load: %v", err)
	}
	return s2, v.UUID
}

// TestLegacyRecordBackfillsBlockSize: a record written before the field
// existed must come back as 512 AND be rewritten to say so.
//
// Reinterpreting an absent field at every call site is how "unrecorded" ends
// up meaning different things in different places -- the REST API omitted it
// entirely while the reconcile layer was actively pinning the volume to 512,
// so a client could not tell "512, pinned" from "unmanaged".
func TestLegacyRecordBackfillsBlockSize(t *testing.T) {
	s, uuid := legacyStore(t, nil)
	v, ok := s.Get(uuid)
	if !ok {
		t.Fatal("volume missing after reload")
	}
	if v.BlockSize != DefaultBlockSize {
		t.Errorf("block size = %d, want it backfilled to %d", v.BlockSize, DefaultBlockSize)
	}
}

// TestLegacyUnalignedCapacityDoesNotBrickStartup is the regression test for a
// whole-appliance outage, and for the two crash loops the first attempt at
// fixing it introduced.
//
// Nothing enforced alignment before the block-size work, so an ordinary
// {"size":1000000} produced a record that is not a whole number of 512-byte
// blocks. The store must open such a record, and must leave it ALONE: the
// first fix floored it here, which (a) yielded 0 for a sub-block capacity that
// `load` then rejected, and (b) looked like a shrink to the reconcile, because
// a live kernel object created by an older build still reports the unfloored
// size. Alignment is applied where the size is used, not where it is stored --
// appliance.desiredLIO floors what it hands to lio.
func TestLegacyUnalignedCapacityDoesNotBrickStartup(t *testing.T) {
	const unaligned = 1000001 // 1953 whole 512-byte blocks, plus 65 bytes

	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Create(1<<20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(s.DiskPath(v.UUID), unaligned); err != nil {
		t.Fatal(err)
	}
	s2, err := editDB(t, root, func(rec map[string]any) {
		delete(rec, "block_size")
		rec["capacity"] = unaligned
	})
	if err != nil {
		t.Fatalf("a legacy record with an unaligned capacity must not stop the store from "+
			"opening -- that takes every healthy volume down with it: %v", err)
	}
	got, ok := s2.Get(v.UUID)
	if !ok {
		t.Fatal("volume missing after reload")
	}
	if got.Capacity != unaligned {
		t.Errorf("capacity = %d, want the record left at %d -- rewriting it during repair "+
			"is what produced the shrink-unsupported crash loop", got.Capacity, unaligned)
	}
	if got.BlockSize != DefaultBlockSize {
		t.Errorf("block size = %d, want it backfilled to %d", got.BlockSize, DefaultBlockSize)
	}

	// And it must keep opening, indefinitely.
	if _, err := Open(root); err != nil {
		t.Errorf("second Open: %v", err)
	}
}

// TestSubBlockCapacityIsRejectedAsInvalid: a volume smaller than one logical
// block is not a volume and is never supported.
//
// The kernel would present a zero-length device, so there is no valid geometry
// to give it. It is refused with the other malformed-record cases rather than
// carried through the stack and skipped later: the current API cannot produce
// one (Create requires a whole number of blocks, Resize is grow-only and
// aligned), so it can only be hand-edited or pre-alignment.
//
// This replaced a brief attempt to floor such a capacity during startup
// repair, which yielded 0, was marked ready, was persisted, and then failed
// `load`'s own non-positive check on the NEXT Open -- a migration must never
// write a value its loader rejects.
func TestSubBlockCapacityIsRejectedAsInvalid(t *testing.T) {
	for _, capacity := range []int{1, 300, 511} {
		root := t.TempDir()
		s, err := Open(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Create(1<<20, 0); err != nil {
			t.Fatal(err)
		}
		s2, err := editDB(t, root, func(rec map[string]any) {
			delete(rec, "block_size")
			rec["capacity"] = capacity
		})
		// The record is rejected, not carried into the reconcile -- but it
		// costs only itself now. This case is the one a PRE-EXISTING record
		// can trip, because Create used to accept any size > 0, so failing
		// the whole Open turned an upgrade into a permanent crash loop.
		if err != nil {
			t.Errorf("capacity %d: one bad record must not fail the whole store: %v", capacity, err)
			continue
		}
		if n := len(s2.List()); n != 0 {
			t.Errorf("capacity %d (< one 512-byte block) must be rejected as an invalid "+
				"record, not carried into the reconcile; got %d live volumes", capacity, n)
			continue
		}
		rej := s2.RejectedRecords()
		if len(rej) != 1 {
			t.Errorf("capacity %d must be reported as a rejected record", capacity)
			continue
		}
		if !strings.Contains(rej[0].Reason, "block size") {
			t.Errorf("capacity %d: reason should explain the geometry problem, got %q", capacity, rej[0].Reason)
		}
	}
	// One whole block is the smallest valid volume, and must still load.
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(512, 0); err != nil {
		t.Fatalf("a single-block volume is valid: %v", err)
	}
	if _, err := Open(root); err != nil {
		t.Errorf("a single-block volume must reload: %v", err)
	}
	_ = s
}

// TestPoisonBlockSizeIsRejectedAtLoad: a persisted block size describes bytes
// an initiator has already formatted against, so it is validated exactly as
// strictly as the WWN. Anything outside the policy would otherwise bypass the
// REST API's own check and reach the kernel.
//
// The record is now REJECTED rather than failing the whole Open, so what is
// asserted is the property that actually protects the kernel: the poisoned
// record must not become a live volume. Failing Open was only ever the means;
// keeping the value away from the kernel is the end, and it is met by
// excluding the record from the live set.
func TestPoisonBlockSizeIsRejectedAtLoad(t *testing.T) {
	for _, poison := range []int{1024, 2048, 777, -512} {
		root := t.TempDir()
		s, err := Open(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Create(1<<20, 0); err != nil {
			t.Fatal(err)
		}
		s2, err := editDB(t, root, func(rec map[string]any) {
			rec["block_size"] = poison
		})
		if err != nil {
			t.Fatalf("block_size %d: one poisoned record must not fail the whole store: %v", poison, err)
		}
		if n := len(s2.List()); n != 0 {
			t.Errorf("block_size %d must not reach the live set (and so the kernel), got %d volumes", poison, n)
		}
		if len(s2.RejectedRecords()) != 1 {
			t.Errorf("block_size %d must be reported as a rejected record", poison)
		}
	}
}

// TestResizeEnforcesAlignment: storage is a real API boundary, so the
// invariant Create holds must hold here too rather than only one layer up in
// the appliance -- an unaligned grow loses its tail exactly as an unaligned
// create does.
func TestResizeEnforcesAlignment(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Create(1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resize(v.UUID, 1<<20+512); err == nil {
		t.Error("an unaligned grow must be refused by storage, not just by the appliance")
	}
	if _, err := s.Resize(v.UUID, 1<<20+4096); err != nil {
		t.Errorf("an aligned grow must still work: %v", err)
	}
}
