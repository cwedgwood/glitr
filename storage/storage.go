// Package storage is the appliance's storage model: a lean, local stand-in
// for the volume layer of an enterprise array. It owns volumes, their
// persistent identities (UUID + wwn), sparse backing files, snapshots and
// clones (reflink), resize and metadata, plus a JSON record store.
//
// It is one answer rather than the answer. Anything presenting volumes over
// iSCSI needs some notion of what a volume is and where its bytes live, and
// this is a small, readable version of that -- useful to build on, and
// equally reasonable to replace with a real array, an LVM pool or a
// filesystem of your choosing. The library underneath it does not know or
// care which you pick.
//
// It is deliberately iSCSI- and LIO-agnostic: it knows nothing about targets,
// portals, ACLs, LUNs or configfs. Presenting a volume is somebody else's
// job, and needs only its DiskPath and wwn.
package storage

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// State is a volume's lifecycle status.
type State string

const (
	// Ready means the volume's backing file is present and usable.
	Ready State = "ready"
	// Failed means the backing file is missing or shorter than the
	// recorded capacity (detected by startup repair); it is retained,
	// not exported, and manually deletable.
	Failed State = "failed"
)

// Volume is a single storage object. Identities are stable for its
// lifetime; snapshots and clones receive brand-new identities.
type Volume struct {
	UUID     string    `json:"uuid"`             // canonical dashed UUID (primary id)
	WWN      string    `json:"wwn"`              // 16 lowercase hex, derived from UUID
	Capacity int64     `json:"capacity"`         // bytes
	Parent   string    `json:"parent,omitempty"` // provenance: source UUID for snapshot/clone
	Created  time.Time `json:"created"`
	State    State     `json:"state"`
	// BlockSize is the logical block size the initiator sees, in bytes.
	//
	// A create-time property, like the WWN: the kernel refuses to change it
	// while the device is exported (linux v6.6
	// drivers/target/target_core_configfs.c:1119-1123), and changing it under
	// a mounted filesystem would redefine the device's geometry beneath it.
	//
	// Zero means "not recorded", which must be read as 512 rather than as
	// "unmanaged": volumes created before this field existed were made at the
	// kernel default and an initiator may have one mounted right now, so they
	// have to keep reporting 512 forever. BlockSizeOrDefault applies that,
	// and Store.repair backfills the field once on load so that "unrecorded"
	// stops existing rather than being reinterpreted at every call site.
	//
	// NOT omitempty: a client has to be able to tell "512, pinned" from
	// "unmanaged", and omitting the field for exactly the legacy volumes this
	// stack is actively pinning would erase that distinction.
	BlockSize int `json:"block_size"`
}

// Block sizes. The kernel accepts 512/1024/2048/4096; this package allows the
// two that correspond to real disk geometries -- 512n and 4Kn -- because the
// intermediate values have no hardware analogue and only add ways to be
// surprised.
const (
	DefaultBlockSize = 512
	MaxBlockSize     = 4096
)

// ValidBlockSize reports whether n is a block size this store will create.
func ValidBlockSize(n int) bool { return n == DefaultBlockSize || n == MaxBlockSize }

// BlockSizeOrDefault is the volume's block size, treating an unrecorded value
// as the kernel default it was created with.
func (v Volume) BlockSizeOrDefault() int {
	if v.BlockSize == 0 {
		return DefaultBlockSize
	}
	return v.BlockSize
}

// newIdentity generates a fresh UUIDv4 and derives the 16-hex wwn from
// it (the width that fits LIO's NAA designator, which the lio library
// validates).
// It returns an error if the system CSPRNG fails — the identity must
// never fall back to a zero/duplicate value, which would give every
// volume the same UUID/wwn (colliding paths + device identities).
func newIdentity() (uuid, wwn string, err error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40   // version 4
	b[8] = (b[8] & 0x3f) | 0x80   // variant 10
	h := hex.EncodeToString(b[:]) // 32 lowercase hex
	uuid = h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	wwn = h[:16]
	return uuid, wwn, nil
}

// validUUID reports whether s is a canonical dashed UUID (8-4-4-4-12 lower
// hex). Enforced on load so a record's UUID cannot contain path separators
// or "." / ".." that would let DiskPath/volDir escape the volumes dir.
func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
	}
	return true
}

// validWWN reports whether s is 16 lowercase hex digits — the NAA-designator
// width the lio library also validates. Enforced on load so a corrupt or
// foreign record cannot yield a bad device identity, or fail validation later
// at export time.
func validWWN(s string) bool {
	if len(s) != 16 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ReadMetadataForDisk loads the advisory per-volume metadata that sits beside
// a backing file, given the path to that file.
//
// It exists so a tool holding only a LIO backstore's device path can name the
// volume -- its capacity, block size and, for a snapshot, its parent -- without
// opening the store, without the record db, and without the daemon running.
// `applianced inspect` reads the KERNEL rather than the db precisely so it
// still works when the daemon is down, and this preserves that.
//
// The db remains authoritative (see the Layout note on Store): this file is
// advisory, so a caller must treat a mismatch as "the db wins" and must
// tolerate the file being absent -- volumes created before it existed, or a
// backstore whose backing file is not one of ours at all.
//
// Lives here rather than in the caller so the on-disk layout stays owned by
// this package.
func ReadMetadataForDisk(diskPath string) (Volume, error) {
	var v Volume
	data, err := os.ReadFile(filepath.Join(filepath.Dir(diskPath), "metadata.json"))
	if err != nil {
		return v, err
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return v, fmt.Errorf("storage: %s: %w", diskPath, err)
	}
	// Resolve an absent block size the same way the db does, so no caller can
	// read 0 out of this and treat it as a geometry.
	//
	// 0 is not a mismatch a caller can arbitrate with "the db wins" -- it is an
	// absent value that LOOKS like a real one, and it is not a legal block
	// size. It arises two ways: a file written before the field existed, and a
	// record whose block size startup repair backfilled into the db while
	// leaving this file untouched.
	//
	// Normalised on READ rather than by rewriting the files, because rewriting
	// only reaches volumes repair happens to touch: a file that predates the
	// field and is never marked dirty would keep its 0 forever. Doing it here
	// fixes every caller and every file at once, and it gives exactly what the
	// db would give -- 512, which is what those volumes' initiators have always
	// seen, since they were created at the kernel's fileio default.
	//
	// THIS DOES ERASE A DISTINCTION, and the field's own comment above says why
	// it is not omitempty: a client should be able to tell "512, pinned" from
	// "unmanaged". After this a caller cannot. Accepted here and nowhere else,
	// because this function's contract is "what geometry is this disk being
	// served with", which is 512 either way, and because a 0 handed to a caller
	// is a number no device ever had. If a caller ever needs the distinction it
	// must come from a second return value or a sentinel, NOT by removing this
	// line -- the returned Volume is a value type and re-marshalling it would
	// then write the fabricated 512 back to disk as an assertion.
	v.BlockSize = v.BlockSizeOrDefault()
	return v, nil
}
