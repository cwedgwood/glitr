package storage

import "fmt"

// Geometry: the size rules the backing store imposes, as opposed to the ones
// the appliance chooses.
//
// The distinction matters because only one of them is negotiable. A minimum
// object size is a policy: we could allow smaller objects tomorrow and nothing
// on disk would have to change. The granularity is not -- it is a property of
// what the bytes actually live on, so it has to be asked for rather than
// assumed, and a caller that hardcodes it is correct only for as long as this
// store is the only one.

// SizeGranularity is the multiple every object size must be a whole number of
// on a file-backed store.
//
// 4096 because these objects are files on a copy-on-write filesystem, whose
// extents and reflink (FICLONE) operations work in filesystem blocks -- 4096
// on XFS and btrfs as anyone makes them. A size that ends mid-block leaves a
// partial extent, which is the one thing a reflink cannot share, so a snapshot
// silently stops being a pure metadata operation at exactly the boundary.
//
// It is also, deliberately, wider than the smallest thing the kernel would
// accept. A size that is a whole number of 512-byte blocks can still end
// halfway through a 4096-byte one, so holding every object to 4096 means the
// same bytes can be re-presented at 4Kn later without losing a tail.
//
// This is NOT the block size presented to an initiator, which is a separate
// choice made a layer up and can be 512 while this is 4096. The two numbers
// coincide today; they are not the same number and must not be merged.
//
// A different backing store reports something else: a block-backed store would
// report its device's logical block size, which is commonly 512. Ask the store
// (see [Store.SizeGranularity]); do not use this constant directly unless you
// mean specifically a file-backed store.
const SizeGranularity = 4096

// SizeGranularity reports the multiple every object size on this store must be
// a whole number of.
//
// A method rather than a bare constant because it is a property of the backing
// store: an implementation over a block device would report the device's own
// block size, discovered rather than compiled in.
func (s *Store) SizeGranularity() int64 { return SizeGranularity }

// CheckGranularity reports whether size is a whole number of granularity
// bytes, with an error naming both numbers if it is not.
//
// Separate from any minimum, because the two rules fail for unrelated reasons
// and a caller usually wants to say something different about each. Callers
// pass the granularity they got from their store rather than the constant, so
// this stays correct for a store that reports another value.
func CheckGranularity(size, granularity int64) error {
	if granularity <= 0 {
		// Reported by a store rather than written down, so a broken or
		// zero-valued implementation reaches here. Refusing beats the
		// alternative: size%0 panics, and taking it as "no constraint"
		// would quietly accept sizes the store cannot represent.
		return fmt.Errorf("storage: size granularity %d is not positive", granularity)
	}
	if size%granularity != 0 {
		return fmt.Errorf("size %d must be a multiple of %d", size, granularity)
	}
	return nil
}
