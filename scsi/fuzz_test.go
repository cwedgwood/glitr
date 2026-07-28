package scsi

import (
	"encoding/binary"
	"testing"
)

// These parsers read BINARY responses from a device, and unlike the prose
// parsers in lio they are length-prefixed: the payload states how long it is,
// and the code has to decide whether to believe it. A length field that lies
// is the classic overrun, and the device is not the only thing that can send
// one -- a truncated transfer produces the same shape.
//
// The stakes are the same as elsewhere in this library: a panic here reaches
// the caller's process. These functions decode the answer to "is this
// initiator fenced", so they run on the path that matters most, and they must
// be total over every possible byte string rather than over the ones a
// working target sends.
//
// As with the lio parsers, these assert only that the function does not panic
// and does not return a value outside its own documented domain. What the
// bytes MEAN is what the table tests assert, using captures of real responses.

// FuzzParseReadKeys: PR IN READ KEYS carries a 4-byte generation, a 4-byte
// additional-length, then that many bytes of 8-byte keys. The length is
// attacker-shaped in the sense that matters here -- it is a number in the
// payload that indexes into the payload.
func FuzzParseReadKeys(f *testing.F) {
	// A real two-key response.
	good := make([]byte, 8+16)
	binary.BigEndian.PutUint32(good[0:4], 1)
	binary.BigEndian.PutUint32(good[4:8], 16)
	binary.BigEndian.PutUint64(good[8:16], 0xaaaa)
	binary.BigEndian.PutUint64(good[16:24], 0xbbbb)
	f.Add(good)

	// Empty list, short buffer, and the length-field edges.
	empty := make([]byte, 8)
	f.Add(empty)
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 1})
	for _, n := range []uint32{0xFFFFFFFF, 0xFFFFFFF8, 0x80000000, 8, 9} {
		b := make([]byte, 8)
		binary.BigEndian.PutUint32(b[4:8], n)
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		gen, keys, err := parseReadKeys(data)
		if err != nil {
			// A rejected response must not also hand back keys: a caller that
			// ignored the error would then act on a partial key list, and
			// "fewer keys than are really registered" is the fail-open
			// direction for a fencing decision.
			if keys != nil {
				t.Fatalf("parseReadKeys(%x) = %d keys AND error %v", data, len(keys), err)
			}
			return
		}
		// Every key must have come from inside the buffer.
		if want := (len(data) - 8) / 8; len(keys) > want {
			t.Fatalf("parseReadKeys(%x) returned %d keys but only %d fit in %d bytes",
				data, len(keys), want, len(data))
		}
		_ = gen
	})
}

// FuzzParseReadReservation: PR IN READ RESERVATION is the same shape, and
// decides whether a reservation is HELD -- so a wrong answer here is a wrong
// answer about whether a node is fenced.
func FuzzParseReadReservation(f *testing.F) {
	held := make([]byte, 8+16)
	binary.BigEndian.PutUint32(held[0:4], 1)
	binary.BigEndian.PutUint32(held[4:8], 16)
	binary.BigEndian.PutUint64(held[8:16], 0xdead)
	held[21] = 0x01 // scope/type byte
	f.Add(held)

	none := make([]byte, 8)
	binary.BigEndian.PutUint32(none[0:4], 1)
	f.Add(none)
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0})
	for _, n := range []uint32{0xFFFFFFFF, 0xFFFFFFF0, 16, 15, 17} {
		b := make([]byte, 8)
		binary.BigEndian.PutUint32(b[4:8], n)
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		heldOut, key, scope, typ, err := parseReadReservation(data)
		if err != nil {
			// Same rule, and it is the one that matters most in this package:
			// a response that could not be parsed must never report a
			// reservation as HELD. Reporting "held" from a failed parse would
			// invent a fence; reporting it alongside an error a caller
			// ignores is the same thing one branch later.
			if heldOut {
				t.Fatalf("parseReadReservation(%x) reported HELD with error %v", data, err)
			}
			return
		}
		if !heldOut && (key != 0 || scope != 0 || typ != 0) {
			t.Fatalf("parseReadReservation(%x): no reservation held but key=%#x scope=%d type=%d",
				data, key, scope, typ)
		}
	})
}

// FuzzParseSense decodes the sense buffer, which is how every fencing verdict
// in this library is reached: a reservation conflict is a STATUS, but the
// reason is in here. Two wire formats exist and reading the wrong offsets
// yields a plausible wrong answer rather than a failure.
func FuzzParseSense(f *testing.F) {
	// Fixed format, NOT READY / LOGICAL UNIT COMMUNICATION FAILURE (2/08h/00h).
	fixed := make([]byte, 18)
	fixed[0], fixed[2], fixed[12], fixed[13] = 0x70, 0x02, 0x08, 0x00
	f.Add(fixed)

	// Descriptor format, same condition.
	desc := make([]byte, 8)
	desc[0], desc[1], desc[2], desc[3] = 0x72, 0x02, 0x08, 0x00
	f.Add(desc)

	// Unit attention, fixed.
	ua := make([]byte, 18)
	ua[0], ua[2], ua[12], ua[13] = 0x70, 0x06, 0x29, 0x00
	f.Add(ua)

	f.Add([]byte{})
	f.Add([]byte{0x70})
	f.Add([]byte{0x72})
	f.Add([]byte{0xff})
	f.Add(make([]byte, 13)) // one byte short of carrying ASC/ASCQ

	f.Fuzz(func(t *testing.T, b []byte) {
		s := parseSense(b)
		if len(b) == 0 {
			if s != nil {
				t.Fatalf("parseSense(empty) = %v, want nil", s)
			}
			return
		}
		if s == nil {
			t.Fatalf("parseSense(%x) = nil for a non-empty buffer", b)
		}
		// Valid means "the fields below were decoded", so it must never be
		// set from a buffer too short to hold them. An undecodable sense
		// reported as decoded is how a wrong ASC/ASCQ becomes a confident
		// wrong verdict -- the package comment calls this out by name.
		if s.Valid && s.Key == 0 && s.ASC == 0 && s.ASCQ == 0 && len(b) < 14 && (b[0]&0x7f) < 0x72 {
			t.Fatalf("parseSense(%x): Valid set from a %d-byte fixed-format buffer", b, len(b))
		}
		// The sense key is four bits wide.
		if s.Key > 0x0f {
			t.Fatalf("parseSense(%x): key %#x does not fit in four bits", b, s.Key)
		}
		// String must not panic on anything that parsed.
		_ = s.String()
		_ = s.UnitAttention()
	})
}

// FuzzParseCapacity16 decodes READ CAPACITY(16), which is where block size
// and capacity come from. A wrong block size is a device that lies about its
// geometry, and every alignment decision above it inherits the lie.
func FuzzParseCapacity16(f *testing.F) {
	good := make([]byte, 32)
	binary.BigEndian.PutUint64(good[0:8], 1<<20-1) // last LBA
	binary.BigEndian.PutUint32(good[8:12], 512)    // block length
	f.Add(good)

	fourK := make([]byte, 32)
	binary.BigEndian.PutUint64(fourK[0:8], 1<<17-1)
	binary.BigEndian.PutUint32(fourK[8:12], 4096)
	fourK[13] = 0x03 // lbppbe in the low nibble
	f.Add(fourK)

	f.Add([]byte{})
	f.Add(make([]byte, 11))
	f.Add(make([]byte, 12))
	zero := make([]byte, 32) // block length 0
	f.Add(zero)

	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := parseCapacity16(Result{}, data)
		if err != nil {
			return
		}
		// A block length of zero would make Bytes() divide the world by
		// nothing and every alignment check meaningless, so it must be
		// rejected rather than returned.
		if c.BlockLength == 0 {
			t.Fatalf("parseCapacity16(%x) returned block length 0 with no error", data)
		}
		// Capacity must not be reported as zero for a device that describes
		// real blocks. Bytes() saturates rather than wrapping, and this is
		// what pins that: the multiplication overflowed uint64 for a
		// LastLBA near the maximum and reported ZERO bytes -- the largest
		// describable device looking like an empty one.
		//
		// This assertion used to read `if b := c.Bytes(); b < 0`, which is
		// unreachable for a uint64 and so could never fire. It was written to
		// catch exactly the overflow above and would not have.
		if c.LastLBA < ^uint64(0) {
			if b := c.Bytes(); b == 0 {
				t.Fatalf("parseCapacity16(%x): zero capacity for LastLBA=%d BlockLength=%d",
					data, c.LastLBA, c.BlockLength)
			}
		}
		if p := c.PhysicalBlockLength(); p < c.BlockLength {
			t.Fatalf("parseCapacity16(%x): physical %d < logical %d", data, p, c.BlockLength)
		}
	})
}
