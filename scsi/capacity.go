package scsi

import (
	"encoding/binary"
	"fmt"
)

// opReadCapacity16 is SERVICE ACTION IN(16) / READ CAPACITY(16) (SBC-4 5.16).
const (
	opServiceActionIn16 = 0x9e
	saReadCapacity16    = 0x10
)

// Capacity is what READ CAPACITY(16) reports: the device's geometry, from the
// device itself.
//
// This replaces parsing sg_readcap's table. The values here are the ones an
// initiator's block layer is built from, read straight off the wire.
type Capacity struct {
	// LastLBA is the highest addressable logical block. The block COUNT is
	// LastLBA+1 -- an off-by-one that is easy to get wrong and shows up as a
	// capacity that is one block short.
	LastLBA uint64 `json:"last_lba"`
	// BlockLength is the LOGICAL block size in bytes.
	BlockLength uint32 `json:"block_length"`
	// LBPPBExp is the logical-blocks-per-physical-block exponent. Physical
	// block size is BlockLength << LBPPBExp, so a non-zero value is what a
	// 512e device looks like: 512-byte logical blocks inside 4096-byte
	// physical ones.
	//
	// MEASURED: LIO's fileio backend implements no get_lbppbe, so this stays 0
	// and physical always equals logical -- the reason this project supports
	// clean 512n and 4Kn only, and refuses to claim 512e.
	LBPPBExp uint8 `json:"lbppbe"`
	// LowestAlignedLBA is the alignment offset in logical blocks.
	LowestAlignedLBA uint16 `json:"lowest_aligned_lba"`
	Result           Result `json:"result"`
}

// Bytes is the device's capacity: (LastLBA + 1) blocks of BlockLength.
//
// Saturates at MaxUint64 rather than wrapping. Both halves can overflow --
// LastLBA is a full uint64, so a device reporting the maximum made LastLBA+1
// zero and this return ZERO CAPACITY for the largest device it could
// describe. A capacity that wraps is not a smaller device, it is a wrong
// answer, and every allocation decision above it inherits it. Found by
// fuzzing.
func (c Capacity) Bytes() uint64 {
	blocks := c.LastLBA + 1
	if blocks == 0 { // LastLBA was MaxUint64
		return ^uint64(0)
	}
	if bl := uint64(c.BlockLength); bl != 0 && blocks > ^uint64(0)/bl {
		return ^uint64(0)
	}
	return blocks * uint64(c.BlockLength)
}

// PhysicalBlockLength is the physical block size the device advertises.
//
// parseCapacity16 refuses a response whose shift would overflow, so this
// cannot wrap for any Capacity that came from it. It is computed in 64 bits
// anyway, because a zero value or one built by hand can still reach here and
// a physical block SMALLER than the logical one is a fact no device can
// represent -- it would make an alignment check pass on a device that is not
// aligned.
func (c Capacity) PhysicalBlockLength() uint32 {
	// The exponent is bounded FIRST. LBPPBExp is a uint8 and the parser only
	// ever stores 0..15, but a hand-built value can hold 255 -- and in Go a
	// shift by 64 or more yields ZERO rather than panicking, so this returned
	// a physical block of 0: smaller than the logical one, which is the exact
	// thing the comment above says cannot happen here, and which makes an
	// alignment check pass on a device that is not aligned.
	if c.LBPPBExp > maxLBPPBExp {
		return c.BlockLength
	}
	p := uint64(c.BlockLength) << c.LBPPBExp
	if p > uint64(^uint32(0)) {
		return c.BlockLength
	}
	return uint32(p)
}

// maxLBPPBExp is the widest LOGICAL BLOCKS PER PHYSICAL BLOCK EXPONENT the
// field can hold: SBC-4 4.6 gives it four bits.
const maxLBPPBExp = 15

// ReadCapacity16 issues READ CAPACITY(16).
func (d *Device) ReadCapacity16() (Capacity, error) {
	const alloc = 32
	cdb := make([]byte, 16)
	cdb[0] = opServiceActionIn16
	cdb[1] = saReadCapacity16
	binary.BigEndian.PutUint32(cdb[10:14], alloc)

	r, err := d.send(cdb, alloc, nil)
	if err != nil {
		return Capacity{}, err
	}
	c := Capacity{Result: r}
	if !r.OK() {
		return c, &StatusError{Op: "READ CAPACITY(16)", Result: r}
	}
	return parseCapacity16(r, r.Data)
}

// parseCapacity16 decodes the READ CAPACITY(16) parameter data.
//
// Split out from the command so the decode can be tested against a buffer
// without a device. It was inline, which is why the 512e case in the unit
// tests set LBPPBExp by hand instead of decoding byte 13 -- and why a decode
// that read the wrong nibble would have passed.
func parseCapacity16(r Result, data []byte) (Capacity, error) {
	c := Capacity{Result: r}
	if len(data) < 16 {
		return c, fmt.Errorf("scsi: READ CAPACITY(16) returned %d bytes, want at least 16",
			len(data))
	}
	c.LastLBA = binary.BigEndian.Uint64(data[0:8])
	c.BlockLength = binary.BigEndian.Uint32(data[8:12])
	if c.BlockLength == 0 {
		return c, fmt.Errorf("scsi: READ CAPACITY(16) reported a block length of 0")
	}
	// Byte 13: bits 7-4 are P_I_EXPONENT, bits 3-0 are LOGICAL BLOCKS PER
	// PHYSICAL BLOCK EXPONENT (SBC-4 5.16.2). The low nibble is LBPPBE.
	//
	// The comment used to state these the other way round while the code took
	// the low nibble. The code is right -- it matches linux v6.6
	// drivers/scsi/sd.c ("physical_block_size = (1 << (buffer[13] & 0xf)) *
	// sector_size") and sg3_utils -- but anyone trusting the comment and
	// "fixing" the code to >> 4 would break the 512e detection the blocksize
	// suite asserts on, and no unit test would have caught it.
	// TestLBPPBEIsTheLowNibble now decodes a real buffer.
	c.LBPPBExp = data[13] & 0x0f
	// Self-consistency, not policy: a response whose physical block size
	// cannot be represented is describing a device that cannot exist, and
	// silently wrapping it yields a physical block SMALLER than the logical
	// one. That is not a smaller device, it is a wrong answer that every
	// alignment decision above this inherits. Found by fuzzing, which
	// produced block length 4012912688 with a non-zero exponent.
	if uint64(c.BlockLength)<<c.LBPPBExp > uint64(^uint32(0)) {
		return c, fmt.Errorf(
			"scsi: READ CAPACITY(16) reported block length %d with LBPPBE %d, whose "+
				"physical block size does not fit in 32 bits", c.BlockLength, c.LBPPBExp)
	}
	// Bytes 14-15: bits 0-13 are LOWEST ALIGNED LOGICAL BLOCK ADDRESS.
	c.LowestAlignedLBA = binary.BigEndian.Uint16(data[14:16]) & 0x3fff
	return c, nil
}
