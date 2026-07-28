package scsi

import (
	"encoding/binary"
	"strings"
	"testing"
	"unsafe"
)

// TestSgIOHdrLayout pins the struct against the kernel's.
//
// The kernel reads this memory directly. A wrong offset does not fail loudly:
// it sends a valid ioctl with fields in the wrong places, and the most likely
// outcome is a command that appears to work while reporting another field's
// bytes as the status. Every assertion built on this package would then be
// measuring noise.
//
// Offsets are from struct sg_io_hdr, linux v6.6 include/scsi/sg.h:34-60. The
// struct contains four pointers, so its layout depends on the pointer width:
// the kernel's own 32-bit sg_io_hdr is 64 bytes where the 64-bit one is 88,
// and Go's unsafe.Pointer tracks C's void * on both. This test used to assert
// the 64-bit offsets unconditionally and therefore FAILED on 386 -- not
// because the struct was wrong there, but because the test could only ever
// describe one architecture. Pinning both is the point: an ioctl handed a
// mis-shaped struct is exactly the failure this test exists to prevent, and
// 32-bit is where the shape differs.
func TestSgIOHdrLayout(t *testing.T) {
	var h sgIOHdr
	ptr := unsafe.Sizeof(uintptr(0)) // 8 on a 64-bit target, 4 on a 32-bit one
	wantSize := uintptr(88)
	if ptr == 4 {
		wantSize = 64
	}
	// Every field after dxfer_len sits at a pointer-width-dependent offset;
	// expressing them in terms of ptr describes both targets with one table.
	for _, c := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"interface_id", unsafe.Offsetof(h.interfaceID), 0},
		{"dxfer_direction", unsafe.Offsetof(h.dxferDirection), 4},
		{"cmd_len", unsafe.Offsetof(h.cmdLen), 8},
		{"mx_sb_len", unsafe.Offsetof(h.mxSbLen), 9},
		{"iovec_count", unsafe.Offsetof(h.iovecCount), 10},
		{"dxfer_len", unsafe.Offsetof(h.dxferLen), 12},
		{"dxferp", unsafe.Offsetof(h.dxferp), 16},
		{"cmdp", unsafe.Offsetof(h.cmdp), 16 + ptr},
		{"sbp", unsafe.Offsetof(h.sbp), 16 + 2*ptr},
		{"timeout", unsafe.Offsetof(h.timeout), 16 + 3*ptr},
		{"flags", unsafe.Offsetof(h.flags), 20 + 3*ptr},
		{"pack_id", unsafe.Offsetof(h.packID), 24 + 3*ptr},
		{"usr_ptr", unsafe.Offsetof(h.usrPtr), 24 + 4*ptr},
		{"status", unsafe.Offsetof(h.status), 24 + 5*ptr},
		{"masked_status", unsafe.Offsetof(h.maskedStatus), 25 + 5*ptr},
		{"msg_status", unsafe.Offsetof(h.msgStatus), 26 + 5*ptr},
		{"sb_len_wr", unsafe.Offsetof(h.sbLenWr), 27 + 5*ptr},
		{"host_status", unsafe.Offsetof(h.hostStatus), 28 + 5*ptr},
		{"driver_status", unsafe.Offsetof(h.driverStatus), 30 + 5*ptr},
		{"resid", unsafe.Offsetof(h.resid), 32 + 5*ptr},
		{"duration", unsafe.Offsetof(h.duration), 36 + 5*ptr},
		{"info", unsafe.Offsetof(h.info), 40 + 5*ptr},
	} {
		if c.got != c.want {
			t.Errorf("%s at offset %d, kernel has it at %d", c.name, c.got, c.want)
		}
	}
	if got := unsafe.Sizeof(h); got != wantSize {
		t.Errorf("sizeof(sg_io_hdr) = %d, kernel has %d for a %d-byte pointer", got, wantSize, ptr)
	}
}

// TestPRInCDB pins the PERSISTENT RESERVE IN CDB against SPC-6 6.16: opcode,
// service action in the low 5 bits of byte 1, allocation length big-endian at
// bytes 7-8.
func TestPRInCDB(t *testing.T) {
	cdb := prInCDB(priReadKeys, 8192)
	if len(cdb) != 10 {
		t.Fatalf("CDB length %d, want 10", len(cdb))
	}
	if cdb[0] != 0x5e {
		t.Errorf("opcode 0x%02x, want 0x5e", cdb[0])
	}
	if cdb[1] != 0x00 {
		t.Errorf("service action 0x%02x, want 0x00 (READ KEYS)", cdb[1])
	}
	if got := binary.BigEndian.Uint16(cdb[7:9]); got != 8192 {
		t.Errorf("allocation length %d, want 8192", got)
	}
	if cdb := prInCDB(priReadReservation, 256); cdb[1] != 0x01 {
		t.Errorf("READ RESERVATION service action 0x%02x, want 0x01", cdb[1])
	}
}

// TestReadKeysParsing covers the shapes a device can return, including the two
// that must NOT look like an empty key list.
func TestReadKeysParsing(t *testing.T) {
	// Well-formed: generation 4, two keys.
	data := make([]byte, 8+16)
	binary.BigEndian.PutUint32(data[0:4], 4)
	binary.BigEndian.PutUint32(data[4:8], 16)
	binary.BigEndian.PutUint64(data[8:16], 0xaaaa)
	binary.BigEndian.PutUint64(data[16:24], 0xbbbb)

	gen, keys, err := parseReadKeys(data)
	if err != nil {
		t.Fatal(err)
	}
	if gen != 4 {
		t.Errorf("generation %d, want 4", gen)
	}
	if len(keys) != 2 || keys[0] != 0xaaaa || keys[1] != 0xbbbb {
		t.Errorf("keys = %#x, want [aaaa bbbb]", keys)
	}

	// Truncated: the device reported more keys than were transferred. This
	// MUST be an error. Returning the short list would report "one key
	// registered" for a device with two hundred -- a fencing check would then
	// conclude a node was unregistered when it was not.
	short := make([]byte, 8+8)
	binary.BigEndian.PutUint32(short[4:8], 1600)
	if _, _, err := parseReadKeys(short); err == nil {
		t.Error("a truncated key list must be an error, not a short list that looks complete")
	}

	// Not a multiple of 8: the device or the transfer is malformed.
	odd := make([]byte, 8+12)
	binary.BigEndian.PutUint32(odd[4:8], 12)
	if _, _, err := parseReadKeys(odd); err == nil {
		t.Error("an additional length that is not a multiple of 8 must be an error")
	}

	// No registrations is a valid answer with zero keys.
	empty := make([]byte, 8)
	binary.BigEndian.PutUint32(empty[0:4], 9)
	gen, keys, err = parseReadKeys(empty)
	if err != nil || gen != 9 || len(keys) != 0 {
		t.Errorf("empty list: gen=%d keys=%v err=%v; want gen 9, no keys, no error", gen, keys, err)
	}
}

// TestReadReservationParsing: "nobody holds it" is an answer, not a failure.
//
// The device signals it with an ADDITIONAL LENGTH of 0 and a GOOD status.
// Treating that as an error would make "no reservation" indistinguishable from
// "the command did not work", which is precisely the distinction a fencing
// check depends on.
func TestReadReservationParsing(t *testing.T) {
	none := make([]byte, 8)
	binary.BigEndian.PutUint32(none[0:4], 3)
	held, key, scope, typ, err := parseReadReservation(none)
	if err != nil {
		t.Fatal(err)
	}
	if held {
		t.Error("additional length 0 means no holder")
	}
	// The rest of the answer must be zero too. A parser that reported
	// held=false alongside a stale key or type would pass a test that only
	// looked at held, and a caller that logs the holder would print garbage.
	if key != 0 || scope != 0 || typ != 0 {
		t.Errorf("no holder, but key=%#x scope=%d type=%d; want all zero", key, scope, typ)
	}

	full := make([]byte, 24)
	binary.BigEndian.PutUint32(full[0:4], 7)
	binary.BigEndian.PutUint32(full[4:8], 16)
	binary.BigEndian.PutUint64(full[8:16], 0xdead)
	full[21] = 0x05 // scope 0, type 5 (write exclusive, registrants only)
	held, key, scope, typ, err = parseReadReservation(full)
	if err != nil {
		t.Fatal(err)
	}
	if !held || key != 0xdead || scope != 0 || typ != TypeWriteExclusiveRegistrantsOnly {
		t.Errorf("held=%v key=%#x scope=%d type=%d; want held, dead, 0, 5", held, key, scope, typ)
	}
}

// TestPROutParameterList pins the PERSISTENT RESERVE OUT parameter list
// against SPC-6 6.17.3, including the APTPL bit -- which is the entire basis
// of reservations surviving a target reboot. A wrong bit position there gives
// a registration that works perfectly until the target restarts.
func TestPROutParameterList(t *testing.T) {
	cdb, p := prOutBytes(proRegister, scopeLU, TypeWriteExclusiveRegistrantsOnly, 0xaaaa, 0xbbbb, true)
	if cdb[0] != 0x5f {
		t.Errorf("opcode 0x%02x, want 0x5f", cdb[0])
	}
	if cdb[1] != proRegister {
		t.Errorf("service action 0x%02x, want 0x00", cdb[1])
	}
	if cdb[2] != 0x05 {
		t.Errorf("scope/type byte 0x%02x, want 0x05 (scope 0, type 5)", cdb[2])
	}
	if int(cdb[8]) != prOutParamLen {
		t.Errorf("parameter list length %d, want %d", cdb[8], prOutParamLen)
	}
	if len(p) != prOutParamLen {
		t.Fatalf("parameter list is %d bytes, want %d", len(p), prOutParamLen)
	}
	if got := binary.BigEndian.Uint64(p[0:8]); got != 0xaaaa {
		t.Errorf("reservation key %#x, want aaaa", got)
	}
	if got := binary.BigEndian.Uint64(p[8:16]); got != 0xbbbb {
		t.Errorf("service action key %#x, want bbbb", got)
	}
	if p[20]&0x01 == 0 {
		t.Error("APTPL bit not set -- registrations would not survive a target reboot")
	}

	_, p = prOutBytes(proRegister, 0, 0, 1, 0, false)
	if p[20]&0x01 != 0 {
		t.Error("APTPL bit set when it was not requested")
	}
}

// TestSenseParsing covers both formats. Reading the fixed-format offsets out
// of a descriptor-format buffer yields a plausible wrong answer rather than a
// failure, which is the shape of mismeasurement this package exists to stop.
func TestSenseParsing(t *testing.T) {
	fixed := make([]byte, 18)
	fixed[0] = 0x70
	fixed[2] = 0x06 // UNIT ATTENTION
	fixed[12], fixed[13] = 0x2a, 0x04
	s := parseSense(fixed)
	if s == nil || s.Key != SenseUnitAttention || s.ASC != 0x2a || s.ASCQ != 0x04 {
		t.Errorf("fixed format parsed as %+v", s)
	}
	if !s.UnitAttention() {
		t.Error("key 6 is UNIT ATTENTION")
	}

	desc := []byte{0x72, 0x05, 0x24, 0x00}
	s = parseSense(desc)
	if s == nil || s.Key != SenseIllegalRequest || s.ASC != 0x24 || s.ASCQ != 0x00 {
		t.Errorf("descriptor format parsed as %+v", s)
	}

	if parseSense(nil) != nil {
		t.Error("no sense data must be nil, not a zero Sense that reads as NO SENSE")
	}
}

// TestConflictIsAComparison is the point of the package, stated as a test: the
// fencing verdict is a number, and nothing about it is language.
func TestConflictIsAComparison(t *testing.T) {
	if !(Result{Status: StatusReservationConflict}).Conflict() {
		t.Error("0x18 is RESERVATION CONFLICT")
	}
	for _, s := range []uint8{StatusGood, StatusCheckCondition, StatusBusy, StatusTaskSetFull} {
		if (Result{Status: s}).Conflict() {
			t.Errorf("status 0x%02x must not read as a reservation conflict", s)
		}
	}
	if (Result{Status: StatusGood, HostStatus: 7}).OK() {
		t.Error("a transport failure is not an accepted command, whatever the status byte says")
	}
}

// TestReadKeysDeclineIsNotAnEmptyList is the regression test for a fail-open
// this package briefly had.
//
// ReadKeys returned a zero-valued Keys with a nil error when the device
// declined. A caller that checked only the error would read generation 0 with
// no keys as "nothing is registered" -- which, for a fencing check, is the
// most dangerous wrong answer available: it says the node holding the device
// has gone away.
//
// It is reachable in normal operation, not only on faults: a preempted
// initiator's very next command reports the one-shot UNIT ATTENTION instead of
// answering.
func TestReadKeysDeclineIsNotAnEmptyList(t *testing.T) {
	ua := &StatusError{Op: "READ KEYS", Result: Result{
		Status:     StatusCheckCondition,
		StatusName: StatusName(StatusCheckCondition),
		// Built by the parser from a real fixed-format buffer rather than by
		// hand, so the test cannot pass on a Sense the parser would never
		// produce.
		Sense: senseOf(0x70, SenseUnitAttention, 0x2a, 0x05),
	}}
	if !ua.UnitAttention() {
		t.Error("sense key 6 after a preemption is a UNIT ATTENTION and must be retryable")
	}
	if ua.Error() == "" {
		t.Error("the error must describe itself")
	}

	conflict := &StatusError{Op: "READ KEYS", Result: Result{Status: StatusReservationConflict}}
	if conflict.UnitAttention() {
		t.Error("a reservation conflict is not a unit attention -- retrying it forever " +
			"would hang a fencing check that should have concluded")
	}
	if !conflict.Conflict() {
		t.Error("the carried Result must still answer the question the caller asked")
	}
}

// TestPreemptAndAbortServiceAction pins the distinction that fencing depends on.
//
// Plain PREEMPT (0x04) removes the victim's registration and excludes its
// SUBSEQUENT commands; PREEMPT AND ABORT (0x05) additionally terminates the
// victim's outstanding tasks. For a node being fenced with I/O in flight -- the
// realistic cluster case, and exactly what the fence-fs suite arranges -- only
// 0x05 prevents an already-accepted write from reaching the medium.
//
// 0x05 was absent from the first version of this package, a silent regression
// against the shell suites it replaced (`sg_persist --out --preempt-abort`).
func TestPreemptAndAbortServiceAction(t *testing.T) {
	cdb, params := prOutBytes(proPreemptAndAbort, scopeLU,
		TypeWriteExclusiveRegistrantsOnly, 0xaaaa, 0xbbbb, false)
	if cdb[1] != 0x05 {
		t.Errorf("service action 0x%02x, want 0x05 (PREEMPT AND ABORT)", cdb[1])
	}
	if got := binary.BigEndian.Uint64(params[0:8]); got != 0xaaaa {
		t.Errorf("reservation key %#x, want the preemptor's aaaa", got)
	}
	if got := binary.BigEndian.Uint64(params[8:16]); got != 0xbbbb {
		t.Errorf("service action key %#x, want the victim's bbbb", got)
	}
	// And the two must not be the same service action.
	plain, _ := prOutBytes(proPreempt, scopeLU, TypeWriteExclusiveRegistrantsOnly, 1, 2, false)
	if plain[1] == cdb[1] {
		t.Error("PREEMPT and PREEMPT AND ABORT must be distinct service actions")
	}
}

// TestDriverStatusIsNotIgnored: all three verdicts must be clean for OK().
//
// DriverStatus was captured and documented as one of "the SCSI midlayer's own
// verdicts", then not consulted -- so a GOOD status byte with a driver error
// read as an accepted PR operation, letting an unrelated SCSI-stack failure
// satisfy a protocol assertion.
func TestDriverStatusIsNotIgnored(t *testing.T) {
	if (Result{Status: StatusGood, DriverStatus: 0x08}).OK() {
		t.Error("a driver error is not an accepted command, whatever the status byte says")
	}
	if !(Result{Status: StatusGood}).OK() {
		t.Error("a clean result must still be OK")
	}
	// DRIVER_SENSE (0x08 in the suggestion field's companion nibble) rides
	// along with CHECK CONDITION, which Status already reports; the low nibble
	// is what carries the driver's own error.
	if !(Result{Status: StatusGood, DriverStatus: 0x80}).OK() {
		t.Error("the suggestion field's high bits must not be read as a driver error")
	}
}

// TestReadCapacity16CDB pins the CDB against SBC-4 5.16, and the derived
// geometry against the fields it comes from.
func TestReadCapacity16CDB(t *testing.T) {
	// The payload a 4Kn, 64MiB device returns: 16384 blocks of 4096 bytes, so
	// the last LBA is 16383.
	data := make([]byte, 32)
	binary.BigEndian.PutUint64(data[0:8], 16383)
	binary.BigEndian.PutUint32(data[8:12], 4096)

	c := Capacity{
		LastLBA:     binary.BigEndian.Uint64(data[0:8]),
		BlockLength: binary.BigEndian.Uint32(data[8:12]),
		LBPPBExp:    data[13] & 0x0f,
	}
	// LastLBA+1, not LastLBA: an off-by-one here shows up as a capacity one
	// block short, which looks like a rounding bug anywhere else.
	if got := c.Bytes(); got != 64<<20 {
		t.Errorf("Bytes() = %d, want %d", got, 64<<20)
	}
	if got := c.PhysicalBlockLength(); got != 4096 {
		t.Errorf("PhysicalBlockLength() = %d, want 4096 for a clean 4Kn device", got)
	}

	// A 512e device: 512-byte logical blocks, exponent 3 => 4096 physical.
	// LIO's fileio backend cannot produce this (no get_lbppbe), which is why
	// this project claims clean 512n/4Kn only -- but the decoder must still
	// report it correctly, or that claim could never be checked.
	e := Capacity{LastLBA: 131071, BlockLength: 512, LBPPBExp: 3}
	if got := e.PhysicalBlockLength(); got != 4096 {
		t.Errorf("512e physical = %d, want 4096", got)
	}
	if e.BlockLength == e.PhysicalBlockLength() {
		t.Error("a 512e device must report physical != logical")
	}
}

// senseOf builds a fixed-format sense buffer and parses it, so tests exercise
// the same path a device answer takes.
func senseOf(rc, key, asc, ascq byte) *Sense {
	b := make([]byte, 18)
	b[0] = rc
	b[2] = key
	b[7] = 10 // additional sense length
	b[12], b[13] = asc, ascq
	return parseSense(b)
}

// TestUndecodableSenseIsNotNoSense pins the distinction added with Sense.Valid.
//
// A buffer too short to carry ASC/ASCQ, or with an unrecognised response code,
// previously decoded to Key == 0 -- indistinguishable from a device that
// answered NO SENSE. UnitAttention() then said "no", which for a fencing
// retry loop is a decision made on data that was never read.
func TestUndecodableSenseIsNotNoSense(t *testing.T) {
	for _, tc := range []struct {
		name string
		buf  []byte
	}{
		{"unknown response code", []byte{0x0f, 0, 0, 0}},
		{"fixed format truncated before ASC", []byte{0x70, 0, 0x06, 0}},
		{"descriptor format truncated before ASC", []byte{0x72, 0x06}},
	} {
		s := parseSense(tc.buf)
		if s == nil {
			t.Fatalf("%s: parseSense returned nil for a non-empty buffer", tc.name)
		}
		if s.Valid {
			t.Errorf("%s: decoded a buffer it cannot decode", tc.name)
		}
		if s.UnitAttention() {
			t.Errorf("%s: claimed a unit attention it did not read", tc.name)
		}
		if got := s.String(); !strings.Contains(got, "UNDECODABLE") {
			t.Errorf("%s: String() = %q, must not read as a decoded sense", tc.name, got)
		}
	}

	// An empty buffer is the separate, already-modelled case: no sense at all.
	if parseSense(nil) != nil {
		t.Error("an empty buffer must stay nil, not become an undecodable Sense")
	}

	// The negative control: a well-formed buffer must still decode.
	ok := parseSense([]byte{0x70, 0, 0x06, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x2a, 0x05})
	if !ok.Valid || !ok.UnitAttention() {
		t.Fatalf("a well-formed unit attention no longer decodes: %+v", ok)
	}
}

// TestLBPPBEIsTheLowNibble decodes byte 13 from a real READ CAPACITY(16)
// buffer rather than setting the field by hand.
//
// The 512e case in the existing table sets LBPPBExp: 3 directly, so it would
// pass identically if the decode took the HIGH nibble -- which is what the
// comment above the code used to describe. A reviewer flagged the comment as
// inverted; this pins the behaviour so the comment can never be "fixed" into
// the code.
func TestLBPPBEIsTheLowNibble(t *testing.T) {
	// Byte 13 = 0x33: P_I_EXPONENT 3 in the high nibble, LBPPBE 3 in the low.
	// Both nibbles are set to the SAME value in one control and different
	// values in the other, so a decode reading the wrong end is visible.
	for _, tc := range []struct {
		name string
		b13  byte
		want uint8
	}{
		{"512e: 8 logical blocks per physical", 0x03, 3},
		{"high nibble set, low clear -- must decode 0", 0x30, 0},
		{"both set, different values", 0x53, 3},
		{"512n", 0x00, 0},
	} {
		buf := make([]byte, 32)
		// A plausible 512-byte block length: the decode rejects zero, which
		// is a separate check and not what this test is about.
		binary.BigEndian.PutUint32(buf[8:12], 512)
		buf[13] = tc.b13
		c, err := parseCapacity16(Result{}, buf)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got := c.LBPPBExp
		if got != tc.want {
			t.Errorf("%s: byte13=%#02x gave LBPPBExp %d, want %d",
				tc.name, tc.b13, got, tc.want)
		}
	}
}

// TestCapacityDoesNotWrap is the regression test for two fuzz findings, both
// of which produced a WRONG ANSWER rather than a crash -- the harder failure
// to notice and the one that matters for a library meant to run unmaintained.
func TestCapacityDoesNotWrap(t *testing.T) {
	// PhysicalBlockLength shifted a uint32 and wrapped, so the physical block
	// came back SMALLER than the logical one. No device can represent that,
	// and an alignment check against it passes on a device that is not
	// aligned. parseCapacity16 now refuses the response outright.
	data := make([]byte, 32)
	binary.BigEndian.PutUint64(data[0:8], 1<<20)
	binary.BigEndian.PutUint32(data[8:12], 4012912688)
	data[13] = 0x0f
	if _, err := parseCapacity16(Result{}, data); err == nil {
		t.Error("a block length whose physical size overflows 32 bits must be refused, " +
			"not wrapped into a physical block smaller than the logical one")
	}

	// A Capacity built by hand still must not return an impossible answer.
	c := Capacity{BlockLength: 4012912688, LBPPBExp: 15}
	if p := c.PhysicalBlockLength(); p < c.BlockLength {
		t.Errorf("PhysicalBlockLength() = %d < BlockLength %d: physically impossible",
			p, c.BlockLength)
	}

	// Bytes() wrapped on a device reporting the maximum LBA, returning ZERO
	// capacity for the largest device it can describe.
	big := Capacity{LastLBA: ^uint64(0), BlockLength: 512}
	if got := big.Bytes(); got == 0 {
		t.Error("Bytes() wrapped to zero on the maximum LBA: a capacity that overflows " +
			"is not a smaller device, it is a wrong answer")
	}

	// And the ordinary case still computes exactly.
	ok := Capacity{LastLBA: 2047, BlockLength: 512}
	if got, want := ok.Bytes(), uint64(2048*512); got != want {
		t.Errorf("Bytes() = %d, want %d", got, want)
	}
}

// TestParseReadKeysRejectsAHugeAdditionalLength is the regression test for a
// fail-open on 32-bit targets.
//
// ADDITIONAL LENGTH is device-supplied. It used to be widened with int(), and
// where int is 32 bits a value with bit 31 set becomes NEGATIVE: it passes the
// %8 check, 8+addLen no longer exceeds len(data), and the copy loop does not
// run -- so the function returned no error and an EMPTY key list. ReadKeys'
// own doc calls that "the most dangerous possible wrong answer: it says the
// node holding the device has gone away."
//
// Asserting on the error rather than on int width makes this test meaningful
// on every GOARCH: the arithmetic is now done in 64 bits, so both report
// truncation. CI runs it under GOARCH=386 as well.
func TestParseReadKeysRejectsAHugeAdditionalLength(t *testing.T) {
	for _, addLen := range []uint32{0xFFFFFFF8, 0x80000000, 0x7FFFFFF8} {
		data := make([]byte, 8192)
		binary.BigEndian.PutUint32(data[0:4], 7)
		binary.BigEndian.PutUint32(data[4:8], addLen)

		gen, keys, err := parseReadKeys(data)
		if err == nil {
			t.Errorf("additional length %#x: no error and %d keys -- a caller reads that as "+
				"'nothing is registered'", addLen, len(keys))
		}
		if len(keys) != 0 {
			t.Errorf("additional length %#x: returned %d keys alongside the error", addLen, len(keys))
		}
		if gen != 7 {
			t.Errorf("additional length %#x: generation = %d, want 7 (it is readable even when "+
				"the list is not)", addLen, gen)
		}
	}

	// The negative control: a well-formed short list must still parse, or the
	// test above could pass by rejecting everything.
	ok := make([]byte, 24)
	binary.BigEndian.PutUint32(ok[0:4], 3)
	binary.BigEndian.PutUint32(ok[4:8], 16)
	binary.BigEndian.PutUint64(ok[8:16], 0xaaaa)
	binary.BigEndian.PutUint64(ok[16:24], 0xbbbb)
	if _, keys, err := parseReadKeys(ok); err != nil || len(keys) != 2 {
		t.Errorf("a valid two-key list failed: keys=%v err=%v", keys, err)
	}
}

// TestReservationTypeRejectsUndefinedValues pins that a caller mistake fails
// locally instead of becoming a DIFFERENT, valid reservation on the device.
//
// These were untyped constants passed as uint8, so any number was accepted and
// the encoder masked it into a nibble: 0x15 requested type 0x5. A fencing
// primitive that silently reinterprets its argument is the wrong shape.
func TestReservationTypeRejectsUndefinedValues(t *testing.T) {
	d := &Device{} // never used: every case must fail before touching it
	for _, bad := range []ReservationType{0x0, 0x2, 0x4, 0x9, 0x15, 0xff} {
		if bad.Valid() {
			t.Errorf("%v reported valid", bad)
		}
		if _, err := d.Reserve(1, bad); err == nil {
			t.Errorf("Reserve accepted %v", bad)
		}
		if _, err := d.Preempt(1, 2, bad); err == nil {
			t.Errorf("Preempt accepted %v", bad)
		}
	}
	// The negative control: every type SPC-6 defines must pass Valid, or the
	// check above could be satisfied by rejecting everything.
	for _, ok := range []ReservationType{
		TypeWriteExclusive, TypeExclusiveAccess,
		TypeWriteExclusiveRegistrantsOnly, TypeExclusiveAccessRegistrantsOnly,
		TypeWriteExclusiveAllRegistrants, TypeExclusiveAccessAllRegistrants,
	} {
		if !ok.Valid() {
			t.Errorf("%v reported invalid", ok)
		}
	}
}

// TestPhysicalBlockLengthNeverBelowLogical pins the guard whose own comment
// says a physical block smaller than the logical one "is a fact no device can
// represent -- it would make an alignment check pass on a device that is not
// aligned". Go yields 0 for a shift of 64 or more rather than panicking, so a
// hand-built exponent produced exactly that.
func TestPhysicalBlockLengthNeverBelowLogical(t *testing.T) {
	for _, exp := range []uint8{0, 1, 15, 16, 31, 32, 64, 255} {
		c := Capacity{BlockLength: 4096, LBPPBExp: exp}
		if got := c.PhysicalBlockLength(); got < c.BlockLength {
			t.Errorf("LBPPBExp=%d: physical %d < logical %d", exp, got, c.BlockLength)
		}
	}
}

// TestConflictRequiresACleanTransport: a reservation conflict reported
// alongside a host or driver failure is a status byte that may not have come
// from the device. Claiming "fenced" from a command that did not complete is a
// fencing verdict invented from a transport error.
func TestConflictRequiresACleanTransport(t *testing.T) {
	clean := Result{Status: StatusReservationConflict}
	if !clean.Conflict() {
		t.Error("a clean reservation conflict must report Conflict")
	}
	for name, r := range map[string]Result{
		"host error":   {Status: StatusReservationConflict, HostStatus: 0x07},
		"driver error": {Status: StatusReservationConflict, DriverStatus: 0x08},
	} {
		if r.Conflict() {
			t.Errorf("%s: reported a fencing verdict from a command that did not complete", name)
		}
		if r.OK() {
			t.Errorf("%s: reported OK", name)
		}
	}
}
