package scsi

import (
	"encoding/binary"
	"fmt"
)

// PERSISTENT RESERVE opcodes (SPC-6 6.16, 6.17).
const (
	opPersistentReserveIn  = 0x5e
	opPersistentReserveOut = 0x5f
)

// PERSISTENT RESERVE IN service actions (SPC-6 6.16.1).
const (
	priReadKeys        = 0x00
	priReadReservation = 0x01
)

// PERSISTENT RESERVE OUT service actions (SPC-6 6.17.1).
const (
	proRegister                  = 0x00
	proReserve                   = 0x01
	proRelease                   = 0x02
	proClear                     = 0x03
	proPreempt                   = 0x04
	proPreemptAndAbort           = 0x05
	proRegisterIgnoreExistingKey = 0x06
)

// ReservationType is a SCSI-3 persistent reservation type (SPC-6 5.14.2).
//
// A named type rather than a bare integer because these values used to be
// untyped constants passed as uint8, so any number at all -- a status byte, a
// sense key, an off-by-one -- was accepted by Reserve and Preempt and then
// silently masked to its low nibble before reaching the device. Making the
// mistake unrepresentable costs nothing here and is impossible to add later
// without breaking every caller.
type ReservationType uint8

// Reservation types (SPC-6 5.14.2). WriteExclusiveRegistrantsOnly is what this
// project's fencing uses: registrants may write, everyone else is excluded.
const (
	TypeWriteExclusive                 ReservationType = 0x1
	TypeExclusiveAccess                ReservationType = 0x3
	TypeWriteExclusiveRegistrantsOnly  ReservationType = 0x5
	TypeExclusiveAccessRegistrantsOnly ReservationType = 0x6
	TypeWriteExclusiveAllRegistrants   ReservationType = 0x7
	TypeExclusiveAccessAllRegistrants  ReservationType = 0x8
)

// Valid reports whether t is a reservation type SPC-6 defines.
func (t ReservationType) Valid() bool {
	switch t {
	case TypeWriteExclusive, TypeExclusiveAccess,
		TypeWriteExclusiveRegistrantsOnly, TypeExclusiveAccessRegistrantsOnly,
		TypeWriteExclusiveAllRegistrants, TypeExclusiveAccessAllRegistrants:
		return true
	}
	return false
}

// String renders the type as SPC-6 names it, or "reservation type 0xNN" for
// one the standard does not define.
func (t ReservationType) String() string {
	switch t {
	case TypeWriteExclusive:
		return "Write Exclusive"
	case TypeExclusiveAccess:
		return "Exclusive Access"
	case TypeWriteExclusiveRegistrantsOnly:
		return "Write Exclusive, Registrants Only"
	case TypeExclusiveAccessRegistrantsOnly:
		return "Exclusive Access, Registrants Only"
	case TypeWriteExclusiveAllRegistrants:
		return "Write Exclusive, All Registrants"
	case TypeExclusiveAccessAllRegistrants:
		return "Exclusive Access, All Registrants"
	}
	return fmt.Sprintf("reservation type %#02x", uint8(t))
}

// errBadResType reports a reservation type the standard does not define.
//
// Refused locally rather than sent: the encoder masks the type into a nibble,
// so an out-of-range value did not fail -- it became a DIFFERENT, valid type
// and the device acted on it. 0x15 requested type 0x5.
func errBadResType(op string, t ReservationType) error {
	return fmt.Errorf("scsi: %s: %v is not a reservation type SPC-6 defines", op, t)
}

// scopeLU is the only scope SPC-6 defines for these commands (5.14.1).
const scopeLU = 0x0

// prOutParamLen is the fixed PERSISTENT RESERVE OUT parameter list length
// (SPC-6 6.17.3): 8 bytes reservation key, 8 bytes service-action key, 4 bytes
// obsolete scope-specific address, flags, reserved, 2 bytes obsolete.
const prOutParamLen = 24

// Keys is the answer to PERSISTENT RESERVE IN / READ KEYS.
type Keys struct {
	// Generation is PRGENERATION, which the device increments on every
	// registration change. It is how a caller detects that something moved
	// between two reads without having to diff the key list.
	Generation uint32   `json:"generation"`
	Keys       []uint64 `json:"keys"`
	Result     Result   `json:"result"`
}

// Reservation is the answer to PERSISTENT RESERVE IN / READ RESERVATION.
type Reservation struct {
	Generation uint32 `json:"generation"`
	// Held is false when no reservation exists. The device signals this with
	// an ADDITIONAL LENGTH of 0, NOT with an error -- so "no holder" and "the
	// command failed" are different answers and must not be conflated.
	Held   bool            `json:"held"`
	Key    uint64          `json:"key,omitempty"`
	Scope  uint8           `json:"scope,omitempty"`
	Type   ReservationType `json:"type,omitempty"`
	Result Result          `json:"result"`
}

// ReadKeys returns the registered reservation keys.
//
// This replaces counting occurrences of the string "0x" in a CLI's output. The
// count here is the number of 8-byte keys the device reported, derived from
// the ADDITIONAL LENGTH field.
func (d *Device) ReadKeys() (Keys, error) {
	// 8-byte header plus room for keys. 8KiB holds 1023 registrations, far
	// past anything a real target will report; a device with more would be
	// truncated, which the length check below turns into an error rather than
	// a short list that looks like a complete one.
	const alloc = 8192
	r, err := d.send(prInCDB(priReadKeys, alloc), alloc, nil)
	if err != nil {
		return Keys{}, err
	}
	k := Keys{Result: r}
	if !r.OK() {
		// NOT a silent empty list. A caller that ignored the Result would read
		// generation 0 with no keys as "nothing is registered", which for a
		// fencing check is the most dangerous possible wrong answer: it says
		// the node holding the device has gone away.
		//
		// This is reachable in normal operation, not just on faults -- a
		// preempted initiator's next command reports the one-shot UNIT
		// ATTENTION rather than answering. MEASURED on the lab (Azure Linux
		// 3.0, kernel 6.6.144.1): after PREEMPT, the victim's next PR IN
		// returns CHECK CONDITION with sense 6/2Ah/05h, REGISTRATIONS
		// PREEMPTED, and only the command AFTER that returns the real answer.
		return k, &StatusError{Op: "READ KEYS", Result: r}
	}
	gen, keys, err := parseReadKeys(r.Data)
	if err != nil {
		return k, err
	}
	k.Generation, k.Keys = gen, keys
	return k, nil
}

// parseReadKeys decodes a READ KEYS payload (SPC-6 6.16.2): a 4-byte
// PRGENERATION, a 4-byte ADDITIONAL LENGTH, then that many bytes of 8-byte
// keys.
//
// Split from the I/O so it can be tested against payloads a real device is
// unlikely to produce on demand -- notably the truncated case, which must be
// an error and not a short list that reads as complete.
func parseReadKeys(data []byte) (generation uint32, keys []uint64, err error) {
	if len(data) < 8 {
		return 0, nil, fmt.Errorf("scsi: READ KEYS returned %d bytes, want at least 8", len(data))
	}
	generation = binary.BigEndian.Uint32(data[0:4])
	// int64, not int: this is a DEVICE-SUPPLIED uint32, and on a 32-bit target
	// int is 32 bits, so a value with bit 31 set becomes negative. A negative
	// multiple of 8 passes the %8 check, 8+addLen then does not exceed
	// len(data), and the loop below does not execute -- so this returned no
	// error and NO KEYS. ReadKeys' own doc calls that "the most dangerous
	// possible wrong answer: it says the node holding the device has gone
	// away". Measured on 386 semantics: 64-bit reports truncation, 32-bit
	// reported success with an empty list.
	addLen := int64(binary.BigEndian.Uint32(data[4:8]))
	if addLen%8 != 0 {
		return generation, nil, fmt.Errorf(
			"scsi: READ KEYS additional length %d is not a multiple of 8", addLen)
	}
	if 8+addLen > int64(len(data)) {
		return generation, nil, fmt.Errorf(
			"scsi: READ KEYS reported %d bytes of keys but only %d were transferred -- the "+
				"allocation length was too small and the list is truncated", addLen, len(data)-8)
	}
	for off := int64(8); off < 8+addLen; off += 8 {
		keys = append(keys, binary.BigEndian.Uint64(data[off:off+8]))
	}
	return generation, keys, nil
}

// ReadReservation returns the current reservation, if any.
func (d *Device) ReadReservation() (Reservation, error) {
	const alloc = 256
	r, err := d.send(prInCDB(priReadReservation, alloc), alloc, nil)
	if err != nil {
		return Reservation{}, err
	}
	v := Reservation{Result: r}
	if !r.OK() {
		// See ReadKeys: "not held" and "could not tell" must not be the same
		// answer.
		return v, &StatusError{Op: "READ RESERVATION", Result: r}
	}
	if len(r.Data) >= 4 {
		v.Generation = binary.BigEndian.Uint32(r.Data[0:4])
	}
	held, key, scope, typ, err := parseReadReservation(r.Data)
	if err != nil {
		return v, err
	}
	v.Held, v.Key, v.Scope, v.Type = held, key, scope, typ
	return v, nil
}

// parseReadReservation decodes a READ RESERVATION payload (SPC-6 6.16.3).
//
// An ADDITIONAL LENGTH of 0 means no reservation is held. That is an ANSWER,
// with a GOOD status -- not a failure. Conflating it with an error would make
// "nobody holds this" indistinguishable from "the command did not work", which
// is exactly the distinction a fencing check rests on.
func parseReadReservation(data []byte) (held bool, key uint64, scope uint8, typ ReservationType, err error) {
	if len(data) < 8 {
		return false, 0, 0, 0, fmt.Errorf(
			"scsi: READ RESERVATION returned %d bytes, want at least 8", len(data))
	}
	addLen := int(binary.BigEndian.Uint32(data[4:8]))
	if addLen == 0 {
		return false, 0, 0, 0, nil
	}
	if addLen < 16 || len(data) < 24 {
		return false, 0, 0, 0, fmt.Errorf(
			"scsi: READ RESERVATION additional length %d with %d bytes transferred",
			addLen, len(data))
	}
	return true, binary.BigEndian.Uint64(data[8:16]), data[21] >> 4, ReservationType(data[21] & 0x0f), nil
}

// Register registers key for this initiator (I_T nexus), replacing oldKey.
//
// aptpl requests that the registration persist across a target power loss. It
// is the whole basis of this project's reboot-persistence behaviour: without
// it the kernel keeps nothing.
//
// ignoreExisting selects REGISTER AND IGNORE EXISTING KEY, which registers
// unconditionally rather than requiring oldKey to match. Callers registering
// for the first time want it; callers rotating a key deliberately do not,
// because the match is what proves they knew the current value.
func (d *Device) Register(oldKey, key uint64, aptpl, ignoreExisting bool) (Result, error) {
	sa := byte(proRegister)
	if ignoreExisting {
		sa = proRegisterIgnoreExistingKey
	}
	return d.prOut(sa, 0, 0, oldKey, key, aptpl)
}

// Reserve takes a reservation of the given type using an existing registration.
func (d *Device) Reserve(key uint64, resType ReservationType) (Result, error) {
	if !resType.Valid() {
		return Result{}, errBadResType("reserve", resType)
	}
	return d.prOut(proReserve, scopeLU, resType, key, 0, false)
}

// Release releases a reservation held with key.
func (d *Device) Release(key uint64, resType ReservationType) (Result, error) {
	if !resType.Valid() {
		return Result{}, errBadResType("release", resType)
	}
	return d.prOut(proRelease, scopeLU, resType, key, 0, false)
}

// Clear removes the reservation and ALL registrations.
func (d *Device) Clear(key uint64) (Result, error) {
	return d.prOut(proClear, 0, 0, key, 0, false)
}

// Preempt removes victim's registration (and any reservation it holds) in
// favour of key's holder.
//
// It does NOT terminate commands the victim has already issued. For fencing a
// node that may have I/O in flight -- which is the realistic cluster case --
// use PreemptAndAbort.
func (d *Device) Preempt(key, victim uint64, resType ReservationType) (Result, error) {
	if !resType.Valid() {
		return Result{}, errBadResType("preempt", resType)
	}
	return d.prOut(proPreempt, scopeLU, resType, key, victim, false)
}

// PreemptAndAbort removes victim's registration AND aborts the victim's
// outstanding tasks (SPC-6 5.14.11.4). This is the fencing operation a cluster
// actually wants: plain PREEMPT excludes subsequent commands but permits
// already-accepted ones to complete, so a victim write in flight when the
// fence lands can still reach the medium.
//
// The distinction is the whole point of fencing a node with queued I/O, and it
// is why the shell suites this package replaced used
// `sg_persist --out --preempt-abort`. Dropping it was a silent regression in
// the primitive, caught by cross-model review.
func (d *Device) PreemptAndAbort(key, victim uint64, resType ReservationType) (Result, error) {
	if !resType.Valid() {
		return Result{}, errBadResType("preemptandabort", resType)
	}
	return d.prOut(proPreemptAndAbort, scopeLU, resType, key, victim, false)
}

// Unregister removes this initiator's registration by registering key 0.
func (d *Device) Unregister(key uint64) (Result, error) {
	return d.prOut(proRegister, 0, 0, key, 0, false)
}

// prOut issues a PERSISTENT RESERVE OUT.
func (d *Device) prOut(sa, scope byte, resType ReservationType, key, saKey uint64, aptpl bool) (Result, error) {
	cdb, p := prOutBytes(sa, scope, resType, key, saKey, aptpl)
	return d.send(cdb, 0, p)
}

// prOutBytes builds a PERSISTENT RESERVE OUT CDB and its parameter list
// (SPC-6 6.17). Split from the I/O so the byte layout -- especially the APTPL
// bit, on which surviving a target reboot entirely depends -- is pinned by a
// test rather than by a reboot.
func prOutBytes(sa, scope byte, resType ReservationType, key, saKey uint64, aptpl bool) (cdb, params []byte) {
	cdb = []byte{
		opPersistentReserveOut,
		sa & 0x1f,
		scope<<4 | byte(resType)&0x0f,
		0, 0,
		0, 0, 0, prOutParamLen, // parameter list length, 4 bytes big-endian
		0,
	}
	params = make([]byte, prOutParamLen)
	binary.BigEndian.PutUint64(params[0:8], key)
	binary.BigEndian.PutUint64(params[8:16], saKey)
	if aptpl {
		params[20] |= 0x01 // APTPL (SPC-6 6.17.3)
	}
	return cdb, params
}

// prInCDB builds a PERSISTENT RESERVE IN CDB (SPC-6 6.16).
func prInCDB(sa byte, alloc int) []byte {
	cdb := make([]byte, 10)
	cdb[0] = opPersistentReserveIn
	cdb[1] = sa & 0x1f
	binary.BigEndian.PutUint16(cdb[7:9], uint16(alloc))
	return cdb
}
