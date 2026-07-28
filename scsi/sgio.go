// Package scsi issues SCSI commands to a block device through the Linux SG_IO
// ioctl, and reports what the device answered as NUMBERS: the status byte, and
// the sense key/ASC/ASCQ when there is sense data.
//
// It exists because this project's most important assertions -- does fencing
// actually exclude a node -- were matching English. The fencing verdict came
// from grepping tool output for "Reservation conflict" or "Invalid exchange",
// the latter being strerror(EBADE) and therefore dependent on the initiator's
// locale; the lab had to generate en_US.UTF-8 to keep the suite passing. A
// SCSI status byte is 0x18 in every language.
//
// It is a library rather than test scaffolding because anything that fences
// needs it.
//
// Scope is deliberately narrow: PERSISTENT RESERVE IN and OUT, which is what
// fencing is built from. It is not a general SCSI stack.
package scsi

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// sgIO is the SG_IO ioctl (linux v6.6 include/scsi/sg.h:63).
const sgIO = 0x2285

// dxfer_direction values (linux v6.6 include/scsi/sg.h:24-28).
const (
	dxferNone    = -1
	dxferToDev   = -2
	dxferFromDev = -3
)

// DefaultTimeout bounds a single SG_IO command when Device.Timeout is unset.
// Generous, because the alternative to waiting is a fencing verdict that never
// arrives.
const DefaultTimeout = 20 * time.Second

// sgIOHdr mirrors struct sg_io_hdr (linux v6.6 include/scsi/sg.h:34-60).
//
// Field order and types are load-bearing: the kernel reads this layout
// directly, and Go's natural alignment on 64-bit is what makes it match --
// dxferLen lands at offset 12, the three pointers at 16/24/32, and usrPtr at
// 56 after packID's padding. TestSgIOHdrLayout pins it.
type sgIOHdr struct {
	interfaceID    int32
	dxferDirection int32
	cmdLen         uint8
	mxSbLen        uint8
	iovecCount     uint16
	dxferLen       uint32
	// unsafe.Pointer, not uintptr. Identical size, alignment and offset on
	// every supported platform, but the GC can SEE these, so the buffers
	// cannot be collected or moved while the kernel holds them. As uintptr
	// they were invisible and correctness depended entirely on the
	// runtime.KeepAlive calls below plus Go's current non-moving GC.
	dxferp       unsafe.Pointer
	cmdp         unsafe.Pointer
	sbp          unsafe.Pointer
	timeout      uint32
	flags        uint32
	packID       int32
	usrPtr       unsafe.Pointer
	status       uint8
	maskedStatus uint8
	msgStatus    uint8
	sbLenWr      uint8
	hostStatus   uint16
	driverStatus uint16
	resid        int32
	duration     uint32
	info         uint32
}

// Result is what a device said in response to one command.
//
// A Result with Status GOOD is a success; anything else is the device
// declining, and the reason is in Status (and in Sense when the status is
// CHECK CONDITION). None of it is a string, which is the point: callers
// compare against protocol constants.
type Result struct {
	// Status is the SCSI status byte: StatusGood, StatusReservationConflict,
	// StatusCheckCondition, ...
	Status uint8 `json:"status"`
	// StatusName is the constant's name, for humans reading JSON. Never match
	// on it.
	StatusName string `json:"status_name"`
	// Sense is populated when the device returned sense data.
	Sense *Sense `json:"sense,omitempty"`
	// Data is the command's data-in payload, truncated to what was actually
	// transferred (allocation length minus residual).
	Data []byte `json:"-"`
	// HostStatus and DriverStatus are the SCSI midlayer's own verdicts.
	// Reported rather than folded into the status because a transport failure
	// and a device refusal are different diagnoses, and collapsing them is how
	// "the write failed" came to mean six different things.
	HostStatus   uint16 `json:"host_status"`
	DriverStatus uint16 `json:"driver_status"`
}

// OK reports whether the device accepted the command.
//
// All three verdicts must be clean. DriverStatus was captured, documented as
// one of "the SCSI midlayer's own verdicts", and then not consulted -- so a
// GOOD status byte accompanied by a driver error read as an accepted PR
// operation. In a safety harness that is a route for an unrelated SCSI-stack
// failure to satisfy a protocol assertion.
//
// The driver byte splits into a low nibble of DRIVER_* codes (DRIVER_OK 0x00,
// DRIVER_BUSY 0x01 ... DRIVER_SENSE 0x08, DRIVER_TIMEOUT 0x06, DRIVER_HARD
// 0x07) and a HIGH nibble of SUGGEST_* hints (SUGGEST_RETRY 0x10 ...
// SUGGEST_SENSE 0x80) -- linux v6.6 include/scsi/scsi.h. Masking with 0x0f
// keeps the codes and discards only the hints, so DRIVER_SENSE (0x08) makes
// OK() false, which is what TestResultOKRejectsDriverError pins.
//
// An earlier version of this comment claimed the opposite -- that the mask
// EXCLUDED DRIVER_SENSE because it lived in the suggestion field. It does not;
// it is in the nibble the mask keeps. The code was right and the citation was
// wrong, which is the worse of the two: a wrong citation next to a
// load-bearing mask carries the authority of having been checked.
func (r Result) OK() bool {
	return r.Status == StatusGood && r.HostStatus == 0 && r.DriverStatus&0x0f == 0
}

// Conflict reports whether the device refused because another initiator holds
// a conflicting reservation -- that is, this initiator is fenced.
//
// This is the whole point of the package: a comparison against 0x18, not a
// search for a word in a sentence that varies by tool, version and locale.
func (r Result) Conflict() bool {
	// The transport verdicts must be clean too. OK() already argues why all
	// three bytes matter; a reservation conflict reported ALONGSIDE a host or
	// driver failure is a status byte that may not have come from the device,
	// and reading it as "this initiator is fenced" would claim a fencing
	// verdict from a command that did not complete. Requiring them clean makes
	// an uncertain conflict report false here -- the caller then sees neither
	// OK() nor Conflict(), which is the honest "I cannot tell".
	return r.Status == StatusReservationConflict && r.HostStatus == 0 && r.DriverStatus&0x0f == 0
}

// String renders a Result for a human. Callers must not match on it.
func (r Result) String() string {
	s := fmt.Sprintf("status=0x%02x (%s)", r.Status, StatusName(r.Status))
	if r.Sense != nil {
		s += " " + r.Sense.String()
	}
	if r.HostStatus != 0 || r.DriverStatus != 0 {
		s += fmt.Sprintf(" host=0x%04x driver=0x%04x", r.HostStatus, r.DriverStatus)
	}
	return s
}

// Device is an open SCSI block device.
type Device struct {
	f *os.File
	// Timeout bounds a single command. Zero means DefaultTimeout.
	//
	// Settable because it was a package constant, which left a caller
	// fencing a slow or busy array with no way to allow for it: the command
	// would fail on the kernel's timer rather than on the device's answer,
	// and a fencing verdict that times out is not a verdict.
	Timeout time.Duration
	// owned reports whether Close should close f. False for a Device built
	// from a caller's file, whose lifetime belongs to the caller.
	owned bool
}

// Open opens a block device for SG_IO. O_RDWR is required: the kernel refuses
// PERSISTENT RESERVE OUT on a read-only handle.
func Open(path string) (*Device, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &Device{f: f, owned: true}, nil
}

// NewDevice wraps an already-open file, which must be a block device opened
// O_RDWR. The caller keeps ownership: Close does NOT close f.
//
// Open was the only constructor, so a program that already held the fd --
// because it opened the device with its own flags, or was handed one by
// systemd, or shares it with another subsystem -- could not use this package
// at all without opening the device a second time.
func NewDevice(f *os.File) *Device { return &Device{f: f} }

// File returns the underlying file. It remains owned by whoever created it.
func (d *Device) File() *os.File { return d.f }

// Close releases the device if this package opened it, and is a no-op for a
// Device built by NewDevice.
func (d *Device) Close() error {
	if !d.owned {
		return nil
	}
	return d.f.Close()
}

// timeoutMS is the per-command timeout in milliseconds.
func (d *Device) timeoutMS() uint32 {
	t := d.Timeout
	if t <= 0 {
		t = DefaultTimeout
	}
	return uint32(t / time.Millisecond)
}

// send issues one CDB. dataIn is the expected data-in length (0 for none);
// dataOut is the data-out payload (nil for none). A command may not do both.
//
// A non-GOOD status is NOT an error. The device answered, and what it said is
// exactly what the caller is asking about -- a RESERVATION CONFLICT is a
// successful measurement of a fenced initiator. Errors are reserved for the
// ioctl itself failing, which means the command never reached the device.
func (d *Device) send(cdb []byte, dataIn int, dataOut []byte) (Result, error) {
	if dataIn > 0 && len(dataOut) > 0 {
		return Result{}, fmt.Errorf("scsi: a command cannot transfer in both directions")
	}
	sense := make([]byte, 32)
	h := sgIOHdr{
		interfaceID: 'S',
		cmdLen:      uint8(len(cdb)),
		mxSbLen:     uint8(len(sense)),
		timeout:     d.timeoutMS(),
		cmdp:        unsafe.Pointer(&cdb[0]),
		sbp:         unsafe.Pointer(&sense[0]),
	}
	var buf []byte
	switch {
	case dataIn > 0:
		buf = make([]byte, dataIn)
		h.dxferDirection = dxferFromDev
		h.dxferLen = uint32(dataIn)
		h.dxferp = unsafe.Pointer(&buf[0])
	case len(dataOut) > 0:
		buf = dataOut
		h.dxferDirection = dxferToDev
		h.dxferLen = uint32(len(dataOut))
		h.dxferp = unsafe.Pointer(&buf[0])
	default:
		h.dxferDirection = dxferNone
	}

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, d.f.Fd(), sgIO, uintptr(unsafe.Pointer(&h)))
	// Belt and braces. The struct now holds unsafe.Pointer, so the GC keeps
	// the buffers reachable on its own; these remain because the pointers are
	// reachable only through a struct the kernel is writing into, and being
	// explicit about the lifetime costs nothing.
	runtime.KeepAlive(cdb)
	runtime.KeepAlive(sense)
	runtime.KeepAlive(buf)
	if errno != 0 {
		return Result{}, fmt.Errorf("scsi: SG_IO ioctl on %s: %w", d.f.Name(), errno)
	}

	r := Result{
		Status:       h.status,
		HostStatus:   h.hostStatus,
		DriverStatus: h.driverStatus,
	}
	r.StatusName = StatusName(r.Status)
	if h.sbLenWr > 0 {
		r.Sense = parseSense(sense[:h.sbLenWr])
	}
	if dataIn > 0 {
		n := dataIn - int(h.resid)
		n = max(n, 0)
		n = min(n, dataIn)
		r.Data = buf[:n]
	}
	return r, nil
}
