package scsi

import "fmt"

// SCSI status byte values (SAM-5 5.3.1). These are the numbers that replace
// grepping tool output for a sentence.
const (
	StatusGood                = 0x00
	StatusCheckCondition      = 0x02
	StatusConditionMet        = 0x04
	StatusBusy                = 0x08
	StatusReservationConflict = 0x18
	StatusTaskSetFull         = 0x28
	StatusACAActive           = 0x30
	StatusTaskAborted         = 0x40
)

// StatusName renders a status byte's constant name, for humans reading logs
// and JSON. It is never the thing to assert on.
func StatusName(s uint8) string {
	switch s {
	case StatusGood:
		return "GOOD"
	case StatusCheckCondition:
		return "CHECK CONDITION"
	case StatusConditionMet:
		return "CONDITION MET"
	case StatusBusy:
		return "BUSY"
	case StatusReservationConflict:
		return "RESERVATION CONFLICT"
	case StatusTaskSetFull:
		return "TASK SET FULL"
	case StatusACAActive:
		return "ACA ACTIVE"
	case StatusTaskAborted:
		return "TASK ABORTED"
	}
	return fmt.Sprintf("UNKNOWN(0x%02x)", s)
}

// Sense keys (SPC-6 4.5.6). Only the ones this project reasons about are
// named; the rest are reported numerically.
const (
	SenseNoSense        = 0x0
	SenseRecoveredError = 0x1
	SenseNotReady       = 0x2
	SenseMediumError    = 0x3
	SenseHardwareError  = 0x4
	SenseIllegalRequest = 0x5
	SenseUnitAttention  = 0x6
	SenseDataProtect    = 0x7
	SenseAborted        = 0xb
)

// Sense is decoded sense data: the three numbers that identify a condition.
//
// ASC/ASCQ matter here beyond diagnostics. A LUN topology change raises a
// one-shot UNIT ATTENTION (key 0x6) that the next command consumes, which is
// why a harness that does not expect it sees an unrelated step fail once.
// Knowing the pair lets a caller drain it deliberately instead of retrying
// blindly.
type Sense struct {
	Key  uint8 `json:"key"`
	ASC  uint8 `json:"asc"`
	ASCQ uint8 `json:"ascq"`
	// Raw is the sense buffer as returned, so a condition this package does
	// not model can still be inspected rather than lost.
	Raw []byte `json:"raw,omitempty"`
	// Valid is false when the buffer could not be decoded -- an unrecognised
	// response code, or one too short to carry ASC/ASCQ.
	//
	// Without it, "did not decode" and "decoded as nothing" were the same
	// answer: an undecodable buffer yielded Key == 0, which reads as NO SENSE
	// and answers false to UnitAttention(). That is the distinction StatusError
	// exists to preserve one file away.
	Valid bool `json:"valid"`
}

// UnitAttention reports whether this is the one-shot condition raised after a
// topology change, reset, or reservation preemption.
//
// Requires Valid: an undecodable buffer must not answer this question at all,
// in either direction.
func (s Sense) UnitAttention() bool { return s.Valid && s.Key == SenseUnitAttention }

// String renders sense for a human. Callers must not match on it.
func (s Sense) String() string {
	if !s.Valid {
		return fmt.Sprintf("sense=UNDECODABLE (%d bytes, response code 0x%02x)",
			len(s.Raw), firstByte(s.Raw))
	}
	return fmt.Sprintf("sense=%d/%02Xh/%02Xh (%s)", s.Key, s.ASC, s.ASCQ, senseKeyName(s.Key))
}

func firstByte(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

func senseKeyName(k uint8) string {
	switch k {
	case SenseNoSense:
		return "NO SENSE"
	case SenseRecoveredError:
		return "RECOVERED ERROR"
	case SenseNotReady:
		return "NOT READY"
	case SenseMediumError:
		return "MEDIUM ERROR"
	case SenseHardwareError:
		return "HARDWARE ERROR"
	case SenseIllegalRequest:
		return "ILLEGAL REQUEST"
	case SenseUnitAttention:
		return "UNIT ATTENTION"
	case SenseDataProtect:
		return "DATA PROTECT"
	case SenseAborted:
		return "ABORTED COMMAND"
	}
	return fmt.Sprintf("KEY(0x%x)", k)
}

// parseSense decodes both sense-data formats.
//
// Response codes 0x70/0x71 are the fixed format (key at byte 2, ASC/ASCQ at
// 12/13); 0x72/0x73 are the descriptor format, where they move to bytes 1/2/3.
// LIO emits fixed format, but a real initiator stack can see either and
// reading the wrong offsets yields a plausible-looking wrong answer rather
// than a failure -- exactly the kind of mismeasurement this package exists to
// stop. SPC-6 4.5.1-4.5.3.
func parseSense(b []byte) *Sense {
	if len(b) == 0 {
		return nil
	}
	s := &Sense{Raw: append([]byte(nil), b...)}
	switch b[0] & 0x7f {
	case 0x70, 0x71: // fixed
		if len(b) <= 13 {
			return s // too short to carry ASC/ASCQ: decoded nothing
		}
		s.Key = b[2] & 0x0f
		s.ASC, s.ASCQ = b[12], b[13]
		s.Valid = true
	case 0x72, 0x73: // descriptor
		if len(b) <= 3 {
			return s
		}
		s.Key, s.ASC, s.ASCQ = b[1]&0x0f, b[2], b[3]
		s.Valid = true
	default:
		// Unknown response code: keep Raw, claim nothing.
		return s
	}
	return s
}
