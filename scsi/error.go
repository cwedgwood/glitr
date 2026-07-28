package scsi

import "fmt"

// StatusError reports that a device declined a command that has no meaningful
// non-GOOD answer -- the PERSISTENT RESERVE IN commands, whose whole purpose
// is to return data.
//
// It exists so a caller cannot mistake "the device did not answer" for "the
// answer is empty". A READ KEYS that returns no keys because it was refused
// looks identical, in a bare struct, to one that returns no keys because
// nothing is registered; for a fencing check those are opposite conclusions.
//
// The Result is carried, so a caller can still ask what happened -- notably
// whether this was the transient UNIT ATTENTION that follows a preemption and
// should be drained, or a real fault.
type StatusError struct {
	Op string
	Result
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("scsi: device declined %s: %s", e.Op, e.Result.String())
}

// UnitAttention reports whether the device declined with a UNIT ATTENTION,
// the one-shot condition raised after a preemption, reset or topology change.
//
// It is cleared by being reported, so the correct response is to reissue the
// command once, not to treat it as a failure. MEASURED on the lab: after
// PREEMPT the victim sees sense 6/2Ah/05h (REGISTRATIONS PREEMPTED) on its
// next command, and the real status on the one after.
func (e *StatusError) UnitAttention() bool {
	return e.Sense != nil && e.Sense.UnitAttention()
}
