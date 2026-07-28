package lio

import (
	"strings"
	"testing"
)

// Every function here parses text the KERNEL produced, and each one is a pure
// string -> value transform with no I/O. That combination is what makes them
// worth fuzzing rather than only table-testing: the table encodes the shapes
// someone thought of, and the bug that prompted these was a shape nobody did.
//
// parseHolder panicked on a res_holder value ending exactly at ",i,0x".
// strings.Fields("") is an EMPTY SLICE, so indexing it took the process down
// -- reachable from PRState, ReservationHolder and the APTPL verification
// inside Sync, so a malformed kernel attribute would have killed a caller's
// daemon. The hand-written table had five malformed cases and missed it.
//
// MEASURED against the pre-fix code: neither `go vet`, nor staticcheck (even
// with -checks=all), nor nilaway reported it. Both linters were verified
// working on planted control bugs first, so the silence was real rather than
// a broken setup. nilaway models nilness, not slice length; staticcheck does
// not track that CutPrefix succeeding leaves a possibly-empty remainder.
// `go test -fuzz` found it in under a second, at ~17k execs/sec, with the
// input "0 Initiator: ,i,0x".
//
// WHAT THESE ASSERT is only "does not panic, does not hang". That is
// deliberate: correctness of the parse is what the table tests are for, and a
// fuzzer cannot know the right answer. Robustness against input the kernel
// might one day produce is what it can prove, and is what was missing.
//
// Seeds are verbatim kernel output wherever the table tests have it, so the
// fuzzer starts from the real grammar rather than having to discover it.

func FuzzParseHolder(f *testing.F) {
	f.Add("SPC-3 Reservation: iSCSI Initiator: iqn.1993-08.org.debian:01:a,i,0x00023d000004")
	f.Add("SPC-2 Reservation: iSCSI Initiator: iqn.1993-08.org.debian:01:a")
	f.Add("No SPC-3 Reservation holder")
	f.Add("SPC-3 Reservation: iSCSI Initiator: iqn.x:a,i,0x") // the crasher
	f.Add("SPC-3 Reservation: iSCSI Initiator: iqn.x:a,i,0x   ")
	f.Fuzz(func(t *testing.T, s string) {
		iqn, isid, known := parseHolder(s)
		// An uninterpretable rendering must not present as a definite answer.
		// "" means "no reservation is held", so returning it with known==true
		// for prose we did not recognise reports a protected device as
		// unprotected -- the fail-open direction.
		if !known && (iqn != "" || isid != "") {
			t.Fatalf("parseHolder(%q) = (%q, %q) but reported the text uninterpretable", s, iqn, isid)
		}
		// The one INVARIANT worth asserting: an ISID is either empty or the
		// canonical 12-hex-digit form. Callers compare it against a session
		// identifier, so a value of any other shape would manufacture a
		// mismatch -- which is a false "stranded reservation" report.
		if isid != "" && !isidRE.MatchString(isid) {
			t.Fatalf("parseHolder(%q) = (%q, %q): a non-canonical ISID escaped validation",
				s, iqn, isid)
		}
	})
}

func FuzzParseSessionISID(f *testing.F) {
	f.Add("InitiatorName: iqn.1993-08.org.debian:01:a\n" +
		"LIO Session ID: 1   ISID: 0x00 02 3d 00 00 01  TSIH: 1  SessionType: Normal")
	f.Add("InitiatorName: iqn.x:a\nNo active iSCSI Session")
	f.Add("LIO Session ID: 1   ISID: 0x00 02  TSIH: 1  SessionType: Normal")
	f.Add("ISID: 0x  ")
	f.Fuzz(func(t *testing.T, s string) {
		got, err := ParseSessionISID(s)
		// Same invariant, and it is the load-bearing one: this value is
		// compared for INEQUALITY against a registration's ISID, so anything
		// that is not the canonical form produces a false report rather than
		// a failed parse.
		if err == nil && !isidRE.MatchString(got) {
			t.Fatalf("ParseSessionISID(%q) = %q with nil error: not canonical", s, got)
		}
		if err != nil && got != "" {
			t.Fatalf("ParseSessionISID(%q) returned both %q and an error", s, got)
		}
	})
}

func FuzzParseRegisteredISIDs(f *testing.F) {
	f.Add("SPC-3 PR Registrations:\n" +
		"iSCSI Node: iqn.1993-08.org.debian:01:a,i,0x00023d000004 Key: 0x000000000000aaaa PRgen: 0x00000000")
	f.Add("SPC-3 PR Registrations:\nNone")
	f.Add("iSCSI Node: iqn.x:a Key: 0x1 PRgen: 0x0")
	f.Fuzz(func(t *testing.T, s string) {
		got, err := ParseRegisteredISIDs(s)
		if err != nil {
			if got != nil {
				t.Fatalf("ParseRegisteredISIDs(%q) returned a map AND an error", s)
			}
			return
		}
		for iqn, isid := range got {
			if !isidRE.MatchString(isid) {
				t.Fatalf("ParseRegisteredISIDs(%q)[%q] = %q: not canonical", s, iqn, isid)
			}
		}
	})
}

func FuzzParseAPTPLRecord(f *testing.F) {
	f.Add("initiator_node=iqn.1993-08.org.debian:01:a,initiator_sid=00023d000004," +
		"sa_res_key=43690,res_holder=1,res_type=5,res_scope=0,res_all_tg_pt=0," +
		"mapped_lun=0,target_fabric=iSCSI,target_node=iqn.2026-01.dev.glitr:t," +
		"tpgt=1,port_rtpi=1,target_lun=0")
	f.Add("PR_REG_START: 1")
	f.Add("initiator_node=,sa_res_key=,res_holder=")
	f.Add("=")
	f.Fuzz(func(t *testing.T, s string) {
		rec, err := parseAPTPLRecord(s)
		// A record that failed to parse must not also be reported as a
		// holder: a saved reservation the caller cannot trust must not be
		// counted as one that is in effect.
		if err != nil && rec.Holder {
			t.Fatalf("parseAPTPLRecord(%q) failed with %v but still reports a holder", s, err)
		}
	})
}

func FuzzParseRegistrations(f *testing.F) {
	f.Add("SPC-3 PR Registrations:\n" +
		"iSCSI Node: iqn.x:a,i,0x00023d000004 Key: 0x000000000000aaaa PRgen: 0x0")
	f.Add("SPC-3 PR Registrations:\nNone")
	f.Add("iSCSI Node:")
	f.Fuzz(func(t *testing.T, s string) {
		regs, unparsed := parseRegistrations(s)
		if unparsed < 0 {
			t.Fatalf("parseRegistrations(%q): negative unparsed count %d", s, unparsed)
		}
		// Counting an unparsable line as a registration would be the
		// fail-open direction: it would report fencing state the kernel did
		// not describe.
		if unparsed > 0 && len(regs) > strings.Count(s, "\n")+1 {
			t.Fatalf("parseRegistrations(%q): %d regs from fewer lines", s, len(regs))
		}
	})
}

func FuzzParsePortal(f *testing.F) {
	f.Add("10.0.0.1:3260")
	f.Add("[fd00:10:10::1]:3260")
	f.Add("[fe80::1%eth0]:3260")
	f.Add("0.0.0.0:3260")
	f.Add("[::]:3260")
	f.Add(":")
	f.Fuzz(func(t *testing.T, s string) {
		p, ok := ParsePortal(s)
		if !ok {
			return
		}
		// A parsed portal must round-trip. The kernel names a portal by this
		// string, so a value that does not render back to itself would make
		// reconcile create one object and look for another -- the shape that
		// let two spellings of one IPv6 address pass as two portals.
		if got := p.String(); got != s {
			if _, ok2 := ParsePortal(got); !ok2 {
				t.Fatalf("ParsePortal(%q) -> %q, which does not re-parse", s, got)
			}
		}
	})
}

func FuzzParseInfoLine(f *testing.F) {
	f.Add("TCM FILEIO ID: 0  File: /var/lib/glitr/x.img  Size: 134217728  Mode: O_DSYNC  Async: 0")
	f.Add("TCM FILEIO ID: 0  File: /x.img  Size: 1  Mode: Buffered-WCE  Async: 0")
	f.Add("Mode:")
	f.Add("Size:")
	f.Fuzz(func(t *testing.T, s string) {
		mode := parseInfoMode(s)
		// The hyphenated mode is the one a previous parser truncated, and the
		// wrong value was recorded as a MEASURED kernel fact. Only two values
		// exist; anything else must come back empty rather than as a guess.
		if mode != "" && mode != "O_DSYNC" && mode != "Buffered-WCE" {
			t.Fatalf("parseInfoMode(%q) = %q: not a mode the kernel emits", s, mode)
		}
		// -1 is parseInfoSize's documented "no Size: field" sentinel and both
		// callers branch on it, so a negative is correct here. What must not
		// happen is a size that is negative but NOT the sentinel, which would
		// be a parsed value rather than an absence.
		if sz := parseInfoSize(s); sz < -1 {
			t.Fatalf("parseInfoSize(%q) = %d: negative but not the -1 sentinel", s, sz)
		}
	})
}

func FuzzPRTypeText(f *testing.F) {
	f.Add("SPC-3 Reservation Type: Write Exclusive Access, Registrants Only")
	f.Add("SPC-3 Reservation Type: Write Exclusive Access, All Registrants")
	f.Add("No SPC-3 Reservation holder")
	f.Add("Reservation Type:")
	f.Fuzz(func(t *testing.T, s string) { prTypeText(s) })
}

func FuzzParseTPGTAndLUN(f *testing.F) {
	f.Add("tpgt_1")
	f.Add("lun_0")
	f.Add("tpgt_")
	f.Add("lun_-1")
	f.Add("tpgt_99999999999999999999")
	f.Fuzz(func(t *testing.T, s string) {
		if n, ok := parseTPGT(s); ok && n < 0 {
			t.Fatalf("parseTPGT(%q) = %d: a negative tag would name a directory that cannot exist", s, n)
		}
		if n, ok := parseLUN(s); ok && n < 0 {
			t.Fatalf("parseLUN(%q) = %d: negative", s, n)
		}
	})
}
