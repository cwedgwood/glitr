package lio

import "testing"

// Fixtures captured VERBATIM from the lab target (Azure Linux 3.0, kernel
// 6.6.144.1-1.azl3), not hand-written, because the point of these tests is that
// the parse matches what the kernel actually emits.
const (
	aclInfoFixture = `InitiatorName: iqn.1993-08.org.debian:01:glitr-init-a
InitiatorAlias: initiator
LIO Session ID: 1   ISID: 0x00 02 3d 00 00 01  TSIH: 1  SessionType: Normal
Session State: TARG_SESS_STATE_LOGGED_IN`

	prRegFixture = `SPC-3 PR Registrations:
iSCSI Node: iqn.1993-08.org.debian:01:glitr-init-a,i,0x00023d000004 Key: 0x000000000000aaaa PRgen: 0x00000000
iSCSI Node: iqn.1993-08.org.debian:01:glitr-init-b,i,0x00023d000002 Key: 0x000000000000bbbb PRgen: 0x00000001`
)

func TestParseSessionISID(t *testing.T) {
	got, err := ParseSessionISID(aclInfoFixture)
	if err != nil {
		t.Fatalf("the kernel's own ACL info must parse: %v", err)
	}
	if got != "00023d000001" {
		t.Errorf("got %q, want %q -- the kernel prints the ISID byte-spaced and this "+
			"must reduce to the canonical form the registration list uses", got, "00023d000001")
	}
}

// TestParseSessionISIDStopsAtTheFieldBoundary is the specific trap. The ISID's
// bytes are separated by single spaces while the LINE's fields are separated by
// runs of them, so a greedy match can swallow a following field. A previous
// parser in this codebase truncated "Buffered-WCE" to "Buffered" through the
// same class of mistake, and the wrong value was recorded as a measured kernel
// fact.
//
// This asserts on the RAW regex rather than on ParseSessionISID, because
// ParseSessionISID validates its result against ^[0-9a-f]{12}$ -- so a boundary
// failure would surface there as a shape error, and a length check on the
// returned value could never fail. Testing the capture directly is what makes
// this able to fail for the reason it names.
func TestParseSessionISIDStopsAtTheFieldBoundary(t *testing.T) {
	m := sessionISIDRE.FindStringSubmatch(aclInfoFixture)
	if m == nil {
		t.Fatal("the kernel's own ACL info must match")
	}
	if m[1] != "00 02 3d 00 00 01" {
		t.Errorf("captured %q: the capture ran past the ISID field", m[1])
	}

	// A following field made only of hex digits and spaces, itself followed by
	// two spaces, is the case where greedy and non-greedy diverge. "TSIH"
	// cannot exercise it because ":" and "T" are outside the character class.
	const hexNextField = `LIO Session ID: 1   ISID: 0x00 02 3d 00 00 01  AB CD  TSIH: 1`
	m = sessionISIDRE.FindStringSubmatch(hexNextField)
	if m == nil {
		t.Fatal("must still match when the next field is hex-shaped")
	}
	if m[1] != "00 02 3d 00 00 01" {
		t.Errorf("captured %q: a greedy match swallowed the next field", m[1])
	}
}

func TestParseSessionISIDRejectsAMalformedLine(t *testing.T) {
	// A shape change must be an ERROR, not a value: the suite compares two
	// ISIDs for inequality, so a parser that quietly returns something wrong
	// could make identical sessions look rotated.
	for name, blob := range map[string]string{
		"no isid at all": "InitiatorName: iqn.example:x\nSession State: TARG_SESS_STATE_FREE",
		"truncated hex":  "LIO Session ID: 1   ISID: 0x00 02  TSIH: 1  SessionType: Normal",
		"logged out acl": "InitiatorName: iqn.example:x\nNo active iSCSI Session",
	} {
		if got, err := ParseSessionISID(blob); err == nil {
			t.Errorf("%s: expected an error, got %q", name, got)
		}
	}
}

func TestParseRegisteredISIDs(t *testing.T) {
	got, err := ParseRegisteredISIDs(prRegFixture)
	if err != nil {
		t.Fatalf("the kernel's own registration list must parse: %v", err)
	}
	want := map[string]string{
		"iqn.1993-08.org.debian:01:glitr-init-a": "00023d000004",
		"iqn.1993-08.org.debian:01:glitr-init-b": "00023d000002",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d registrations, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got ISID %q, want %q", k, got[k], v)
		}
	}
}

// TestParseRegisteredISIDsIgnoresRegistrationsWithoutOne: the ",i,0x..." suffix
// is emitted only when isid_present_at_reg is set, so its ABSENCE is meaningful
// -- that registration accepts PR commands from any session. Absent must not be
// confused with "no registration".
func TestParseRegisteredISIDsIgnoresRegistrationsWithoutOne(t *testing.T) {
	const noISID = `SPC-3 PR Registrations:
iSCSI Node: iqn.1993-08.org.debian:01:glitr-init-a Key: 0x000000000000aaaa PRgen: 0x00000000`
	got, err := ParseRegisteredISIDs(noISID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("a registration with no ISID suffix must not appear in the map, got %v", got)
	}
}

func TestParseRegisteredISIDsOnAnEmptyList(t *testing.T) {
	got, err := ParseRegisteredISIDs("SPC-3 PR Registrations:\nNone")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("an empty registration list must yield nothing, got %v", got)
	}
}

// TestParseHolderExtractsTheISID: res_holder carries the same ",i,0x..."
// suffix the registration list does, and the stranded check needs it. It used
// to be pulled out by a SECOND regex in stranded.go while parseHolder threw it
// away, so one file had the holder and the other had the session, from two
// parses of the same string.
func TestParseHolderExtractsTheISID(t *testing.T) {
	const iqn = "iqn.1993-08.org.debian:01:glitr-init-a"
	for name, tc := range map[string]struct {
		in         string
		wantIQN    string
		wantISID   string
		wantReason string
	}{
		"spc-3 with isid": {
			in:       "SPC-3 Reservation: iSCSI Initiator: " + iqn + ",i,0x00023d000004",
			wantIQN:  iqn,
			wantISID: "00023d000004",
		},
		"spc-3 without isid": {
			in:         "SPC-3 Reservation: iSCSI Initiator: " + iqn,
			wantIQN:    iqn,
			wantISID:   "",
			wantReason: "no suffix means the registration accepts any session",
		},
		"spc-2": {
			in:         "SPC-2 Reservation: iSCSI Initiator: " + iqn,
			wantIQN:    iqn,
			wantISID:   "",
			wantReason: "SPC-2 reservations are not bound to a session",
		},
		"no holder": {
			in:      "No SPC-3 Reservation holder",
			wantIQN: "",
		},
		"malformed isid": {
			in:         "SPC-3 Reservation: iSCSI Initiator: " + iqn + ",i,0x0002",
			wantIQN:    iqn,
			wantISID:   "",
			wantReason: "a bad extraction must not become a session claim",
		},
		// The table above tested every malformed shape EXCEPT the one that
		// panicked: a value ending exactly at the prefix. strings.Fields("")
		// is an empty slice, so indexing it took the process down -- from
		// PRState, ReservationHolder, and the APTPL check inside Sync.
		"isid prefix and nothing after it": {
			in:         "SPC-3 Reservation: iSCSI Initiator: " + iqn + ",i,0x",
			wantIQN:    iqn,
			wantISID:   "",
			wantReason: "an empty remainder must not panic",
		},
		"isid prefix then only spaces": {
			in:         "SPC-3 Reservation: iSCSI Initiator: " + iqn + ",i,0x   ",
			wantIQN:    iqn,
			wantISID:   "",
			wantReason: "whitespace-only remainder must not panic either",
		},
	} {
		gotIQN, gotISID, _ := parseHolder(tc.in)
		if gotIQN != tc.wantIQN {
			t.Errorf("%s: holder = %q, want %q", name, gotIQN, tc.wantIQN)
		}
		if gotISID != tc.wantISID {
			t.Errorf("%s: isid = %q, want %q (%s)", name, gotISID, tc.wantISID, tc.wantReason)
		}
	}
}
