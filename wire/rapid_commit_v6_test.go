// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package wire

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestRapidCommitIsAZeroLengthOptionThatRoundTrips is RFC 9915 §21.14:
// "option-code: OPTION_RAPID_COMMIT (14). option-len: 0." A Solicit carrying it
// encodes to the four octets 000e0000 after the client identifier and decodes
// back to present (claymore666/docker-net-dhcp#926).
func TestRapidCommitIsAZeroLengthOptionThatRoundTrips(t *testing.T) {
	m := &MessageV6{Type: MsgSolicit, XID: 0x1a2b3c, Options: OptionsV6{
		{Code: OptV6ClientID, Data: mustHex("abcd")},
		RapidCommitOption(),
	}}
	raw, err := EncodeV6(m)
	if err != nil {
		t.Fatalf("EncodeV6: %v", err)
	}
	if want := mustHex("011a2b3c" + "00010002abcd" + "000e0000"); !bytes.Equal(raw, want) {
		t.Fatalf("Solicit octets %x, want %x", raw, want)
	}
	back, err := DecodeV6(raw)
	if err != nil {
		t.Fatalf("DecodeV6: %v", err)
	}
	if on, err := back.Options.RapidCommit(); err != nil || !on {
		t.Errorf("RapidCommit() = %v, %v; want true, nil", on, err)
	}
	if id, ok := back.Options.First(OptV6ClientID); !ok || !bytes.Equal(id, mustHex("abcd")) {
		t.Errorf("the client identifier before Rapid Commit changed: %x", id)
	}
}

// TestRapidCommitAbsentIsFalseWithoutAnError is the other direction: an area
// with no option 14, and one with other zero-length options, reads false, nil.
func TestRapidCommitAbsentIsFalseWithoutAnError(t *testing.T) {
	for name, opts := range map[string]OptionsV6{
		"empty":       nil,
		"other":       {{Code: OptV6ClientID, Data: mustHex("abcd")}},
		"code 13":     {{Code: OptV6StatusCode, Data: nil}},
		"code 15 (0)": {{Code: 15, Data: nil}},
	} {
		if on, err := opts.RapidCommit(); on || err != nil {
			t.Errorf("%s: RapidCommit() = %v, %v; want false, nil", name, on, err)
		}
	}
}

// TestRapidCommitWithAPayloadIsRefusedAndNeverTrue is §21.14's "option-len: 0"
// read as a rule: an instance carrying octets is not the option. The refusal
// is ErrV6BadOption and the returned bool is false, because true is what lets a
// Reply be taken as a commit. The second case is a valid instance followed by
// a bad one: every instance is judged, not the first.
func TestRapidCommitWithAPayloadIsRefusedAndNeverTrue(t *testing.T) {
	for name, opts := range map[string]OptionsV6{
		"one octet":       {{Code: OptV6RapidCommit, Data: []byte{0}}},
		"two octets":      {{Code: OptV6RapidCommit, Data: []byte{0, 0}}},
		"valid then bad":  {RapidCommitOption(), {Code: OptV6RapidCommit, Data: []byte{1}}},
		"bad then valid":  {{Code: OptV6RapidCommit, Data: []byte{1}}, RapidCommitOption()},
		"after a sibling": {{Code: OptV6ClientID, Data: mustHex("ab")}, {Code: OptV6RapidCommit, Data: mustHex("ff")}},
	} {
		on, err := opts.RapidCommit()
		if !errors.Is(err, ErrV6BadOption) {
			t.Errorf("%s: error %v, want ErrV6BadOption", name, err)
		}
		if on {
			t.Errorf("%s: RapidCommit() returned true beside an error", name)
		}
	}
}

// TestRapidCommitRepeatedWithNoPayloadIsStillPresent: RFC 9915 does not forbid
// two zero-length instances, and neither is a defect the decoder should turn
// into a refusal.
func TestRapidCommitRepeatedWithNoPayloadIsStillPresent(t *testing.T) {
	opts := OptionsV6{RapidCommitOption(), RapidCommitOption()}
	if on, err := opts.RapidCommit(); err != nil || !on {
		t.Errorf("RapidCommit() = %v, %v; want true, nil", on, err)
	}
}

// TestRapidCommitIsNamedInASummary: the journal renders option codes by name,
// and an unnamed 14 would print as option6(14).
func TestRapidCommitIsNamedInASummary(t *testing.T) {
	m := &MessageV6{Type: MsgReply, XID: 1, Options: OptionsV6{RapidCommitOption()}}
	if s := m.Summary(); !strings.Contains(s, "rapid-commit") || strings.Contains(s, "option6(14)") {
		t.Errorf("Summary() = %q, want the option named rapid-commit", s)
	}
	if got := OptV6RapidCommit.String(); got != "rapid-commit" {
		t.Errorf("OptV6RapidCommit renders as %q", got)
	}
}

// FuzzRapidCommit drives the accessor over arbitrary option areas. The
// property: a refusal carries false, a true means every instance of code 14 in
// the area has length zero, and no input panics.
func FuzzRapidCommit(f *testing.F) {
	f.Add(mustHex("000e0000"))
	f.Add(mustHex("000e0001ff"))
	f.Add(mustHex("000e0000" + "000e0001ff"))
	f.Add(mustHex("000e0001ff" + "000e0000"))
	f.Add(mustHex("000e00"))
	f.Add(mustHex("000e0002ff"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		opts, err := ParseOptionsV6(b)
		if err != nil {
			return
		}
		on, err := opts.RapidCommit()
		if err != nil && on {
			t.Fatalf("true beside error %v for %x", err, b)
		}
		if on {
			for _, v := range opts.All(OptV6RapidCommit) {
				if len(v) != 0 {
					t.Fatalf("true with an instance of %d octet(s) in %x", len(v), b)
				}
			}
		}
		if err == nil && !on && opts.Count(OptV6RapidCommit) != 0 {
			t.Fatalf("an instance of 14 in %x read as absent without an error", b)
		}
	})
}
