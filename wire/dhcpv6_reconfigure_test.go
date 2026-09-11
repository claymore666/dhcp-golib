// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package wire

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"testing"
)

// The Reconfigure codec's own fixtures: RFC 9915 §21.11's Authentication
// option, §21.19's Reconfigure Message option, §21.20's Reconfigure Accept
// option, and §20.4's RKAP digest.
//
// THE DIGEST IN THIS FILE IS NOT COMPUTED BY THE SUBJECT. rkapSignHere writes
// RFC 2104's construction out — "H(K XOR opad, H(K XOR ipad, text))" — and
// chooses the zeroed span itself. A test that signed with RKAPVerify's own
// helper would be f(x) == f(x): every mutant of the span or of the hashed
// range would move both sides together and die nowhere.

// rkapKey is the 128 bits §20.4.2 fixes, as a fixture value.
var rkapKey = mustHex("000102030405060708090a0b0c0d0e0f")

// md5BlockLen is RFC 2104 §2's B, "the block length of the hash function": 64
// for MD5, RFC 1321's block size.
const md5BlockLen = 64

// rkapSignHere is RFC 2104 §2, written out, over a message whose Authentication
// option Value has already been zeroed.
//
// RFC 2104 §2: "(1) append zeros to the end of K to create a B byte string
// (e.g., if K is of length 20 bytes and B=64, then K will be appended with 44
// zero bytes 0x00) (2) XOR (bitwise exclusive-OR) the B byte string computed in
// step (1) with ipad (3) append the stream of data 'text' to the B byte string
// resulting from step (2) (4) apply H to the stream generated in step (3) (5)
// XOR (bitwise exclusive-OR) the B byte string computed in step (1) with opad
// (6) append the H result from step (4) to the B byte string resulting from
// step (5) (7) apply H to the stream generated in step (6) and output the
// result".
func rkapSignHere(key, text []byte) []byte {
	k := make([]byte, md5BlockLen)
	copy(k, key)
	ipad := make([]byte, md5BlockLen)
	opad := make([]byte, md5BlockLen)
	for i := range md5BlockLen {
		ipad[i] = k[i] ^ 0x36
		opad[i] = k[i] ^ 0x5c
	}
	inner := md5.Sum(append(append([]byte(nil), ipad...), text...))
	outer := md5.Sum(append(append([]byte(nil), opad...), inner[:]...))
	return outer[:]
}

// reconfigureFixture builds a Reconfigure carrying opts, signs it under key
// over the span zeroSpan names, and returns the octets a client would receive.
//
// zeroLen is how many octets of the authentication information the SIGNER
// blanks before hashing: 16 is §20.4.3's "the HMAC-MD5 field", 17 is the whole
// authentication information including §20.4.1's Type octet, and 0 is a signer
// that blanked nothing. It is a parameter so the two wrong spans can be built
// and refused.
func reconfigureFixture(t *testing.T, key []byte, replay uint64, zeroLen int, opts OptionsV6) []byte {
	t.Helper()
	// A NON-ZERO placeholder, so that "the signer blanked nothing" is a
	// different message from "the signer blanked the Value". With zeros in
	// the field the two are the same octets and the zeroLen parameter would
	// measure nothing.
	placeholder := bytes.Repeat([]byte{0xa5}, RKAPValueLen)
	auth, err := EncodeRKAPAuth(RKAPTypeDigest, placeholder, replay)
	if err != nil {
		t.Fatalf("EncodeRKAPAuth: %v", err)
	}
	msg := &MessageV6{Type: MsgReconfigure, XID: 0x0a0b0c}
	msg.Options = append(msg.Options, opts...)
	msg.Options = append(msg.Options, OptionV6{Code: OptV6Auth, Data: auth})
	raw, err := EncodeV6(msg)
	if err != nil {
		t.Fatalf("EncodeV6: %v", err)
	}
	// The Value's offset in raw, found by the signer's own walk: the option
	// was appended last, so it is the tail of the message.
	end := len(raw)
	start := end - RKAPValueLen
	signed := append([]byte(nil), raw...)
	for i := end - zeroLen; i < end; i++ {
		signed[i] = 0
	}
	copy(raw[start:end], rkapSignHere(key, signed))
	return raw
}

// reconfMsgOption is §21.19's option carrying t.
func reconfMsgOption(t MessageTypeV6) OptionV6 {
	return OptionV6{Code: OptV6ReconfMsg, Data: []byte{byte(t)}}
}

// TestTheReconfigureMessageOptionReadsAllThreeMsgTypes is §21.19: "msg-type: 5
// for Renew message, 6 for Rebind message, 11 for Information-request message."
// All three are valid, and a codec that implements two of them fails a
// MUST-accept rather than enforcing a MUST-drop.
func TestTheReconfigureMessageOptionReadsAllThreeMsgTypes(t *testing.T) {
	for _, want := range []MessageTypeV6{MsgRenew, MsgRebind, MsgInformationRequest} {
		v, err := EncodeReconfigureMessage(want)
		if err != nil {
			t.Fatalf("EncodeReconfigureMessage(%s): %v", want, err)
		}
		if len(v) != 1 || MessageTypeV6(v[0]) != want {
			t.Fatalf("%s encodes to % x, want the single octet %#02x (§21.19 option-len 1)", want, v, byte(want))
		}
		got, ok, err := OptionsV6{{Code: OptV6ReconfMsg, Data: v}}.ReconfigureMessage()
		if err != nil || !ok || got != want {
			t.Fatalf("ReconfigureMessage = %s, %v, %v; want %s, true, nil", got, ok, err, want)
		}
	}
}

// TestTheReconfigureMessageOptionRefusesEveryOtherMsgType drives §16.11's "the
// Reconfigure Message option msg-type is not a valid value" over the whole
// octet space §21.19 leaves out, and over the two lengths that are not one.
func TestTheReconfigureMessageOptionRefusesEveryOtherMsgType(t *testing.T) {
	for v := 0; v < 256; v++ {
		typ := MessageTypeV6(v)
		if typ.ReconfigurableBy() {
			continue
		}
		_, ok, err := OptionsV6{{Code: OptV6ReconfMsg, Data: []byte{byte(v)}}}.ReconfigureMessage()
		if !ok {
			t.Fatalf("msg-type %d: the option reports absent", v)
		}
		if !errors.Is(err, ErrV6BadOption) {
			t.Fatalf("msg-type %d: err = %v, want ErrV6BadOption", v, err)
		}
	}
	for _, bad := range [][]byte{{}, {5, 0}, {5, 6, 11}} {
		if _, _, err := (OptionsV6{{Code: OptV6ReconfMsg, Data: bad}}).ReconfigureMessage(); !errors.Is(err, ErrV6BadOption) {
			t.Fatalf("a %d-octet Reconfigure Message: err = %v, want ErrV6BadOption (§21.19 option-len 1)", len(bad), err)
		}
	}
	if _, ok, err := (OptionsV6{}).ReconfigureMessage(); ok || err != nil {
		t.Fatalf("an absent Reconfigure Message reports %v, %v; want false, nil — §16.11 tells absence and invalidity apart", ok, err)
	}
	two := OptionsV6{reconfMsgOption(MsgRenew), reconfMsgOption(MsgRebind)}
	if _, _, err := two.ReconfigureMessage(); !errors.Is(err, ErrV6BadOption) {
		t.Fatalf("two Reconfigure Message options: err = %v, want ErrV6BadOption (§21 singleton)", err)
	}
}

// TestTheReconfigureAcceptOptionIsZeroLength is §21.20: "option-len: 0."
func TestTheReconfigureAcceptOptionIsZeroLength(t *testing.T) {
	raw, err := EncodeOptionsV6(OptionsV6{{Code: OptV6ReconfAccept}})
	if err != nil {
		t.Fatalf("EncodeOptionsV6: %v", err)
	}
	if want := mustHex("00140000"); !bytes.Equal(raw, want) {
		t.Fatalf("Reconfigure Accept encodes to % x, want % x (code 20, length 0)", raw, want)
	}
	ok, err := OptionsV6{{Code: OptV6ReconfAccept}}.ReconfigureAccept()
	if !ok || err != nil {
		t.Fatalf("ReconfigureAccept = %v, %v; want true, nil", ok, err)
	}
	ok, err = OptionsV6{{Code: OptV6ReconfAccept, Data: []byte{0}}}.ReconfigureAccept()
	if !ok || !errors.Is(err, ErrV6BadOption) {
		t.Fatalf("a 1-octet Reconfigure Accept = %v, %v; want true, ErrV6BadOption — discard the OPTION, not the message", ok, err)
	}
	if ok, err := (OptionsV6{}).ReconfigureAccept(); ok || err != nil {
		t.Fatalf("an absent Reconfigure Accept = %v, %v; want false, nil", ok, err)
	}
}

// TestTheAuthenticationOptionRoundTrips is §21.11's layout: three one-octet
// fields, a 64-bit replay detection field, then the authentication information.
func TestTheAuthenticationOptionRoundTrips(t *testing.T) {
	v, err := EncodeRKAPAuth(RKAPTypeKey, rkapKey, 0x0102030405060708)
	if err != nil {
		t.Fatalf("EncodeRKAPAuth: %v", err)
	}
	want := mustHex("030100" + "0102030405060708" + "01" + hex.EncodeToString(rkapKey))
	if !bytes.Equal(v, want) {
		t.Fatalf("the option value is\n  % x\nwant\n  % x", v, want)
	}
	a, ok, err := OptionsV6{{Code: OptV6Auth, Data: v}}.Auth()
	if !ok || err != nil {
		t.Fatalf("Auth = %v, %v; want present and no error", ok, err)
	}
	if a.Protocol != AuthProtocolRKAP || a.Algorithm != AuthAlgorithmHMAC || a.RDM != AuthRDMMonotonic {
		t.Fatalf("decoded protocol/algorithm/RDM %d/%d/%d, want 3/1/0 (§20.4.1)", a.Protocol, a.Algorithm, a.RDM)
	}
	if a.Replay != 0x0102030405060708 {
		t.Fatalf("decoded replay detection %#x, want %#x", a.Replay, uint64(0x0102030405060708))
	}
	typ, val, err := a.RKAP()
	if err != nil || typ != RKAPTypeKey || !bytes.Equal(val, rkapKey) {
		t.Fatalf("RKAP = %d, % x, %v; want type 1 and the key", typ, val, err)
	}
}

// TestTheAuthenticationOptionRefusesWhatIsNotRKAP drives each field §20.4.1
// fixes, one at a time, with the rest correct: a message authenticated under
// another protocol is not authenticated under this one.
func TestTheAuthenticationOptionRefusesWhatIsNotRKAP(t *testing.T) {
	good := Auth{
		Protocol: AuthProtocolRKAP, Algorithm: AuthAlgorithmHMAC, RDM: AuthRDMMonotonic,
		Info: append([]byte{RKAPTypeDigest}, make([]byte, RKAPValueLen)...),
	}
	if _, _, err := good.RKAP(); err != nil {
		t.Fatalf("the control is refused: %v", err)
	}
	for _, tc := range []struct {
		name string
		mut  func(a *Auth)
	}{
		{"protocol 2 (delayed authentication)", func(a *Auth) { a.Protocol = 2 }},
		{"protocol 0", func(a *Auth) { a.Protocol = 0 }},
		{"algorithm 0", func(a *Auth) { a.Algorithm = 0 }},
		{"RDM 1", func(a *Auth) { a.RDM = 1 }},
		{"no Type octet", func(a *Auth) { a.Info = a.Info[1:] }},
		{"an octet too many", func(a *Auth) { a.Info = append(a.Info, 0) }},
		{"empty", func(a *Auth) { a.Info = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := good
			a.Info = append([]byte(nil), good.Info...)
			tc.mut(&a)
			if _, _, err := a.RKAP(); !errors.Is(err, ErrV6Auth) {
				t.Fatalf("RKAP err = %v, want ErrV6Auth", err)
			}
		})
	}
	short := make([]byte, AuthFixedLen-1)
	if _, err := DecodeAuth(short); !errors.Is(err, ErrV6BadOption) {
		t.Fatalf("a %d-octet Authentication option: %v, want ErrV6BadOption (§21.11 fixes %d)", len(short), err, AuthFixedLen)
	}
	v, _ := EncodeRKAPAuth(RKAPTypeDigest, make([]byte, RKAPValueLen), 1)
	two := OptionsV6{{Code: OptV6Auth, Data: v}, {Code: OptV6Auth, Data: v}}
	if _, ok, err := two.Auth(); !ok || !errors.Is(err, ErrV6Auth) {
		t.Fatalf("two Authentication options = %v, %v; want present and ErrV6Auth (§21 singleton)", ok, err)
	}
}

// TestRKAPVerifyAcceptsTheSpanRFC9915Defines is §20.4.3's positive direction,
// with the digest produced by this file's own RFC 2104 construction over the
// 16-octet Value: "the HMAC-MD5 field in the Authentication option is set to 0
// for the HMAC-MD5 computation" (§20.4.2).
func TestRKAPVerifyAcceptsTheSpanRFC9915Defines(t *testing.T) {
	raw := reconfigureFixture(t, rkapKey, 1, RKAPValueLen, OptionsV6{reconfMsgOption(MsgRenew)})
	if err := RKAPVerify(raw, rkapKey); err != nil {
		t.Fatalf("a correctly signed Reconfigure is refused: %v", err)
	}
}

// TestRKAPVerifyRefusesAWrongZeroedSpan is defeat row D-4: a signer that blanks
// §20.4.1's Type octet along with the Value, or that blanks nothing, has not
// signed what §20.4.3 says to sign.
func TestRKAPVerifyRefusesAWrongZeroedSpan(t *testing.T) {
	for _, zeroLen := range []int{0, RKAPValueLen + 1} {
		raw := reconfigureFixture(t, rkapKey, 1, zeroLen, OptionsV6{reconfMsgOption(MsgRenew)})
		if err := RKAPVerify(raw, rkapKey); !errors.Is(err, ErrRKAPDigest) {
			t.Fatalf("a signer that blanked %d octet(s) is accepted: %v", zeroLen, err)
		}
	}
}

// TestRKAPVerifyCoversTheWholeMessage is defeat row D-5: §20.4.2 hashes "the
// entire DHCP Reconfigure message, including the Authentication option", so an
// octet flipped anywhere outside the digest field breaks it. The unflipped
// control is here too, or the red would be measuring "hard" rather than "this
// flip".
func TestRKAPVerifyCoversTheWholeMessage(t *testing.T) {
	base := reconfigureFixture(t, rkapKey, 1, RKAPValueLen, OptionsV6{
		reconfMsgOption(MsgRenew),
		{Code: OptV6ServerID, Data: mustHex("00030001aabbccddeeff")},
	})
	if err := RKAPVerify(base, rkapKey); err != nil {
		t.Fatalf("the control is refused: %v", err)
	}
	for _, tc := range []struct {
		name string
		at   int
	}{
		{"the msg-type octet", 0},
		{"the transaction-id", 2},
		{"the Reconfigure Message option's code", 4},
		{"the Reconfigure Message option's msg-type", 8},
		{"the Server Identifier's last octet", 9 + 4 + 10 - 1},
		{"the Authentication option's replay detection field", len(base) - RKAPValueLen - 1 - 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := append([]byte(nil), base...)
			raw[tc.at] ^= 0xff
			if err := RKAPVerify(raw, rkapKey); !errors.Is(err, ErrRKAPDigest) {
				t.Fatalf("flipping octet %d is accepted: %v", tc.at, err)
			}
		})
	}
}

// TestRKAPVerifyReadsTheOctetsThatArrived is defeat row D-3: the digest is taken
// over the received message, not over a re-encoding of the decoded one. An
// option this codec does not name, an option order the encoder would not
// produce, and a zero-length option are all messages §16 requires be kept
// ("Clients, relay agents, and servers MUST NOT discard messages that contain
// unknown options"), and all three must verify.
func TestRKAPVerifyReadsTheOctetsThatArrived(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts OptionsV6
	}{
		{"an unknown option code", OptionsV6{
			{Code: OptionCodeV6(0xBEEF), Data: mustHex("cafe")},
			reconfMsgOption(MsgRebind),
		}},
		{"the Reconfigure Message option last", OptionsV6{
			{Code: OptV6ClientID, Data: mustHex("00030001112233445566")},
			reconfMsgOption(MsgInformationRequest),
		}},
		{"a zero-length unknown option", OptionsV6{
			{Code: OptionCodeV6(0x7fff)},
			reconfMsgOption(MsgRenew),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := reconfigureFixture(t, rkapKey, 1, RKAPValueLen, tc.opts)
			if err := RKAPVerify(raw, rkapKey); err != nil {
				t.Fatalf("a correctly signed Reconfigure is refused: %v", err)
			}
			m, err := DecodeV6(raw)
			if err != nil {
				t.Fatalf("DecodeV6: %v", err)
			}
			if m.Type != MsgReconfigure {
				t.Fatalf("decoded %s, want RECONFIGURE", m.Type)
			}
		})
	}
}

// TestRKAPVerifyRefusesAKeyThatIsNotOneHundredAndTwentyEightBits is defeat row
// D-14: §20.4.2's "The reconfigure key is 128 bits long", enforced rather than
// padded. A short key silently zero-extended is a key two servers can share a
// prefix of.
func TestRKAPVerifyRefusesAKeyThatIsNotOneHundredAndTwentyEightBits(t *testing.T) {
	raw := reconfigureFixture(t, rkapKey, 1, RKAPValueLen, OptionsV6{reconfMsgOption(MsgRenew)})
	for _, n := range []int{0, 1, 15, 17, 64} {
		if err := RKAPVerify(raw, make([]byte, n)); !errors.Is(err, ErrRKAPKey) {
			t.Fatalf("a %d-octet key: %v, want ErrRKAPKey", n, err)
		}
	}
	if err := RKAPVerify(raw, make([]byte, RKAPValueLen)); !errors.Is(err, ErrRKAPDigest) {
		t.Fatalf("an all-zero key of the right length verifies something: %v", err)
	}
}

// TestRKAPVerifyRefusesAMessageWithNoAuthenticationOption is §16.11's "the
// message does not include authentication", told apart from "fails
// authentication validation" by the error it returns.
func TestRKAPVerifyRefusesAMessageWithNoAuthenticationOption(t *testing.T) {
	msg := &MessageV6{Type: MsgReconfigure, XID: 1, Options: OptionsV6{reconfMsgOption(MsgRenew)}}
	raw, err := EncodeV6(msg)
	if err != nil {
		t.Fatalf("EncodeV6: %v", err)
	}
	if err := RKAPVerify(raw, rkapKey); !errors.Is(err, ErrV6Auth) {
		t.Fatalf("a Reconfigure with no Authentication option: %v, want ErrV6Auth", err)
	}
	if err := RKAPVerify(raw[:2], rkapKey); !errors.Is(err, ErrV6Short) {
		t.Fatalf("a truncated message: %v, want ErrV6Short", err)
	}
}

// TestRKAPVerifyRefusesASecondAuthenticationOption is defeat row A5's shape: with
// two of them, the instance that is ZEROED and the instance that is COMPARED
// can differ, and an attacker chooses which.
func TestRKAPVerifyRefusesASecondAuthenticationOption(t *testing.T) {
	raw := reconfigureFixture(t, rkapKey, 1, RKAPValueLen, OptionsV6{reconfMsgOption(MsgRenew)})
	second, err := EncodeRKAPAuth(RKAPTypeDigest, make([]byte, RKAPValueLen), 2)
	if err != nil {
		t.Fatalf("EncodeRKAPAuth: %v", err)
	}
	extra, err := EncodeOptionsV6(OptionsV6{{Code: OptV6Auth, Data: second}})
	if err != nil {
		t.Fatalf("EncodeOptionsV6: %v", err)
	}
	if err := RKAPVerify(append(append([]byte(nil), raw...), extra...), rkapKey); !errors.Is(err, ErrV6Auth) {
		t.Fatalf("two Authentication options verify: %v, want ErrV6Auth", err)
	}
}
