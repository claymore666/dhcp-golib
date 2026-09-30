// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package wire

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// The typed readers and writers for options 77, 80, 108 and 145 and message
// type 9 (claymore666/docker-net-dhcp#1120, #1031, #1027, #1119).

// roundTrip carries options through Encode and Decode, so a codec claim is
// made about bytes on the wire and not about a map handed from one call to
// the next (claymore666/docker-net-dhcp#1120).
func roundTrip(t *testing.T, opts Options) Options {
	t.Helper()
	m := &Message{Op: BootRequest, HType: HTypeEthernet, CHAddr: []byte{1, 2, 3, 4, 5, 6}, Options: opts}
	m.SetType(MsgDiscover)
	b, err := Encode(m)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	back, err := Decode(b)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return back.Options
}

func classOf(n int, fill byte) []byte { return bytes.Repeat([]byte{fill}, n) }

func TestUserClassOneInstanceIsAtMost254Octets(t *testing.T) {
	v, err := EncodeUserClass(classOf(254, 'a'))
	if err != nil {
		t.Fatalf("254 octets refused: %v", err)
	}
	if len(v) != 255 || v[0] != 254 {
		t.Fatalf("value is %d octets starting %d, want 255 starting 254", len(v), v[0])
	}
	got, ok, err := roundTrip(t, Options{OptUserClass: v}).UserClass()
	if err != nil || !ok || len(got) != 1 || !bytes.Equal(got[0], classOf(254, 'a')) {
		t.Fatalf("254-octet class did not survive the wire: %v %v %d", ok, err, len(got))
	}
	// 255 octets plus the length octet is 256, which a one-octet option
	// length would wrap to 0 (claymore666/docker-net-dhcp#1120).
	if _, err := EncodeUserClass(classOf(255, 'a')); !errors.Is(err, ErrBadOptionValue) {
		t.Fatalf("255-octet class: got %v, want ErrBadOptionValue", err)
	}
}

func TestUserClassListPlusCountFitsOneOctetOfLength(t *testing.T) {
	// RFC 3004 section 4: Len = UC_Len_1 + ... + UC_Len_m + m (claymore666/docker-net-dhcp#1120).
	cases := []struct {
		name    string
		classes [][]byte
		ok      bool
	}{
		{"127 and 126 make 255", [][]byte{classOf(127, 'a'), classOf(126, 'b')}, true},
		{"127 and 127 make 256", [][]byte{classOf(127, 'a'), classOf(127, 'b')}, false},
		{"200 and 100", [][]byte{classOf(200, 'a'), classOf(100, 'b')}, false},
		{"127 ones", func() [][]byte {
			out := make([][]byte, 127)
			for i := range out {
				out[i] = []byte{'x'}
			}
			return out
		}(), true},
		{"128 ones make 256", func() [][]byte {
			out := make([][]byte, 128)
			for i := range out {
				out[i] = []byte{'x'}
			}
			return out
		}(), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := EncodeUserClass(c.classes...)
			if !c.ok {
				if !errors.Is(err, ErrBadOptionValue) {
					t.Fatalf("got %v, want ErrBadOptionValue", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			got, ok, err := roundTrip(t, Options{OptUserClass: v}).UserClass()
			if err != nil || !ok || len(got) != len(c.classes) {
				t.Fatalf("round trip: %v %v %d classes, want %d", ok, err, len(got), len(c.classes))
			}
			for i := range got {
				if !bytes.Equal(got[i], c.classes[i]) {
					t.Fatalf("class %d changed", i)
				}
			}
		})
	}
}

func TestUserClassEncodeRefusesAnEmptyClassAndAnEmptyList(t *testing.T) {
	if _, err := EncodeUserClass(); !errors.Is(err, ErrBadOptionValue) {
		t.Fatalf("no class: got %v", err)
	}
	if _, err := EncodeUserClass([]byte("a"), nil); !errors.Is(err, ErrBadOptionValue) {
		t.Fatalf("empty second class: got %v", err)
	}
	if _, err := EncodeUserClass([]byte{}); !errors.Is(err, ErrBadOptionValue) {
		t.Fatalf("empty class: got %v", err)
	}
}

func TestUserClassDecodeRefusesWhatRFC3004Forbids(t *testing.T) {
	cases := []struct {
		name string
		v    []byte
	}{
		{"empty value", []byte{}},
		{"zero-length instance alone", []byte{0}},
		{"zero-length instance after a good one", []byte{1, 'a', 0}},
		{"zero-length instance before a good one", []byte{0, 1, 'a'}},
		{"instance runs past the value", []byte{5, 'a', 'b'}},
		{"second instance runs past the value", []byte{1, 'a', 3, 'b'}},
		{"length octet with no data", []byte{1, 'a', 1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok, err := Options{OptUserClass: c.v}.UserClass()
			if !ok || !errors.Is(err, ErrBadOptionValue) || got != nil {
				t.Fatalf("got %q %v %v, want nil, present, ErrBadOptionValue", got, ok, err)
			}
		})
	}
}

func TestUserClassKeepsANulAndSeveralClassesInOrder(t *testing.T) {
	want := [][]byte{{'a', 0, 'b'}, {0}, []byte("docker")}
	v, err := EncodeUserClass(want...)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v, []byte{3, 'a', 0, 'b', 1, 0, 6, 'd', 'o', 'c', 'k', 'e', 'r'}) {
		t.Fatalf("encoded %x", v)
	}
	got, ok, err := roundTrip(t, Options{OptUserClass: v}).UserClass()
	if err != nil || !ok || len(got) != 3 {
		t.Fatalf("%v %v %d", ok, err, len(got))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("class %d: got %x want %x", i, got[i], want[i])
		}
	}
	if _, ok, err := (Options{}).UserClass(); ok || err != nil {
		t.Fatalf("absent option: %v %v", ok, err)
	}
}

func TestRapidCommitEmptyIsPresentAndSurvivesTheWire(t *testing.T) {
	back := roundTrip(t, Options{OptRapidCommit: EncodeRapidCommit()})
	v, present := back[OptRapidCommit]
	if !present || len(v) != 0 {
		t.Fatalf("option 80 lost or grew on the wire: present %v, %x", present, v)
	}
	if on, err := back.RapidCommit(); !on || err != nil {
		t.Fatalf("RapidCommit: %v %v", on, err)
	}
	if on, err := roundTrip(t, Options{}).RapidCommit(); on || err != nil {
		t.Fatalf("absent option read as %v %v", on, err)
	}
}

func TestRapidCommitWithAValueIsRefused(t *testing.T) {
	for _, v := range [][]byte{{0}, {1}, {0, 0}} {
		on, err := Options{OptRapidCommit: v}.RapidCommit()
		if on || !errors.Is(err, ErrBadOptionValue) {
			t.Fatalf("%x: got %v %v, want false, ErrBadOptionValue", v, on, err)
		}
	}
}

func TestIPv6OnlyPreferredCarriesAThirtyTwoBitUnsignedValue(t *testing.T) {
	for _, want := range []uint32{0, 1, 300, 1800, 1 << 31, 0xFFFFFFFF} {
		got, ok, err := roundTrip(t, Options{OptIPv6OnlyPreferred: EncodeIPv6OnlyPreferred(want)}).IPv6OnlyPreferred()
		if err != nil || !ok || got != want {
			t.Fatalf("%d: got %d %v %v", want, got, ok, err)
		}
	}
	if !bytes.Equal(EncodeIPv6OnlyPreferred(300), []byte{0, 0, 0x01, 0x2C}) {
		t.Fatalf("300 seconds encoded as %x, want 0000012c", EncodeIPv6OnlyPreferred(300))
	}
}

func TestIPv6OnlyPreferredOfAnotherLengthIsRefusedNotAbsent(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 5, 8} {
		got, ok, err := Options{OptIPv6OnlyPreferred: make([]byte, n)}.IPv6OnlyPreferred()
		if got != 0 || !ok || !errors.Is(err, ErrBadOptionValue) {
			t.Fatalf("%d octets: got %d %v %v, want 0, present, ErrBadOptionValue", n, got, ok, err)
		}
		// The generic reader answers a wrong length as it answers absence,
		// which is the lie this accessor exists to avoid (claymore666/docker-net-dhcp#1027).
		if _, ok := (Options{OptIPv6OnlyPreferred: make([]byte, n)}).Uint32(OptIPv6OnlyPreferred); ok && n != 4 {
			t.Fatalf("generic Uint32 accepted %d octets", n)
		}
	}
	if got, ok, err := (Options{}).IPv6OnlyPreferred(); got != 0 || ok || err != nil {
		t.Fatalf("absent option: %d %v %v", got, ok, err)
	}
}

func TestForcerenewNonceCapableIsSentAsOneAlgorithmAndReadAsAList(t *testing.T) {
	if !bytes.Equal(EncodeForcerenewNonceCapable(), []byte{1}) {
		t.Fatalf("sent %x, want one octet, 01", EncodeForcerenewNonceCapable())
	}
	algs, ok, err := roundTrip(t, Options{OptForcerenewNonce: EncodeForcerenewNonceCapable()}).ForcerenewNonceAlgorithms()
	if err != nil || !ok || !bytes.Equal(algs, []byte{1}) {
		t.Fatalf("own option: %v %v %v", algs, ok, err)
	}
	// RFC 6704 section 3.1.1 Figure 1: "a sequence of algorithms". Two octets
	// are two algorithms, and neither is dropped (claymore666/docker-net-dhcp#1119).
	algs, ok, err = Options{OptForcerenewNonce: {1, 2}}.ForcerenewNonceAlgorithms()
	if err != nil || !ok || !bytes.Equal(algs, []byte{1, 2}) {
		t.Fatalf("two algorithms: %v %v %v", algs, ok, err)
	}
	if algs, ok, err := (Options{OptForcerenewNonce: {}}).ForcerenewNonceAlgorithms(); algs != nil || !ok || !errors.Is(err, ErrBadOptionValue) {
		t.Fatalf("empty list: %v %v %v", algs, ok, err)
	}
	if _, ok, err := (Options{}).ForcerenewNonceAlgorithms(); ok || err != nil {
		t.Fatalf("absent option: %v %v", ok, err)
	}
}

func TestTheNewOptionsEncodeToTheBytesTheirRFCsDraw(t *testing.T) {
	uc, err := EncodeUserClass([]byte("ab"))
	if err != nil {
		t.Fatal(err)
	}
	m := &Message{Op: BootRequest, HType: HTypeEthernet, CHAddr: []byte{1, 2, 3, 4, 5, 6}, Options: Options{
		OptUserClass:         uc,
		OptRapidCommit:       EncodeRapidCommit(),
		OptIPv6OnlyPreferred: EncodeIPv6OnlyPreferred(300),
		OptForcerenewNonce:   EncodeForcerenewNonceCapable(),
	}}
	m.SetType(MsgDiscover)
	b, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	// Ascending by code: 53, 77, 80, 108, 145, then END. Written by hand from
	// RFC 3004 section 4, RFC 4039 section 4, RFC 8925 section 3.1 and RFC 6704
	// section 3.1.1, not from the encoder (claymore666/docker-net-dhcp#1120).
	want := []byte{
		53, 1, 1,
		77, 3, 2, 'a', 'b',
		80, 0,
		108, 4, 0, 0, 0x01, 0x2C,
		145, 1, 1,
		255,
	}
	if got := b[HeaderLen : HeaderLen+len(want)]; !bytes.Equal(got, want) {
		t.Fatalf("options bytes\n got %x\nwant %x", got, want)
	}
}

func TestMessageTypeNineIsDHCPFORCERENEWAndNotAnUnknownType(t *testing.T) {
	if MsgForceRenew != 9 || MsgForceRenew.String() != "DHCPFORCERENEW" {
		t.Fatalf("type 9 is %d %q", uint8(MsgForceRenew), MsgForceRenew)
	}
	m := &Message{Op: BootReply, HType: HTypeEthernet, CHAddr: []byte{1, 2, 3, 4, 5, 6}}
	m.SetType(MsgForceRenew)
	b, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	if b[HeaderLen] != 53 || b[HeaderLen+2] != 9 {
		t.Fatalf("option 53 carries %x, want 9", b[HeaderLen:HeaderLen+3])
	}
	back, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if typ, ok := back.Type(); !ok || typ != MsgForceRenew {
		t.Fatalf("decoded type %v %v", typ, ok)
	}
	if s := back.Summary(); !strings.HasPrefix(s, "DHCPFORCERENEW ") {
		t.Fatalf("summary %q does not name the type", s)
	}
	// The neighbours are still unknown (claymore666/docker-net-dhcp#1119).
	if got := MessageType(10).String(); got != "msgtype(10)" {
		t.Fatalf("type 10 is %q", got)
	}
}

func TestEveryNewOptionCodeHasAName(t *testing.T) {
	want := map[OptionCode]string{
		OptUserClass:         "user-class",
		OptRapidCommit:       "rapid-commit",
		OptAuthentication:    "authentication",
		OptIPv6OnlyPreferred: "ipv6-only-preferred",
		OptForcerenewNonce:   "forcerenew-nonce-capable",
	}
	num := map[OptionCode]uint8{OptUserClass: 77, OptRapidCommit: 80, OptAuthentication: 90, OptIPv6OnlyPreferred: 108, OptForcerenewNonce: 145}
	for c, name := range want {
		if uint8(c) != num[c] || c.String() != name {
			t.Fatalf("option %d is %q, want %d %q", uint8(c), c, num[c], name)
		}
	}
}

func TestTheTypedReadersReturnCopies(t *testing.T) {
	uc, _ := EncodeUserClass([]byte("ab"), []byte("cd"))
	o := Options{OptUserClass: uc, OptForcerenewNonce: {1, 2}}
	classes, _, _ := o.UserClass()
	classes[0][0] = 'Z'
	algs, _, _ := o.ForcerenewNonceAlgorithms()
	algs[0] = 9
	again, _, _ := o.UserClass()
	if string(again[0]) != "ab" || o[OptForcerenewNonce][0] != 1 {
		t.Fatalf("a caller's write reached the option: %q %v", again[0], o[OptForcerenewNonce])
	}
}

func TestUserClassEveryPrefixOfAGoodValueIsRefusedOrWhole(t *testing.T) {
	good, _ := EncodeUserClass([]byte("abc"), []byte("de"), []byte("f"))
	for n := 0; n <= len(good); n++ {
		classes, ok, err := Options{OptUserClass: good[:n]}.UserClass()
		if !ok {
			t.Fatalf("prefix %d read as absent", n)
		}
		if err != nil {
			if classes != nil {
				t.Fatalf("prefix %d returned classes beside an error", n)
			}
			continue
		}
		back, encErr := EncodeUserClass(classes...)
		if encErr != nil || !bytes.Equal(back, good[:n]) {
			t.Fatalf("prefix %d decoded to %q and re-encoded to %x", n, classes, back)
		}
	}
}

// FuzzDecodeV4NewOptions feeds arbitrary octets to every reader this file's
// options add. The property is that a value either fails or re-encodes to
// itself, and that nothing panics on any input (claymore666/docker-net-dhcp#1119).
func FuzzDecodeV4NewOptions(f *testing.F) {
	good, _ := EncodeUserClass([]byte("abc"), []byte("d"))
	auth, _ := EncodeForcerenewAuth(ForcerenewTypeDigest, make([]byte, ForcerenewNonceLen), 7)
	for _, s := range [][]byte{
		{}, {0}, {1}, {255}, {5, 'a'}, {1, 'a', 0}, good, good[:3],
		EncodeIPv6OnlyPreferred(300), EncodeIPv6OnlyPreferred(300)[:3], {0, 0, 0, 0, 0},
		{1}, {1, 2}, auth, auth[:10], auth[:11], auth[:27], append(append([]byte(nil), auth...), 0),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v []byte) {
		// Decode joins a repeated option into a value past 255 octets, which
		// the reader accepts and EncodeUserClass cannot write back (claymore666/docker-net-dhcp#1120).
		if len(v) > 255 {
			v = v[:255]
		}
		o := Options{OptUserClass: v, OptRapidCommit: v, OptIPv6OnlyPreferred: v, OptForcerenewNonce: v, OptAuthentication: v}
		if classes, ok, err := o.UserClass(); ok && err == nil {
			if enc, encErr := EncodeUserClass(classes...); encErr != nil || !bytes.Equal(enc, v) {
				t.Fatalf("user class %x decoded to %q and re-encoded as %x, %v", v, classes, enc, encErr)
			}
		}
		if on, err := o.RapidCommit(); on && (err != nil || len(v) != 0) {
			t.Fatalf("rapid commit read as present for %x with %v", v, err)
		}
		if secs, ok, err := o.IPv6OnlyPreferred(); ok && err == nil && !bytes.Equal(EncodeIPv6OnlyPreferred(secs), v) {
			t.Fatalf("option 108 %x decoded to %d", v, secs)
		}
		if algs, ok, err := o.ForcerenewNonceAlgorithms(); ok && err == nil && !bytes.Equal(algs, v) {
			t.Fatalf("option 145 %x decoded to %v", v, algs)
		}
		if a, ok, err := o.ForcerenewAuth(); ok && err == nil {
			if enc, encErr := EncodeForcerenewAuth(a.Type, a.Value[:], a.Replay); encErr != nil || !bytes.Equal(enc, v) {
				t.Fatalf("option 90 %x decoded to %+v and re-encoded as %x, %v", v, a, enc, encErr)
			}
		}
	})
}
