// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package wire

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// The option area of a Router Advertisement, built one option at a time.
//
// EVERY FIXTURE HERE IS WRITTEN FROM THE RFC's FIELD DIAGRAM AND NOT FROM THE
// DECODER. The defect this file exists for is an option read into the wrong
// field — the route preference taken off the prefix-length octet, the RDNSS
// lifetime read where its Reserved field is, the prefix read from offset 8
// when its own length says it starts there only sometimes — and every one of
// those produces a plausible value. A builder derived from the decoder agrees
// with it in exactly the cases where both are wrong.
func raWith(opts ...[]byte) []byte {
	b := make([]byte, raFixedLen)
	b[0] = ICMPv6RouterAdvert
	b[5] = raFlagManaged
	be16(b[6:8], 1800)
	for _, o := range opts {
		b = append(b, o...)
	}
	return b
}

// mtuOption is RFC 4861 section 4.6.4: Type 5, Length 1, two reserved octets,
// then the MTU.
func mtuOption(mtu uint32) []byte {
	o := make([]byte, mtuOptLen)
	o[0] = NDOptMTU
	o[1] = mtuOptLen / 8
	be32(o[4:8], mtu)
	return o
}

// rioOption is RFC 4191 section 2.3: Type 24, Length in units of 8, the prefix
// length, the "|Resvd|Prf|Resvd|" octet, the route lifetime, then as much of
// the prefix as Length leaves room for.
func rioOption(units int, prefixLen uint8, prf uint8, lifetime uint32, prefix netip.Addr) []byte {
	o := make([]byte, units*8)
	o[0] = NDOptRouteInfo
	o[1] = uint8(units)
	o[2] = prefixLen
	o[3] = prf << 3
	be32(o[4:8], lifetime)
	if prefix.IsValid() && units > 1 {
		p := prefix.As16()
		copy(o[8:], p[:])
	}
	return o
}

// rdnssOption is RFC 8106 section 5.1: Type 25, Length 1 + 2 per address, two
// reserved octets, the lifetime, then the addresses.
func rdnssOption(lifetime uint32, addrs ...netip.Addr) []byte {
	o := make([]byte, 8+16*len(addrs))
	o[0] = NDOptRDNSS
	o[1] = uint8(len(o) / 8)
	be32(o[4:8], lifetime)
	for i, a := range addrs {
		b := a.As16()
		copy(o[8+16*i:], b[:])
	}
	return o
}

// dnsslOption is RFC 8106 section 5.2: Type 31, the lifetime, then the names in
// RFC 1035 section 3.1 form, zero-padded to a multiple of 8 octets.
func dnsslOption(lifetime uint32, names ...string) []byte {
	o := make([]byte, 8)
	o[0] = NDOptDNSSL
	be32(o[4:8], lifetime)
	for _, n := range names {
		for _, label := range strings.Split(n, ".") {
			o = append(o, uint8(len(label)))
			o = append(o, label...)
		}
		o = append(o, 0)
	}
	for len(o)%8 != 0 {
		o = append(o, 0)
	}
	o[1] = uint8(len(o) / 8)
	return o
}

// TestTheMTUOptionIsReadFromItsOwnOffset drives RFC 4861 section 4.6.4's
// "MTU 32-bit unsigned integer. The recommended MTU for the link." The two
// reserved octets sit between the length and the value, so an MTU read from
// offset 2 rather than 4 gives a number that still looks like an MTU.
func TestTheMTUOptionIsReadFromItsOwnOffset(t *testing.T) {
	for _, want := range []uint32{0, 1280, 1500, 9000, 0xFFFFFFFF} {
		ra, err := DecodeRouterAdvert(raWith(mtuOption(want)))
		if err != nil {
			t.Fatalf("DecodeRouterAdvert with MTU %d: %v", want, err)
		}
		if ra.MTU != want {
			t.Errorf("MTU decoded as %d, the option carried %d", ra.MTU, want)
		}
		if ra.IgnoredOptions != 0 {
			t.Errorf("a well-formed MTU option was counted as ignored (%d)", ra.IgnoredOptions)
		}
	}

	// The last one wins, RFC 4861 section 6.3.4.
	ra, err := DecodeRouterAdvert(raWith(mtuOption(1500), mtuOption(1280)))
	if err != nil {
		t.Fatalf("DecodeRouterAdvert: %v", err)
	}
	if ra.MTU != 1280 {
		t.Errorf("two MTU options 1500 then 1280 decoded to %d; section 6.3.4 makes the most recently received one authoritative", ra.MTU)
	}
}

// TestAnMTUOptionOfTheWrongLengthIsIgnoredAndItsSiblingsAreNot is the
// option-level refusal: RFC 4861 section 4.6.4 gives the MTU option Length 1,
// and an option declaring 2 is not one. The advertisement is still read.
func TestAnMTUOptionOfTheWrongLengthIsIgnoredAndItsSiblingsAreNot(t *testing.T) {
	bad := make([]byte, 16)
	bad[0] = NDOptMTU
	bad[1] = 2
	be32(bad[4:8], 1400)

	ra, err := DecodeRouterAdvert(raWith(bad, rdnssOption(600, netip.MustParseAddr("fd00::1"))))
	if err != nil {
		t.Fatalf("DecodeRouterAdvert: %v", err)
	}
	if ra.MTU != 0 {
		t.Errorf("MTU is %d; an option of the wrong length is not a value to take", ra.MTU)
	}
	if ra.IgnoredOptions != 1 {
		t.Errorf("IgnoredOptions = %d, want exactly 1", ra.IgnoredOptions)
	}
	if len(ra.RDNSS) != 1 {
		t.Fatalf("%d RDNSS option(s) survived the refused sibling, want 1", len(ra.RDNSS))
	}
	if !ra.Managed {
		t.Error("the M flag of an advertisement carrying one refused option was lost")
	}
}

// TestTheRouteInformationOptionChecksItsLengthAgainstItsPrefixLength drives
// RFC 4191 section 2.3's own table, which is the only thing that says how many
// octets of prefix are present: "The Length field is 1, 2, or 3 depending on
// the Prefix Length. If Prefix Length is greater than 64, then Length must be
// 3. If Prefix Length is greater than 0, then Length must be 2 or 3. If Prefix
// Length is zero, then Length must be 1, 2, or 3." and "The value ranges from
// 0 to 128."
func TestTheRouteInformationOptionChecksItsLengthAgainstItsPrefixLength(t *testing.T) {
	pfx := netip.MustParseAddr("2001:db8:1:2::")
	for _, tc := range []struct {
		name      string
		units     int
		prefixLen uint8
		ok        bool
	}{
		{"zero prefix in one unit", 1, 0, true},
		{"zero prefix in two units", 2, 0, true},
		{"zero prefix in three units", 3, 0, true},
		{"64 bits in one unit", 1, 64, false},
		{"64 bits in two units", 2, 64, true},
		{"65 bits in two units", 2, 65, false},
		{"65 bits in three units", 3, 65, true},
		{"128 bits in two units", 2, 128, false},
		{"128 bits in three units", 3, 128, true},
		{"129 bits", 3, 129, false},
		{"255 bits", 3, 255, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ra, err := DecodeRouterAdvert(raWith(rioOption(tc.units, tc.prefixLen, 0, 600, pfx)))
			if err != nil {
				t.Fatalf("DecodeRouterAdvert: %v", err)
			}
			if tc.ok {
				if len(ra.Routes) != 1 {
					t.Fatalf("%d route(s), want 1; section 2.3 admits Length %d with Prefix Length %d", len(ra.Routes), tc.units, tc.prefixLen)
				}
				if got := ra.Routes[0].Prefix.Bits(); got != int(tc.prefixLen) {
					t.Errorf("prefix length decoded as %d, the option carried %d", got, tc.prefixLen)
				}
				if ra.IgnoredOptions != 0 {
					t.Errorf("an admitted option was counted as ignored")
				}
				return
			}
			if len(ra.Routes) != 0 {
				t.Errorf("%d route(s) from an option section 2.3 refuses", len(ra.Routes))
			}
			if ra.IgnoredOptions != 1 {
				t.Errorf("IgnoredOptions = %d, want exactly 1", ra.IgnoredOptions)
			}
		})
	}
}

// TestTheRoutePreferenceIsTwoBitsSignedAndReservedIsARefusal drives the field
// RFC 4191 section 2.3 calls a "2-bit signed integer" and the sentence beside
// it: "If the Reserved (10) value is received, the Route Information Option
// MUST be ignored."
func TestTheRoutePreferenceIsTwoBitsSignedAndReservedIsARefusal(t *testing.T) {
	pfx := netip.MustParseAddr("2001:db8::")
	for _, tc := range []struct {
		name string
		bits uint8
		want RoutePreference
		ok   bool
	}{
		{"medium", 0x0, RoutePrefMedium, true},
		{"high", 0x1, RoutePrefHigh, true},
		{"reserved", 0x2, RoutePrefMedium, false},
		{"low", 0x3, RoutePrefLow, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opt := rioOption(2, 64, tc.bits, 600, pfx)
			// The two Resvd fields around Prf are set to ones, so a decoder
			// masking the wrong bits reads a different preference.
			opt[3] |= 0xE7
			ra, err := DecodeRouterAdvert(raWith(opt))
			if err != nil {
				t.Fatalf("DecodeRouterAdvert: %v", err)
			}
			if !tc.ok {
				if len(ra.Routes) != 0 || ra.IgnoredOptions != 1 {
					t.Fatalf("the reserved preference gave %d route(s) and %d ignored option(s), want 0 and 1",
						len(ra.Routes), ra.IgnoredOptions)
				}
				return
			}
			if len(ra.Routes) != 1 {
				t.Fatalf("%d route(s), want 1", len(ra.Routes))
			}
			if ra.Routes[0].Pref != tc.want {
				t.Errorf("preference bits %#02b decoded as %s (%d), want %s", tc.bits, ra.Routes[0].Pref, ra.Routes[0].Pref, tc.want)
			}
		})
	}

	// The ordering the signed field exists for, checked as an ordering rather
	// than as three constants.
	if !(RoutePrefHigh > RoutePrefMedium && RoutePrefMedium > RoutePrefLow) {
		t.Errorf("the preferences do not order high > medium > low: %d %d %d", RoutePrefHigh, RoutePrefMedium, RoutePrefLow)
	}
}

// TestTheRouteInformationPrefixIsMaskedAndItsLifetimeIsItsOwn drives section
// 2.3's "The bits in the prefix after the prefix length (if any) are reserved
// and MUST be initialized to zero by the sender and ignored by the receiver."
// and "A value of all one bits (0xffffffff) represents infinity."
func TestTheRouteInformationPrefixIsMaskedAndItsLifetimeIsItsOwn(t *testing.T) {
	// A sender that did not zero the trailing bits.
	dirty := netip.MustParseAddr("2001:db8:0:0:dead:beef:dead:beef")
	ra, err := DecodeRouterAdvert(raWith(rioOption(3, 48, 1, 0xFFFFFFFF, dirty)))
	if err != nil {
		t.Fatalf("DecodeRouterAdvert: %v", err)
	}
	if len(ra.Routes) != 1 {
		t.Fatalf("%d route(s), want 1", len(ra.Routes))
	}
	got := ra.Routes[0]
	if want := netip.MustParsePrefix("2001:db8::/48"); got.Prefix != want {
		t.Errorf("prefix decoded as %s, want %s with the bits past the length ignored", got.Prefix, want)
	}
	if got.Lifetime != 0xFFFFFFFF {
		t.Errorf("route lifetime decoded as %d, the option carried infinity", got.Lifetime)
	}
	if s := got.String(); !strings.Contains(s, "high") {
		t.Errorf("RouteInfo.String() = %q, want the preference in it", s)
	}
}

// TestTheRecursiveDNSServerOptionCarriesItsAddressesAndOneLifetime drives RFC
// 8106 section 5.1: "All of the addresses share the same Lifetime value. If it
// is desirable to have different Lifetime values, multiple RDNSS options can be
// used." — which is why the decoded shape is one struct per option and not a
// flat list of addresses.
func TestTheRecursiveDNSServerOptionCarriesItsAddressesAndOneLifetime(t *testing.T) {
	a1, a2 := netip.MustParseAddr("fd00::53"), netip.MustParseAddr("fe80::1")
	ra, err := DecodeRouterAdvert(raWith(
		rdnssOption(600, a1, a2),
		rdnssOption(0, netip.MustParseAddr("fd00::54")),
	))
	if err != nil {
		t.Fatalf("DecodeRouterAdvert: %v", err)
	}
	if len(ra.RDNSS) != 2 {
		t.Fatalf("%d RDNSS option(s), want 2 so each keeps its own lifetime", len(ra.RDNSS))
	}
	if ra.RDNSS[0].Lifetime != 600 || len(ra.RDNSS[0].Addrs) != 2 {
		t.Fatalf("first option: lifetime %d over %d address(es), want 600 over 2", ra.RDNSS[0].Lifetime, len(ra.RDNSS[0].Addrs))
	}
	if ra.RDNSS[0].Addrs[0] != a1 || ra.RDNSS[0].Addrs[1] != a2 {
		t.Errorf("addresses decoded as %v, want %v — and a link-local resolver is legal, section 5.1's note", ra.RDNSS[0].Addrs, []netip.Addr{a1, a2})
	}
	// The withdrawal, which is a lifetime of zero and NOT an absent option.
	if ra.RDNSS[1].Lifetime != 0 || len(ra.RDNSS[1].Addrs) != 1 {
		t.Errorf("the zero-lifetime option decoded as lifetime %d over %d address(es); section 5.1's \"A value of zero means that the RDNSS addresses MUST no longer be used\" needs both",
			ra.RDNSS[1].Lifetime, len(ra.RDNSS[1].Addrs))
	}
	if ra.IgnoredOptions != 0 {
		t.Errorf("IgnoredOptions = %d over two well-formed options", ra.IgnoredOptions)
	}
}

// TestTheRecursiveDNSServerOptionIsCheckedAsSection531SaysToCheckIt drives
// "the value of the Length field in the RDNSS option is greater than or equal
// to the minimum value (3) and satisfies the requirement that
// (Length - 1) % 2 == 0. ... the addresses should be unicast addresses."
func TestTheRecursiveDNSServerOptionIsCheckedAsSection531SaysToCheckIt(t *testing.T) {
	sized := func(units int) []byte {
		o := make([]byte, units*8)
		o[0] = NDOptRDNSS
		o[1] = uint8(units)
		be32(o[4:8], 600)
		// Every whole 16-octet slot the length leaves room for gets a unicast
		// address, so a row that is refused is refused for its LENGTH and not
		// for an address the fixture forgot to fill in.
		for i := 8; i+16 <= len(o); i += 16 {
			o[i] = 0xFD
			o[i+15] = uint8(i)
		}
		return o
	}
	for _, tc := range []struct {
		name string
		opt  []byte
		ok   bool
	}{
		{"one unit", sized(1), false},
		{"two units", sized(2), false},
		{"three units", sized(3), true},
		{"four units", sized(4), false},
		{"five units", sized(5), true},
		{"a multicast resolver", rdnssOption(600, netip.MustParseAddr("ff02::1")), false},
		{"the unspecified address", rdnssOption(600, netip.IPv6Unspecified()), false},
		{"a link-local resolver", rdnssOption(600, netip.MustParseAddr("fe80::1")), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ra, err := DecodeRouterAdvert(raWith(tc.opt))
			if err != nil {
				t.Fatalf("DecodeRouterAdvert: %v", err)
			}
			if got := len(ra.RDNSS); (got == 1) != tc.ok {
				t.Fatalf("%d RDNSS option(s) survived, want %v", got, tc.ok)
			}
			if want := 0; tc.ok && ra.IgnoredOptions != want {
				t.Errorf("IgnoredOptions = %d, want %d", ra.IgnoredOptions, want)
			}
			if !tc.ok && ra.IgnoredOptions != 1 {
				t.Errorf("IgnoredOptions = %d, want exactly 1", ra.IgnoredOptions)
			}
		})
	}
}

// TestTheSearchListOptionDecodesItsLabelsAndDropsItsPadding drives RFC 8106
// section 5.2's encoding, including the sentence that makes the padding
// indistinguishable from a name: "Because the size of this field MUST be a
// multiple of 8 octets, for the minimum multiple including the domain name
// representations, the remaining octets other than the encoding parts of the
// domain name representations MUST be padded with zeros."
//
// A decoder that appends every name it reads returns the names plus one empty
// string per padding octet, and every one of those is a search domain a
// resolver would try.
func TestTheSearchListOptionDecodesItsLabelsAndDropsItsPadding(t *testing.T) {
	for _, tc := range []struct {
		name  string
		names []string
	}{
		{"one short name", []string{"lan"}},
		{"one long name", []string{"corp.example.test"}},
		{"two names", []string{"lan", "example.test"}},
		{"three names", []string{"a", "bb", "ccc.dddd"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opt := dnsslOption(1800, tc.names...)
			if len(opt)%8 != 0 {
				t.Fatalf("the fixture itself is %d octets, not a multiple of 8", len(opt))
			}
			ra, err := DecodeRouterAdvert(raWith(opt))
			if err != nil {
				t.Fatalf("DecodeRouterAdvert: %v", err)
			}
			if len(ra.DNSSL) != 1 {
				t.Fatalf("%d DNSSL option(s), want 1", len(ra.DNSSL))
			}
			got := ra.DNSSL[0]
			if got.Lifetime != 1800 {
				t.Errorf("lifetime %d, want 1800", got.Lifetime)
			}
			if len(got.Names) != len(tc.names) {
				t.Fatalf("decoded %d name(s) %q, want exactly %d %q — the padding is not a name",
					len(got.Names), got.Names, len(tc.names), tc.names)
			}
			for i := range tc.names {
				if got.Names[i] != tc.names[i] {
					t.Errorf("name %d decoded as %q, want %q", i, got.Names[i], tc.names[i])
				}
			}
		})
	}
}

// TestTheSearchListOptionRefusesTheEncodingsSection52Forbids drives "the
// domain names MUST NOT be encoded in the compressed form described in Section
// 4.1.4 of [RFC1035]" and the label form RFC 1035 section 3.1 allows.
//
// IT RUNS UNDER ITS OWN DEADLINE. A compression pointer is a jump, and a
// decoder that followed one inside its own option would loop; a hanging test
// and a failing one bank identically, so this one fails by deadline rather
// than by hanging the suite.
func TestTheSearchListOptionRefusesTheEncodingsSection52Forbids(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, tc := range []struct {
			name string
			body []byte
		}{
			{"a compression pointer", []byte{0xC0, 0x08, 0, 0, 0, 0, 0, 0}},
			{"a label length of 64", append([]byte{64}, make([]byte, 7)...)},
			{"a reserved length form", []byte{0x80, 'a', 0, 0, 0, 0, 0, 0}},
			{"a label running past the option", []byte{60, 'a', 'b', 0, 0, 0, 0, 0}},
			// AN OPTION THAT IS NOTHING BUT PADDING. Section 5.2's Domain
			// Names field is "one or more domain names", and the padding it
			// then describes is what FOLLOWS them: "if necessary, null
			// bytes... to fill the remaining octets". An option with no name
			// in it at all is not a shorter list, it is a malformed option,
			// and the difference matters because the alternative is an entry
			// carrying a lifetime and nothing to apply it to.
			{"nothing but padding", make([]byte, 8)},
		} {
			opt := append([]byte{NDOptDNSSL, 2, 0, 0, 0, 0, 0x07, 0x08}, tc.body...)
			ra, err := DecodeRouterAdvert(raWith(opt))
			if err != nil {
				t.Errorf("%s: DecodeRouterAdvert: %v; the option is refused, not the message", tc.name, err)
				continue
			}
			if len(ra.DNSSL) != 0 {
				t.Errorf("%s: %d search list option(s) survived", tc.name, len(ra.DNSSL))
			}
			if ra.IgnoredOptions != 1 {
				t.Errorf("%s: IgnoredOptions = %d, want exactly 1", tc.name, ra.IgnoredOptions)
			}
		}
	}()
	select {
	case <-done:
	case <-t.Context().Done():
		t.Fatal("the search list decode did not finish inside the test's own deadline; a forbidden encoding was followed rather than refused")
	}
}

// TestAnOptionLengthOfZeroOrAnOverrunDiscardsTheWholePacket is the OTHER
// refusal level, and the pair with the tests above is the whole rule. RFC 4861
// section 4.6: "The value 0 is invalid. Nodes MUST silently discard an ND
// packet that contains an option with length zero." It is the packet's verdict
// and not the option's, so the flags and every option already decoded go with
// it.
func TestAnOptionLengthOfZeroOrAnOverrunDiscardsTheWholePacket(t *testing.T) {
	for _, typ := range []uint8{NDOptMTU, NDOptRouteInfo, NDOptRDNSS, NDOptDNSSL} {
		zero := make([]byte, 8)
		zero[0] = typ
		zero[1] = 0
		// Behind a well-formed RDNSS, so the assertion is that what was
		// already decoded does not survive either.
		if _, err := DecodeRouterAdvert(raWith(rdnssOption(600, netip.MustParseAddr("fd00::53")), zero)); !errors.Is(err, ErrNDOption) {
			t.Errorf("option type %d with length zero: error %v, want ErrNDOption and no advertisement", typ, err)
		}

		over := make([]byte, 8)
		over[0] = typ
		over[1] = 3
		if _, err := DecodeRouterAdvert(raWith(over)); !errors.Is(err, ErrNDOption) {
			t.Errorf("option type %d declaring 24 octets with 8 present: error %v, want ErrNDOption", typ, err)
		}
	}
}

// TestAnUnrecognisedOptionIsNotCountedAsIgnored separates the two silences.
// RFC 4861 section 4.6: "Future versions of this protocol may define new option
// types. Receivers MUST silently ignore any options they do not recognize and
// continue processing the message." An advertisement carrying one is not
// defective, and a counter that says it is would rise on every link with a
// router newer than this decoder.
func TestAnUnrecognisedOptionIsNotCountedAsIgnored(t *testing.T) {
	unknown := make([]byte, 16)
	unknown[0] = 200
	unknown[1] = 2
	ra, err := DecodeRouterAdvert(raWith(unknown, mtuOption(1500)))
	if err != nil {
		t.Fatalf("DecodeRouterAdvert: %v", err)
	}
	if ra.IgnoredOptions != 0 {
		t.Errorf("IgnoredOptions = %d for an option of a type this decoder does not read", ra.IgnoredOptions)
	}
	if ra.MTU != 1500 {
		t.Errorf("the option after the unknown one decoded as MTU %d; the walk did not continue past it", ra.MTU)
	}
}

// TestTheDecoderDoesNotSetTheRouterAddress pins the boundary the Router field's
// own comment states: the source address is in the IPv6 header and this package
// decodes the ICMPv6 message. A decoder that filled it in from anything would
// be filling it in from a value it invented.
func TestTheDecoderDoesNotSetTheRouterAddress(t *testing.T) {
	ra, err := DecodeRouterAdvert(raWith(mtuOption(1500)))
	if err != nil {
		t.Fatalf("DecodeRouterAdvert: %v", err)
	}
	if ra.Router.IsValid() {
		t.Errorf("Router = %s; the ICMPv6 body does not carry the source address", ra.Router)
	}
	if s := ra.String(); strings.Contains(s, "from") {
		t.Errorf("RouterAdvert.String() = %q, and it names a router the decode did not read", s)
	}
}

// TestTheDnsmasqShapedAdvertisementDecodesEveryOption is the fixture the
// design's phase-1 measurement described: dnsmasq 2.91 in ra-only mode with
// --ra-param mtu and option6 dns-server/domain-search emits a Prefix
// Information option, an MTU option, an RDNSS and a DNSSL in one frame. One
// option at a time says each decoder works; this says they work in each other's
// company, which is where an off-by-one in the walk lives.
func TestTheDnsmasqShapedAdvertisementDecodesEveryOption(t *testing.T) {
	pio := make([]byte, pioLen)
	pio[0] = NDOptPrefixInfo
	pio[1] = pioLen / 8
	pio[2] = 64
	pio[3] = pioFlagOnLink | pioFlagAuto
	be32(pio[4:8], 1800)
	be32(pio[8:12], 600)
	p := netip.MustParseAddr("fd00:98::").As16()
	copy(pio[16:32], p[:])

	frame := raWith(
		pio,
		mtuOption(1280),
		rdnssOption(1200, netip.MustParseAddr("fd00:98::1")),
		dnsslOption(1200, "lan"),
		rioOption(2, 56, 1, 900, netip.MustParseAddr("2001:db8:aa00::")),
	)
	ra, err := DecodeRouterAdvert(frame)
	if err != nil {
		t.Fatalf("DecodeRouterAdvert: %v", err)
	}
	switch {
	case len(ra.Prefixes) != 1:
		t.Fatalf("%d prefix(es), want 1", len(ra.Prefixes))
	case ra.MTU != 1280:
		t.Fatalf("MTU %d, want 1280", ra.MTU)
	case len(ra.RDNSS) != 1 || len(ra.RDNSS[0].Addrs) != 1:
		t.Fatalf("RDNSS decoded as %v", ra.RDNSS)
	case len(ra.DNSSL) != 1 || len(ra.DNSSL[0].Names) != 1:
		t.Fatalf("DNSSL decoded as %v", ra.DNSSL)
	case len(ra.Routes) != 1:
		t.Fatalf("%d route(s), want 1", len(ra.Routes))
	}
	if ra.Prefixes[0].Prefix != netip.MustParseAddr("fd00:98::") || ra.Prefixes[0].PrefixLen != 64 {
		t.Errorf("the prefix option decoded as %s", ra.Prefixes[0])
	}
	if ra.RDNSS[0].Addrs[0] != netip.MustParseAddr("fd00:98::1") {
		t.Errorf("the resolver decoded as %s", ra.RDNSS[0].Addrs[0])
	}
	if ra.DNSSL[0].Names[0] != "lan" {
		t.Errorf("the search domain decoded as %q", ra.DNSSL[0].Names[0])
	}
	if ra.Routes[0].Prefix != netip.MustParsePrefix("2001:db8:aa00::/56") || ra.Routes[0].Pref != RoutePrefHigh {
		t.Errorf("the route decoded as %s", ra.Routes[0])
	}
	if s := ra.String(); !strings.Contains(s, "mtu=1280") || !strings.Contains(s, "lan") {
		t.Errorf("RouterAdvert.String() = %q, and it does not name what was decoded", s)
	}
}

// TestADecodedAdvertisementKeepsNothingOfItsInputBuffer drives the aliasing
// shape: ring 3 reads every frame into one reusable buffer, so a decoded value
// holding a sub-slice of its input is rewritten by the next frame rather than
// by a writer the race detector can see.
func TestADecodedAdvertisementKeepsNothingOfItsInputBuffer(t *testing.T) {
	buf := make([]byte, 512)
	first := raWith(
		mtuOption(9000),
		rdnssOption(600, netip.MustParseAddr("fd00::53")),
		dnsslOption(600, "first.example"),
		rioOption(2, 64, 1, 600, netip.MustParseAddr("2001:db8:1::")),
	)
	n := copy(buf, first)
	ra, err := DecodeRouterAdvert(buf[:n])
	if err != nil {
		t.Fatalf("DecodeRouterAdvert: %v", err)
	}

	second := raWith(
		mtuOption(1280),
		rdnssOption(600, netip.MustParseAddr("fd00::54")),
		dnsslOption(600, "second.example"),
		rioOption(2, 64, 1, 600, netip.MustParseAddr("2001:db8:2::")),
	)
	for i := range buf {
		buf[i] = 0xAA
	}
	copy(buf, second)

	switch {
	case ra.MTU != 9000:
		t.Errorf("MTU is %d after the buffer was reused, want 9000", ra.MTU)
	case ra.RDNSS[0].Addrs[0] != netip.MustParseAddr("fd00::53"):
		t.Errorf("the resolver is %s after the buffer was reused", ra.RDNSS[0].Addrs[0])
	case ra.DNSSL[0].Names[0] != "first.example":
		t.Errorf("the search domain is %q after the buffer was reused", ra.DNSSL[0].Names[0])
	case ra.Routes[0].Prefix != netip.MustParsePrefix("2001:db8:1::/64"):
		t.Errorf("the route is %s after the buffer was reused", ra.Routes[0].Prefix)
	}
}
