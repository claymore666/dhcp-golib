// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package wire

import (
	"net/netip"
	"strings"
	"testing"
)

// pref64Option is RFC 8781 §4's Figure 1 written octet by octet: Type 38,
// Length 2, the 16-bit "Scaled Lifetime (13) | PLC (3)" field as two octets,
// then the twelve octets of the prefix. It is built from the diagram and not
// from the decoder (claymore666/docker-net-dhcp#1028).
func pref64Option(hi, lo byte, prefix12 string) []byte {
	o := []byte{38, 2, hi, lo}
	return append(o, mustHex(prefix12)...)
}

// pref64Prefix has a distinct, non-zero octet in every position, so a
// prefix cut at the wrong length or read from the wrong offset differs.
const pref64Prefix = "20010db8" + "0122" + "0344" + "0566" + "0778"

// TestPREF64FieldIsScaledLifetimeThenPLCInThatBitOrder pins the exact bits. The
// field 0x0B29 is 0000101100101 001: thirteen bits of Scaled Lifetime, which
// are 0x165 = 357, then three bits of PLC, which are 001 = a /64. The lifetime
// is 357 x 8 = 2856 s. A decoder that takes the PLC from the high bits reads
// 000 (a /96) and 0x0B29 & 0x1FFF = 2857 instead.
func TestPREF64FieldIsScaledLifetimeThenPLCInThatBitOrder(t *testing.T) {
	ra, err := DecodeRouterAdvert(raWith(pref64Option(0x0B, 0x29, pref64Prefix)))
	if err != nil {
		t.Fatalf("DecodeRouterAdvert: %v", err)
	}
	if len(ra.PREF64) != 1 {
		t.Fatalf("%d PREF64 entries, want 1", len(ra.PREF64))
	}
	got := ra.PREF64[0]
	if want := netip.MustParsePrefix("2001:db8:122:344::/64"); got.Prefix != want {
		t.Errorf("prefix %s, want %s: PLC is the LOW three bits of the field", got.Prefix, want)
	}
	if got.Lifetime != 2856 {
		t.Errorf("lifetime %d, want 2856: Scaled Lifetime is the HIGH thirteen bits, times 8", got.Lifetime)
	}
	if ra.IgnoredOptions != 0 {
		t.Errorf("a valid option was counted as ignored (%d)", ra.IgnoredOptions)
	}
}

// TestPREF64PLCZeroToFiveGiveSixLengthsAndSixAndSevenAreRefused is RFC 8781
// §4: "The PLC field values 0, 1, 2, 3, 4, and 5 indicate the NAT64 prefix
// length of 96, 64, 56, 48, 40, and 32 bits, respectively. The receiver MUST
// ignore the PREF64 option if the Prefix Length Code field is not set to one of
// those values." Every option carries the same distinct prefix octets, so the
// expected prefix is the cut at each length, and PLC 5 is the /32.
func TestPREF64PLCZeroToFiveGiveSixLengthsAndSixAndSevenAreRefused(t *testing.T) {
	cases := []struct {
		plc  byte
		want string // empty means refused
	}{
		{0, "2001:db8:122:344:566:778::/96"},
		{1, "2001:db8:122:344::/64"},
		{2, "2001:db8:122:300::/56"},
		{3, "2001:db8:122::/48"},
		{4, "2001:db8:100::/40"},
		{5, "2001:db8::/32"},
		{6, ""},
		{7, ""},
	}
	for _, tc := range cases {
		// Scaled Lifetime 1 is 0x0008 in the field: bit 3 set.
		ra, err := DecodeRouterAdvert(raWith(pref64Option(0x00, 0x08|tc.plc, pref64Prefix), mtuOption(1500)))
		if err != nil {
			t.Fatalf("PLC %d: DecodeRouterAdvert: %v", tc.plc, err)
		}
		if ra.MTU != 1500 {
			t.Errorf("PLC %d: the MTU option after it was lost: the walk did not move on", tc.plc)
		}
		if tc.want == "" {
			if len(ra.PREF64) != 0 {
				t.Errorf("PLC %d: yielded %v, RFC 8781 §4 says ignore it", tc.plc, ra.PREF64)
			}
			if ra.IgnoredOptions != 1 {
				t.Errorf("PLC %d: IgnoredOptions %d, want 1", tc.plc, ra.IgnoredOptions)
			}
			continue
		}
		if len(ra.PREF64) != 1 {
			t.Fatalf("PLC %d: %d entries, want 1", tc.plc, len(ra.PREF64))
		}
		if got := ra.PREF64[0].Prefix.String(); got != tc.want {
			t.Errorf("PLC %d: prefix %s, want %s", tc.plc, got, tc.want)
		}
		if ra.PREF64[0].Lifetime != 8 {
			t.Errorf("PLC %d: lifetime %d, want 8 (Scaled Lifetime 1)", tc.plc, ra.PREF64[0].Lifetime)
		}
	}
}

// TestPREF64LifetimeIsTheScaledValueTimesEightAndItsMaximumFits pins §4.1:
// "The receiver MUST multiply the Scaled Lifetime value by 8 ... The maximum
// lifetime of the NAT64 prefix is thus 65528 seconds." 8191 is thirteen one
// bits, so the field is 0xFFF8 with PLC 0; the product is 65528, and a caller's
// 16-bit type would have held it by seven.
func TestPREF64LifetimeIsTheScaledValueTimesEightAndItsMaximumFits(t *testing.T) {
	for _, tc := range []struct {
		hi, lo byte
		want   uint32
	}{
		{0xFF, 0xF8, 65528}, // 8191 x 8, PLC 0
		{0x00, 0x08, 8},     // 1 x 8
		{0x00, 0x10, 16},    // 2 x 8
		{0x80, 0x00, 4096 * 8},
	} {
		ra, err := DecodeRouterAdvert(raWith(pref64Option(tc.hi, tc.lo, pref64Prefix)))
		if err != nil || len(ra.PREF64) != 1 {
			t.Fatalf("field %02x%02x: %v, %d entries", tc.hi, tc.lo, err, len(ra.PREF64))
		}
		if ra.PREF64[0].Lifetime != tc.want {
			t.Errorf("field %02x%02x: lifetime %d, want %d", tc.hi, tc.lo, ra.PREF64[0].Lifetime, tc.want)
		}
	}
}

// TestPREF64ZeroLifetimeIsAWithdrawalTheCallerSees is §4.1: "A lifetime of 0
// indicates that the prefix SHOULD NOT be used anymore." The entry is kept, so
// the caller can drop the prefix it holds, and Withdrawn says so; §5 allows two
// options in one RA "when gracefully renumbering", one withdrawing the old
// prefix and one carrying the new.
func TestPREF64ZeroLifetimeIsAWithdrawalTheCallerSees(t *testing.T) {
	ra, err := DecodeRouterAdvert(raWith(
		pref64Option(0x00, 0x00, "0064ff9b0000000000000000"),
		pref64Option(0x00, 0x08, pref64Prefix),
	))
	if err != nil {
		t.Fatalf("DecodeRouterAdvert: %v", err)
	}
	if len(ra.PREF64) != 2 {
		t.Fatalf("%d entries, want 2: a withdrawal must not be dropped by the decoder", len(ra.PREF64))
	}
	if !ra.PREF64[0].Withdrawn() || ra.PREF64[0].Lifetime != 0 {
		t.Errorf("first entry %+v, want a withdrawal", ra.PREF64[0])
	}
	if ra.PREF64[1].Withdrawn() {
		t.Errorf("second entry %+v read as withdrawn, its lifetime is 8", ra.PREF64[1])
	}
	if ra.PREF64[0].Prefix.Bits() != 96 {
		t.Errorf("withdrawal prefix %s, want the /96 it named", ra.PREF64[0].Prefix)
	}
}

// TestPREF64OfTheWrongLengthIsIgnoredAndItsSiblingsAreNot is §4: "The receiver
// MUST ignore the PREF64 option if the Length field value is not 2." Length 1
// (8 octets) and 3 (24 octets) are each well-formed for the walk, which moves
// on by the declared length, so the option after them decodes.
func TestPREF64OfTheWrongLengthIsIgnoredAndItsSiblingsAreNot(t *testing.T) {
	short := []byte{38, 1, 0x00, 0x08, 0, 0, 0, 0}
	long := append(pref64Option(0x00, 0x08, pref64Prefix), 0, 0, 0, 0, 0, 0, 0, 0)
	long[1] = 3
	for name, bad := range map[string][]byte{"length 1": short, "length 3": long} {
		ra, err := DecodeRouterAdvert(raWith(bad, mtuOption(1400), pref64Option(0x00, 0x08, pref64Prefix)))
		if err != nil {
			t.Fatalf("%s: DecodeRouterAdvert: %v", name, err)
		}
		if len(ra.PREF64) != 1 {
			t.Errorf("%s: %d entries, want only the well-formed sibling", name, len(ra.PREF64))
		}
		if ra.MTU != 1400 {
			t.Errorf("%s: the MTU sibling was lost", name)
		}
		if ra.IgnoredOptions != 1 {
			t.Errorf("%s: IgnoredOptions %d, want 1", name, ra.IgnoredOptions)
		}
	}
}

// TestPREF64BitsPastThePrefixLengthAreNotPartOfIt: RFC 8781 §4 is silent on
// the bits between the PLC length and bit 95, so the decoder cuts them, and two
// options that differ only there are the same prefix.
func TestPREF64BitsPastThePrefixLengthAreNotPartOfIt(t *testing.T) {
	clean, err := DecodeRouterAdvert(raWith(pref64Option(0x00, 0x09, "20010db801220344"+"00000000")))
	if err != nil {
		t.Fatal(err)
	}
	dirty, err := DecodeRouterAdvert(raWith(pref64Option(0x00, 0x09, "20010db801220344"+"0fffffff")))
	if err != nil {
		t.Fatal(err)
	}
	if len(clean.PREF64) != 1 || len(dirty.PREF64) != 1 {
		t.Fatalf("entries %d and %d, want 1 each", len(clean.PREF64), len(dirty.PREF64))
	}
	if clean.PREF64[0].Prefix != dirty.PREF64[0].Prefix {
		t.Errorf("clean %s, dirty %s: host bits past /64 leaked into the prefix",
			clean.PREF64[0].Prefix, dirty.PREF64[0].Prefix)
	}
}

// TestPREF64IsKeptInWireOrderBesideTheOtherOptions is the preservation control:
// the options that decoded before PREF64 existed still decode, and the new one
// keeps its place and renders.
func TestPREF64IsKeptInWireOrderBesideTheOtherOptions(t *testing.T) {
	rdnss := netip.MustParseAddr("2001:db8::53")
	ra, err := DecodeRouterAdvert(raWith(
		mtuOption(1480),
		pref64Option(0x00, 0x10, "0064ff9b0000000000000000"),
		rdnssOption(600, rdnss),
		pref64Option(0x00, 0x18, pref64Prefix),
	))
	if err != nil {
		t.Fatalf("DecodeRouterAdvert: %v", err)
	}
	if ra.MTU != 1480 || len(ra.RDNSS) != 1 || ra.RDNSS[0].Addrs[0] != rdnss {
		t.Errorf("a sibling option changed: mtu %d, rdnss %v", ra.MTU, ra.RDNSS)
	}
	if len(ra.PREF64) != 2 || ra.PREF64[0].Lifetime != 16 || ra.PREF64[1].Lifetime != 24 {
		t.Fatalf("PREF64 %+v, want lifetimes 16 then 24 in wire order", ra.PREF64)
	}
	if want := netip.MustParsePrefix("64:ff9b::/96"); ra.PREF64[0].Prefix != want {
		t.Errorf("well-known prefix decoded as %s, want %s", ra.PREF64[0].Prefix, want)
	}
	s := ra.String()
	if !strings.Contains(s, "pref64 64:ff9b::/96 lifetime=16s") || !strings.Contains(s, "lifetime=24s") {
		t.Errorf("String() %q does not show both PREF64 entries", s)
	}
}

// TestPREF64ThatRunsPastTheAdvertisementDiscardsThePacket: the walk's
// verdict for an option with no room is the packet's, whatever the type
// (RFC 4861 §4.6), so the option is neither read short nor skipped.
func TestPREF64ThatRunsPastTheAdvertisementDiscardsThePacket(t *testing.T) {
	full := pref64Option(0x00, 0x08, pref64Prefix)
	for _, n := range []int{1, 2, 4, 15} {
		if _, err := DecodeRouterAdvert(raWith(full[:n])); err == nil {
			t.Errorf("a PREF64 option cut to %d octet(s) decoded", n)
		}
	}
}

// FuzzDecodeRouterAdvertPREF64 feeds arbitrary octets as the option area of an
// advertisement. The properties: no panic, and the entries the decoder returns
// are exactly the well-formed type-38 options an independent walk of the same
// octets finds, each with the prefix and lifetime that walk derives.
func FuzzDecodeRouterAdvertPREF64(f *testing.F) {
	f.Add(pref64Option(0x0B, 0x29, pref64Prefix))
	f.Add(pref64Option(0xFF, 0xF8, pref64Prefix))
	f.Add(pref64Option(0x00, 0x00, pref64Prefix))
	f.Add(pref64Option(0x00, 0x0E, pref64Prefix))
	f.Add(pref64Option(0x00, 0x0F, pref64Prefix))
	f.Add(pref64Option(0x00, 0x08, pref64Prefix)[:15])
	f.Add([]byte{38, 1, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{38})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, opts []byte) {
		ra, err := DecodeRouterAdvert(raWith(opts))
		if err != nil {
			return
		}
		var want []PREF64
		for i := 0; i < len(opts); i += int(opts[i+1]) * 8 {
			n := int(opts[i+1]) * 8
			if opts[i] != 38 || n != 16 || opts[i+3]&7 > 5 {
				continue
			}
			field := uint16(opts[i+2])<<8 | uint16(opts[i+3])
			var a [16]byte
			copy(a[:12], opts[i+4:i+16])
			bits := []int{96, 64, 56, 48, 40, 32}[field&7]
			want = append(want, PREF64{
				Prefix:   netip.PrefixFrom(netip.AddrFrom16(a), bits).Masked(),
				Lifetime: uint32(field>>3) * 8,
			})
		}
		if len(ra.PREF64) != len(want) {
			t.Fatalf("%d entries, an independent walk finds %d in %x", len(ra.PREF64), len(want), opts)
		}
		for i := range want {
			if ra.PREF64[i] != want[i] {
				t.Fatalf("entry %d is %+v, want %+v", i, ra.PREF64[i], want[i])
			}
			if ra.PREF64[i].Lifetime > 65528 {
				t.Fatalf("lifetime %d exceeds §4.1's maximum", ra.PREF64[i].Lifetime)
			}
		}
		_ = ra.String()
	})
}
