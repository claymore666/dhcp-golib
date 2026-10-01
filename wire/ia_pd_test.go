// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package wire

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// iaPrefixOption is RFC 8415 §21.22 written octet by octet (code 26, length
// 25): 2001:db8:1::/56, preferred 60 s, valid 120 s.
const iaPrefixOption = "001a" + "0019" +
	"0000003c" + "00000078" + "38" + "20010db8000100000000000000000000"

// TestIAPDIsTwelveOctetsOfFixedFieldsThenItsOptions is RFC 8415 §21.21: code
// 25, "IAID (4 octets) T1 (4 octets) T2 (4 octets) IA_PD-options", the IA_NA's
// layout, and the IA Prefix is option 26 with 25 fixed octets (§21.22)
// (claymore666/docker-net-dhcp#214).
func TestIAPDIsTwelveOctetsOfFixedFieldsThenItsOptions(t *testing.T) {
	if IAPDFixedLen != 12 || IAPrefixFixedLen != 25 {
		t.Fatalf("IAPDFixedLen=%d IAPrefixFixedLen=%d, want 12 and 25", IAPDFixedLen, IAPrefixFixedLen)
	}
	if OptV6IAPD != 25 || OptV6IAPrefix != 26 {
		t.Fatalf("option codes %d, %d, want 25, 26", OptV6IAPD, OptV6IAPrefix)
	}
	value := mustHex("11223344" + "0000012c" + "0000021c" + iaPrefixOption)
	ia, err := DecodeIAPD(value)
	if err != nil {
		t.Fatalf("DecodeIAPD: %v", err)
	}
	if ia.IAID != 0x11223344 || ia.T1 != 300 || ia.T2 != 540 {
		t.Errorf("IAID=%08x T1=%d T2=%d, want 11223344 300 540", ia.IAID, ia.T1, ia.T2)
	}
	ps, err := ia.Options.Prefixes()
	if err != nil || len(ps) != 1 {
		t.Fatalf("Prefixes = %v, %v; want the one prefix", ps, err)
	}
	if ps[0].Prefix != netip.MustParsePrefix("2001:db8:1::/56") || ps[0].PreferredLifetime != 60 || ps[0].ValidLifetime != 120 {
		t.Errorf("prefix %s pref=%d valid=%d, want 2001:db8:1::/56 60 120",
			ps[0].Prefix, ps[0].PreferredLifetime, ps[0].ValidLifetime)
	}
	back, err := EncodeIAPD(ia)
	if err != nil || !bytes.Equal(back, value) {
		t.Errorf("re-encoded %x (%v), want %x", back, err, value)
	}
}

// TestIAPrefixLengthIsTheOctetNotTheAddressAndAbove128IsRefused: §21.22's
// prefix-length octet is the length the client reads, whatever the address
// bytes look like, and 129 and up is no prefix.
func TestIAPrefixLengthIsTheOctetNotTheAddressAndAbove128IsRefused(t *testing.T) {
	for _, n := range []int{0, 1, 24} {
		if _, err := DecodeIAPrefix(make([]byte, n)); !errors.Is(err, ErrV6BadOption) {
			t.Errorf("DecodeIAPrefix on %d octet(s): %v, want %v", n, err, ErrV6BadOption)
		}
	}
	for _, tc := range []struct {
		octet string
		bits  int
	}{{"00", 0}, {"40", 64}, {"80", 128}} {
		p, err := DecodeIAPrefix(mustHex("0000003c" + "00000078" + tc.octet + "20010db8000100000000000000000000"))
		if err != nil || p.Prefix.Bits() != tc.bits {
			t.Errorf("length octet %s: %v, %v; want %d bits", tc.octet, p, err, tc.bits)
		}
	}
	if _, err := DecodeIAPrefix(mustHex("0000003c" + "00000078" + "81" + "20010db8000100000000000000000000")); !errors.Is(err, ErrV6BadOption) {
		t.Errorf("a length of 129 decoded: %v, want %v", err, ErrV6BadOption)
	}
}

// TestIAPrefixValidIsPreferredNotAboveValidAndEncodeRefusesWhatIsNoV6Prefix.
func TestIAPrefixValidIsPreferredNotAboveValidAndEncodeRefusesWhatIsNoV6Prefix(t *testing.T) {
	if !(&IAPrefix{PreferredLifetime: 5, ValidLifetime: 5}).Valid() || (&IAPrefix{PreferredLifetime: 6, ValidLifetime: 5}).Valid() {
		t.Error("Valid() is not preferred <= valid")
	}
	for _, p := range []*IAPrefix{nil, {}, {Prefix: netip.MustParsePrefix("10.0.0.0/8")}, {Prefix: netip.MustParsePrefix("::ffff:10.0.0.0/104")}} {
		if _, err := EncodeIAPrefix(p); !errors.Is(err, ErrV6Encode) {
			t.Errorf("EncodeIAPrefix(%v) = %v, want %v", p, err, ErrV6Encode)
		}
	}
	if _, err := EncodeIAPD(nil); !errors.Is(err, ErrV6Encode) {
		t.Errorf("EncodeIAPD(nil) = %v, want %v", err, ErrV6Encode)
	}
}

// TestIAPDShorterThanItsFixedFieldsOrWithATruncatedPrefixIsRefusedWholesale is
// the truncation row of the defeat list: no panic, no partial answer.
func TestIAPDShorterThanItsFixedFieldsOrWithATruncatedPrefixIsRefusedWholesale(t *testing.T) {
	for _, n := range []int{0, 4, 11} {
		if _, err := DecodeIAPD(make([]byte, n)); !errors.Is(err, ErrV6BadOption) {
			t.Errorf("DecodeIAPD on %d octet(s): %v, want %v", n, err, ErrV6BadOption)
		}
	}
	cut := mustHex("11223344" + "0000012c" + "0000021c" + "001a" + "0019" + "0000003c")
	if _, err := DecodeIAPD(cut); err == nil {
		t.Fatal("DecodeIAPD accepted an IA Prefix that runs past its IA_PD")
	}
	short := mustHex("11223344" + "0000012c" + "0000021c" + "001a" + "0004" + "0000003c")
	ia, err := DecodeIAPD(short)
	if err != nil {
		t.Fatalf("DecodeIAPD: %v", err)
	}
	if ps, err := ia.Options.Prefixes(); !errors.Is(err, ErrV6BadOption) || ps != nil {
		t.Errorf("Prefixes on a 4-octet IA Prefix = %v, %v; want nil and %v", ps, err, ErrV6BadOption)
	}
	good := OptionV6{Code: OptV6IAPD, Data: mustHex("00000001" + "00000000" + "00000000")}
	bad := OptionV6{Code: OptV6IAPD, Data: cut}
	if got, err := (OptionsV6{good, bad}).IAPDs(); err == nil || got != nil {
		t.Errorf("IAPDs = %v, %v; want nil and an error", got, err)
	}
}

// TestIAPDBesideAnIANAKeepsItsOwnStatusPerIA: NoPrefixAvail (6) inside the
// IA_PD and Success inside the IA_NA, then swapped; §21.21 and §21.4 scope a
// Status Code to its IA, so neither lends its status to the other.
func TestIAPDBesideAnIANAKeepsItsOwnStatusPerIA(t *testing.T) {
	const (
		noPrefix = "000d" + "0004" + "0006" + "6e6f"
		ok       = "000d" + "0004" + "0000" + "6f6b"
	)
	for _, tc := range []struct {
		name         string
		na, pd       string
		naCode, pdCd StatusCode
	}{
		{"IA_PD refused, IA_NA granted", ok, noPrefix, StatusSuccess, StatusNoPrefixAvail},
		{"IA_PD granted, IA_NA refused", "000d" + "0004" + "0002" + "6e6f", ok, StatusNoAddrsAvail, StatusSuccess},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := mustHex("07010203" +
				"0003" + "0014" + "aaaaaaaa" + "0000012c" + "0000021c" + tc.na +
				"0019" + "0014" + "aaaaaaaa" + "0000012c" + "0000021c" + tc.pd)
			m, err := DecodeV6(raw)
			if err != nil {
				t.Fatalf("DecodeV6: %v", err)
			}
			nas, err := m.Options.IANAs()
			if err != nil || len(nas) != 1 {
				t.Fatalf("IANAs = %d, %v; want the IA_NA alone", len(nas), err)
			}
			pds, err := m.Options.IAPDs()
			if err != nil || len(pds) != 1 {
				t.Fatalf("IAPDs = %d, %v; want the IA_PD alone", len(pds), err)
			}
			ns, _, _ := nas[0].Options.Status()
			ps, found, _ := pds[0].Options.Status()
			if ns.Code != tc.naCode || !found || ps.Code != tc.pdCd {
				t.Errorf("IA_NA status %v, IA_PD status %v (found=%v), want %v and %v", ns.Code, ps.Code, found, tc.naCode, tc.pdCd)
			}
			if _, found, _ := m.Options.Status(); found {
				t.Error("the message reports a Status Code that only the IAs carry")
			}
			if back, err := EncodeV6(m); err != nil || !bytes.Equal(back, raw) {
				t.Errorf("re-encoded %x (%v), want %x", back, err, raw)
			}
		})
	}
}

// TestIAPDIsNamedAndItsPrefixesShowInASummary: the journal renders ia-pd with
// the prefixes it holds, and a truncated one as the bare name.
func TestIAPDIsNamedAndItsPrefixesShowInASummary(t *testing.T) {
	sum := func(code OptionCodeV6, v string) string {
		return (&MessageV6{Type: MsgAdvertise, XID: 0xbeef, Options: OptionsV6{{Code: code, Data: mustHex(v)}}}).Summary()
	}
	if got, want := sum(OptV6IAPD, "11223344"+"0000012c"+"0000021c"+iaPrefixOption), "ADVERTISE xid=00beef ia-pd(2001:db8:1::/56)"; got != want {
		t.Errorf("Summary() = %q, want %q", got, want)
	}
	if got, want := sum(OptV6IAPD, "11223344"+"0000012c"+"0000021c"+"001a"+"0019"+"0000003c"), "ADVERTISE xid=00beef ia-pd"; got != want {
		t.Errorf("truncated Summary() = %q, want %q", got, want)
	}
	if s := sum(OptV6IAPrefix, strings.TrimPrefix(iaPrefixOption, "001a0019")); !strings.Contains(s, "ia-prefix(2001:db8:1::/56)") {
		t.Errorf("Summary() = %q, want the prefix shown", s)
	}
}

// FuzzDecodeIAPD: whatever DecodeIAPD accepts encodes back to the same octets,
// and nothing panics.
func FuzzDecodeIAPD(f *testing.F) {
	f.Add(mustHex("000000010000000000000000"))
	f.Add(mustHex("11223344" + "0000012c" + "0000021c" + iaPrefixOption))
	f.Add(mustHex("11223344" + "0000012c" + "0000021c" + iaPrefixOption + "000d00020006"))
	f.Add(mustHex("11223344" + "0000012c" + "0000021c" + "001a" + "0019" + "0000003c"))
	f.Add(mustHex("112233"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		ia, err := DecodeIAPD(b)
		if err != nil {
			return
		}
		_, _ = ia.Options.Prefixes()
		back, err := EncodeIAPD(ia)
		if err != nil {
			t.Fatalf("EncodeIAPD refused what DecodeIAPD accepted from %x: %v", b, err)
		}
		if !bytes.Equal(back, b) {
			t.Fatalf("round trip %x -> %x", b, back)
		}
	})
}

// FuzzDecodeIAPrefix: an IA Prefix that decodes encodes back to the same
// octets, except an IPv4-mapped address, which no prefix encoder will write.
func FuzzDecodeIAPrefix(f *testing.F) {
	f.Add(mustHex(strings.TrimPrefix(iaPrefixOption, "001a0019")))
	f.Add(mustHex(strings.TrimPrefix(iaPrefixOption, "001a0019") + "000d00020006"))
	f.Add(mustHex("0000003c0000007881" + "20010db8000100000000000000000000"))
	f.Add(make([]byte, 24))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := DecodeIAPrefix(b)
		if err != nil {
			return
		}
		back, err := EncodeIAPrefix(p)
		if err != nil {
			if p.Prefix.Addr().Is4In6() && errors.Is(err, ErrV6Encode) {
				return
			}
			t.Fatalf("EncodeIAPrefix refused what DecodeIAPrefix accepted from %x: %v", b, err)
		}
		if !bytes.Equal(back, b) {
			t.Fatalf("round trip %x -> %x", b, back)
		}
	})
}
