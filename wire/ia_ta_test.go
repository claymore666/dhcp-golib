// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package wire

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// iaTAAddrOption is RFC 8415 §21.6's IA Address option written octet by octet
// (code 5, length 24): 2001:db8::1, preferred 60 s, valid 120 s.
const iaTAAddrOption = "0005" + "0018" +
	"20010db8000000000000000000000001" + "0000003c" + "00000078"

// TestIATAHasNoT1OrT2SoTheAddressIsTheFirstOption is RFC 8415 §21.5: option
// code 4, "IAID (4 octets)" and then "IA_TA-options", option-len "4 + length of
// IA_TA-options field". An IA_NA reader would take the first eight octets of
// the IA Address option as T1 and T2; this one must hand back the address
// (claymore666/docker-net-dhcp#927).
func TestIATAHasNoT1OrT2SoTheAddressIsTheFirstOption(t *testing.T) {
	if IATAFixedLen != 4 {
		t.Fatalf("IATAFixedLen = %d, want 4 (§21.5: the IAID alone)", IATAFixedLen)
	}
	value := mustHex("11223344" + iaTAAddrOption)
	ia, err := DecodeIATA(value)
	if err != nil {
		t.Fatalf("DecodeIATA: %v", err)
	}
	if ia.IAID != 0x11223344 {
		t.Errorf("IAID = %08x, want 11223344", ia.IAID)
	}
	as, err := ia.Options.Addrs()
	if err != nil || len(as) != 1 {
		t.Fatalf("Addrs = %v, %v; want the one address", as, err)
	}
	if as[0].Addr != netip.MustParseAddr("2001:db8::1") || as[0].PreferredLifetime != 60 || as[0].ValidLifetime != 120 {
		t.Errorf("address %s pref=%d valid=%d, want 2001:db8::1 60 120",
			as[0].Addr, as[0].PreferredLifetime, as[0].ValidLifetime)
	}
	back, err := EncodeIATA(ia)
	if err != nil {
		t.Fatalf("EncodeIATA: %v", err)
	}
	if !bytes.Equal(back, value) {
		t.Errorf("re-encoded %x, want %x", back, value)
	}
}

// TestIATAShorterThanItsIAIDIsRefusedAndAnIAIDAloneIsWhole: §21.5 makes the
// IAID the only fixed field, so 3 octets are short and 4 are a complete
// IA_TA with no options.
func TestIATAShorterThanItsIAIDIsRefusedAndAnIAIDAloneIsWhole(t *testing.T) {
	for _, n := range []int{0, 1, 3} {
		if _, err := DecodeIATA(make([]byte, n)); !errors.Is(err, ErrV6BadOption) {
			t.Errorf("DecodeIATA on %d octet(s): %v, want %v", n, err, ErrV6BadOption)
		}
	}
	ia, err := DecodeIATA(mustHex("00000007"))
	if err != nil {
		t.Fatalf("DecodeIATA on the IAID alone: %v", err)
	}
	if ia.IAID != 7 || len(ia.Options) != 0 {
		t.Errorf("got IAID=%d with %d option(s), want 7 and none", ia.IAID, len(ia.Options))
	}
	if _, err := EncodeIATA(nil); !errors.Is(err, ErrV6Encode) {
		t.Errorf("EncodeIATA(nil) = %v, want %v", err, ErrV6Encode)
	}
}

// TestIATAWithATruncatedOptionIsRefusedWholesale: an IA Address whose length
// runs past the IA_TA leaves no partial answer, and IATAs reports the error
// instead of the IA_TAs it had already read.
func TestIATAWithATruncatedOptionIsRefusedWholesale(t *testing.T) {
	cut := mustHex("11223344" + "0005" + "0018" + "20010db8")
	if _, err := DecodeIATA(cut); err == nil {
		t.Fatal("DecodeIATA accepted an option that runs past its IA_TA")
	}
	good := OptionV6{Code: OptionCodeV6(4), Data: mustHex("00000001")}
	bad := OptionV6{Code: OptionCodeV6(4), Data: cut}
	got, err := (OptionsV6{good, bad}).IATAs()
	if err == nil || got != nil {
		t.Errorf("IATAs = %v, %v; want nil and an error", got, err)
	}
}

// TestIATABesideAnIANACarriesItsOwnStatusPerIA: one Solicit with an IA_NA
// whose Status Code is NoAddrsAvail (2) and an IA_TA whose Status Code is
// Success (0), and then the two swapped. §21.5 and §21.4 scope a Status Code
// to the IA it sits in, so neither may lend its status to the other, and the
// IA_NA must decode as it always did (claymore666/docker-net-dhcp#927).
func TestIATABesideAnIANACarriesItsOwnStatusPerIA(t *testing.T) {
	const (
		no = "000d" + "0004" + "0002" + "6e6f" // Status Code: NoAddrsAvail "no"
		ok = "000d" + "0004" + "0000" + "6f6b" // Status Code: Success "ok"
	)
	for _, tc := range []struct {
		name           string
		na, ta         string
		naCode, taCode StatusCode
		naMsg, taMsg   string
	}{
		{"IA_NA fails, IA_TA succeeds", no, ok, StatusNoAddrsAvail, StatusSuccess, "no", "ok"},
		{"IA_NA succeeds, IA_TA fails", ok, no, StatusSuccess, StatusNoAddrsAvail, "ok", "no"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := mustHex("01010203" +
				"0003" + "0014" + "aaaaaaaa" + "0000012c" + "0000021c" + tc.na +
				"0004" + "000c" + "bbbbbbbb" + tc.ta)
			m, err := DecodeV6(raw)
			if err != nil {
				t.Fatalf("DecodeV6: %v", err)
			}
			nas, err := m.Options.IANAs()
			if err != nil || len(nas) != 1 {
				t.Fatalf("IANAs = %d, %v; want exactly the IA_NA and not the IA_TA", len(nas), err)
			}
			tas, err := m.Options.IATAs()
			if err != nil || len(tas) != 1 {
				t.Fatalf("IATAs = %d, %v; want exactly the IA_TA and not the IA_NA", len(tas), err)
			}
			if nas[0].IAID != 0xaaaaaaaa || nas[0].T1 != 300 || nas[0].T2 != 540 {
				t.Errorf("IA_NA = %08x T1=%d T2=%d, want aaaaaaaa 300 540", nas[0].IAID, nas[0].T1, nas[0].T2)
			}
			if tas[0].IAID != 0xbbbbbbbb {
				t.Errorf("IA_TA IAID = %08x, want bbbbbbbb", tas[0].IAID)
			}
			ns, found, err := nas[0].Options.Status()
			if err != nil || !found || ns.Code != tc.naCode || ns.Message != tc.naMsg {
				t.Errorf("IA_NA status = %v found=%v err=%v, want %v %q", ns, found, err, tc.naCode, tc.naMsg)
			}
			ts, found, err := tas[0].Options.Status()
			if err != nil || !found || ts.Code != tc.taCode || ts.Message != tc.taMsg {
				t.Errorf("IA_TA status = %v found=%v err=%v, want %v %q", ts, found, err, tc.taCode, tc.taMsg)
			}
			if _, found, _ := m.Options.Status(); found {
				t.Error("the message itself reports a Status Code that only the IAs carry")
			}
			back, err := EncodeV6(m)
			if err != nil || !bytes.Equal(back, raw) {
				t.Errorf("re-encoded %x (%v), want %x", back, err, raw)
			}
		})
	}
}

// TestIATAIsNamedAndItsAddressesShowInASummary: the journal renders the option
// as ia-ta with the addresses it holds, like ia-na, and a truncated one as the
// bare name.
func TestIATAIsNamedAndItsAddressesShowInASummary(t *testing.T) {
	sum := func(v string) string {
		return (&MessageV6{Type: MsgAdvertise, XID: 0xbeef, Options: OptionsV6{
			{Code: OptionCodeV6(4), Data: mustHex(v)},
		}}).Summary()
	}
	if got, want := sum("11223344"+iaTAAddrOption), "ADVERTISE xid=00beef ia-ta(2001:db8::1)"; got != want {
		t.Errorf("Summary() = %q, want %q", got, want)
	}
	if got, want := sum("112233"), "ADVERTISE xid=00beef ia-ta"; got != want {
		t.Errorf("Summary() = %q, want %q", got, want)
	}
	if s := sum("00000001"); strings.Contains(s, "option6(4)") {
		t.Errorf("Summary() = %q, want the option named", s)
	}
}

// FuzzDecodeIATA: whatever DecodeIATA accepts encodes back to the same octets
// (§21.5 has no field a decoder may normalise), and nothing panics.
func FuzzDecodeIATA(f *testing.F) {
	f.Add(mustHex("00000000"))
	f.Add(mustHex("11223344" + iaTAAddrOption))
	f.Add(mustHex("11223344" + iaTAAddrOption + "000d00020000"))
	f.Add(mustHex("112233"))
	f.Add(mustHex("11223344" + "0005" + "0018" + "20010db8"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		ia, err := DecodeIATA(b)
		if err != nil {
			return
		}
		back, err := EncodeIATA(ia)
		if err != nil {
			t.Fatalf("EncodeIATA refused what DecodeIATA accepted from %x: %v", b, err)
		}
		if !bytes.Equal(back, b) {
			t.Fatalf("round trip %x -> %x", b, back)
		}
	})
}
