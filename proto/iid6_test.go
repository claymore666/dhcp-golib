// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"testing"
)

// The RFC gives no vector, so these are recomputed outside Go: the input is
// prefix(16) len(1) uvarint-len netIface uvarint-len networkID counter(1)
// secret, and the IID is the digest's last 16 hex digits (dhcp-golib#54):
//
//	python3 -c "import hashlib;print(hashlib.sha256(bytes.fromhex(
//	  '20010db8000100000000000000000000' '40' '06' '0242ac110002' '03' '6c616e'
//	  '00' '000102030405060708090a0b0c0d0e0f')).hexdigest()[-16:])"
var (
	testIIDSecret    = mustHexBytes("000102030405060708090a0b0c0d0e0f")
	testIIDNetIface  = mustHexBytes("0242ac110002")
	testIIDNetworkID = []byte("lan")
)

func TestStablePrivacyIIDMatchesAVectorRecomputedOutsideGo(t *testing.T) {
	cases := []struct {
		prefix  string
		counter uint8
		want    string
	}{
		{"2001:db8:1::/64", 0, "09c3717974cd959e"},
		{"2001:db8:1::/64", 1, "697ab2226a00137b"},
		{"2001:db8:2::/64", 0, "2c1730113e8444fb"},
	}
	for _, c := range cases {
		got := StablePrivacyIID(netip.MustParsePrefix(c.prefix), testIIDNetIface, testIIDNetworkID, c.counter, testIIDSecret)
		if hex.EncodeToString(got[:]) != c.want {
			t.Errorf("%s at DAD_Counter %d: IID %x, want %s", c.prefix, c.counter, got, c.want)
		}
	}
}

func TestStablePrivacyIIDIgnoresHostBitsInThePrefix(t *testing.T) {
	clean := StablePrivacyIID(netip.MustParsePrefix("2001:db8:1::/64"), testIIDNetIface, testIIDNetworkID, 0, testIIDSecret)
	dirty := StablePrivacyIID(netip.PrefixFrom(netip.MustParseAddr("2001:db8:1::dead:beef"), 64), testIIDNetIface, testIIDNetworkID, 0, testIIDSecret)
	if clean != dirty {
		t.Errorf("one /64 with host bits left in hashed to %x, without them to %x", dirty, clean)
	}
}

func TestStablePrivacyIIDReadsEveryInput(t *testing.T) {
	p := netip.MustParsePrefix("2001:db8:1::/64")
	base := StablePrivacyIID(p, testIIDNetIface, testIIDNetworkID, 0, testIIDSecret)
	flip := func(b []byte) []byte { c := append([]byte(nil), b...); c[len(c)-1] ^= 1; return c }
	others := map[string][8]byte{
		"prefix":      StablePrivacyIID(netip.MustParsePrefix("2001:db8:1:1::/64"), testIIDNetIface, testIIDNetworkID, 0, testIIDSecret),
		"prefix len":  StablePrivacyIID(netip.MustParsePrefix("2001:db8:1::/63"), testIIDNetIface, testIIDNetworkID, 0, testIIDSecret),
		"Net_Iface":   StablePrivacyIID(p, flip(testIIDNetIface), testIIDNetworkID, 0, testIIDSecret),
		"Network_ID":  StablePrivacyIID(p, testIIDNetIface, flip(testIIDNetworkID), 0, testIIDSecret),
		"no Network":  StablePrivacyIID(p, testIIDNetIface, nil, 0, testIIDSecret),
		"DAD_Counter": StablePrivacyIID(p, testIIDNetIface, testIIDNetworkID, 1, testIIDSecret),
		"secret_key":  StablePrivacyIID(p, testIIDNetIface, testIIDNetworkID, 0, flip(testIIDSecret)),
		// RFC 7217 §5 concatenates; the length prefixes keep a byte moved
		// across the Net_Iface/Network_ID boundary from hashing alike.
		"boundary": StablePrivacyIID(p, append(append([]byte(nil), testIIDNetIface...), 'l'), []byte("an"), 0, testIIDSecret),
	}
	for name, got := range others {
		if got == base {
			t.Errorf("changing %s left the identifier at %x", name, got)
		}
	}
}

func testParams6Stable() Params6 {
	p := testParams6SLAAC()
	p.IID = IIDModeStablePrivacy
	p.IIDSecret = append([]byte(nil), testIIDSecret...)
	p.IIDNetIface = append([]byte(nil), testIIDNetIface...)
	p.IIDNetworkID = append([]byte(nil), testIIDNetworkID...)
	return p
}

func TestNewSixRefusesAStablePrivacyParamsItCannotRun(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Params6)
		want error
	}{
		{"a 15-octet secret", func(p *Params6) { p.IIDSecret = p.IIDSecret[:15] }, ErrShortIIDSecret},
		{"no secret", func(p *Params6) { p.IIDSecret = nil }, ErrShortIIDSecret},
		{"no Net_Iface", func(p *Params6) { p.IIDNetIface = nil }, ErrNoIIDNetIface},
		{"an undeclared mode", func(p *Params6) { p.IID = IIDMode(99) }, ErrBadIIDMode},
		{"an undeclared mode where none is formed", func(p *Params6) { p.IID = IIDMode(99); p.Mode = Mode6DHCP }, ErrBadIIDMode},
	}
	for _, mode := range []Mode6{Mode6SLAAC, Mode6Auto} {
		for _, c := range cases {
			p := testParams6Stable()
			p.Mode = mode
			c.edit(&p)
			if _, err := New6(p); !errors.Is(err, c.want) {
				t.Errorf("%s, %s: New6 answered %v, want %v", mode, c.name, err, c.want)
			}
		}
	}
}

func TestNewSixAcceptsAStablePrivacyParamsWithoutALinkAddress(t *testing.T) {
	ok := map[string]func(*Params6){
		"a 16-octet secret":             func(p *Params6) {},
		"no link address":               func(p *Params6) { p.LinkAddr = nil },
		"no Network_ID":                 func(p *Params6) { p.IIDNetworkID = nil },
		"a short secret where no SLAAC": func(p *Params6) { p.IIDSecret = p.IIDSecret[:1]; p.Mode = Mode6DHCP },
	}
	for name, edit := range ok {
		p := testParams6Stable()
		edit(&p)
		if _, err := New6(p); err != nil {
			t.Errorf("%s: New6 refused it: %v", name, err)
		}
	}
}

// Every slice and pointer field, found by reflection so a field added later is
// held too: the copy must share no backing memory (dhcp-golib#54).
func TestParams6CloneSharesNoMemoryWithItsSource(t *testing.T) {
	var p Params6
	v := reflect.ValueOf(&p).Elem()
	var held []string
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		switch f.Kind() {
		case reflect.Slice:
			f.Set(reflect.MakeSlice(f.Type(), 1, 1))
		case reflect.Pointer:
			f.Set(reflect.New(f.Type().Elem()))
		default:
			continue
		}
		held = append(held, v.Type().Field(i).Name)
	}
	for _, must := range []string{"DUID", "ORO", "Declined", "Resume", "LinkAddr", "IIDSecret", "IIDNetIface", "IIDNetworkID"} {
		if !slices.Contains(held, must) {
			t.Fatalf("reflection did not reach %s; it found %v", must, held)
		}
	}
	c := reflect.ValueOf(p.Clone())
	for _, name := range held {
		if c.FieldByName(name).Pointer() == v.FieldByName(name).Pointer() {
			t.Errorf("Clone shares %s with its source", name)
		}
	}
}
