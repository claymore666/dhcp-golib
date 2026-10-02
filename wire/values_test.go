// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package wire

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func p4(s string) []byte {
	a := netip.MustParseAddr(s).As4()
	return a[:]
}

// TestOptionValueReaders drives the typed readers on Options, including the
// SHAPE FAILURES: an option present but the wrong length is a different case
// from an option absent, and a reader that folded the two would report a
// truncated router list as "no router" — the shape that makes a host with no
// default route look like a server that sent none.
func TestOptionValueReaders(t *testing.T) {
	o := Options{
		OptRouter:        p4("192.168.99.1"),
		OptDNSServer:     append(p4("192.168.99.1"), p4("192.168.99.2")...),
		OptLeaseTime:     {0, 0, 14, 16},
		OptInterfaceMTU:  {0x05, 0xDC},
		OptDomainName:    []byte("example.test"),
		OptTimeOffset:    {0xFF, 0xFF, 0xC7, 0xC0},
		OptSubnetMask:    {255, 255, 255, 0},
		OptBootfileName:  {},
		OptTFTPServer:    p4("192.168.99.9")[:3],
		OptPosixTimezone: []byte("CET-1CEST,M3.5.0,M10.5.0/3"),
	}

	if a, ok := o.Addr4(OptRouter); !ok || a != netip.MustParseAddr("192.168.99.1") {
		t.Fatalf("Addr4(router) = %v, %v", a, ok)
	}
	if _, ok := o.Addr4(OptTFTPServer); ok {
		t.Fatal("Addr4 accepted a three-octet address option; a truncated value is not an address")
	}
	if _, ok := o.Addr4(OptWPAD); ok {
		t.Fatal("Addr4 returned ok for an absent option")
	}
	if a, ok := o.Addrs4(OptDNSServer); !ok || len(a) != 2 || a[1] != netip.MustParseAddr("192.168.99.2") {
		t.Fatalf("Addrs4(dns) = %v, %v", a, ok)
	}
	if _, ok := o.Addrs4(OptTFTPServer); ok {
		t.Fatal("Addrs4 accepted a value that is not a whole number of addresses")
	}
	if v, ok := o.Uint32(OptLeaseTime); !ok || v != 3600 {
		t.Fatalf("Uint32(lease) = %d, %v; want 3600", v, ok)
	}
	if v, ok := o.Uint16(OptInterfaceMTU); !ok || v != 1500 {
		t.Fatalf("Uint16(mtu) = %d, %v; want 1500", v, ok)
	}
	if v, ok := o.Text(OptDomainName); !ok || v != "example.test" {
		t.Fatalf("Text(domain) = %q, %v", v, ok)
	}
	if v, ok := o.Text(OptBootfileName); !ok || v != "" {
		t.Fatalf("Text of a present, empty option = %q, %v; want %q, true", v, ok, "")
	}
	// RFC 2132 section 3.4: the time offset is a SIGNED 32-bit value, so
	// every timezone west of Greenwich is negative. Read as unsigned it comes
	// back as 4294952896.
	if v, ok := o.Int32(OptTimeOffset); !ok || v != -14400 {
		t.Fatalf("Int32(time offset) = %d, %v; want -14400", v, ok)
	}
}

// TestClasslessRoutesUsesTheRFC3442ExampleTable drives option 121's
// destination descriptor against the worked table in RFC 3442, "Subnet number
// / Subnet mask / Destination descriptor". The rows are the RFC's, not
// invented ones: a fixture written from the prose would encode the same
// misreading twice.
func TestClasslessRoutesUsesTheRFC3442ExampleTable(t *testing.T) {
	gw := "192.168.99.1"
	cases := []struct {
		name       string
		descriptor []byte
		want       string
	}{
		{"default route", []byte{0}, "0.0.0.0/0"},
		{"10.0.0.0/8", []byte{8, 10}, "10.0.0.0/8"},
		{"10.0.0.0/24", []byte{24, 10, 0, 0}, "10.0.0.0/24"},
		{"10.17.0.0/16", []byte{16, 10, 17}, "10.17.0.0/16"},
		{"10.27.129.0/24", []byte{24, 10, 27, 129}, "10.27.129.0/24"},
		{"10.229.0.128/25", []byte{25, 10, 229, 0, 128}, "10.229.0.128/25"},
		{"10.198.122.47/32", []byte{32, 10, 198, 122, 47}, "10.198.122.47/32"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := Options{OptClasslessStaticRte: append(append([]byte(nil), c.descriptor...), p4(gw)...)}
			got, err := o.ClasslessRoutes()
			if err != nil {
				t.Fatalf("ClasslessRoutes: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("got %d routes, want 1: %v", len(got), got)
			}
			if got[0].Dest.String() != c.want {
				t.Fatalf("destination = %s, want %s", got[0].Dest, c.want)
			}
			if got[0].Router != netip.MustParseAddr(gw) {
				t.Fatalf("router = %s, want %s", got[0].Router, gw)
			}
		})
	}
}

// TestClasslessRoutesMasksTheSubnetNumber is RFC 3442's own worked case: "if
// the server sends a route with a subnet number of 129.210.177.132 and a
// subnet mask of 255.255.255.128, the client must install a route to
// 129.210.177.128/25".
func TestClasslessRoutesMasksTheSubnetNumber(t *testing.T) {
	o := Options{OptClasslessStaticRte: append([]byte{25, 129, 210, 177, 132}, p4("192.168.99.1")...)}
	got, err := o.ClasslessRoutes()
	if err != nil {
		t.Fatalf("ClasslessRoutes: %v", err)
	}
	if got[0].Dest.String() != "129.210.177.128/25" {
		t.Fatalf("destination = %s, want 129.210.177.128/25 (RFC 3442 requires the subnet number be ANDed with the mask)", got[0].Dest)
	}
}

// TestClasslessRoutesCarriesOnLinkRoutes: RFC 3442's Local Subnet Routes, a
// router of 0.0.0.0.
func TestClasslessRoutesCarriesOnLinkRoutes(t *testing.T) {
	v := append([]byte{24, 10, 0, 0}, p4("0.0.0.0")...)
	v = append(v, append([]byte{24, 192, 168, 0}, p4("0.0.0.0")...)...)
	v = append(v, append([]byte{0}, p4("192.168.99.1")...)...)
	got, err := Options{OptClasslessStaticRte: v}.ClasslessRoutes()
	if err != nil {
		t.Fatalf("ClasslessRoutes: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d routes, want 3", len(got))
	}
	for i := 0; i < 2; i++ {
		if !got[i].OnLink() {
			t.Fatalf("route %d (%s) is not reported on-link", i, got[i])
		}
		if got[i].IsDefault() {
			t.Fatalf("route %d (%s) is reported as the default route", i, got[i])
		}
	}
	if !got[2].IsDefault() || got[2].OnLink() {
		t.Fatalf("route 2 = %s, want the default route via a gateway", got[2])
	}
}

// TestClasslessRoutesRefusesAPartialList drives the decision that a malformed
// option 121 yields NO routes rather than the ones that happened to parse.
// The first route in each case is well formed, so a decoder that returned what
// it had would pass every one of these.
//
// Each row also names the guard that must refuse it, and that is not
// decoration. The row called "width over 32" was, before review round 1, a
// width of 33 followed by eight octets — and a /33 needs nine, so the
// TRUNCATION guard refused it and the width bound could have been raised to 64
// with this test still green. A row whose length is COMPLETE is the only kind
// that isolates the width bound.
func TestClasslessRoutesRefusesAPartialList(t *testing.T) {
	good := append([]byte{24, 10, 0, 0}, p4("192.168.99.1")...)
	cases := map[string]struct {
		v      []byte
		refusa string
	}{
		"empty option": {[]byte{}, "option 121 is empty"},
		// Width 40, and then the nine octets a /40 would need: five
		// significant subnet octets and a four-octet router. Nothing about
		// its LENGTH is wrong, so only the width bound can refuse it.
		"width over 32, complete length": {
			append(append([]byte(nil), good...), 40, 10, 0, 0, 0, 0, 192, 168, 99, 1),
			"mask width 40 exceeds 32",
		},
		"width over 32, and short with it": {
			append(append([]byte(nil), good...), 33, 10, 0, 0, 0, 192, 168, 99, 1),
			"mask width 33 exceeds 32",
		},
		"truncated router":    {append(append([]byte(nil), good...), 24, 10, 1, 0, 192, 168), "truncated"},
		"truncated subnet":    {append(append([]byte(nil), good...), 24, 10), "truncated"},
		"trailing width byte": {append(append([]byte(nil), good...), 16), "truncated"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := Options{OptClasslessStaticRte: c.v}.ClasslessRoutes()
			if !errors.Is(err, ErrMalformedRoutes) {
				t.Fatalf("err = %v, want ErrMalformedRoutes", err)
			}
			if got != nil {
				t.Fatalf("got %v routes back from a malformed option; a partial routing table is a host that silently cannot reach one destination", got)
			}
			if !strings.Contains(err.Error(), c.refusa) {
				t.Fatalf("err = %q, want the refusal to come from the guard this row is about (%q)", err, c.refusa)
			}
		})
	}
}

// TestStaticRoutesAreHostRoutes holds the decision that option 33's
// destinations come back as /32 rather than as guessed classful prefixes.
func TestStaticRoutesAreHostRoutes(t *testing.T) {
	v := append(p4("10.0.0.0"), p4("192.168.99.1")...)
	got, err := Options{OptStaticRoute: v}.StaticRoutes()
	if err != nil {
		t.Fatalf("StaticRoutes: %v", err)
	}
	if len(got) != 1 || got[0].Dest.String() != "10.0.0.0/32" {
		t.Fatalf("got %v, want one route to 10.0.0.0/32", got)
	}
	if _, err := (Options{OptStaticRoute: v[:7]}).StaticRoutes(); !errors.Is(err, ErrMalformedRoutes) {
		t.Fatalf("a seven-octet option 33 gave err = %v, want ErrMalformedRoutes", err)
	}
}

// TestDomainSearchDecodesCompressedNames drives RFC 3397's own example, which
// is RFC 1035 compression inside the option: "eng.apple.com." and
// "marketing.apple.com." sharing the apple.com suffix.
func TestDomainSearchDecodesCompressedNames(t *testing.T) {
	v := []byte{
		3, 'e', 'n', 'g', 5, 'a', 'p', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		9, 'm', 'a', 'r', 'k', 'e', 't', 'i', 'n', 'g', 0xC0, 0x04,
	}
	got, err := Options{OptDomainSearch: v}.DomainSearch()
	if err != nil {
		t.Fatalf("DomainSearch: %v", err)
	}
	want := []string{"eng.apple.com", "marketing.apple.com"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

// TestDomainSearchRefusesHostileNames. The looping pointer is the one that
// matters: without the jump bound it hangs ring 0, and in the plugin ring 0
// runs on the daemon's own goroutine.
func TestDomainSearchRefusesHostileNames(t *testing.T) {
	cases := map[string][]byte{
		"empty option":       {},
		"ends mid-name":      {3, 'e', 'n', 'g'},
		"label runs past":    {9, 'e', 'n', 'g', 0},
		"pointer past block": {0xC0, 0x40},
		"pointer to itself":  {3, 'e', 'n', 'g', 0xC0, 0x00},
		"half a pointer":     {3, 'e', 'n', 'g', 0xC0},
		"reserved form":      {0x80, 0x01},
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			done := make(chan struct{})
			var err error
			go func() {
				defer close(done)
				_, err = Options{OptDomainSearch: v}.DomainSearch()
			}()
			<-done
			if !errors.Is(err, ErrMalformedNames) {
				t.Fatalf("err = %v, want ErrMalformedNames", err)
			}
		})
	}
}

// TestEncodeFQDNCanonical pins the bytes of option 81, because the option's
// layout — flags, RCODE1, RCODE2, name — is the sort of thing a refactor
// reorders without any test noticing.
func TestEncodeFQDNCanonical(t *testing.T) {
	got, err := EncodeFQDN(FQDNFlagS|FQDNFlagE, "host.example.test.")
	if err != nil {
		t.Fatalf("EncodeFQDN: %v", err)
	}
	want := []byte{
		0x05, 0x00, 0x00,
		4, 'h', 'o', 's', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0,
	}
	if string(got) != string(want) {
		t.Fatalf("option 81 = % x\nwant           % x", got, want)
	}

	// A partial name: RFC 4702 section 2.3 lets a client send one, and the
	// difference from the fully qualified form is the terminating root label.
	partial, err := EncodeFQDN(FQDNFlagS|FQDNFlagE, "host")
	if err != nil {
		t.Fatalf("EncodeFQDN(partial): %v", err)
	}
	if string(partial) != string([]byte{0x05, 0, 0, 4, 'h', 'o', 's', 't'}) {
		t.Fatalf("partial name = % x", partial)
	}

	// E clear is the deprecated ASCII form, and the name must then NOT be in
	// label form. Encoding canonically while the E bit says ASCII is a
	// message no server can read.
	ascii, err := EncodeFQDN(FQDNFlagS, "host.example.test.")
	if err != nil {
		t.Fatalf("EncodeFQDN(ascii): %v", err)
	}
	if string(ascii) != string(append([]byte{0x01, 0, 0}, "host.example.test"...)) {
		t.Fatalf("ascii form = % x", ascii)
	}
}

// TestEncodeFQDNRefusesFlagsAClientMayNotSend drives each of RFC 4702 section
// 2.1's three client-side prohibitions ALONE, so a guard that only catches one
// of them cannot hide behind the others.
func TestEncodeFQDNRefusesFlagsAClientMayNotSend(t *testing.T) {
	cases := map[string]uint8{
		"O set by a client": FQDNFlagE | FQDNFlagO,
		"N and S together":  FQDNFlagE | FQDNFlagN | FQDNFlagS,
		"MBZ nibble set":    FQDNFlagE | 0x10,
	}
	for name, flags := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := EncodeFQDN(flags, "host."); !errors.Is(err, ErrBadFQDNFlags) {
				t.Fatalf("err = %v, want ErrBadFQDNFlags", err)
			}
		})
	}
	// The preservation control: N alone, without S, is legal — a client
	// asking the server to do no updates at all.
	if _, err := EncodeFQDN(FQDNFlagE|FQDNFlagN, "host."); err != nil {
		t.Fatalf("N without S was refused: %v", err)
	}
}

// TestEncodeFQDNRefusesUnencodableNames.
// TestEncodeFQDNBoundsBothForms is review round 1's third finding: the length
// bound lived inside the canonical encoder, so with the E bit CLEAR nothing
// bounded the option at all. A name of 299 octets was accepted here, accepted
// by proto.New, and then refused by Encode on every outgoing message — a
// client that reports a broken transport rather than a bad name.
//
// The rows are the same name under both forms, and the preservation control
// below them is a name that still fits: a bound that refuses everything would
// pass the first half of this test.
func TestEncodeFQDNBoundsBothForms(t *testing.T) {
	over := strings.Repeat("abcdefghij.", 30) // 330 octets before either encoding
	for name, flags := range map[string]uint8{
		"canonical":      FQDNFlagE | FQDNFlagS,
		"ascii, E clear": FQDNFlagS,
	} {
		t.Run(name, func(t *testing.T) {
			v, err := EncodeFQDN(flags, over)
			if !errors.Is(err, ErrBadName) {
				t.Fatalf("err = %v, want ErrBadName for a %d-octet name that cannot fit option 81", err, len(over))
			}
			if v != nil {
				t.Fatalf("got %d octets back beside the error", len(v))
			}
		})
	}

	fits := strings.Repeat("abcdefghij.", 20) + "example.test."
	for name, flags := range map[string]uint8{
		"canonical":      FQDNFlagE | FQDNFlagS,
		"ascii, E clear": FQDNFlagS,
	} {
		t.Run("still encodes/"+name, func(t *testing.T) {
			v, err := EncodeFQDN(flags, fits)
			if err != nil {
				t.Fatalf("EncodeFQDN: %v", err)
			}
			if len(v) > 255 {
				t.Fatalf("the option is %d octets, over the 255 a single instance carries", len(v))
			}
		})
	}

	// THE EDGE, in both directions, because 330 and 233 pin neither. Review
	// rounds 1 through 4 all reported that moving the bound to 254 or to 256
	// survives this test, and it did: a name that is 75 octets too long is
	// refused by any of the three, and one that is 22 octets short is accepted
	// by any of the three.
	//
	// So the two rows below are the LAST accepted length and the FIRST refused
	// one, per encoding, and they are computed from the encoding rather than
	// written as literals. A single option instance carries 255 octets; the
	// flags octet and the two RCODEs are three of them.
	//
	//	ascii     len(out) = 3 + len(name)          -> 252 fits, 253 does not
	//	canonical len(out) = 3 + len(name) + 1      -> 251 fits, 252 does not
	//
	// The extra octet in the canonical form is the length prefix of the first
	// label: k labels of total length L separated by k-1 dots encode to
	// k + (L - (k-1)) = L + 1 octets when the name is not fully qualified.
	for _, edge := range []struct {
		what    string
		flags   uint8
		lastOK  int
		firstNo int
	}{
		{"canonical", FQDNFlagE | FQDNFlagS, 251, 252},
		{"ascii, E clear", FQDNFlagS, 252, 253},
	} {
		t.Run("the exact edge/"+edge.what, func(t *testing.T) {
			ok := nameOfLen(t, edge.lastOK)
			v, err := EncodeFQDN(edge.flags, ok)
			if err != nil {
				t.Fatalf("a %d-octet name was refused: %v", len(ok), err)
			}
			if len(v) != 255 {
				t.Fatalf("a %d-octet name makes a %d-octet option; this row is meant to sit exactly ON the 255-octet edge and does not, so it pins nothing",
					len(ok), len(v))
			}

			no := nameOfLen(t, edge.firstNo)
			v, err = EncodeFQDN(edge.flags, no)
			if !errors.Is(err, ErrBadName) {
				t.Fatalf("a %d-octet name makes a 256-octet option and must be refused; err = %v, %d octet(s) returned",
					len(no), err, len(v))
			}
			if v != nil {
				t.Fatalf("got %d octets back beside the error", len(v))
			}
		})
	}
}

// nameOfLen builds a syntactically valid domain name of exactly n characters:
// labels of at most 63 octets, no empty label, and no trailing dot, since a
// trailing dot adds the root label and would move the encoded length by one.
//
// It fails the test rather than returning something close, because a helper
// that silently returns the wrong length turns an edge row into a row about
// some other number.
func nameOfLen(t *testing.T, n int) string {
	t.Helper()
	if n < 1 {
		t.Fatalf("nameOfLen(%d): a name has at least one octet", n)
	}
	var b strings.Builder
	for b.Len() < n {
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		for i := 0; i < 50 && b.Len() < n; i++ {
			b.WriteByte('a')
		}
	}
	out := b.String()
	if strings.HasSuffix(out, ".") {
		out = out[:len(out)-1] + "a"
	}
	if len(out) != n {
		t.Fatalf("nameOfLen(%d) built %d octets", n, len(out))
	}
	for _, label := range strings.Split(out, ".") {
		if label == "" || len(label) > 63 {
			t.Fatalf("nameOfLen(%d) built a %d-octet label, which RFC 1035 does not allow", n, len(label))
		}
	}
	return out
}

func TestEncodeFQDNRefusesUnencodableNames(t *testing.T) {
	long := ""
	for i := 0; i < 64; i++ {
		long += "a"
	}
	cases := map[string]string{
		"empty label":    "host..example.",
		"64-octet label": long + ".example.",
		"over 252 octets": func() string {
			s := ""
			for i := 0; i < 30; i++ {
				s += "abcdefghij."
			}
			return s
		}(),
	}
	for name, n := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := EncodeFQDN(FQDNFlagE|FQDNFlagS, n); !errors.Is(err, ErrBadName) {
				t.Fatalf("err = %v, want ErrBadName", err)
			}
		})
	}
}

// TestClasslessRoutesReadsOption249ThroughTheRFC3442ExampleTable runs the
// same rows as TestClasslessRoutesUsesTheRFC3442ExampleTable through option
// 249, which has 121's wire format: one decoder, the same masking
// (claymore666/docker-net-dhcp#1030).
func TestClasslessRoutesReadsOption249ThroughTheRFC3442ExampleTable(t *testing.T) {
	gw := "192.168.99.1"
	cases := []struct {
		name       string
		descriptor []byte
		want       string
	}{
		{"default route", []byte{0}, "0.0.0.0/0"},
		{"10.0.0.0/8", []byte{8, 10}, "10.0.0.0/8"},
		{"10.0.0.0/24", []byte{24, 10, 0, 0}, "10.0.0.0/24"},
		{"10.17.0.0/16", []byte{16, 10, 17}, "10.17.0.0/16"},
		{"10.27.129.0/24", []byte{24, 10, 27, 129}, "10.27.129.0/24"},
		{"10.229.0.128/25", []byte{25, 10, 229, 0, 128}, "10.229.0.128/25"},
		{"10.198.122.47/32", []byte{32, 10, 198, 122, 47}, "10.198.122.47/32"},
		{"129.210.177.132/25 masked", []byte{25, 129, 210, 177, 132}, "129.210.177.128/25"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := Options{OptMSClasslessStaticRte: append(append([]byte(nil), c.descriptor...), p4(gw)...)}
			got, err := o.ClasslessRoutes()
			if err != nil {
				t.Fatalf("ClasslessRoutes: %v", err)
			}
			if len(got) != 1 || got[0].Dest.String() != c.want || got[0].Router != netip.MustParseAddr(gw) {
				t.Fatalf("routes = %v, want %s via %s", got, c.want, gw)
			}
		})
	}
}

// TestClasslessRoutesPrefersOption121OverOption249: both present, 121's
// routes come back and 249's do not.
func TestClasslessRoutesPrefersOption121OverOption249(t *testing.T) {
	o := Options{
		OptClasslessStaticRte:   append([]byte{24, 10, 1, 0}, p4("192.168.99.1")...),
		OptMSClasslessStaticRte: append([]byte{24, 10, 2, 0}, p4("192.168.99.2")...),
	}
	got, err := o.ClasslessRoutes()
	if err != nil {
		t.Fatalf("ClasslessRoutes: %v", err)
	}
	if len(got) != 1 || got[0].Dest.String() != "10.1.0.0/24" {
		t.Fatalf("routes = %v, want option 121's 10.1.0.0/24 alone", got)
	}
	if src := o.ClasslessSource(); src != OptClasslessStaticRte {
		t.Fatalf("ClasslessSource = %v, want 121", src)
	}
}

// TestClasslessRoutesNeverFallsThroughFromAPresentOption121 holds that 121
// present means 249 is ignored: an empty or malformed 121 is an error naming
// 121, never the routes of the 249 beside it.
func TestClasslessRoutesNeverFallsThroughFromAPresentOption121(t *testing.T) {
	good249 := append([]byte{24, 10, 2, 0}, p4("192.168.99.2")...)
	for name, v121 := range map[string][]byte{"empty": {}, "truncated": {24, 10, 0}} {
		t.Run(name, func(t *testing.T) {
			o := Options{OptClasslessStaticRte: v121, OptMSClasslessStaticRte: good249}
			got, err := o.ClasslessRoutes()
			if !errors.Is(err, ErrMalformedRoutes) || got != nil {
				t.Fatalf("routes = %v, err = %v; want no routes and ErrMalformedRoutes", got, err)
			}
			if !strings.Contains(err.Error(), "option 121") || strings.Contains(err.Error(), "249") {
				t.Fatalf("err = %q, want it to name option 121 only", err)
			}
		})
	}
}

// TestClasslessRoutesRefusesAPartialListFromOption249 is
// TestClasslessRoutesRefusesAPartialList through 249 with 121 absent: the same
// refusals, each naming 249.
func TestClasslessRoutesRefusesAPartialListFromOption249(t *testing.T) {
	good := append([]byte{24, 10, 0, 0}, p4("192.168.99.1")...)
	cases := map[string]struct {
		v      []byte
		refusa string
	}{
		"empty option": {[]byte{}, "option 249 is empty"},
		"width over 32, complete length": {
			append(append([]byte(nil), good...), 40, 10, 0, 0, 0, 0, 192, 168, 99, 1),
			"option 249 mask width 40 exceeds 32",
		},
		"truncated router": {append(append([]byte(nil), good...), 24, 10, 1, 0, 192, 168), "option 249 truncated"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := Options{OptMSClasslessStaticRte: c.v}.ClasslessRoutes()
			if !errors.Is(err, ErrMalformedRoutes) || got != nil {
				t.Fatalf("routes = %v, err = %v; want no routes and ErrMalformedRoutes", got, err)
			}
			if !strings.Contains(err.Error(), c.refusa) {
				t.Fatalf("err = %q, want it to contain %q", err, c.refusa)
			}
		})
	}
}

// TestClasslessRoutesWithNeitherOptionIsEmpty is the preservation control:
// no 121 and no 249 is no routes and no error, so option 33 stays reachable.
func TestClasslessRoutesWithNeitherOptionIsEmpty(t *testing.T) {
	got, err := Options{OptStaticRoute: append(p4("10.0.0.0"), p4("192.168.99.1")...)}.ClasslessRoutes()
	if got != nil || err != nil {
		t.Fatalf("routes = %v, err = %v, want neither", got, err)
	}
}

// TestVendorSpecificKeepsOptionFortyThreeVerbatim is RFC 2132 section 8.4's
// opaque blob (claymore666/docker-net-dhcp#1034): present-empty and absent are
// different answers, and the result is a copy the lease's map cannot be reached
// through.
func TestVendorSpecificKeepsOptionFortyThreeVerbatim(t *testing.T) {
	blob := []byte{0x01, 0x04, 0xc0, 0xa8, 0x63, 0x09, 0xff}
	o := Options{OptVendorSpecific: blob}
	got, ok := o.VendorSpecific()
	if !ok || string(got) != string(blob) {
		t.Fatalf("VendorSpecific = %x, %v; want %x, true", got, ok, blob)
	}
	got[0] = 0xee
	if again, _ := o.VendorSpecific(); again[0] != 0x01 || o[OptVendorSpecific][0] != 0x01 {
		t.Fatal("VendorSpecific returned the option's own bytes; a write to the result reached the lease")
	}

	got, ok = (Options{OptVendorSpecific: {}}).VendorSpecific()
	if !ok || len(got) != 0 {
		t.Fatalf("a present, empty option 43 = %x, %v; want empty, true", got, ok)
	}
	got, ok = (Options{}).VendorSpecific()
	if ok || got != nil {
		t.Fatalf("an absent option 43 = %x, %v; want nil, false", got, ok)
	}
	if OptVendorSpecific.String() != "vendor-specific" || OptVIVSO.String() != "vendor-identifying-specific" {
		t.Fatalf("names = %q, %q", OptVendorSpecific, OptVIVSO)
	}
}

// TestVendorIdentifyingDecodesEveryEnterpriseBlock is RFC 3925 section 4's
// layout with two enterprises and a legal zero-length block between them
// (claymore666/docker-net-dhcp#1034): every block, in wire order, none skipped.
func TestVendorIdentifyingDecodesEveryEnterpriseBlock(t *testing.T) {
	o := Options{OptVIVSO: {
		0x00, 0x00, 0x01, 0x7f, 3, 'a', 'b', 'c', // enterprise 383
		0x00, 0x00, 0x00, 0x09, 0, // enterprise 9, no data
		0x00, 0x00, 0x0d, 0xe9, 2, 0xff, 0x00, // enterprise 3561
	}}
	got, err := o.VendorIdentifying()
	if err != nil {
		t.Fatalf("VendorIdentifying: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("VendorIdentifying = %+v, want 3 blocks", got)
	}
	if got[0].Enterprise != 383 || string(got[0].Data) != "abc" {
		t.Errorf("block 0 = %+v", got[0])
	}
	if got[1].Enterprise != 9 || got[1].Data == nil || len(got[1].Data) != 0 {
		t.Errorf("block 1 = %+v, want enterprise 9 with empty data", got[1])
	}
	if got[2].Enterprise != 3561 || string(got[2].Data) != "\xff\x00" {
		t.Errorf("block 2 = %+v", got[2])
	}
	got[0].Data[0] = 'z'
	if o[OptVIVSO][5] != 'a' {
		t.Fatal("a block's Data aliases the option's own bytes")
	}

	// An empty block that ENDS the option is as legal as one in the middle: a
	// guard that wants a data octet after the length refuses it.
	for name, v := range map[string][]byte{
		"empty block alone":         {0, 0, 0, 9, 0},
		"empty block after a block": {0, 0, 0, 7, 1, 0xaa, 0, 0, 0, 9, 0},
	} {
		blocks, err := (Options{OptVIVSO: v}).VendorIdentifying()
		if err != nil || len(blocks) == 0 || blocks[len(blocks)-1].Enterprise != 9 || len(blocks[len(blocks)-1].Data) != 0 {
			t.Errorf("%s: VendorIdentifying = %+v, %v; want a last block of enterprise 9, no data, no error", name, blocks, err)
		}
	}

	for name, o := range map[string]Options{"absent": {}, "present, no blocks": {OptVIVSO: {}}} {
		if got, err := o.VendorIdentifying(); err != nil || got != nil {
			t.Errorf("%s: VendorIdentifying = %v, %v; want nil, nil", name, got, err)
		}
	}
}

// TestVendorIdentifyingRefusesATruncatedBlock holds the all-or-nothing
// contract ErrMalformedRoutes sets for routes (claymore666/docker-net-dhcp#1034):
// a cut-short last block fails the list, and the blocks before it are not
// handed back as if they were the whole option.
func TestVendorIdentifyingRefusesATruncatedBlock(t *testing.T) {
	good := []byte{0, 0, 0, 9, 1, 0xaa}
	for name, tail := range map[string][]byte{
		"data shorter than its length": {0, 0, 0, 10, 4, 1, 2},
		"enterprise without a length":  {0, 0, 0, 10},
		"three octets of enterprise":   {0, 0, 10},
		"one stray octet":              {0},
	} {
		o := Options{OptVIVSO: append(append([]byte(nil), good...), tail...)}
		got, err := o.VendorIdentifying()
		if !errors.Is(err, ErrMalformedVendor) {
			t.Errorf("%s: err = %v, want ErrMalformedVendor", name, err)
		}
		if got != nil {
			t.Errorf("%s: a partial list %+v came back with the error", name, got)
		}
	}
}

// TestVendorIdentifyingReadsBlocksAcrossRepeatedInstances is RFC 3396's join
// seen from option 125 (claymore666/docker-net-dhcp#1034): a block longer than
// one option's 255 octets arrives as two instances, and the decoder must have
// joined them before VendorIdentifying reads the length.
func TestVendorIdentifyingReadsBlocksAcrossRepeatedInstances(t *testing.T) {
	o := Options{}
	raw := []byte{byte(OptVIVSO), 6, 0, 0, 0, 9, 3, 'x', byte(OptVIVSO), 2, 'y', 'z', byte(OptEnd)}
	if err := parseOptions(raw, o); err != nil {
		t.Fatalf("parseOptions: %v", err)
	}
	got, err := o.VendorIdentifying()
	if err != nil || len(got) != 1 || got[0].Enterprise != 9 || string(got[0].Data) != "xyz" {
		t.Fatalf("VendorIdentifying = %+v, %v; want one block of enterprise 9 with xyz", got, err)
	}
}
