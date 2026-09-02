package wire

import (
	"errors"
	"net/netip"
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
func TestClasslessRoutesRefusesAPartialList(t *testing.T) {
	good := append([]byte{24, 10, 0, 0}, p4("192.168.99.1")...)
	cases := map[string][]byte{
		"empty option":        {},
		"width over 32":       append(append([]byte(nil), good...), 33, 10, 0, 0, 0, 192, 168, 99, 1),
		"truncated router":    append(append([]byte(nil), good...), 24, 10, 1, 0, 192, 168),
		"truncated subnet":    append(append([]byte(nil), good...), 24, 10),
		"trailing width byte": append(append([]byte(nil), good...), 16),
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := Options{OptClasslessStaticRte: v}.ClasslessRoutes()
			if !errors.Is(err, ErrMalformedRoutes) {
				t.Fatalf("err = %v, want ErrMalformedRoutes", err)
			}
			if got != nil {
				t.Fatalf("got %v routes back from a malformed option; a partial routing table is a host that silently cannot reach one destination", got)
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
