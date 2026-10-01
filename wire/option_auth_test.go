// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package wire

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"testing"
)

// RFC 6704 section 3.1 Forcerenew Nonce Authentication on the wire
// (claymore666/docker-net-dhcp#1119).
//
// There is no published vector, so the frames here are laid out BY OFFSET from
// the RFC 2131 figure and RFC 6704 section 3.1.2, never through Encode or
// forcerenewSpan, and signed with crypto/hmac. This file may import the
// standard library's crypto; the package's own files may not.

const (
	vecOpt90   = 249 // 240 header, option 53 (3 octets), option 54 (6 octets)
	vecValue   = 263 // option 90's code and length, 11 fixed octets, the Type octet
	vecLen     = 300 // a frame padded past END, as a real server's is
	vecReplay  = 0x0102030405060708
	vecDigest  = "f678c3089ffec5a99a427f0d7bf06b0f"
	digestSize = 16
)

// vecNonce is the 128-bit nonce, RFC 6704 section 3.1.3, octets a0 to af (claymore666/docker-net-dhcp#1119).
var vecNonce = func() []byte {
	n := make([]byte, digestSize)
	for i := range n {
		n[i] = 0xA0 + byte(i)
	}
	return n
}()

// frameHdr lays out the RFC 2131 figure 1 fixed header by offset: op 2 (reply),
// htype 1, hlen 6, xid at 4, ciaddr at 12 (a TEST-NET-1 address), chaddr at 28,
// and the magic cookie at 236 (claymore666/docker-net-dhcp#1119).
func frameHdr(total int) []byte {
	f := make([]byte, total)
	f[0], f[1], f[2] = 2, 1, 6
	copy(f[4:8], []byte{0x12, 0x34, 0x56, 0x78})
	copy(f[12:16], []byte{192, 0, 2, 10})
	copy(f[28:34], []byte{2, 0, 0, 0, 0, 1})
	copy(f[236:240], []byte{99, 130, 83, 99})
	return f
}

func opt(code byte, v ...byte) []byte { return append([]byte{code, byte(len(v))}, v...) }

// authVal is RFC 6704 section 3.1.2 written out: protocol 3, algorithm 1,
// RDM 0, the 8-octet replay value big-endian, the Type octet, the 16 octets (claymore666/docker-net-dhcp#1119).
func authVal(typ byte, replay uint64, value []byte) []byte {
	v := []byte{3, 1, 0}
	for s := 56; s >= 0; s -= 8 {
		v = append(v, byte(replay>>uint(s)))
	}
	v = append(v, typ)
	return append(v, value...)
}

func place(f []byte, off int, b []byte) int {
	copy(f[off:], b)
	return off + len(b)
}

// sign writes HMAC-MD5 over f, with the 16 octets at off zeroed, into f at off (claymore666/docker-net-dhcp#1119).
func sign(f []byte, off int, nonce []byte) {
	buf := append([]byte(nil), f...)
	clear(buf[off : off+digestSize])
	// RFC 3118 section 3: hops (octet 3) and giaddr (octets 24 to 27) are zero
	// for the computation, because a relay agent may alter them (claymore666/docker-net-dhcp#1119).
	buf[3] = 0
	clear(buf[24:28])
	m := hmac.New(md5.New, nonce)
	m.Write(buf)
	copy(f[off:], m.Sum(nil))
}

// vecFrame is a FORCERENEW: option 53 = 9, option 54, option 90, END, padding (claymore666/docker-net-dhcp#1119).
func vecFrame() []byte {
	f := frameHdr(vecLen)
	o := place(f, 240, opt(53, 9))
	o = place(f, o, opt(54, 192, 0, 2, 1))
	if o != vecOpt90 {
		panic("layout moved")
	}
	o = place(f, o, opt(90, authVal(2, vecReplay, make([]byte, digestSize))...))
	f[o] = 255
	sign(f, vecValue, vecNonce)
	return f
}

func TestForcerenewVectorVerifiesAndMatchesAnIndependentDigest(t *testing.T) {
	f := vecFrame()
	if got := hex.EncodeToString(f[vecValue : vecValue+digestSize]); got != vecDigest {
		t.Fatalf("digest %s, want %s (computed once with another implementation over the same layout)", got, vecDigest)
	}
	if err := VerifyForcerenew(f, vecNonce); err != nil {
		t.Fatalf("the vector is refused: %v", err)
	}
	m, err := Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	if typ, ok := m.Type(); !ok || typ != MsgForceRenew {
		t.Fatalf("frame decodes as %v %v, want DHCPFORCERENEW", typ, ok)
	}
	a, ok, err := m.Options.ForcerenewAuth()
	if err != nil || !ok || a.Type != ForcerenewTypeDigest || a.Replay != vecReplay || hex.EncodeToString(a.Value[:]) != vecDigest {
		t.Fatalf("decoded option 90: %+v %v %v", a, ok, err)
	}
	span, err := forcerenewSpan(f)
	if err != nil || span != vecValue {
		t.Fatalf("span %d %v, want %d", span, err, vecValue)
	}
	if !bytes.Equal(f[span:span+digestSize], m.Options[OptAuthentication][12:28]) {
		t.Fatal("span and Decode disagree on where the Value is")
	}
}

func TestForcerenewEveryFlippedBitIsRefusedExceptWhatARelayRewrites(t *testing.T) {
	good := vecFrame()
	relay := func(octet int) bool { return octet == 3 || (octet >= 24 && octet < 28) }
	for bit := 0; bit < len(good)*8; bit++ {
		f := append([]byte(nil), good...)
		f[bit/8] ^= 1 << (bit % 8)
		err := VerifyForcerenew(f, vecNonce)
		if relay(bit/8) != (err == nil) {
			t.Fatalf("flipping bit %d (octet %d): verify returned %v", bit, bit/8, err)
		}
	}
}

func TestForcerenewSignedBeforeARelayTouchedHopsAndGiaddrStillVerifies(t *testing.T) {
	// RFC 3118 section 3: the server signed with both fields zero; the relay
	// then set hops to 1 and giaddr to a TEST-NET-2 address. And the other
	// way round: signed with them set, they read as zero to the computation (claymore666/docker-net-dhcp#1119).
	f := vecFrame()
	f[3] = 1
	copy(f[24:28], []byte{198, 51, 100, 1})
	if err := VerifyForcerenew(f, vecNonce); err != nil {
		t.Fatalf("relay-rewritten frame: %v", err)
	}
	g := frameHdr(vecLen)
	g[3] = 3
	copy(g[24:28], []byte{198, 51, 100, 7})
	o := place(g, 240, opt(53, 9))
	at := o + 2 + 12
	o = place(g, o, opt(90, authVal(2, 1, make([]byte, digestSize))...))
	g[o] = 255
	sign(g, at, vecNonce)
	g[3], g[24] = 0, 0
	if err := VerifyForcerenew(g, vecNonce); err != nil {
		t.Fatalf("frame signed with hops and giaddr set: %v", err)
	}
	// Neighbouring header octets are still covered: ciaddr, yiaddr, siaddr (claymore666/docker-net-dhcp#1119).
	for _, off := range []int{12, 16, 20, 23, 28} {
		h := vecFrame()
		h[off] ^= 1
		if err := VerifyForcerenew(h, vecNonce); !errors.Is(err, ErrForcerenewDigest) {
			t.Fatalf("octet %d: %v, want ErrForcerenewDigest", off, err)
		}
	}
}

func TestForcerenewPadOctetsBeforeTheOptionAreSkipped(t *testing.T) {
	f := frameHdr(vecLen)
	o := place(f, 240, opt(53, 9))
	o += 3 // three pad octets, RFC 2132 section 3.1
	at := o + 2 + 12
	o = place(f, o, opt(90, authVal(2, 1, make([]byte, digestSize))...))
	f[o] = 255
	sign(f, at, vecNonce)
	m, err := Decode(f)
	if err != nil || len(m.Options[OptAuthentication]) != 28 {
		t.Fatalf("Decode: %v", err)
	}
	if err := VerifyForcerenew(f, vecNonce); err != nil {
		t.Fatalf("refused: %v", err)
	}
}

func TestForcerenewOverloadOptionThatIsNotOneOctetIsIgnored(t *testing.T) {
	// Decode reads option 52 only when it is exactly one octet, and a repeat
	// joins into two. The file area is then not read, and the walker must not
	// read it either (claymore666/docker-net-dhcp#1119).
	cases := []struct {
		name string
		opts []byte
	}{
		{"two octets", opt(52, 1, 1)},
		{"two options of one octet", append(opt(52, 1), opt(52, 0)...)},
		{"empty", opt(52)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := frameHdr(vecLen)
			o := place(f, 240, opt(53, 9))
			o = place(f, o, c.opts)
			f[o] = 255
			e := place(f, fileOff, opt(90, authVal(2, 5, make([]byte, digestSize))...))
			f[e] = 255
			sign(f, fileOff+2+12, vecNonce)
			m, err := Decode(f)
			if err != nil {
				t.Fatal(err)
			}
			if _, present := m.Options[OptAuthentication]; present {
				t.Fatal("Decode read the file area")
			}
			if err := VerifyForcerenew(f, vecNonce); !errors.Is(err, ErrForcerenewAuth) {
				t.Fatalf("got %v, want ErrForcerenewAuth", err)
			}
		})
	}
}

func TestForcerenewWrongNonceAndForgedDigestsAreRefused(t *testing.T) {
	f := vecFrame()
	other := append([]byte(nil), vecNonce...)
	other[15] ^= 1
	if err := VerifyForcerenew(f, other); !errors.Is(err, ErrForcerenewDigest) {
		t.Fatalf("one bit off in the nonce: %v", err)
	}
	z := vecFrame()
	clear(z[vecValue : vecValue+digestSize])
	if err := VerifyForcerenew(z, vecNonce); !errors.Is(err, ErrForcerenewDigest) {
		t.Fatalf("all-zero digest: %v", err)
	}
}

func TestForcerenewNonceOfAnotherLengthIsRefusedBeforeAnyDigest(t *testing.T) {
	// HMAC with an empty key is defined, so a peer can forge a digest for a
	// verifier that accepts an empty nonce. Sign the frame that way and hand it
	// over: it must still be refused (claymore666/docker-net-dhcp#1119).
	f := vecFrame()
	sign(f, vecValue, []byte{})
	for _, n := range [][]byte{nil, {}, vecNonce[:15], append(append([]byte(nil), vecNonce...), 0)} {
		if err := VerifyForcerenew(f, n); !errors.Is(err, ErrForcerenewNonce) {
			t.Fatalf("%d-octet nonce: %v, want ErrForcerenewNonce", len(n), err)
		}
	}
	// The refusal comes first: garbage octets do not change which error (claymore666/docker-net-dhcp#1119).
	if err := VerifyForcerenew(nil, nil); !errors.Is(err, ErrForcerenewNonce) {
		t.Fatalf("no frame, no nonce: %v", err)
	}
}

func TestForcerenewIsVerifiedOverTheOctetsThatArrived(t *testing.T) {
	// A server may send its options in any order and add options this library
	// does not know. The digest is over what it sent (claymore666/docker-net-dhcp#1119).
	f := frameHdr(vecLen)
	o := place(f, 240, opt(90, authVal(2, 7, make([]byte, digestSize))...))
	at := 240 + 2 + 12
	o = place(f, o, opt(200, 1, 2, 3))
	o = place(f, o, opt(54, 192, 0, 2, 1))
	o = place(f, o, opt(53, 9))
	f[o] = 255
	sign(f, at, vecNonce)
	if err := VerifyForcerenew(f, vecNonce); err != nil {
		t.Fatalf("descending order with an unknown option: %v", err)
	}
	m, err := Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	if typ, _ := m.Type(); typ != MsgForceRenew {
		t.Fatalf("decoded type %v", typ)
	}
}

func TestForcerenewOverAnEncodeOutput(t *testing.T) {
	zero, err := EncodeForcerenewAuth(ForcerenewTypeDigest, make([]byte, digestSize), 42)
	if err != nil {
		t.Fatal(err)
	}
	m := &Message{Op: BootReply, HType: HTypeEthernet, CHAddr: []byte{2, 0, 0, 0, 0, 1}, Options: Options{
		OptServerID:       {192, 0, 2, 1},
		OptAuthentication: zero,
	}}
	m.SetType(MsgForceRenew)
	f, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	// Ascending: 53 (3 octets), 54 (6), then 90, as vecOpt90 counts (claymore666/docker-net-dhcp#1119).
	if f[vecOpt90] != 90 {
		t.Fatalf("option 90 is not at %d: %x", vecOpt90, f[vecOpt90])
	}
	sign(f, vecValue, vecNonce)
	if err := VerifyForcerenew(f, vecNonce); err != nil {
		t.Fatalf("an Encode output signed by offset is refused: %v", err)
	}
}

// areaFrame puts option 90 at areaOff (the file or sname area), an overload
// option carrying ov in the options area, and signs it (claymore666/docker-net-dhcp#1119).
func areaFrame(ov byte, areaOff int) []byte {
	f := frameHdr(vecLen)
	o := place(f, 240, opt(53, 9))
	o = place(f, o, opt(52, ov))
	f[o] = 255
	e := place(f, areaOff, opt(90, authVal(2, 5, make([]byte, digestSize))...))
	f[e] = 255
	sign(f, areaOff+2+12, vecNonce)
	return f
}

func TestForcerenewOptionInAnOverloadedAreaVerifies(t *testing.T) {
	cases := []struct {
		name string
		ov   byte
		off  int
	}{
		{"file, overload 1", 1, fileOff},
		{"sname, overload 2", 2, snameOff},
		{"file, overload 3", 3, fileOff},
		{"sname, overload 3", 3, snameOff},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := areaFrame(c.ov, c.off)
			m, err := Decode(f)
			if err != nil {
				t.Fatal(err)
			}
			if len(m.Options[OptAuthentication]) != 28 {
				t.Fatalf("Decode does not see the option: %d octets", len(m.Options[OptAuthentication]))
			}
			if err := VerifyForcerenew(f, vecNonce); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
}

func TestForcerenewOptionInAnAreaNobodyReadsIsAbsent(t *testing.T) {
	cases := []struct {
		name string
		ov   byte
		off  int
	}{
		{"file, no overload", 0, fileOff},
		{"sname, no overload", 0, snameOff},
		{"sname, overload names file", 1, snameOff},
		{"file, overload names sname", 2, fileOff},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := areaFrame(c.ov, c.off)
			m, err := Decode(f)
			if err != nil {
				t.Fatal(err)
			}
			if _, present := m.Options[OptAuthentication]; present {
				t.Fatal("Decode reads an area the overload option does not name")
			}
			if err := VerifyForcerenew(f, vecNonce); !errors.Is(err, ErrForcerenewAuth) {
				t.Fatalf("got %v, want ErrForcerenewAuth", err)
			}
		})
	}
}

func TestForcerenewTwoAuthenticationOptionsAreRefused(t *testing.T) {
	// Decode concatenates a repeated option into one 56-octet value. A verifier
	// that zeroed only the first instance would accept a second that carries the
	// digest (claymore666/docker-net-dhcp#1119).
	f := frameHdr(vecLen + 40)
	o := place(f, 240, opt(53, 9))
	first := o + 2 + 12
	o = place(f, o, opt(90, authVal(2, 1, make([]byte, digestSize))...))
	second := o + 2 + 12
	o = place(f, o, opt(90, authVal(2, 1, make([]byte, digestSize))...))
	f[o] = 255
	for _, at := range []int{first, second} {
		sign(f, at, vecNonce)
		if err := VerifyForcerenew(f, vecNonce); !errors.Is(err, ErrForcerenewAuth) {
			t.Fatalf("digest in instance at %d: got %v, want ErrForcerenewAuth", at, err)
		}
	}
	m, err := Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(m.Options[OptAuthentication]); n != 56 {
		t.Fatalf("Decode joined the two into %d octets, want 56", n)
	}
	if _, ok, err := m.Options.ForcerenewAuth(); !ok || !errors.Is(err, ErrForcerenewAuth) {
		t.Fatalf("the joined value: %v %v", ok, err)
	}
}

func TestForcerenewAnEmptyInstanceBesideAGoodOneIsRefused(t *testing.T) {
	// Decode reads an empty option 90 and a good one as one good value. The
	// walker counts two and refuses, which is the safe side of the difference (claymore666/docker-net-dhcp#1119).
	f := frameHdr(vecLen)
	o := place(f, 240, opt(53, 9))
	o = place(f, o, opt(90))
	at := o + 2 + 12
	o = place(f, o, opt(90, authVal(2, 1, make([]byte, digestSize))...))
	f[o] = 255
	sign(f, at, vecNonce)
	m, err := Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := m.Options.ForcerenewAuth(); !ok || err != nil {
		t.Fatalf("Decode does not read it as one good option: %v %v", ok, err)
	}
	if err := VerifyForcerenew(f, vecNonce); !errors.Is(err, ErrForcerenewAuth) {
		t.Fatalf("got %v, want ErrForcerenewAuth", err)
	}
}

func TestForcerenewOneInstanceInEachAreaIsRefused(t *testing.T) {
	f := areaFrame(1, fileOff)
	o := 240 + 3 + 3
	o = place(f, o, opt(90, authVal(2, 5, make([]byte, digestSize))...))
	f[o] = 255
	sign(f, fileOff+2+12, vecNonce)
	if err := VerifyForcerenew(f, vecNonce); !errors.Is(err, ErrForcerenewAuth) {
		t.Fatalf("got %v, want ErrForcerenewAuth", err)
	}
}

func TestForcerenewNonceTypeCannotAuthenticateAMessage(t *testing.T) {
	f := frameHdr(vecLen)
	o := place(f, 240, opt(53, 9))
	at := o + 2 + 12
	o = place(f, o, opt(90, authVal(1, 1, make([]byte, digestSize))...))
	f[o] = 255
	sign(f, at, vecNonce)
	if err := VerifyForcerenew(f, vecNonce); !errors.Is(err, ErrForcerenewAuth) {
		t.Fatalf("a Type 1 option with a good digest: %v, want ErrForcerenewAuth", err)
	}
}

func TestForcerenewShapeFaultsAreRefusedAsShapeNotAsDigest(t *testing.T) {
	good := authVal(2, 1, make([]byte, digestSize))
	with := func(edit func(v []byte) []byte) []byte { return edit(append([]byte(nil), good...)) }
	cases := []struct {
		name string
		v    []byte
	}{
		{"protocol 0", with(func(v []byte) []byte { v[0] = 0; return v })},
		{"protocol 1", with(func(v []byte) []byte { v[0] = 1; return v })},
		{"protocol 2", with(func(v []byte) []byte { v[0] = 2; return v })},
		{"protocol 4", with(func(v []byte) []byte { v[0] = 4; return v })},
		{"algorithm 0", with(func(v []byte) []byte { v[1] = 0; return v })},
		{"algorithm 2", with(func(v []byte) []byte { v[1] = 2; return v })},
		{"RDM 1", with(func(v []byte) []byte { v[2] = 1; return v })},
		{"type 0", with(func(v []byte) []byte { v[11] = 0; return v })},
		{"type 3", with(func(v []byte) []byte { v[11] = 3; return v })},
		{"information 0 octets", good[:11]},
		{"information 16 octets", good[:27]},
		{"information 18 octets", append(append([]byte(nil), good...), 0)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, ok, err := (Options{OptAuthentication: c.v}).ForcerenewAuth(); !ok || !errors.Is(err, ErrForcerenewAuth) {
				t.Fatalf("Options: %v %v", ok, err)
			}
			f := frameHdr(vecLen)
			o := place(f, 240, opt(53, 9))
			o = place(f, o, opt(90, c.v...))
			f[o] = 255
			// Never signed: a shape fault must be named before the digest is
			// looked at, or a counter of digest failures counts the wrong thing (claymore666/docker-net-dhcp#1119).
			if err := VerifyForcerenew(f, vecNonce); !errors.Is(err, ErrForcerenewAuth) {
				t.Fatalf("Verify: %v, want ErrForcerenewAuth", err)
			}
		})
	}
}

func TestForcerenewEveryPrefixOfTheOptionValueIsRefused(t *testing.T) {
	v := authVal(2, 1, make([]byte, digestSize))
	for n := 0; n < len(v); n++ {
		a, ok, err := (Options{OptAuthentication: v[:n]}).ForcerenewAuth()
		if !ok || !errors.Is(err, ErrForcerenewAuth) || a != (ForcerenewAuth{}) {
			t.Fatalf("prefix %d: %+v %v %v", n, a, ok, err)
		}
	}
	if _, ok, err := (Options{}).ForcerenewAuth(); ok || err != nil {
		t.Fatalf("absent: %v %v", ok, err)
	}
}

func TestForcerenewEveryPrefixOfTheFrameIsRefusedWithoutAPanic(t *testing.T) {
	good := vecFrame()
	for n := 0; n < len(good); n++ {
		if err := VerifyForcerenew(good[:n], vecNonce); err == nil {
			t.Fatalf("a %d-octet prefix verifies", n)
		}
	}
}

func TestForcerenewReplayValueRoundTripsAndIsBigEndian(t *testing.T) {
	for _, r := range []uint64{0, 1, 1<<63 + 1, 1<<64 - 1, vecReplay} {
		v, err := EncodeForcerenewAuth(ForcerenewTypeNonce, vecNonce, r)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(v, authVal(1, r, vecNonce)) {
			t.Fatalf("replay %d encodes as %x, the RFC layout is %x", r, v, authVal(1, r, vecNonce))
		}
		a, ok, err := (Options{OptAuthentication: v}).ForcerenewAuth()
		if err != nil || !ok || a.Replay != r || a.Type != ForcerenewTypeNonce || !bytes.Equal(a.Value[:], vecNonce) {
			t.Fatalf("replay %d: %+v %v %v", r, a, ok, err)
		}
	}
	v, _ := EncodeForcerenewAuth(ForcerenewTypeDigest, make([]byte, digestSize), vecReplay)
	if !bytes.Equal(v[:12], []byte{3, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 2}) {
		t.Fatalf("fixed part %x", v[:12])
	}
}

func TestEncodeForcerenewAuthRefusesWhatItCouldNotReadBack(t *testing.T) {
	for _, n := range []int{0, 15, 17, 32} {
		if _, err := EncodeForcerenewAuth(ForcerenewTypeNonce, make([]byte, n), 1); !errors.Is(err, ErrForcerenewNonce) {
			t.Fatalf("%d-octet value: %v", n, err)
		}
	}
	for _, typ := range []uint8{0, 3, 255} {
		if _, err := EncodeForcerenewAuth(typ, make([]byte, digestSize), 1); !errors.Is(err, ErrForcerenewAuth) {
			t.Fatalf("type %d: %v", typ, err)
		}
	}
}

func TestForcerenewOctetsAfterENDAreNotOptions(t *testing.T) {
	// Decode stops at END. A second option 90 in the padding is not an option,
	// so the frame carries one and verifies; a walker that read on would count
	// two and refuse a good message (claymore666/docker-net-dhcp#1119).
	f := vecFrame()
	place(f, 280, opt(90, authVal(2, 9, make([]byte, digestSize))...))
	sign(f, vecValue, vecNonce)
	m, err := Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(m.Options[OptAuthentication]); n != 28 {
		t.Fatalf("Decode read %d octets of option 90, want 28", n)
	}
	if err := VerifyForcerenew(f, vecNonce); err != nil {
		t.Fatalf("refused: %v", err)
	}
}

func TestForcerenewAnEndlessAreaIsWalkedToItsEdge(t *testing.T) {
	// No END in the options area: Decode reads to the end of the frame, and so
	// does the walker (claymore666/docker-net-dhcp#1119).
	f := frameHdr(vecOpt90 + 30)
	o := place(f, 240, opt(53, 9))
	o = place(f, o, opt(54, 192, 0, 2, 1))
	place(f, o, opt(90, authVal(2, 1, make([]byte, digestSize))...))
	sign(f, vecValue, vecNonce)
	if _, err := Decode(f); err != nil {
		t.Fatal(err)
	}
	if err := VerifyForcerenew(f, vecNonce); err != nil {
		t.Fatalf("refused: %v", err)
	}
}

func TestForcerenewSpanRefusesAFrameThatIsNotOne(t *testing.T) {
	if _, err := forcerenewSpan(make([]byte, HeaderLen-1)); !errors.Is(err, ErrShort) {
		t.Fatalf("short: %v", err)
	}
	f := vecFrame()
	f[236] = 0
	if _, err := forcerenewSpan(f); !errors.Is(err, ErrBadCookie) {
		t.Fatalf("cookie: %v", err)
	}
	g := frameHdr(vecLen)
	place(g, 240, opt(53, 9))
	g[243] = 255
	if _, err := forcerenewSpan(g); !errors.Is(err, ErrForcerenewAuth) {
		t.Fatalf("no option 90: %v", err)
	}
}

// FuzzForcerenewSpan holds the raw walker to Decode: for any octets both accept,
// they agree on which 16 octets are the Value, and a message Decode reads as
// one digest-type option 90 is one the walker finds, unless the walker refuses it
// for the option's own shape or count (claymore666/docker-net-dhcp#1119).
func FuzzForcerenewSpan(f *testing.F) {
	good := vecFrame()
	f.Add(good)
	for _, n := range []int{0, 10, HeaderLen - 1, HeaderLen, 249, 262, 263, 279, 280, 299} {
		f.Add(good[:n])
	}
	f.Add(areaFrame(1, fileOff))
	f.Add(areaFrame(2, snameOff))
	f.Add(areaFrame(3, fileOff))
	f.Add(areaFrame(0, fileOff))
	f.Fuzz(func(t *testing.T, raw []byte) {
		span, spanErr := forcerenewSpan(raw)
		verErr := VerifyForcerenew(raw, vecNonce)
		if verErr == nil && spanErr != nil {
			t.Fatalf("verified with no span: %v", spanErr)
		}
		m, decErr := Decode(raw)
		if decErr != nil {
			return
		}
		v := m.Options[OptAuthentication]
		if spanErr == nil {
			if span < 0 || span+digestSize > len(raw) {
				t.Fatalf("span %d out of range of %d", span, len(raw))
			}
			if len(v) != 28 || !bytes.Equal(raw[span:span+digestSize], v[12:28]) {
				t.Fatalf("walker and Decode disagree: span %d, Decode value %x", span, v)
			}
			return
		}
		// A refusal for the option's own shape or count is stricter than Decode
		// on purpose: an empty first instance and a good second read as one
		// good value there, and the walker sees two. Every other refusal is a
		// disagreement about the octets, which is the bug this holds against (claymore666/docker-net-dhcp#1119).
		if errors.Is(spanErr, ErrForcerenewAuth) {
			return
		}
		if a, ok, err := m.Options.ForcerenewAuth(); ok && err == nil && a.Type == ForcerenewTypeDigest {
			t.Fatalf("Decode reads a digest-type option 90 the walker refused: %v", spanErr)
		}
	})
}
