// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// DHCPFORCERENEW (RFC 3203) with Forcerenew Nonce Authentication (RFC 6704),
// driven in the pure ring (claymore666/docker-net-dhcp#1119). The digest of
// every frame here is computed by this file from the RFC's construction
// (HMAC-MD5 over the octets, the digest field zeroed, hops and giaddr zeroed)
// and not by the library's own signer, so a verifier that agrees with a
// signer that is wrong in the same way does not pass. The fixtures come from
// fakes_test.go alone.

const (
	frServer = "192.168.99.1"
	frAddr   = "192.168.99.50"
	frOther  = "192.168.99.51"
)

var (
	frNonce  = []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
	frNonce2 = []byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf}
)

func frAuthVal(typ byte, replay uint64, value []byte) []byte {
	v := []byte{3, 1, 0}
	for s := 56; s >= 0; s -= 8 {
		v = append(v, byte(replay>>uint(s)))
	}
	v = append(v, typ)
	return append(v, value...)
}

// frSpec is one FORCERENEW frame, field by field; its zero value is not
// useful, frNew gives the frame the server would send to the BOUND fixture.
type frSpec struct {
	op      byte
	xid     uint32
	hops    byte
	giaddr  [4]byte
	ciaddr  [4]byte
	chaddr  []byte
	msgType byte
	replay  uint64
	nonce   []byte
	typ     byte
	omit90  bool
	rawAuth []byte
	before  []byte // options placed before option 90
	after   []byte // options placed after option 90
}

func frNew(replay uint64) frSpec {
	return frSpec{
		op: 2, xid: 0xFEEDF00D, ciaddr: [4]byte{192, 168, 99, 50},
		chaddr: testCHAddr, msgType: 9, replay: replay, nonce: frNonce, typ: 2,
	}
}

func frOpt(code byte, v ...byte) []byte { return append([]byte{code, byte(len(v))}, v...) }

func (s frSpec) build() []byte {
	f := make([]byte, 300)
	f[0], f[1], f[2], f[3] = s.op, 1, 6, s.hops
	f[4], f[5], f[6], f[7] = byte(s.xid>>24), byte(s.xid>>16), byte(s.xid>>8), byte(s.xid)
	copy(f[12:16], s.ciaddr[:])
	copy(f[24:28], s.giaddr[:])
	copy(f[28:34], s.chaddr)
	copy(f[236:240], []byte{99, 130, 83, 99})
	o := 240
	o += copy(f[o:], frOpt(53, s.msgType))
	o += copy(f[o:], frOpt(54, 192, 168, 99, 1))
	o += copy(f[o:], s.before)
	digestAt := -1
	if !s.omit90 {
		val := s.rawAuth
		if val == nil {
			val = frAuthVal(s.typ, s.replay, make([]byte, 16))
		}
		if len(val) == 28 && val[11] == 2 {
			digestAt = o + 2 + 12
		}
		o += copy(f[o:], frOpt(90, val...))
	}
	o += copy(f[o:], s.after)
	f[o] = 255
	if digestAt >= 0 {
		buf := append([]byte(nil), f...)
		clear(buf[digestAt : digestAt+16])
		buf[3] = 0
		clear(buf[24:28])
		h := hmac.New(md5.New, s.nonce)
		h.Write(buf)
		copy(f[digestAt:], h.Sum(nil))
	}
	return f
}

func frEvent(t *testing.T, raw []byte, dst string) Event {
	t.Helper()
	dec, err := wire.Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var d netip.Addr
	if dst != "" {
		d = netip.MustParseAddr(dst)
	}
	return ReceivedTo(dec, raw, d)
}

func frAuth1(t *testing.T, nonce []byte, replay uint64) []byte {
	t.Helper()
	v, err := wire.EncodeForcerenewAuth(wire.ForcerenewTypeNonce, nonce, replay)
	if err != nil {
		t.Fatalf("EncodeForcerenewAuth: %v", err)
	}
	return v
}

// frAcquire is machineIn(StateBound) with the server's options on the wire:
// the OFFER lists option 145, the ACK carries option 90 type 1 unless nonce is
// nil, in which case neither does.
func frAcquire(t *testing.T, p Params, nonce []byte, replay uint64) *Machine {
	t.Helper()
	m := newMachine(t, p)
	_, acts := m.Step(0, 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	offer := offerFor(disc, frAddr, frServer)
	if nonce != nil {
		offer.Options[wire.OptForcerenewNonce] = wire.EncodeForcerenewNonceCapable()
	}
	_, acts = m.Step(at(1), 2, received(t, offer))
	req := mustSend(t, acts, wire.MsgRequest)
	ack := ackFor(req, frAddr, frServer, 3600)
	if nonce != nil {
		ack.Options[wire.OptAuthentication] = frAuth1(t, nonce, replay)
	}
	m.Step(at(2), 3, received(t, ack))
	if m.State() != StateBound {
		t.Fatalf("fixture reached %s, want BOUND", m.State())
	}
	return m
}

func frBound(t *testing.T) *Machine { return frAcquire(t, testParams(), frNonce, 5) }

// frToRenewing takes a BOUND machine to RENEWING by T1 and returns the request.
func frToRenewing(t *testing.T, m *Machine) *wire.Message {
	t.Helper()
	t1, ok := m.lease.RenewAt()
	if !ok {
		t.Fatal("no T1")
	}
	_, acts := m.Step(t1, 4, TimerFired(TimerRenew))
	if m.State() != StateRenewing {
		t.Fatalf("reached %s, want RENEWING", m.State())
	}
	return mustSend(t, acts, wire.MsgRequest)
}

func frEncoded(t *testing.T, m *wire.Message) *wire.Message {
	t.Helper()
	raw, err := wire.Encode(m)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	dec, err := wire.Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return dec
}

func frJournalText(acts []Action) string {
	var sb strings.Builder
	for _, a := range acts {
		if a.Kind == ActJournal {
			sb.WriteString(a.Note + "\n")
		}
	}
	return sb.String()
}

func frHeld(t *testing.T, m *Machine) Lease {
	t.Helper()
	l, ok := m.Lease()
	if !ok {
		t.Fatal("no lease held")
	}
	return l
}

func frRefusals(m *Machine) map[ForcerenewRefusal]uint64 {
	c := m.ForcerenewCounters()
	out := map[ForcerenewRefusal]uint64{}
	for _, r := range AllForcerenewRefusals() {
		if c.Refused[r] != 0 {
			out[r] = c.Refused[r]
		}
	}
	return out
}

func frWantRefusal(t *testing.T, m *Machine, want ForcerenewRefusal) {
	t.Helper()
	got := frRefusals(m)
	if len(got) != 1 || got[want] != 1 {
		t.Fatalf("refusals = %v, want only %s once", got, want)
	}
	if c := m.ForcerenewCounters(); c.Renewed != 0 || c.AlreadyRenewing != 0 {
		t.Fatalf("a refused frame was also counted as obeyed: %+v", c)
	}
}

// frSend steps one frame addressed to the leased address.
func frSend(t *testing.T, m *Machine, now Instant, s frSpec) (State, []Action) {
	t.Helper()
	return m.Step(now, 9, frEvent(t, s.build(), frAddr))
}

// TestAnAuthenticFORCERENEWRenewsLikeT1 is the accept case and the control for
// every refusal below: the frame the server would send, and the DHCPREQUEST it
// causes is the T1 renewal's, byte for byte (RFC 3203 section 2.2: "the client
// ... SHOULD ... go to the RENEW state").
func TestAnAuthenticFORCERENEWRenewsLikeT1(t *testing.T) {
	forced := frBound(t)
	state, acts := frSend(t, forced, at(100), frNew(6))
	if state != StateRenewing {
		t.Fatalf("state = %s, want RENEWING", state)
	}
	got := mustSend(t, acts, wire.MsgRequest)

	timed := frBound(t)
	t1, _ := timed.lease.RenewAt()
	_, tacts := timed.Step(t1, 9, TimerFired(TimerRenew))
	want := mustSend(t, tacts, wire.MsgRequest)

	if got.CIAddr != want.CIAddr || !bytes.Equal(got.Options[wire.OptMessageType], want.Options[wire.OptMessageType]) {
		t.Fatalf("forced renewal differs from T1's: ciaddr %s vs %s", got.CIAddr, want.CIAddr)
	}
	if got.CIAddr.String() != frAddr {
		t.Fatalf("renewal ciaddr = %s, want the leased address", got.CIAddr)
	}
	for _, code := range []wire.OptionCode{wire.OptServerID, wire.OptRequestedIP} {
		if _, ok := got.Options[code]; ok {
			t.Fatalf("a renewal carried option %d (RFC 2131 table 5)", code)
		}
	}
	if c := forced.ForcerenewCounters(); c.Renewed != 1 || c.RefusedTotal() != 0 {
		t.Fatalf("counters = %+v, want one Renewed", c)
	}
	if l := frHeld(t, forced); l.ForcerenewReplay != 6 || !bytes.Equal(l.ForcerenewNonce, frNonce) {
		t.Fatalf("lease carries nonce %x floor %d, want the nonce and 6", l.ForcerenewNonce, l.ForcerenewReplay)
	}
}

// TestTheRenewalACKAfterAForcedRenewKeepsTheNonceAndTheFloor covers the whole
// round: BOUND, forced to RENEWING, the server's ACK (no option 90, RFC 6704
// section 3.1.3), BOUND again with the nonce and the advanced floor.
func TestTheRenewalACKAfterAForcedRenewKeepsTheNonceAndTheFloor(t *testing.T) {
	m := frBound(t)
	_, acts := frSend(t, m, at(100), frNew(9))
	req := mustSend(t, acts, wire.MsgRequest)
	m.Step(at(101), 10, received(t, ackFor(req, frAddr, frServer, 3600)))
	if m.State() != StateBound {
		t.Fatalf("state = %s, want BOUND", m.State())
	}
	l := frHeld(t, m)
	if !bytes.Equal(l.ForcerenewNonce, frNonce) || l.ForcerenewReplay != 9 {
		t.Fatalf("after the renewal ACK: nonce %x floor %d, want the nonce and 9", l.ForcerenewNonce, l.ForcerenewReplay)
	}
	// The value 9 is spent; 9 again is a replay, 10 is the next frame.
	m.Step(at(102), 11, frEvent(t, frNew(9).build(), frAddr))
	if got := m.ForcerenewCounters().Refused[ForcerenewRefusalReplay]; got != 1 {
		t.Fatalf("a repeated value after the round: Replay refusals = %d, want 1", got)
	}
	if state, _ := frSend(t, m, at(103), frNew(10)); state != StateRenewing {
		t.Fatalf("the next value was refused, state %s", state)
	}
}

// TestTheReplayFloorIsStrict is the floor's boundary: the lease's own value
// and everything under it is refused, one above is accepted (RFC 3118 section
// 5.3, monotonic counter), including at the top of the 64-bit range where a
// signed comparison would flip.
func TestTheReplayFloorIsStrict(t *testing.T) {
	cases := []struct {
		name     string
		floor    uint64
		replay   uint64
		accepted bool
	}{
		{"below", 5, 4, false},
		{"equal", 5, 5, false},
		{"above by one", 5, 6, true},
		{"zero against floor zero", 0, 0, false},
		{"one against floor zero", 0, 1, true},
		{"over 2^63", 5, 1<<63 + 1, true},
		{"floor over 2^63, below it", 1<<63 + 1, 1<<63 - 1, false},
		{"floor over 2^63, above it", 1<<63 + 1, 1<<63 + 2, true},
		{"top of the range", 5, 1<<64 - 1, true},
		{"floor at the top, equal", 1<<64 - 1, 1<<64 - 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := frAcquire(t, testParams(), frNonce, tc.floor)
			state, _ := frSend(t, m, at(100), frNew(tc.replay))
			if tc.accepted {
				if state != StateRenewing || m.ForcerenewCounters().Renewed != 1 {
					t.Fatalf("accepted value refused: state %s, %+v", state, frRefusals(m))
				}
				return
			}
			if state != StateBound {
				t.Fatalf("refused value moved the machine to %s", state)
			}
			frWantRefusal(t, m, ForcerenewRefusalReplay)
			if l := frHeld(t, m); l.ForcerenewReplay != tc.floor {
				t.Fatalf("a refused frame moved the floor to %d", l.ForcerenewReplay)
			}
		})
	}
}

// TestTheSameBytesAreAcceptedOnceAndRefusedOnReplay is the capture-and-resend
// attack: an observer on the link replays the frame that renewed us.
func TestTheSameBytesAreAcceptedOnceAndRefusedOnReplay(t *testing.T) {
	m := frBound(t)
	raw := frNew(6).build()
	state, acts := m.Step(at(100), 9, frEvent(t, raw, frAddr))
	if state != StateRenewing {
		t.Fatalf("first copy: state %s", state)
	}
	req := mustSend(t, acts, wire.MsgRequest)
	m.Step(at(101), 10, received(t, ackFor(req, frAddr, frServer, 3600)))
	if m.State() != StateBound {
		t.Fatalf("round did not finish, state %s", m.State())
	}
	state, acts = m.Step(at(102), 11, frEvent(t, raw, frAddr))
	if state != StateBound || count(acts, ActSend) != 0 {
		t.Fatalf("the replayed copy acted: state %s, %v", state, RenderActions(acts))
	}
	if got := m.ForcerenewCounters().Refused[ForcerenewRefusalReplay]; got != 1 {
		t.Fatalf("Replay refusals = %d, want 1", got)
	}
}

// TestEveryRefusalLeavesTheMachineAsItWas runs one frame per refusal reason
// against a fresh BOUND machine, and asks the same three things of each: the
// state is BOUND, nothing was sent, the floor did not move, and exactly the
// named counter moved. A refusal that also renewed would be the worst way for
// this feature to fail.
func TestEveryRefusalLeavesTheMachineAsItWas(t *testing.T) {
	bad := frNew(6)
	cases := []struct {
		name string
		want ForcerenewRefusal
		raw  func() []byte
		dst  string
	}{
		{"broadcast", ForcerenewRefusalNotUnicast, bad.build, "255.255.255.255"},
		{"subnet-directed broadcast", ForcerenewRefusalNotUnicast, bad.build, "192.168.99.255"},
		{"multicast", ForcerenewRefusalNotUnicast, bad.build, "224.0.0.1"},
		{"unspecified", ForcerenewRefusalNotUnicast, bad.build, "0.0.0.0"},
		{"no destination recorded", ForcerenewRefusalNotUnicast, bad.build, ""},
		{"an IPv6 destination", ForcerenewRefusalNotUnicast, bad.build, "fe80::1"},
		{"another host's unicast", ForcerenewRefusalNotOurAddress, bad.build, frOther},
		{"a request, not a reply", ForcerenewRefusalNotThisClient, func() []byte { s := bad; s.op = 1; return s.build() }, frAddr},
		{"another client's hardware address", ForcerenewRefusalNotThisClient, func() []byte {
			s := bad
			s.chaddr = []byte{2, 0, 0, 0, 0, 9}
			return s.build()
		}, frAddr},
		{"another leased address in ciaddr", ForcerenewRefusalNotThisClient, func() []byte { s := bad; s.ciaddr = [4]byte{192, 168, 99, 51}; return s.build() }, frAddr},
		{"no ciaddr", ForcerenewRefusalNotThisClient, func() []byte { s := bad; s.ciaddr = [4]byte{}; return s.build() }, frAddr},
		{"no option 90", ForcerenewRefusalNoAuth, func() []byte { s := bad; s.omit90 = true; return s.build() }, frAddr},
		{"option 90 type 1 where a digest belongs", ForcerenewRefusalMalformedAuth, func() []byte { s := bad; s.typ = 1; return s.build() }, frAddr},
		{"option 90 type 1 below the floor is a shape refusal first", ForcerenewRefusalMalformedAuth, func() []byte { s := bad; s.typ = 1; s.replay = 1; return s.build() }, frAddr},
		{"wrong protocol", ForcerenewRefusalMalformedAuth, func() []byte {
			s := bad
			v := frAuthVal(2, 6, make([]byte, 16))
			v[0] = 2
			s.rawAuth = v
			return s.build()
		}, frAddr},
		{"wrong algorithm", ForcerenewRefusalMalformedAuth, func() []byte {
			s := bad
			v := frAuthVal(2, 6, make([]byte, 16))
			v[1] = 2
			s.rawAuth = v
			return s.build()
		}, frAddr},
		{"wrong RDM", ForcerenewRefusalMalformedAuth, func() []byte {
			s := bad
			v := frAuthVal(2, 6, make([]byte, 16))
			v[2] = 1
			s.rawAuth = v
			return s.build()
		}, frAddr},
		{"short digest", ForcerenewRefusalMalformedAuth, func() []byte { s := bad; s.rawAuth = frAuthVal(2, 6, make([]byte, 15)); return s.build() }, frAddr},
		{"long digest", ForcerenewRefusalMalformedAuth, func() []byte { s := bad; s.rawAuth = frAuthVal(2, 6, make([]byte, 17)); return s.build() }, frAddr},
		{"a spent replay value is refused as a replay before the digest is read", ForcerenewRefusalReplay, func() []byte { s := bad; s.replay = 1; s.nonce = frNonce2; return s.build() }, frAddr},
		{"digest of the wrong nonce", ForcerenewRefusalBadDigest, func() []byte { s := bad; s.nonce = frNonce2; return s.build() }, frAddr},
		{"one digest byte flipped", ForcerenewRefusalBadDigest, func() []byte {
			raw := bad.build()
			i := bytes.Index(raw, []byte{90, 28}) + 2 + 12
			raw[i] ^= 0x01
			return raw
		}, frAddr},
		{"an octet outside the digest flipped", ForcerenewRefusalBadDigest, func() []byte {
			raw := bad.build()
			raw[8] ^= 0x01
			return raw
		}, frAddr},
		{"replay value rewritten after signing", ForcerenewRefusalBadDigest, func() []byte {
			raw := bad.build()
			raw[bytes.Index(raw, []byte{90, 28})+2+10] ^= 0x10
			return raw
		}, frAddr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := frBound(t)
			raw := tc.raw()
			dec, err := wire.Decode(raw)
			if err != nil {
				t.Fatalf("the codec refused the frame, so the machine never saw it and this row tests nothing: %v", err)
			}
			var d netip.Addr
			if tc.dst != "" {
				d = netip.MustParseAddr(tc.dst)
			}
			state, acts := m.Step(at(100), 9, ReceivedTo(dec, raw, d))
			if state != StateBound {
				t.Fatalf("state = %s", state)
			}
			if n := count(acts, ActSend); n != 0 {
				t.Fatalf("a refused frame sent %d messages", n)
			}
			frWantRefusal(t, m, tc.want)
			if l := frHeld(t, m); l.ForcerenewReplay != 5 {
				t.Fatalf("floor moved to %d", l.ForcerenewReplay)
			}
			if !strings.Contains(frJournalText(acts), "refused") {
				t.Fatalf("a refusal left no journal note: %q", frJournalText(acts))
			}
		})
	}
}

// TestTheXIDOfAFORCERENEWMeansNothing: a server-initiated frame answers no
// transaction of this client, so a machine that gated type 9 on xid would drop
// every real one. Three values, one of which is this machine's own.
func TestTheXIDOfAFORCERENEWMeansNothing(t *testing.T) {
	for _, xid := range []uint32{0, 0xDEADBEEF, 0xFFFFFFFF} {
		m := frBound(t)
		s := frNew(6)
		s.xid = xid
		if state, _ := frSend(t, m, at(100), s); state != StateRenewing {
			t.Fatalf("xid %#x: state %s, %v", xid, state, frRefusals(m))
		}
	}
}

// TestADigestDoesNotDependOnOptionOrderOrOtherOptions signs three layouts of
// one message with this file's own HMAC, so the machine's acceptance is not a
// property of the library's encoder: other options before and after option 90,
// and an option the library has never heard of.
func TestADigestDoesNotDependOnOptionOrderOrOtherOptions(t *testing.T) {
	layouts := map[string]func(*frSpec){
		"an unknown option before":    func(s *frSpec) { s.before = frOpt(224, 1, 2, 3) },
		"an unknown option after":     func(s *frSpec) { s.after = frOpt(225, 9) },
		"a message option and a pad":  func(s *frSpec) { s.before = frOpt(56, 'h', 'i'); s.after = []byte{0, 0} },
		"hops and giaddr set (relay)": func(s *frSpec) { s.hops = 3; s.giaddr = [4]byte{10, 1, 2, 3} },
	}
	for name, mut := range layouts {
		t.Run(name, func(t *testing.T) {
			m := frBound(t)
			s := frNew(6)
			mut(&s)
			if state, _ := frSend(t, m, at(100), s); state != StateRenewing {
				t.Fatalf("an authentic frame was refused: %v", frRefusals(m))
			}
		})
	}
}

// TestOnlyAFrameForTheLeasedAddressIsAccepted: the destination check names the
// address of THIS lease, and an address in the same subnet is not enough.
func TestOnlyAFrameForTheLeasedAddressIsAccepted(t *testing.T) {
	m := frBound(t)
	raw := frNew(6).build()
	// The 4-in-6 spelling of the same address is the same destination.
	dec, _ := wire.Decode(raw)
	state, _ := m.Step(at(100), 9, ReceivedTo(dec, raw, netip.MustParseAddr("::ffff:192.168.99.50")))
	if state != StateRenewing {
		t.Fatalf("4in6 form of the leased address refused: %v", frRefusals(m))
	}
}

// TestAFORCERENEWWithNoNonceIsRefusedForThatReason: a lease whose ACK carried
// no option 90 has nothing to authenticate with, so a frame, signed with any
// key, gets the one answer that tells the operator which server to configure.
func TestAFORCERENEWWithNoNonceIsRefusedForThatReason(t *testing.T) {
	m := frAcquire(t, testParams(), nil, 0)
	state, acts := frSend(t, m, at(100), frNew(6))
	if state != StateBound || count(acts, ActSend) != 0 {
		t.Fatalf("acted with no nonce: %s %v", state, RenderActions(acts))
	}
	frWantRefusal(t, m, ForcerenewRefusalNoNonce)
}

// TestTheNonceIsNotTakenFromTheOffer: RFC 6704 section 3.1.3 puts the nonce in
// the DHCPACK. An option 90 on the OFFER must not be what a later frame is
// checked against.
func TestTheNonceIsNotTakenFromTheOffer(t *testing.T) {
	m := newMachine(t, testParams())
	_, acts := m.Step(0, 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	offer := offerFor(disc, frAddr, frServer)
	offer.Options[wire.OptAuthentication] = frAuth1(t, frNonce2, 3)
	_, acts = m.Step(at(1), 2, received(t, offer))
	req := mustSend(t, acts, wire.MsgRequest)
	m.Step(at(2), 3, received(t, ackFor(req, frAddr, frServer, 3600)))
	frSend(t, m, at(100), func() frSpec { s := frNew(6); s.nonce = frNonce2; return s }())
	frWantRefusal(t, m, ForcerenewRefusalNoNonce)
}

// TestAnACKWithoutAValidOption90AfterAnOfferWith145RestartsTheExchange is
// RFC 6704 section 3.1.4: "If the DHCPOFFER carried FORCERENEW_NONCE_CAPABLE
// and the DHCPACK omits a valid DHCP authentication option, the client MUST
// discard the message and return to the INIT state". Each variant of "not a
// valid option 90" is its own case, and the control is the same exchange with
// a valid one.
func TestAnACKWithoutAValidOption90AfterAnOfferWith145RestartsTheExchange(t *testing.T) {
	variants := map[string][]byte{
		"absent":                 nil,
		"a digest, not a nonce":  frAuthVal(2, 3, make([]byte, 16)),
		"wrong protocol":         func() []byte { v := frAuthVal(1, 3, nonceBytes()); v[0] = 0; return v }(),
		"wrong algorithm":        func() []byte { v := frAuthVal(1, 3, nonceBytes()); v[1] = 9; return v }(),
		"wrong RDM":              func() []byte { v := frAuthVal(1, 3, nonceBytes()); v[2] = 5; return v }(),
		"nonce of 15 octets":     frAuthVal(1, 3, nonceBytes()[:15]),
		"nonce of 17 octets":     frAuthVal(1, 3, append(nonceBytes(), 0)),
		"truncated below header": {3, 1, 0},
	}
	for name, val := range variants {
		t.Run(name, func(t *testing.T) {
			m := newMachine(t, testParams())
			_, acts := m.Step(0, 1, Simple(EvStart))
			disc := mustSend(t, acts, wire.MsgDiscover)
			offer := offerFor(disc, frAddr, frServer)
			offer.Options[wire.OptForcerenewNonce] = wire.EncodeForcerenewNonceCapable()
			_, acts = m.Step(at(1), 2, received(t, offer))
			req := mustSend(t, acts, wire.MsgRequest)
			ack := ackFor(req, frAddr, frServer, 3600)
			if val != nil {
				ack.Options[wire.OptAuthentication] = val
			}
			state, acts := m.Step(at(2), 3, received(t, ack))
			if state == StateBound {
				t.Fatalf("the ACK was taken as a lease")
			}
			if _, held := m.Lease(); held {
				t.Fatal("a lease is held from a discarded ACK")
			}
			if state != StateInit && state != StateSelecting {
				t.Fatalf("state = %s, want a restart", state)
			}
			if c := m.ForcerenewCounters(); c.AckRefused != 1 || c.RefusedTotal() != 0 {
				t.Fatalf("counters = %+v, want one AckRefused and no FORCERENEW refusal", c)
			}
			if !strings.Contains(frJournalText(acts), "RFC 6704") {
				t.Fatalf("no journal note: %q", frJournalText(acts))
			}
			if count(acts, ActLeaseAcquired) != 0 {
				t.Fatal("a discarded ACK announced a lease")
			}
		})
	}
	t.Run("control: a valid option 90 is a lease", func(t *testing.T) {
		m := frBound(t)
		if m.ForcerenewCounters().AckRefused != 0 {
			t.Fatal("a valid ACK was counted as refused")
		}
	})
	t.Run("control: an OFFER without 145 puts no demand on the ACK", func(t *testing.T) {
		m := frAcquire(t, testParams(), nil, 0)
		if m.State() != StateBound || m.ForcerenewCounters().AckRefused != 0 {
			t.Fatalf("state %s, %+v", m.State(), m.ForcerenewCounters())
		}
	})
}

func nonceBytes() []byte { return append([]byte(nil), frNonce...) }

// TestTheRestartAfterADiscardedACKIsDelayedByDesync: a server that always
// answers a 145 OFFER with a bare ACK would otherwise be asked again at wire
// speed. With the desync window on, the machine waits.
func TestTheRestartAfterADiscardedACKIsDelayedByDesync(t *testing.T) {
	p := testParams()
	p.DesyncMin = 2 * Second
	p.DesyncMax = 4 * Second
	m := newMachine(t, p)
	_, acts := m.Step(0, 1, Simple(EvStart))
	if count(acts, ActSend) != 0 {
		t.Fatal("the fixture sent before its desync")
	}
	_, acts = m.Step(at(5), 2, TimerFired(TimerDesync))
	disc := mustSend(t, acts, wire.MsgDiscover)
	offer := offerFor(disc, frAddr, frServer)
	offer.Options[wire.OptForcerenewNonce] = wire.EncodeForcerenewNonceCapable()
	_, acts = m.Step(at(6), 3, received(t, offer))
	req := mustSend(t, acts, wire.MsgRequest)
	_, acts = m.Step(at(7), 4, received(t, ackFor(req, frAddr, frServer, 3600)))
	if count(acts, ActSend) != 0 {
		t.Fatalf("the restart sent at once: %v", RenderActions(acts))
	}
	if _, ok := find(acts, ActSetTimer); !ok {
		t.Fatal("the restart armed no timer")
	}
}

// frToRebinding takes a RENEWING machine on to REBINDING at T2.
func frToRebinding(t *testing.T, m *Machine) *wire.Message {
	t.Helper()
	t2, ok := m.lease.RebindAt()
	if !ok {
		t.Fatal("no T2")
	}
	_, acts := m.Step(t2, 5, TimerFired(TimerRebind))
	if m.State() != StateRebinding {
		t.Fatalf("reached %s, want REBINDING", m.State())
	}
	return mustSend(t, acts, wire.MsgRequest)
}

// TestRenewingAndRebindingSpendTheValueAndSendNothing: the lease is already
// being renewed, so an authentic frame advances the floor (so it cannot be
// replayed once BOUND) and restarts nothing. Restarting would let a stream of
// fresh values hold the retransmission timer back for ever.
func TestRenewingAndRebindingSpendTheValueAndSendNothing(t *testing.T) {
	for _, st := range []State{StateRenewing, StateRebinding} {
		t.Run(st.String(), func(t *testing.T) {
			m := frBound(t)
			frToRenewing(t, m)
			if st == StateRebinding {
				frToRebinding(t, m)
			}
			state, acts := frSend(t, m, at(100000), frNew(8))
			if state != st {
				t.Fatalf("state = %s, want it unchanged", state)
			}
			if count(acts, ActSend) != 0 || count(acts, ActSetTimer) != 0 || count(acts, ActCancelTimer) != 0 {
				t.Fatalf("the frame acted: %v", RenderActions(acts))
			}
			c := m.ForcerenewCounters()
			if c.AlreadyRenewing != 1 || c.Renewed != 0 || c.RefusedTotal() != 0 {
				t.Fatalf("counters = %+v, want one AlreadyRenewing", c)
			}
			if l := frHeld(t, m); l.ForcerenewReplay != 8 {
				t.Fatalf("floor = %d, want 8", l.ForcerenewReplay)
			}
			// The same bytes again, and a forged one, are refused.
			frSend(t, m, at(100001), frNew(8))
			bad := frNew(9)
			bad.nonce = frNonce2
			frSend(t, m, at(100002), bad)
			c = m.ForcerenewCounters()
			if c.Refused[ForcerenewRefusalReplay] != 1 || c.Refused[ForcerenewRefusalBadDigest] != 1 || c.AlreadyRenewing != 1 {
				t.Fatalf("counters = %+v", c)
			}
			if l := frHeld(t, m); l.ForcerenewReplay != 8 {
				t.Fatalf("a refused frame moved the floor to %d", l.ForcerenewReplay)
			}
		})
	}
}

// TestAFORCERENEWOutsideTheStatesThatHoldALeaseIsRefused: STOPPED, INIT,
// SELECTING, REQUESTING, REBOOTING and PROBING hold no lease to renew. Each is
// reached through its own door by machineIn, and none of them acts.
func TestAFORCERENEWOutsideTheStatesThatHoldALeaseIsRefused(t *testing.T) {
	for _, st := range []State{StateStopped, StateInit, StateSelecting, StateRequesting, StateRebooting, StateProbing} {
		t.Run(st.String(), func(t *testing.T) {
			m := machineIn(t, st)
			state, acts := m.Step(at(50), 9, frEvent(t, frNew(6).build(), frAddr))
			if state != st || count(acts, ActSend) != 0 || count(acts, ActSetTimer) != 0 {
				t.Fatalf("the frame acted: %s %v", state, RenderActions(acts))
			}
			frWantRefusal(t, m, ForcerenewRefusalWrongState)
		})
	}
}

// TestAnAuthenticFORCERENEWWithNoServerToAskChangesNothing: the one place an
// authentic frame cannot be obeyed. The floor stays where it was, so the frame
// is not spent by a client that did nothing about it.
func TestAnAuthenticFORCERENEWWithNoServerToAskChangesNothing(t *testing.T) {
	m := frBound(t)
	m.lease.ServerID = netip.Addr{}
	state, acts := frSend(t, m, at(100), frNew(6))
	if state != StateBound || count(acts, ActSend) != 0 {
		t.Fatalf("acted with no server: %s %v", state, RenderActions(acts))
	}
	frWantRefusal(t, m, ForcerenewRefusalNoServer)
	if l := frHeld(t, m); l.ForcerenewReplay != 5 {
		t.Fatalf("the floor moved to %d on a frame that was not acted on", l.ForcerenewReplay)
	}
}

// TestTheNonceCarriesAcrossRenewalACKsByTheRulesOfTheRFC walks the rules a
// renewal's ACK has to follow, each against the one it could be confused with.
func TestTheNonceCarriesAcrossRenewalACKsByTheRulesOfTheRFC(t *testing.T) {
	renewWith := func(t *testing.T, mut func(*wire.Message)) *Machine {
		t.Helper()
		m := frBound(t)
		req := frToRenewing(t, m)
		ack := ackFor(req, frAddr, frServer, 3600)
		mut(ack)
		m.Step(at(4000), 12, received(t, ack))
		if m.State() != StateBound {
			t.Fatalf("state = %s, want BOUND", m.State())
		}
		return m
	}
	t.Run("no option 90 keeps both", func(t *testing.T) {
		l := frHeld(t, renewWith(t, func(*wire.Message) {}))
		if !bytes.Equal(l.ForcerenewNonce, frNonce) || l.ForcerenewReplay != 5 {
			t.Fatalf("nonce %x floor %d", l.ForcerenewNonce, l.ForcerenewReplay)
		}
	})
	t.Run("the same nonce with a lower value does not lower the floor", func(t *testing.T) {
		m := renewWith(t, func(a *wire.Message) { a.Options[wire.OptAuthentication] = frAuth1(t, frNonce, 2) })
		if l := frHeld(t, m); l.ForcerenewReplay != 5 {
			t.Fatalf("floor = %d, want it held at 5", l.ForcerenewReplay)
		}
		if state, _ := frSend(t, m, at(4001), frNew(4)); state != StateBound {
			t.Fatal("a value below the old floor was accepted after a lower-valued ACK")
		}
	})
	t.Run("the same nonce with a higher value raises it", func(t *testing.T) {
		m := renewWith(t, func(a *wire.Message) { a.Options[wire.OptAuthentication] = frAuth1(t, frNonce, 50) })
		if l := frHeld(t, m); l.ForcerenewReplay != 50 {
			t.Fatalf("floor = %d, want 50", l.ForcerenewReplay)
		}
	})
	t.Run("a new nonce resets the floor to its own value", func(t *testing.T) {
		m := renewWith(t, func(a *wire.Message) { a.Options[wire.OptAuthentication] = frAuth1(t, frNonce2, 1) })
		if l := frHeld(t, m); !bytes.Equal(l.ForcerenewNonce, frNonce2) || l.ForcerenewReplay != 1 {
			t.Fatalf("nonce %x floor %d", l.ForcerenewNonce, l.ForcerenewReplay)
		}
		old := frNew(7)
		if state, _ := frSend(t, m, at(4001), old); state != StateBound {
			t.Fatal("a frame under the retired nonce was obeyed")
		}
		frWantRefusal(t, m, ForcerenewRefusalBadDigest)
		fresh := frNew(2)
		fresh.nonce = frNonce2
		if state, _ := frSend(t, m, at(4002), fresh); state != StateRenewing {
			t.Fatalf("a frame under the new nonce was refused: %v", frRefusals(m))
		}
	})
	t.Run("an ACK from another server in REBINDING drops it", func(t *testing.T) {
		m := frBound(t)
		frToRenewing(t, m)
		req := frToRebinding(t, m)
		m.Step(at(5000), 13, received(t, ackFor(req, frAddr, "192.168.99.2", 3600)))
		if m.State() != StateBound {
			t.Fatalf("state = %s", m.State())
		}
		if l := frHeld(t, m); len(l.ForcerenewNonce) != 0 || l.ForcerenewReplay != 0 {
			t.Fatalf("a lease from another server inherited %x/%d", l.ForcerenewNonce, l.ForcerenewReplay)
		}
		frSend(t, m, at(5001), frNew(6))
		frWantRefusal(t, m, ForcerenewRefusalNoNonce)
	})
	t.Run("an ACK with a type 2 option 90 gives no nonce", func(t *testing.T) {
		m := renewWith(t, func(a *wire.Message) { a.Options[wire.OptAuthentication] = frAuthVal(2, 99, make([]byte, 16)) })
		if l := frHeld(t, m); l.ForcerenewReplay != 5 || !bytes.Equal(l.ForcerenewNonce, frNonce) {
			t.Fatalf("a digest-typed option replaced the held nonce: %x/%d", l.ForcerenewNonce, l.ForcerenewReplay)
		}
	})
}

// TestALostLeaseTakesTheNonceWithIt: after a NAK, an expiry or a release, no
// frame signed with the old nonce can reach a later lease.
func TestALostLeaseTakesTheNonceWithIt(t *testing.T) {
	t.Run("NAK in RENEWING", func(t *testing.T) {
		m := frBound(t)
		req := frToRenewing(t, m)
		nak := nakFor(req, frServer, "no")
		nak.Options[wire.OptAuthentication] = frAuth1(t, frNonce2, 1)
		m.Step(at(4000), 12, received(t, nak))
		if _, held := m.Lease(); held || m.fr.have {
			t.Fatalf("the lease or its key survived a NAK: held %v key %v", held, m.fr.have)
		}
	})
	t.Run("expiry", func(t *testing.T) {
		m := frBound(t)
		frToRenewing(t, m)
		m.Step(at(2+3600), 12, TimerFired(TimerExpire))
		if _, held := m.Lease(); held || m.fr.have {
			t.Fatalf("the lease or its key survived expiry: held %v key %v", held, m.fr.have)
		}
	})
	t.Run("release", func(t *testing.T) {
		m := frBound(t)
		m.Step(at(10), 12, Simple(EvRelease))
		if _, held := m.Lease(); held || m.fr.have {
			t.Fatalf("the lease or its key survived a release: held %v key %v", held, m.fr.have)
		}
	})
}

// frDriveACD fires TimerACD until the machine leaves PROBING, bounded.
func frDriveACD(t *testing.T, m *Machine, now Instant) {
	t.Helper()
	for i := 0; i < 40 && m.State() != StateBound; i++ {
		now = now.Add(10 * Second)
		m.Step(now, uint64(i+1), TimerFired(TimerACD))
	}
	if m.State() != StateBound {
		t.Fatalf("never left %s", m.State())
	}
}

// TestTheNonceIsTakenFromEveryACKThatMakesALease is the source table: each way
// into BOUND, with a nonce on the wire and with none. The nonce is read from
// the ACK in every one, and an OFFER, a NAK or a digest-typed option never
// supplies it.
func TestTheNonceIsTakenFromEveryACKThatMakesALease(t *testing.T) {
	t.Run("selecting then requesting", func(t *testing.T) {
		if l := frHeld(t, frBound(t)); !bytes.Equal(l.ForcerenewNonce, frNonce) || l.ForcerenewReplay != 5 {
			t.Fatalf("%x/%d", l.ForcerenewNonce, l.ForcerenewReplay)
		}
	})
	t.Run("rapid commit", func(t *testing.T) {
		p := testParams()
		p.RapidCommit = true
		m := newMachine(t, p)
		_, acts := m.Step(0, 1, Simple(EvStart))
		disc := mustSend(t, acts, wire.MsgDiscover)
		ack := ackFor(disc, frAddr, frServer, 3600)
		ack.Options[wire.OptRapidCommit] = wire.EncodeRapidCommit()
		ack.Options[wire.OptAuthentication] = frAuth1(t, frNonce, 7)
		m.Step(at(1), 2, received(t, ack))
		if m.State() != StateBound {
			t.Fatalf("state = %s", m.State())
		}
		if l := frHeld(t, m); !bytes.Equal(l.ForcerenewNonce, frNonce) || l.ForcerenewReplay != 7 {
			t.Fatalf("%x/%d", l.ForcerenewNonce, l.ForcerenewReplay)
		}
	})
	t.Run("rapid commit without option 90 is accepted, with no nonce", func(t *testing.T) {
		// No OFFER, so no capability to hold the ACK against; RFC 6704
		// section 3.1.4 keys the discard to the OFFER's option 145.
		p := testParams()
		p.RapidCommit = true
		m := newMachine(t, p)
		_, acts := m.Step(0, 1, Simple(EvStart))
		disc := mustSend(t, acts, wire.MsgDiscover)
		ack := ackFor(disc, frAddr, frServer, 3600)
		ack.Options[wire.OptRapidCommit] = wire.EncodeRapidCommit()
		m.Step(at(1), 2, received(t, ack))
		if m.State() != StateBound || m.ForcerenewCounters().AckRefused != 0 {
			t.Fatalf("state %s, %+v", m.State(), m.ForcerenewCounters())
		}
		if l := frHeld(t, m); len(l.ForcerenewNonce) != 0 {
			t.Fatalf("invented a nonce: %x", l.ForcerenewNonce)
		}
	})
	t.Run("INIT-REBOOT", func(t *testing.T) {
		m := newMachine(t, resumeParams(testRebootAddr, at(3600), true))
		_, acts := m.Step(0, 1, Simple(EvStart))
		req := mustSend(t, acts, wire.MsgRequest)
		ack := ackFor(req, testRebootAddr, frServer, 3600)
		ack.Options[wire.OptAuthentication] = frAuth1(t, frNonce, 4)
		m.Step(at(1), 2, received(t, ack))
		if m.State() != StateBound {
			t.Fatalf("state = %s", m.State())
		}
		if l := frHeld(t, m); !bytes.Equal(l.ForcerenewNonce, frNonce) || l.ForcerenewReplay != 4 {
			t.Fatalf("%x/%d", l.ForcerenewNonce, l.ForcerenewReplay)
		}
	})
	t.Run("through PROBING", func(t *testing.T) {
		m := newMachine(t, acdParams(ConflictWait))
		_, acts := m.Step(0, 1, Simple(EvStart))
		disc := mustSend(t, acts, wire.MsgDiscover)
		offer := offerFor(disc, frAddr, frServer)
		offer.Options[wire.OptForcerenewNonce] = wire.EncodeForcerenewNonceCapable()
		_, acts = m.Step(at(1), 2, received(t, offer))
		req := mustSend(t, acts, wire.MsgRequest)
		ack := ackFor(req, frAddr, frServer, 3600)
		ack.Options[wire.OptAuthentication] = frAuth1(t, frNonce, 3)
		m.Step(at(2), 3, received(t, ack))
		if m.State() != StateProbing {
			t.Fatalf("state = %s, want PROBING", m.State())
		}
		frDriveACD(t, m, at(2))
		if l := frHeld(t, m); !bytes.Equal(l.ForcerenewNonce, frNonce) || l.ForcerenewReplay != 3 {
			t.Fatalf("%x/%d", l.ForcerenewNonce, l.ForcerenewReplay)
		}
		if state, _ := frSend(t, m, at(500), frNew(4)); state != StateRenewing {
			t.Fatalf("a frame after PROBING was refused: %v", frRefusals(m))
		}
	})
	t.Run("a digest-typed option 90 on an ACK is no nonce", func(t *testing.T) {
		m := newMachine(t, testParams())
		_, acts := m.Step(0, 1, Simple(EvStart))
		disc := mustSend(t, acts, wire.MsgDiscover)
		_, acts = m.Step(at(1), 2, received(t, offerFor(disc, frAddr, frServer)))
		req := mustSend(t, acts, wire.MsgRequest)
		ack := ackFor(req, frAddr, frServer, 3600)
		ack.Options[wire.OptAuthentication] = frAuthVal(2, 1, frNonce)
		m.Step(at(2), 3, received(t, ack))
		frSend(t, m, at(100), frNew(6))
		frWantRefusal(t, m, ForcerenewRefusalNoNonce)
	})
}

// TestAResumedMachineHoldsNoNonceAndRefusesForThatReason is the stated gap:
// proto.Resume carries an address and an expiry and not the nonce, so the
// client that came back from a restart refuses every FORCERENEW until its next
// ACK, even one signed with the nonce it was given before the restart.
func TestAResumedMachineHoldsNoNonceAndRefusesForThatReason(t *testing.T) {
	m := newMachine(t, resumeParams(frAddr, at(3600), true))
	_, acts := m.Step(0, 1, Simple(EvStart))
	req := mustSend(t, acts, wire.MsgRequest)
	m.Step(at(1), 2, received(t, ackFor(req, frAddr, frServer, 3600)))
	if m.State() != StateBound {
		t.Fatalf("state = %s", m.State())
	}
	frSend(t, m, at(100), frNew(6))
	frWantRefusal(t, m, ForcerenewRefusalNoNonce)
}

// TestEveryDISCOVERAndREQUESTCarriesOption145AndNothingElseDoes is RFC 6704
// section 3.1.1 ("MUST include ... in DHCPDISCOVER and DHCPREQUEST") read off
// the bytes each path puts on the wire, with the two messages that are not
// either as the control: they are not asking for a lease and say nothing of
// forcerenew.
func TestEveryDISCOVERAndREQUESTCarriesOption145AndNothingElseDoes(t *testing.T) {
	has := func(m *wire.Message) bool {
		dec := frEncoded(t, m)
		v, ok := dec.Options[wire.OptForcerenewNonce]
		return ok && bytes.Equal(v, wire.EncodeForcerenewNonceCapable())
	}
	m := newMachine(t, testParams())
	_, acts := m.Step(0, 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	_, again := m.Step(at(5), 2, TimerFired(TimerRetransmit))
	msgs := map[string]*wire.Message{"DISCOVER": disc, "DISCOVER retransmitted": mustSend(t, again, wire.MsgDiscover)}
	_, acts = m.Step(at(6), 3, received(t, offerFor(disc, frAddr, frServer)))
	msgs["REQUEST (SELECTING)"] = mustSend(t, acts, wire.MsgRequest)
	bound := frBound(t)
	_, acts = bound.Step(at(100), 9, TimerFired(TimerRenew))
	msgs["REQUEST (renewing)"] = mustSend(t, acts, wire.MsgRequest)
	rb := newMachine(t, resumeParams(testRebootAddr, at(3600), true))
	_, acts = rb.Step(0, 1, Simple(EvStart))
	msgs["REQUEST (INIT-REBOOT)"] = mustSend(t, acts, wire.MsgRequest)
	for name, msg := range msgs {
		if !has(msg) {
			t.Errorf("%s does not carry option 145 = {1}", name)
		}
	}
	t.Run("DECLINE", func(t *testing.T) {
		mm := frAcquire(t, acdParams(ConflictOff), frNonce, 1)
		_, acts := mm.Step(at(10), 1, Simple(EvConflictDetected))
		if has(mustSend(t, acts, wire.MsgDecline)) {
			t.Fatal("a DECLINE carries option 145")
		}
	})
	t.Run("RELEASE", func(t *testing.T) {
		mm := frBound(t)
		_, acts := mm.Step(at(10), 1, Simple(EvRelease))
		if has(mustSend(t, acts, wire.MsgRelease)) {
			t.Fatal("a RELEASE carries option 145")
		}
	})
}

// TestTheRefusalNamesAreCompleteAndDistinct is the totality check for the
// enumeration and the counter array: every reason has its own text, its own
// slot, and a place in AllForcerenewRefusals.
func TestTheRefusalNamesAreCompleteAndDistinct(t *testing.T) {
	all := AllForcerenewRefusals()
	if len(all) != int(numForcerenewRefusal)-1 {
		t.Fatalf("AllForcerenewRefusals lists %d reasons, the enumeration has %d", len(all), int(numForcerenewRefusal)-1)
	}
	seen := map[string]ForcerenewRefusal{}
	var c ForcerenewCounters
	for i, r := range all {
		if r == ForcerenewRefusalNone || r >= numForcerenewRefusal {
			t.Fatalf("reason %d is out of range", r)
		}
		name := r.String()
		if name == "" || strings.HasPrefix(name, "forcerenew-refusal(") {
			t.Fatalf("reason %d has no text: %q", r, name)
		}
		if prev, dup := seen[name]; dup {
			t.Fatalf("reasons %d and %d share the text %q", prev, r, name)
		}
		seen[name] = r
		c.Refused[r] = uint64(i + 1)
	}
	if got, want := c.RefusedTotal(), uint64(len(all)*(len(all)+1)/2); got != want {
		t.Fatalf("RefusedTotal = %d, want %d", got, want)
	}
	if ForcerenewRefusalNone.String() != "acted on" || !strings.HasPrefix(numForcerenewRefusal.String(), "forcerenew-refusal(") {
		t.Fatal("the zero value or the sentinel prints wrongly")
	}
}

// TestFORCERENEWReplaysFromTheJournalWithItsDestination: ring 1 decides a
// frame on the destination, which is not in the frame's bytes, so the journal
// records it. The control is the clean replay; the attack is the entry an
// earlier release wrote, which has no destination and must replay as the
// refusal it would have been, never as the renewal.
func TestFORCERENEWReplaysFromTheJournalWithItsDestination(t *testing.T) {
	p := testParams()
	m := newMachine(t, p)
	var es []JournalEntry
	step := func(now Instant, rnd uint64, ev Event) []Action {
		from := m.State()
		to, acts := m.Step(now, rnd, ev)
		es = append(es, NewJournalEntry(uint64(len(es)), now, rnd, ev, from, to, acts))
		return acts
	}
	acts := step(0, 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	offer := offerFor(disc, frAddr, frServer)
	offer.Options[wire.OptForcerenewNonce] = wire.EncodeForcerenewNonceCapable()
	acts = step(at(1), 2, received(t, offer))
	req := mustSend(t, acts, wire.MsgRequest)
	ack := ackFor(req, frAddr, frServer, 3600)
	ack.Options[wire.OptAuthentication] = frAuth1(t, frNonce, 5)
	step(at(2), 3, received(t, ack))
	step(at(100), 9, frEvent(t, frNew(6).build(), frAddr))
	if m.State() != StateRenewing {
		t.Fatalf("fixture state %s", m.State())
	}
	last := len(es) - 1
	if es[last].Dst.String() != frAddr {
		t.Fatalf("the journal recorded destination %v", es[last].Dst)
	}

	res, err := Replay(p, es)
	if err != nil {
		t.Fatalf("the clean journal did not replay: %v", err)
	}
	if res.State != StateRenewing {
		t.Fatalf("replayed to %s", res.State)
	}

	old := append([]JournalEntry(nil), es...)
	old[last].Dst = netip.Addr{}
	_, err = Replay(p, old)
	var div Divergence
	if !errors.As(err, &div) || !errors.Is(err, ErrReplayDiverged) || div.Seq != uint64(last) {
		t.Fatalf("an entry with no destination replayed as %v, want a divergence at the frame", err)
	}

	raw, err := json.Marshal(es[last])
	if err != nil {
		t.Fatal(err)
	}
	var back JournalEntry
	if err := json.Unmarshal(raw, &back); err != nil || back.Dst != es[last].Dst {
		t.Fatalf("destination lost through JSON: %v %v", back.Dst, err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	delete(generic, "Dst")
	oldRaw, _ := json.Marshal(generic)
	var oldBack JournalEntry
	if err := json.Unmarshal(oldRaw, &oldBack); err != nil || oldBack.Dst.IsValid() {
		t.Fatalf("a record from before the field decoded to %v (%v)", oldBack.Dst, err)
	}
}

// TestTheLeaseHandedOutDoesNotAliasTheVerifyingKey: a caller that scribbles on
// the nonce it was given, from Lease() or from the announced lease, must not
// change what authenticates the next frame.
func TestTheLeaseHandedOutDoesNotAliasTheVerifyingKey(t *testing.T) {
	m := newMachine(t, testParams())
	_, acts := m.Step(0, 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	_, acts = m.Step(at(1), 2, received(t, offerFor(disc, frAddr, frServer)))
	req := mustSend(t, acts, wire.MsgRequest)
	ack := ackFor(req, frAddr, frServer, 3600)
	ack.Options[wire.OptAuthentication] = frAuth1(t, frNonce, 5)
	_, acts = m.Step(at(2), 3, received(t, ack))
	announced, ok := find(acts, ActLeaseAcquired)
	if !ok {
		t.Fatal("no lease announced")
	}
	for i := range announced.Lease.ForcerenewNonce {
		announced.Lease.ForcerenewNonce[i] = 0xEE
	}
	held, _ := m.Lease()
	for i := range held.ForcerenewNonce {
		held.ForcerenewNonce[i] = 0xDD
	}
	if state, _ := frSend(t, m, at(100), frNew(6)); state != StateRenewing {
		t.Fatalf("the verifying key followed a caller's write: %v", frRefusals(m))
	}
}
