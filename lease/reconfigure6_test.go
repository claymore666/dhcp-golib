// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"crypto/hmac"
	"crypto/md5"
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// The Reconfigure counters at the ring that reports them, RFC 9915 §16.11 and
// §18.2.11: ring 1 decides and this ring mirrors, so a mirror that never ran
// leaves two numbers at zero while the machine counts.
//
// THE MIRROR IS WHAT THESE DRIVE. proto's suite owns which rule fired; what is
// asserted here is that Manager.Stats and Manager.ReconfigureCounters report
// it at all, read off a manager that ran a real exchange.

// reconfKey6 is §20.4.2's 128-bit reconfigure key for this fixture.
var reconfKey6 = mustHex("0f0e0d0c0b0a09080706050403020100")

// clientUnicast6 is the address the fixture unicasts a Reconfigure to, which
// is what §16.11's first bullet is about.
var clientUnicast6 = netip.MustParseAddr(test6Addr)

// keyedServer6 is answerNormally6 whose Reply carries §20.4.3's reconfigure
// key, so the client this rig builds has one recorded.
func keyedServer6(t *testing.T) server6Behaviour {
	t.Helper()
	auth, err := wire.EncodeRKAPAuth(wire.RKAPTypeKey, reconfKey6, 0)
	if err != nil {
		t.Fatalf("EncodeRKAPAuth: %v", err)
	}
	return func(req *wire.MessageV6, _ int) []*wire.MessageV6 {
		switch req.Type {
		case wire.MsgSolicit:
			return []*wire.MessageV6{advertiseFor(t, req)}
		case wire.MsgRequest6, wire.MsgRenew, wire.MsgRebind, wire.MsgDecline6, wire.MsgRelease6:
			rep := replyFor(t, req)
			rep.Options = append(rep.Options, optV6(wire.OptV6Auth, auth))
			return []*wire.MessageV6{rep}
		}
		return nil
	}
}

// digestSpan6 finds §20.4.1's 16-octet Value in an encoded message by walking
// §21.11's layout, and does NOT ask the code under test where it is: a fixture
// that called wire's own span function would sign whatever that function
// believes in, and a fixture and a subject that agree on a wrong answer agree
// silently.
func digestSpan6(t *testing.T, raw []byte) (int, int) {
	t.Helper()
	for i := 4; i+4 <= len(raw); {
		code := int(raw[i])<<8 | int(raw[i+1])
		n := int(raw[i+2])<<8 | int(raw[i+3])
		i += 4
		if n > len(raw)-i {
			t.Fatalf("option %d overruns the message", code)
		}
		if code == int(wire.OptV6Auth) {
			// protocol, algorithm, RDM, eight octets of replay detection,
			// then §20.4.1's Type octet: the Value starts after those.
			start := i + 3 + 8 + 1
			return start, start + md5.Size
		}
		i += n
	}
	t.Fatalf("no Authentication option in the message")
	return 0, 0
}

// reconfigureRaw builds a Reconfigure naming kind and signs it with key,
// §20.4.3: "the client computes an HMAC-MD5 over the Reconfigure message, with
// zeroes substituted for the HMAC-MD5 field".
func reconfigureRaw(t *testing.T, kind wire.MessageTypeV6, key []byte, replay uint64) []byte {
	t.Helper()
	msgType, err := wire.EncodeReconfigureMessage(kind)
	if err != nil {
		t.Fatalf("EncodeReconfigureMessage: %v", err)
	}
	// The placeholder is not zero, so a signer that forgot to zero the field
	// signs octets the verifier does not.
	placeholder := make([]byte, md5.Size)
	for i := range placeholder {
		placeholder[i] = 0xa5
	}
	auth, err := wire.EncodeRKAPAuth(wire.RKAPTypeDigest, placeholder, replay)
	if err != nil {
		t.Fatalf("EncodeRKAPAuth: %v", err)
	}
	raw, err := wire.EncodeV6(&wire.MessageV6{
		Type: wire.MsgReconfigure, XID: 0x4242,
		Options: wire.OptionsV6{
			optV6(wire.OptV6ClientID, test6DUID),
			optV6(wire.OptV6ServerID, test6ServerDUID),
			optV6(wire.OptV6ReconfMsg, msgType),
			optV6(wire.OptV6Auth, auth),
		},
	})
	if err != nil {
		t.Fatalf("EncodeV6: %v", err)
	}
	start, end := digestSpan6(t, raw)
	zeroed := append([]byte(nil), raw...)
	for i := start; i < end; i++ {
		zeroed[i] = 0
	}
	mac := hmac.New(md5.New, key)
	mac.Write(zeroed)
	copy(raw[start:end], mac.Sum(nil))
	return raw
}

// injectTo delivers a datagram with the destination §16.11's first bullet is
// about. fakeServer6.injectRaw reports none, which is itself a discard.
func (s *fakeServer6) injectTo(raw []byte, to netip.Addr) {
	select {
	case s.inbound <- Inbound{Payload: raw, From: netip.MustParseAddr("fe80::1"), To: to}:
	case <-s.closed:
	}
}

// TestAnAcceptedReconfigureReachesStatsAndTheCounters drives the mirror for
// claymore666/docker-net-dhcp#925: the number a caller reads is this ring's,
// and it is taken from ring 1 at every Step.
//
// THE RENEW ON THE WIRE IS THE EVIDENCE AND THE COUNTER RIDES ON IT. A manager
// that raised the number and started nothing would pass a test that read the
// number alone.
func TestAnAcceptedReconfigureReachesStatsAndTheCounters(t *testing.T) {
	r := newRig6(t, testParams6(), keyedServer6(t))
	r.acquire6(t)

	if got := r.mgr.Stats().ReconfiguresAccepted; got != 0 {
		t.Fatalf("Stats.ReconfiguresAccepted is %d before any Reconfigure arrived", got)
	}

	r.server.injectTo(reconfigureRaw(t, wire.MsgRenew, reconfKey6, 1), clientUnicast6)
	r.waitSent(t, wire.MsgRenew)
	r.settle(t)

	st := r.mgr.Stats()
	if st.ReconfiguresAccepted != 1 {
		t.Errorf("Stats.ReconfiguresAccepted is %d after one answered Reconfigure, want 1", st.ReconfiguresAccepted)
	}
	if st.ReconfiguresRefused != 0 {
		t.Errorf("Stats.ReconfiguresRefused is %d on an answered Reconfigure, want 0", st.ReconfiguresRefused)
	}
	c := r.mgr.ReconfigureCounters()
	if c.Accepted != 1 || c.RefusedTotal() != 0 {
		t.Errorf("ReconfigureCounters reports %d accepted and %d refused, want 1 and 0", c.Accepted, c.RefusedTotal())
	}
}

// TestARefusedReconfigureReachesStatsWithTheRuleThatRefusedIt is the other
// half, and the reason the per-rule split is exported at all: the total says a
// Reconfigure changed nothing and only the split says whether that is a server
// to go and fix.
func TestARefusedReconfigureReachesStatsWithTheRuleThatRefusedIt(t *testing.T) {
	r := newRig6(t, testParams6(), keyedServer6(t))
	r.acquire6(t)

	wrongKey := mustHex("00112233445566778899aabbccddeeff")
	r.server.injectTo(reconfigureRaw(t, wire.MsgRenew, wrongKey, 1), clientUnicast6)
	r.journal.waitAppended(t, "the Step on the refused Reconfigure",
		func(e proto.JournalEntry6) bool {
			return e.Kind == proto.EvReceived && len(e.Raw) > 0 && e.Raw[0] == byte(wire.MsgReconfigure)
		})
	r.settle(t)

	st := r.mgr.Stats()
	if st.ReconfiguresRefused != 1 {
		t.Errorf("Stats.ReconfiguresRefused is %d after one refused Reconfigure, want 1", st.ReconfiguresRefused)
	}
	if st.ReconfiguresAccepted != 0 {
		t.Errorf("Stats.ReconfiguresAccepted is %d on a refused Reconfigure, want 0", st.ReconfiguresAccepted)
	}
	c := r.mgr.ReconfigureCounters()
	if got := c.Refused[proto.ReconfigureRefusalBadDigest]; got != 1 {
		t.Errorf("ReconfigureCounters.Refused[%v] is %d, want 1: the total cannot say which rule refused",
			proto.ReconfigureRefusalBadDigest, got)
	}
	if got := len(r.server.sentMessages()); got != 2 {
		t.Errorf("%d message(s) went out; a refused Reconfigure must not have started an exchange", got)
	}
}

// TestAV4ManagerReportsNoReconfigureCounters is the preservation half: the
// fields are v6's, a v4 manager never touches them, and the accessor answers
// its zero value and reaches into no machine it does not have.
func TestAV4ManagerReportsNoReconfigureCounters(t *testing.T) {
	r := newRig(t, testParams(), answerNormally, Fault{})
	if ev := r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("the first event is %s, want acquired", ev)
	}
	st := r.mgr.Stats()
	if st.ReconfiguresAccepted != 0 || st.ReconfiguresRefused != 0 {
		t.Errorf("a v4 manager reports %d accepted and %d refused Reconfigure(s)", st.ReconfiguresAccepted, st.ReconfiguresRefused)
	}
	if c := r.mgr.ReconfigureCounters(); c.Accepted != 0 || c.RefusedTotal() != 0 {
		t.Errorf("a v4 manager's ReconfigureCounters is not the zero value: %+v", c)
	}
}
