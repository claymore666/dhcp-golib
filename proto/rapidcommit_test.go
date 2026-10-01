// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// Rapid Commit, option 80, RFC 4039 (claymore666/docker-net-dhcp#1031). The
// wire assertions read the message after wire.Encode and wire.Decode. The
// fixtures come from fakes_test.go alone, so this file builds when its
// neighbours are switched off.

const (
	rcAddr     = "192.168.99.50"
	rcOtherIP  = "192.168.99.51"
	rcServer   = "192.168.99.1"
	rcOtherSID = "192.168.99.2"
)

func rcParams() Params {
	p := testParams()
	p.RapidCommit = true
	return p
}

func rcWire(t *testing.T, m *wire.Message) *wire.Message {
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

// rcSelecting starts p and returns the machine in SELECTING with the DISCOVER
// it sent, at instant 10 s so a lease clock has somewhere to start from.
func rcSelecting(t *testing.T, p Params) (*Machine, *wire.Message) {
	t.Helper()
	m := newMachine(t, p)
	_, acts := m.Step(at(10), 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	if m.State() != StateSelecting {
		t.Fatalf("fixture reached %s, want SELECTING", m.State())
	}
	return m, disc
}

// rcAck is a DHCPACK answering disc with option 80 on it.
func rcAck(disc *wire.Message, yiaddr, sid string, lease uint32) *wire.Message {
	a := ackFor(disc, yiaddr, sid, lease)
	a.Options[wire.OptRapidCommit] = wire.EncodeRapidCommit()
	return a
}

func rcSends(acts []Action) int { return count(acts, ActSend) }

func rcTimerActs(acts []Action, k ActionKind) []TimerID {
	var ids []TimerID
	for _, a := range acts {
		if a.Kind == k {
			ids = append(ids, a.Timer)
		}
	}
	return ids
}

func rcHasTimer(acts []Action, k ActionKind, id TimerID) bool {
	for _, got := range rcTimerActs(acts, k) {
		if got == id {
			return true
		}
	}
	return false
}

func rcJournal(acts []Action) string { return journalText(acts) }

// TestRapidCommitIsOffByDefaultAndSendsNothing: the zero Params value and
// DefaultParams put no option 80 on the DISCOVER, and the same Params with the
// flag on does (claymore666/docker-net-dhcp#1031).
func TestRapidCommitIsOffByDefaultAndSendsNothing(t *testing.T) {
	if DefaultParams(testCHAddr).RapidCommit {
		t.Fatal("DefaultParams turns Rapid Commit on")
	}
	_, off := rcSelecting(t, testParams())
	if _, ok := rcWire(t, off).Options[wire.OptRapidCommit]; ok {
		t.Fatal("a client with RapidCommit false put option 80 on the DISCOVER")
	}
	_, on := rcSelecting(t, rcParams())
	got := rcWire(t, on)
	v, ok := got.Options[wire.OptRapidCommit]
	if !ok || len(v) != 0 {
		t.Fatalf("the preservation control: option 80 = %x present=%v, want present with no octets", v, ok)
	}
	if present, err := got.Options.RapidCommit(); err != nil || !present {
		t.Fatalf("option 80 does not decode as Rapid Commit: %v/%v", present, err)
	}
}

// TestRapidCommitIsOnEveryDiscoverAndOnNoRequest drives the DISCOVER and its
// retransmission, then the four REQUEST senders: SELECTING, RENEWING,
// REBINDING and INIT-REBOOT. RFC 4039 section 3 allows the option in a
// DHCPDISCOVER alone (claymore666/docker-net-dhcp#1031).
func TestRapidCommitIsOnEveryDiscoverAndOnNoRequest(t *testing.T) {
	m, disc := rcSelecting(t, rcParams())
	if _, ok := rcWire(t, disc).Options[wire.OptRapidCommit]; !ok {
		t.Fatal("the DISCOVER carries no option 80")
	}
	_, acts := m.Step(at(14), 2, TimerFired(TimerRetransmit))
	re := mustSend(t, acts, wire.MsgDiscover)
	if _, ok := rcWire(t, re).Options[wire.OptRapidCommit]; !ok {
		t.Error("the retransmitted DISCOVER carries no option 80")
	}

	reqs := map[string]*wire.Message{}
	_, acts = m.Step(at(15), 3, received(t, offerFor(disc, rcAddr, rcServer)))
	req := mustSend(t, acts, wire.MsgRequest)
	reqs["selecting"] = rcWire(t, req)
	m.Step(at(16), 4, received(t, ackFor(req, rcAddr, rcServer, 3600)))
	if m.State() != StateBound {
		t.Fatalf("fixture reached %s, want BOUND", m.State())
	}
	t1, _ := m.lease.RenewAt()
	_, acts = m.Step(t1, 5, TimerFired(TimerRenew))
	reqs["renewing"] = rcWire(t, mustSend(t, acts, wire.MsgRequest))
	t2, _ := m.lease.RebindAt()
	_, acts = m.Step(t2, 6, TimerFired(TimerRebind))
	reqs["rebinding"] = rcWire(t, mustSend(t, acts, wire.MsgRequest))

	rp := resumeParams(rcAddr, at(3600), true)
	rp.RapidCommit = true
	rm := newMachine(t, rp)
	_, acts = rm.Step(0, 7, Simple(EvStart))
	reqs["init-reboot"] = rcWire(t, mustSend(t, acts, wire.MsgRequest))

	for name, msg := range reqs {
		if _, ok := msg.Options[wire.OptRapidCommit]; ok {
			t.Errorf("the %s REQUEST carries option 80", name)
		}
	}
	if len(reqs) != 4 {
		t.Fatalf("drove %d REQUEST senders, want 4", len(reqs))
	}
}

// TestADeclineAndAReleaseCarryNoRapidCommit: RFC 2131 Table 5 lists no option
// 80 for either. The machine has no DHCPINFORM builder
// (claymore666/docker-net-dhcp#1031).
func TestADeclineAndAReleaseCarryNoRapidCommit(t *testing.T) {
	bound := func(t *testing.T) *Machine {
		t.Helper()
		m, disc := rcSelecting(t, rcParams())
		m.Step(at(11), 2, received(t, rcAck(disc, rcAddr, rcServer, 3600)))
		if m.State() != StateBound {
			t.Fatalf("fixture reached %s, want BOUND", m.State())
		}
		return m
	}
	t.Run("decline", func(t *testing.T) {
		m := bound(t)
		_, acts := m.Step(at(20), 3, Simple(EvConflictDetected))
		if _, ok := rcWire(t, mustSend(t, acts, wire.MsgDecline)).Options[wire.OptRapidCommit]; ok {
			t.Error("DHCPDECLINE carries option 80")
		}
	})
	t.Run("release", func(t *testing.T) {
		m := bound(t)
		_, acts := m.Step(at(20), 3, Simple(EvRelease))
		if _, ok := rcWire(t, mustSend(t, acts, wire.MsgRelease)).Options[wire.OptRapidCommit]; ok {
			t.Error("DHCPRELEASE carries option 80")
		}
	})
}

// TestNewRefusesOption80InTheParameterListOfARapidCommitClient: RFC 4039
// section 3 says option 80 "MUST NOT appear in a Parameter Request List"
// (claymore666/docker-net-dhcp#1031).
func TestNewRefusesOption80InTheParameterListOfARapidCommitClient(t *testing.T) {
	p := rcParams()
	p.ParameterList = []wire.OptionCode{wire.OptSubnetMask, wire.OptRouter, wire.OptRapidCommit}
	if _, err := New(p); !errors.Is(err, ErrBadRapidCommit) {
		t.Fatalf("New with option 80 in the list = %v, want ErrBadRapidCommit", err)
	}
	p.RapidCommit = false
	if _, err := New(p); err != nil {
		t.Fatalf("the same list on a client that does not send the option is not this feature's input: %v", err)
	}
	ok := rcParams()
	ok.ParameterList = []wire.OptionCode{wire.OptSubnetMask, wire.OptRouter}
	if _, err := New(ok); err != nil {
		t.Fatalf("a clean list was refused: %v", err)
	}
}

// TestARapidAckInSelectingIsTheLeaseAndSendsNoRequest: the ACK carrying option
// 80 takes the ordinary lease path, which is observed as the lease, the timers
// and the events an ordinary ACK produces, and as no message going out. The
// lease clock starts at the DISCOVER, the message the server answered
// (claymore666/docker-net-dhcp#1031).
func TestARapidAckInSelectingIsTheLeaseAndSendsNoRequest(t *testing.T) {
	m, disc := rcSelecting(t, rcParams())
	to, acts := m.Step(at(12), 2, received(t, rcAck(disc, rcAddr, rcServer, 3600)))
	if to != StateBound {
		t.Fatalf("state %s, want BOUND\n%v", to, RenderActions(acts))
	}
	if n := rcSends(acts); n != 0 {
		t.Fatalf("%d message(s) sent, the rapid lease needs no REQUEST", n)
	}
	a, ok := find(acts, ActLeaseAcquired)
	if !ok || count(acts, ActLeaseAcquired) != 1 {
		t.Fatalf("want exactly one ActLeaseAcquired:\n%v", RenderActions(acts))
	}
	if a.Lease.Addr.Addr() != netip.MustParseAddr(rcAddr) || a.Lease.ServerID != netip.MustParseAddr(rcServer) {
		t.Fatalf("lease %v from %v", a.Lease.Addr, a.Lease.ServerID)
	}
	if a.Lease.Start != at(10) {
		t.Errorf("lease Start %v, want the DISCOVER's instant %v", a.Lease.Start, at(10))
	}
	if l, held := m.Lease(); !held || l.Addr != a.Lease.Addr {
		t.Errorf("the machine holds %v/%v, the event said %v", l.Addr, held, a.Lease.Addr)
	}
	for _, id := range []TimerID{TimerExpire, TimerRenew, TimerRebind} {
		if !rcHasTimer(acts, ActSetTimer, id) {
			t.Errorf("timer %s was not armed", id)
		}
	}
	if !rcHasTimer(acts, ActCancelTimer, TimerRetransmit) {
		t.Error("the DISCOVER retransmission was left armed")
	}
	if c := m.RapidCommitCounters(); c.Accepted != 1 || c.Refused != 0 {
		t.Errorf("counters %+v, want Accepted 1 Refused 0", c)
	}
	if j := rcJournal(acts); !strings.Contains(j, "no DHCPREQUEST sent") || strings.Contains(j, "discarded") {
		t.Errorf("journal says the lease was not taken, or not rapid:\n%s", j)
	}
	_, acts = m.Step(at(13), 3, TimerFired(TimerRetransmit))
	if rcSends(acts) != 0 {
		t.Error("a stale DISCOVER retransmission fired in BOUND and sent a message")
	}
}

// TestARapidAckTakesTheSamePathAnOrdinaryAckTakes: under conflict detection the
// lease waits in PROBING exactly as it does after a REQUEST
// (claymore666/docker-net-dhcp#1031).
func TestARapidAckTakesTheSamePathAnOrdinaryAckTakes(t *testing.T) {
	for _, mode := range []ConflictMode{ConflictOff, ConflictAsync, ConflictWait} {
		ordinary := acdParams(mode)
		om, disc := rcSelecting(t, ordinary)
		_, acts := om.Step(at(11), 2, received(t, offerFor(disc, rcAddr, rcServer)))
		req := mustSend(t, acts, wire.MsgRequest)
		om.Step(at(12), 3, received(t, ackFor(req, rcAddr, rcServer, 3600)))

		rp := acdParams(mode)
		rp.RapidCommit = true
		rm, rdisc := rcSelecting(t, rp)
		rm.Step(at(12), 3, received(t, rcAck(rdisc, rcAddr, rcServer, 3600)))
		if rm.State() != om.State() {
			t.Errorf("conflict mode %v: a rapid ACK reached %s, an ordinary one %s", mode, rm.State(), om.State())
		}
		_, oheld := om.Lease()
		_, rheld := rm.Lease()
		if oheld != rheld {
			t.Errorf("conflict mode %v: held %v after a rapid ACK, %v after an ordinary one", mode, rheld, oheld)
		}
	}
}

// TestARapidAckWithAnInfiniteLeaseTimeIsTheLeaseAnOrdinaryAckGives: the
// infinite value (RFC 2132 section 9.2) is not a lease of zero, so the rapid
// ACK reaches the state and holds the lease the OFFER, REQUEST, ACK path does
// (claymore666/docker-net-dhcp#1031).
func TestARapidAckWithAnInfiniteLeaseTimeIsTheLeaseAnOrdinaryAckGives(t *testing.T) {
	om, disc := rcSelecting(t, testParams())
	_, acts := om.Step(at(11), 2, received(t, offerFor(disc, rcAddr, rcServer)))
	req := mustSend(t, acts, wire.MsgRequest)
	om.Step(at(12), 3, received(t, ackFor(req, rcAddr, rcServer, 0xFFFFFFFF)))

	rm, rdisc := rcSelecting(t, rcParams())
	rm.Step(at(12), 3, received(t, rcAck(rdisc, rcAddr, rcServer, 0xFFFFFFFF)))
	if rm.State() != om.State() || om.State() != StateBound {
		t.Fatalf("a rapid ACK reached %s, an ordinary one %s, want both BOUND", rm.State(), om.State())
	}
	rl, rheld := rm.Lease()
	ol, oheld := om.Lease()
	if !rheld || !oheld || !rl.LeaseTime.IsInfinite() || !ol.LeaseTime.IsInfinite() {
		t.Errorf("held %v/%v, lease times %v/%v, want both held and infinite", rheld, oheld, rl.LeaseTime, ol.LeaseTime)
	}
	if c := rm.RapidCommitCounters(); c.Accepted != 1 || c.Refused != 0 {
		t.Errorf("counters %+v, want Accepted 1 Refused 0", c)
	}
}

// TestARapidAckIsRefusedWhereItAnswersNothingTheClientSent: no lease, no
// message, the DISCOVER's retransmission untouched, and the refusal counted
// and journalled. A valid rapid ACK then takes the lease, so the refusal left
// the machine usable (claymore666/docker-net-dhcp#1031).
func TestARapidAckIsRefusedWhereItAnswersNothingTheClientSent(t *testing.T) {
	type mut func(a *wire.Message)
	for _, tc := range []struct {
		name    string
		params  func() Params
		mutate  mut
		counted bool
		journal string
	}{
		{"the DISCOVER did not ask for it", testParams, nil, true, "did not ask"},
		{"no server identifier", rcParams, func(a *wire.Message) { delete(a.Options, wire.OptServerID) }, true, "server identifier"},
		{"an unspecified server identifier", rcParams, func(a *wire.Message) { a.Options[wire.OptServerID] = addr4("0.0.0.0") }, true, "server identifier"},
		{"a lease time of zero", rcParams, func(a *wire.Message) { a.Options[wire.OptLeaseTime] = u32(0) }, true, "lease time is 0"},
		{"no lease time", rcParams, func(a *wire.Message) { delete(a.Options, wire.OptLeaseTime) }, true, "yiaddr and lease time"},
		{"no yiaddr", rcParams, func(a *wire.Message) { a.YIAddr = netip.IPv4Unspecified() }, true, "yiaddr and lease time"},
		{"a malformed option 80", rcParams, func(a *wire.Message) { a.Options[wire.OptRapidCommit] = []byte{1} }, true, "malformed"},
		{"a stale transaction", rcParams, func(a *wire.Message) { a.XID ^= 0xFFFF }, false, "does not match"},
		{"another host's chaddr", rcParams, func(a *wire.Message) { a.CHAddr = []byte{2, 2, 2, 2, 2, 2} }, false, "chaddr"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, disc := rcSelecting(t, tc.params())
			ack := rcAck(disc, rcAddr, rcServer, 3600)
			if tc.mutate != nil {
				tc.mutate(ack)
			}
			to, acts := m.Step(at(11), 2, received(t, ack))
			if to != StateSelecting {
				t.Fatalf("state %s, want SELECTING\n%v", to, RenderActions(acts))
			}
			if _, ok := find(acts, ActLeaseAcquired); ok {
				t.Fatal("a lease was acquired")
			}
			if rcSends(acts) != 0 {
				t.Error("a message was sent")
			}
			if rcHasTimer(acts, ActCancelTimer, TimerRetransmit) {
				t.Error("the DISCOVER retransmission was cancelled")
			}
			if _, held := m.Lease(); held {
				t.Error("the machine holds a lease")
			}
			want := uint64(0)
			if tc.counted {
				want = 1
			}
			if c := m.RapidCommitCounters(); c.Refused != want || c.Accepted != 0 {
				t.Errorf("counters %+v, want Refused %d Accepted 0", c, want)
			}
			if j := rcJournal(acts); !strings.Contains(j, tc.journal) {
				t.Errorf("journal %q does not say %q", j, tc.journal)
			}
			if tc.params().RapidCommit {
				m.Step(at(12), 3, received(t, rcAck(disc, rcAddr, rcServer, 3600)))
				if m.State() != StateBound {
					t.Errorf("after the refusal a valid rapid ACK reached %s, want BOUND", m.State())
				}
			}
		})
	}
}

// TestARapidAckFromADeniedOrUnlistedServerIsRefused: Params.Servers is the
// nearest thing to an offer set the machine keeps
// (claymore666/docker-net-dhcp#1031).
func TestARapidAckFromADeniedOrUnlistedServerIsRefused(t *testing.T) {
	deny := netip.MustParseAddr(rcOtherSID)
	for name, pol := range map[string]ServerPolicy{
		"deny list":  {Deny: []netip.Addr{deny}},
		"allow list": {Allow: []netip.Addr{netip.MustParseAddr(rcServer)}},
	} {
		t.Run(name, func(t *testing.T) {
			p := rcParams()
			p.Servers = pol
			m, disc := rcSelecting(t, p)
			to, acts := m.Step(at(11), 2, received(t, rcAck(disc, rcAddr, rcOtherSID, 3600)))
			if to != StateSelecting {
				t.Fatalf("state %s, want SELECTING", to)
			}
			if _, ok := find(acts, ActLeaseAcquired); ok {
				t.Fatal("a lease was acquired from an excluded server")
			}
			m.Step(at(12), 3, received(t, rcAck(disc, rcAddr, rcServer, 3600)))
			if m.State() != StateBound {
				t.Errorf("the permitted server's rapid ACK reached %s, want BOUND", m.State())
			}
		})
	}
}

// TestARapidAckInInitIsRefused: INIT has no DISCOVER outstanding, even with the
// transaction id of the last one (claymore666/docker-net-dhcp#1031).
func TestARapidAckInInitIsRefused(t *testing.T) {
	m, disc := rcSelecting(t, rcParams())
	m.Step(at(11), 2, Simple(EvLinkDown))
	if m.State() != StateInit {
		t.Fatalf("fixture reached %s, want INIT", m.State())
	}
	to, acts := m.Step(at(12), 3, received(t, rcAck(disc, rcAddr, rcServer, 3600)))
	if to != StateInit {
		t.Fatalf("state %s, want INIT", to)
	}
	if _, ok := find(acts, ActLeaseAcquired); ok {
		t.Fatal("a lease was acquired in INIT")
	}
	if c := m.RapidCommitCounters(); c.Refused != 1 || c.Accepted != 0 {
		t.Errorf("counters %+v, want Refused 1", c)
	}
	if j := rcJournal(acts); !strings.Contains(j, "refused") || strings.Contains(j, "ignored in INIT") {
		t.Errorf("journal %q does not say, once, that the ACK was refused", j)
	}
	_, acts = m.Step(at(13), 4, received(t, ackFor(disc, rcAddr, rcServer, 3600)))
	if !strings.Contains(rcJournal(acts), "ignored in INIT") || m.RapidCommitCounters().Refused != 1 {
		t.Errorf("an ACK with no option 80 in INIT changed: %q, counters %+v", rcJournal(acts), m.RapidCommitCounters())
	}
}

// TestARefusedRapidAckLeavesTheDiscoverRetransmissionAlive: the timer fires
// after a refusal and the DISCOVER still asks for Rapid Commit
// (claymore666/docker-net-dhcp#1031).
func TestARefusedRapidAckLeavesTheDiscoverRetransmissionAlive(t *testing.T) {
	m, disc := rcSelecting(t, rcParams())
	ack := rcAck(disc, rcAddr, rcServer, 0)
	m.Step(at(11), 2, received(t, ack))
	_, acts := m.Step(at(14), 3, TimerFired(TimerRetransmit))
	re := mustSend(t, acts, wire.MsgDiscover)
	if _, ok := rcWire(t, re).Options[wire.OptRapidCommit]; !ok {
		t.Error("the DISCOVER sent after the refusal carries no option 80")
	}
	if re.XID != disc.XID {
		t.Errorf("xid %#x, want the transaction's %#x", re.XID, disc.XID)
	}
}

// TestAnAckWithoutOption80InSelectingIsStillDiscarded: a Rapid Commit client
// keeps RFC 2131 section 4.4.1's rule for every ACK that lacks the option
// (claymore666/docker-net-dhcp#1031).
func TestAnAckWithoutOption80InSelectingIsStillDiscarded(t *testing.T) {
	m, disc := rcSelecting(t, rcParams())
	to, acts := m.Step(at(11), 2, received(t, ackFor(disc, rcAddr, rcServer, 3600)))
	if to != StateSelecting {
		t.Fatalf("state %s, want SELECTING", to)
	}
	if _, ok := find(acts, ActLeaseAcquired); ok {
		t.Fatal("a plain ACK in SELECTING acquired a lease")
	}
	if j := rcJournal(acts); !strings.Contains(j, "DHCPACK in SELECTING: discarded") {
		t.Errorf("journal %q lost the section 4.4.1 discard", j)
	}
	if c := m.RapidCommitCounters(); c != (RapidCommitCounters{}) {
		t.Errorf("counters %+v, want none", c)
	}
}

// TestAPlainOfferToARapidDiscoverFallsBackToTheFourMessageExchange: RFC 4039
// section 3. The REQUEST has no option 80, the ACK finishes the lease, and the
// clock starts at the REQUEST (claymore666/docker-net-dhcp#1031).
func TestAPlainOfferToARapidDiscoverFallsBackToTheFourMessageExchange(t *testing.T) {
	m, disc := rcSelecting(t, rcParams())
	to, acts := m.Step(at(11), 2, received(t, offerFor(disc, rcAddr, rcServer)))
	if to != StateRequesting {
		t.Fatalf("state %s, want REQUESTING", to)
	}
	req := mustSend(t, acts, wire.MsgRequest)
	if _, ok := rcWire(t, req).Options[wire.OptRapidCommit]; ok {
		t.Error("the REQUEST carries option 80")
	}
	if !rcHasTimer(acts, ActSetTimer, TimerRetransmit) {
		t.Error("the REQUEST has no retransmission armed")
	}
	_, acts = m.Step(at(13), 3, received(t, ackFor(req, rcAddr, rcServer, 3600)))
	if m.State() != StateBound {
		t.Fatalf("state %s, want BOUND", m.State())
	}
	a, _ := find(acts, ActLeaseAcquired)
	if a.Lease.Start != at(11) {
		t.Errorf("lease Start %v, want the REQUEST's instant %v", a.Lease.Start, at(11))
	}
	if !rcHasTimer(acts, ActCancelTimer, TimerRetransmit) {
		t.Error("the REQUEST retransmission was left armed")
	}
	if c := m.RapidCommitCounters(); c != (RapidCommitCounters{}) {
		t.Errorf("counters %+v, the fallback is not a rapid lease", c)
	}
}

// TestARapidAckInRequestingIsTakenOnlyFromTheServerAndAddressAsked: a server's
// rapid commit of the DISCOVER arriving after another server's OFFER is not the
// answer to this REQUEST (claymore666/docker-net-dhcp#1031).
func TestARapidAckInRequestingIsTakenOnlyFromTheServerAndAddressAsked(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rapid  bool
		yiaddr string
		sid    string
		want   State
		refuse uint64
		// malformed puts a one-octet option 80 on the ACK, plain takes it off.
		malformed, plain bool
	}{
		{"another server", true, rcAddr, rcOtherSID, StateRequesting, 1, false, false},
		{"another address", true, rcOtherIP, rcServer, StateRequesting, 1, false, false},
		{"the server and address asked", true, rcAddr, rcServer, StateBound, 0, false, false},
		{"the server and address asked, option 80 malformed", true, rcAddr, rcServer, StateRequesting, 1, true, false},
		{"a client that did not ask, another server", false, rcAddr, rcOtherSID, StateBound, 0, false, false},
		{"no option 80, another server, as before the feature", true, rcAddr, rcOtherSID, StateBound, 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testParams()
			p.RapidCommit = tc.rapid
			m, disc := rcSelecting(t, p)
			_, acts := m.Step(at(11), 2, received(t, offerFor(disc, rcAddr, rcServer)))
			req := mustSend(t, acts, wire.MsgRequest)
			ack := ackFor(req, tc.yiaddr, tc.sid, 3600)
			ack.Options[wire.OptRapidCommit] = wire.EncodeRapidCommit()
			if tc.malformed {
				ack.Options[wire.OptRapidCommit] = []byte{1}
			}
			if tc.plain {
				delete(ack.Options, wire.OptRapidCommit)
			}
			to, acts := m.Step(at(12), 3, received(t, ack))
			if to != tc.want {
				t.Fatalf("state %s, want %s\n%v", to, tc.want, RenderActions(acts))
			}
			if c := m.RapidCommitCounters(); c.Refused != tc.refuse || c.Accepted != 0 {
				t.Errorf("counters %+v, want Refused %d Accepted 0", c, tc.refuse)
			}
			if tc.want == StateRequesting {
				if _, ok := find(acts, ActLeaseAcquired); ok {
					t.Error("a lease was acquired")
				}
				m.Step(at(13), 4, received(t, ackFor(req, rcAddr, rcServer, 3600)))
				if m.State() != StateBound {
					t.Errorf("the plain ACK from the server asked reached %s, want BOUND", m.State())
				}
			}
		})
	}
}

// TestARapidLeaseReplaysFromTheJournal: the ACK is re-decoded from its bytes, so
// option 80 comes back with it and no event kind was added. Replay under the
// same Params reaches the same lease; under RapidCommit false it diverges,
// because the flag is part of the seed (claymore666/docker-net-dhcp#1031).
func TestARapidLeaseReplaysFromTheJournal(t *testing.T) {
	p := rcParams()
	m := newMachine(t, p)
	var es []JournalEntry
	acts := stepAndRecord(m, &es, at(10), 0xA1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	stepAndRecord(m, &es, at(12), 0xA2, received(t, rcAck(disc, rcAddr, rcServer, 3600)))
	live, held := m.Lease()
	if !held || m.State() != StateBound {
		t.Fatalf("the recorded run is %s held=%v, there is nothing to replay", m.State(), held)
	}

	ev, err := es[1].Event()
	if err != nil {
		t.Fatalf("the ACK entry does not decode: %v", err)
	}
	if !hasRapidOption(ev.Msg) {
		t.Fatal("the journalled ACK lost option 80 in its bytes")
	}
	got, err := Replay(p, es)
	if err != nil {
		t.Fatalf("the run does not replay under the params it ran with: %v", err)
	}
	if !got.Held || got.State != StateBound || got.Lease.Addr != live.Addr || got.Lease.Start != live.Start ||
		got.Lease.LeaseTime != live.LeaseTime || got.Lease.ServerID != live.ServerID {
		t.Fatalf("the replay reached %+v, the run held %+v", got, live)
	}

	plain := testParams()
	if _, err := Replay(plain, es); !errors.Is(err, ErrReplayDiverged) {
		t.Fatalf("Replay with RapidCommit false = %v, want ErrReplayDiverged", err)
	}
}

// TestANilMessageInInitIsIgnoredNotDereferenced: INIT looks at the message for
// option 80 before any validity check has run (claymore666/docker-net-dhcp#1031).
func TestANilMessageInInitIsIgnoredNotDereferenced(t *testing.T) {
	m, _ := rcSelecting(t, rcParams())
	m.Step(at(11), 2, Simple(EvLinkDown))
	to, acts := m.Step(at(12), 3, Event{Kind: EvReceived})
	if to != StateInit {
		t.Fatalf("state %s, want INIT", to)
	}
	if !strings.Contains(rcJournal(acts), "ignored in INIT") || m.RapidCommitCounters().Refused != 0 {
		t.Errorf("a nil message in INIT: %q, counters %+v", rcJournal(acts), m.RapidCommitCounters())
	}
}

// TestAnOfferCarryingOption80InInitIsNotCountedAsARefusedAck: only a DHCPACK is
// the rapid answer the counter names (claymore666/docker-net-dhcp#1031).
func TestAnOfferCarryingOption80InInitIsNotCountedAsARefusedAck(t *testing.T) {
	m, disc := rcSelecting(t, rcParams())
	m.Step(at(11), 2, Simple(EvLinkDown))
	off := offerFor(disc, rcAddr, rcServer)
	off.Options[wire.OptRapidCommit] = wire.EncodeRapidCommit()
	m.Step(at(12), 3, received(t, off))
	if c := m.RapidCommitCounters(); c != (RapidCommitCounters{}) {
		t.Errorf("counters %+v, want none: an OFFER is not a rapid ACK", c)
	}
}

// TestANakCarryingOption80InSelectingIsStillDiscarded: a DHCPNAK is not the
// rapid answer, whatever else it carries (claymore666/docker-net-dhcp#1031).
func TestANakCarryingOption80InSelectingIsStillDiscarded(t *testing.T) {
	m, disc := rcSelecting(t, rcParams())
	nak := nakFor(disc, rcServer, "no")
	nak.Options[wire.OptRapidCommit] = wire.EncodeRapidCommit()
	to, acts := m.Step(at(11), 2, received(t, nak))
	if to != StateSelecting {
		t.Fatalf("state %s, want SELECTING", to)
	}
	if j := rcJournal(acts); !strings.Contains(j, "DHCPNAK in SELECTING: discarded") {
		t.Errorf("journal %q lost the section 4.4.1 discard", j)
	}
	if c := m.RapidCommitCounters(); c != (RapidCommitCounters{}) {
		t.Errorf("counters %+v, want none", c)
	}
}
