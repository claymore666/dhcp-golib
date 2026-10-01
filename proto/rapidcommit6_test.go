// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"bytes"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// This file builds from fakes6_test.go and fakes_test.go and from nothing else
// in the package's tests, so a run with the other test files switched off
// still compiles it (claymore666/docker-net-dhcp#926).

const rc6Addr = "fd00:99::183"

var rc6RA = []byte{
	134, 0, 0, 0,
	64, 0x40, 0x07, 0x08,
	0, 0, 0, 0,
	0, 0, 0, 0,
}

func rc6Params(on bool) Params6 {
	p := testParams6()
	p.RapidCommit = on
	return p
}

func rc6Journal(acts []Action) string {
	var b strings.Builder
	for _, a := range acts {
		if a.Kind == ActJournal {
			b.WriteString("\n\t" + a.Note)
		}
	}
	return b.String()
}

func rc6Says(acts []Action, sub string) bool { return strings.Contains(rc6Journal(acts), sub) }

// rc6On the wire: how many option 14s the message carries once it is encoded
// and decoded again, and whether the bytes hold the option's own four octets.
func rc6OnTheWire(t *testing.T, msg *wire.MessageV6) (count int, raw []byte) {
	t.Helper()
	raw, err := wire.EncodeV6(msg)
	if err != nil {
		t.Fatalf("EncodeV6: %v", err)
	}
	back, err := wire.DecodeV6(raw)
	if err != nil {
		t.Fatalf("DecodeV6: %v", err)
	}
	for _, o := range back.Options.All(wire.OptV6RapidCommit) {
		if len(o) != 0 {
			t.Errorf("option 14 carries %d octets, §21.14 says option-len is 0", len(o))
		}
	}
	return back.Options.Count(wire.OptV6RapidCommit), raw
}

func rc6Reply14(t *testing.T, xid uint32, extra ...wire.OptionV6) Event {
	t.Helper()
	opts := []wire.OptionV6{
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{rc6Addr, 300, 300}}),
		wire.RapidCommitOption(),
	}
	return receivedV6(t, wire.MsgReply, xid, append(opts, extra...)...)
}

func rc6Kinds(acts []Action) []ActionKind {
	var k []ActionKind
	for _, a := range acts {
		if a.Kind != ActJournal {
			k = append(k, a.Kind)
		}
	}
	return k
}

func rc6Acquired(acts []Action) int {
	n := 0
	for _, a := range acts {
		if a.Kind == ActLeaseAcquired {
			n++
		}
	}
	return n
}

func rc6Armed(acts []Action, id TimerID) (Duration, bool) {
	for _, a := range acts {
		if a.Kind == ActSetTimer && a.Timer == id {
			return a.After, true
		}
	}
	return 0, false
}

func rc6Cancelled(acts []Action, id TimerID) bool {
	for _, a := range acts {
		if a.Kind == ActCancelTimer && a.Timer == id {
			return true
		}
	}
	return false
}

// rc6Refusals is the ActFailed refusals acts reported, by status code.
func rc6Refusals(acts []Action, code wire.StatusCode) int {
	n := 0
	for _, a := range acts {
		if a.Kind == ActFailed && a.Reason == ReasonNak && a.Status == code {
			n++
		}
	}
	return n
}

// rc6Bound takes a machine to BOUND through the four-message exchange.
func rc6Bound(t *testing.T, p Params6) *Machine6 {
	t.Helper()
	m, _ := solicit6(t, p)
	m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	m.Step(at(3), 0, reply(t, uint32(capXIDRequest), rc6Addr))
	if s, _ := m.Step(at(4), 0, DADResult(addr6(rc6Addr), false)); s != State6Bound {
		t.Fatalf("the exchange left the machine in %s, want %s", s, State6Bound)
	}
	return m
}

func rc6Counters(t *testing.T, m *Machine6, accepted, refused uint64) {
	t.Helper()
	if c := m.RapidCommitCounters(); c.Accepted != accepted || c.Refused != refused {
		t.Errorf("RapidCommitCounters = %+v, want accepted %d refused %d", c, accepted, refused)
	}
}

func TestRapidCommit6IsOffByDefaultAndSendsNothing(t *testing.T) {
	if DefaultParams6().RapidCommit {
		t.Fatal("DefaultParams6 asks for Rapid Commit")
	}
	for name, p := range map[string]Params6{"defaults": testParams6(), "explicit false": rc6Params(false)} {
		t.Run(name, func(t *testing.T) {
			m, sol := solicit6(t, p)
			if n, _ := rc6OnTheWire(t, sol); n != 0 {
				t.Errorf("a Solicit from a client that never asked carries %d option 14", n)
			}
			rc6Counters(t, m, 0, 0)
		})
	}
}

func TestRapidCommit6IsOnTheSolicitAndItsRetransmission(t *testing.T) {
	_, plain := solicit6(t, rc6Params(false))
	m, sol := solicit6(t, rc6Params(true))
	n, raw := rc6OnTheWire(t, sol)
	if n != 1 {
		t.Fatalf("the Solicit carries %d option 14, want 1", n)
	}
	if !bytes.Contains(raw, []byte{0x00, 0x0e, 0x00, 0x00}) {
		t.Errorf("the encoded Solicit %x holds no zero-length option 14", raw)
	}
	if len(sol.Options) != len(plain.Options)+1 {
		t.Errorf("the rapid Solicit has %d options, the plain one %d: only option 14 may differ", len(sol.Options), len(plain.Options))
	}
	// The first RT with no Advertise is the retransmission, and it is built
	// again: it must carry the option and keep the transaction id.
	_, acts := m.Step(at(3), 0, TimerFired(Timer6Retransmit))
	again := mustSendV6(t, acts, wire.MsgSolicit)
	if again.XID != sol.XID {
		t.Errorf("the retransmitted Solicit has xid %06x, want %06x (§16.1)", again.XID, sol.XID)
	}
	if n, _ := rc6OnTheWire(t, again); n != 1 {
		t.Errorf("the retransmitted Solicit carries %d option 14, want 1", n)
	}
}

func TestRapidCommit6IsOnNoMessageButTheSolicit(t *testing.T) {
	check := func(t *testing.T, msg *wire.MessageV6, want wire.MessageTypeV6) {
		t.Helper()
		if msg.Type != want {
			t.Fatalf("got a %s, want a %s", msg.Type, want)
		}
		if n, _ := rc6OnTheWire(t, msg); n != 0 {
			t.Errorf("a %s carries %d option 14; §18.2.1 puts it in the Solicit only", want, n)
		}
	}
	p := rc6Params(true)
	t.Run("Request", func(t *testing.T) {
		m, _ := solicit6(t, p)
		_, acts := m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
		check(t, mustSendV6(t, acts, wire.MsgRequest6), wire.MsgRequest6)
	})
	t.Run("Renew and Rebind", func(t *testing.T) {
		m := rc6Bound(t, p)
		s, acts := m.Step(at(160), 3, TimerFired(Timer6Renew))
		if s != State6Renewing {
			t.Fatalf("T1 left the machine in %s", s)
		}
		check(t, mustSendV6(t, acts, wire.MsgRenew), wire.MsgRenew)
		s, acts = m.Step(at(250), 3, TimerFired(Timer6Rebind))
		if s != State6Rebinding {
			t.Fatalf("T2 left the machine in %s", s)
		}
		check(t, mustSendV6(t, acts, wire.MsgRebind), wire.MsgRebind)
	})
	t.Run("Release", func(t *testing.T) {
		m := rc6Bound(t, p)
		_, acts := m.Step(at(100), 3, Simple(EvRelease))
		check(t, mustSendV6(t, acts, wire.MsgRelease6), wire.MsgRelease6)
	})
	t.Run("Decline", func(t *testing.T) {
		m, _ := solicit6(t, p)
		m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
		m.Step(at(3), 0, reply(t, uint32(capXIDRequest), rc6Addr))
		_, acts := m.Step(at(4), 3, DADResult(addr6(rc6Addr), true))
		check(t, mustSendV6(t, acts, wire.MsgDecline6), wire.MsgDecline6)
	})
	t.Run("Confirm", func(t *testing.T) {
		q := p
		q.Resume = &Resume6{
			Addrs:      []Addr6{{Addr: addr6(rc6Addr), Preferred: 300 * Second, Valid: 300 * Second}},
			ServerDUID: append([]byte(nil), testServerDUID...),
			T1:         150 * Second,
			T2:         240 * Second,
		}
		m := newMachine6(t, q)
		m.Step(at(0), 0, Simple(EvStart))
		_, acts := m.Step(at(1), capXIDSolicit, TimerFired(Timer6Delay))
		check(t, mustSendV6(t, acts, wire.MsgConfirm), wire.MsgConfirm)
	})
	t.Run("Information-request", func(t *testing.T) {
		m, _ := solicit6(t, p)
		_, acts := m.Step(at(2), 3, RouterAdvertRaw(mustRA(t, rc6RA), rc6RA))
		check(t, mustSendV6(t, acts, wire.MsgInformationRequest), wire.MsgInformationRequest)
	})
}

func TestARapid6ReplyInSelectingIsTheLeaseAndSendsNoRequest(t *testing.T) {
	m, sol := solicit6(t, rc6Params(true))
	s, acts := m.Step(at(2), 0, rc6Reply14(t, sol.XID))
	if s != State6DAD {
		t.Fatalf("a Reply with option 14 left the machine in %s, want %s\n%s", s, State6DAD, rc6Journal(acts))
	}
	if hasSendV6(acts, wire.MsgRequest6) {
		t.Error("a Request went out after the Reply that completed the exchange")
	}
	if !rc6Cancelled(acts, Timer6Retransmit) {
		t.Error("the Solicit's retransmission was left running")
	}
	if !rc6Says(acts, "lease taken, no Request sent") {
		t.Errorf("the rapid lease was not journalled:%s", rc6Journal(acts))
	}
	rc6Counters(t, m, 1, 0)

	s, acts = m.Step(at(3), 0, DADResult(addr6(rc6Addr), false))
	if s != State6Bound {
		t.Fatalf("a clean DAD result left the machine in %s", s)
	}
	if rc6Acquired(acts) != 1 {
		t.Errorf("%d lease-acquired actions, want 1", rc6Acquired(acts))
	}
	l, held := m.Lease()
	if !held || len(l.Addrs) != 1 || l.Addrs[0].Addr != addr6(rc6Addr) {
		t.Fatalf("lease = %+v held %t, want %s", l, held, rc6Addr)
	}
	if !bytes.Equal(l.ServerDUID, testServerDUID) || l.T1 != 150*Second || l.T2 != 240*Second {
		t.Errorf("lease server %x T1 %s T2 %s, want %x 150s 240s", l.ServerDUID, l.T1, l.T2, testServerDUID)
	}
	if l.Start != at(1) {
		t.Errorf("the lease starts at %v, want the Solicit's instant %v", l.Start, at(1))
	}
	if d, ok := rc6Armed(acts, Timer6Renew); !ok || d != 150*Second-at(3).Sub(at(1)) {
		t.Errorf("T1 armed %s %t, want the lease's 150s counted from the Solicit", d, ok)
	}
}

func TestARapid6ReplyTakesTheSamePathAnOrdinaryReplyTakes(t *testing.T) {
	rapid, sol := solicit6(t, rc6Params(true))
	_, rReply := rapid.Step(at(2), 0, rc6Reply14(t, sol.XID))
	_, rDAD := rapid.Step(at(3), 0, DADResult(addr6(rc6Addr), false))

	plain, _ := solicit6(t, rc6Params(false))
	plain.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	_, pReply := plain.Step(at(3), 0, reply(t, uint32(capXIDRequest), rc6Addr))
	_, pDAD := plain.Step(at(4), 0, DADResult(addr6(rc6Addr), false))

	for name, pair := range map[string][2][]Action{"reply": {rReply, pReply}, "dad": {rDAD, pDAD}} {
		got, want := rc6Kinds(pair[0]), rc6Kinds(pair[1])
		if len(got) != len(want) {
			t.Errorf("%s step: rapid actions %v, ordinary %v", name, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%s step: rapid actions %v, ordinary %v", name, got, want)
				break
			}
		}
	}
	rl, _ := rapid.Lease()
	pl, _ := plain.Lease()
	if len(rl.Addrs) != len(pl.Addrs) || rl.Addrs[0] != pl.Addrs[0] || rl.T1 != pl.T1 || rl.T2 != pl.T2 || !bytes.Equal(rl.ServerDUID, pl.ServerDUID) {
		t.Errorf("rapid lease %+v, ordinary lease %+v", rl, pl)
	}
	if rapid.State() != plain.State() {
		t.Errorf("rapid ends in %s, ordinary in %s", rapid.State(), plain.State())
	}
}

func TestARapid6ReplyIsDiscardedWhereItAnswersNothingTheClientSent(t *testing.T) {
	good := func(t *testing.T) []wire.OptionV6 {
		return []wire.OptionV6{
			optClientID(capDUID), optServerID(testServerDUID),
			optIANA(t, capIAID, 150, 240, []iaAddrSpec{{rc6Addr, 300, 300}}),
		}
	}
	for _, tc := range []struct {
		name     string
		on       bool
		xid      uint32
		opts     func(t *testing.T) []wire.OptionV6
		say      string
		refused  uint64
		wantSelc bool
	}{
		{"a transaction id from another exchange", true, 0x111111,
			func(t *testing.T) []wire.OptionV6 { return append(good(t), wire.RapidCommitOption()) },
			"does not match the outstanding", 1, true},
		{"no Server Identifier", true, uint32(capXIDSolicit),
			func(t *testing.T) []wire.OptionV6 {
				return []wire.OptionV6{optClientID(capDUID), wire.RapidCommitOption(),
					optIANA(t, capIAID, 150, 240, []iaAddrSpec{{rc6Addr, 300, 300}})}
			},
			"carries no Server Identifier option", 1, true},
		{"no option 14 (RFC 8415 18.2.1)", true, uint32(capXIDSolicit),
			good, "Reply without Rapid Commit arrived while soliciting", 0, true},
		{"a malformed option 14", true, uint32(capXIDSolicit),
			func(t *testing.T) []wire.OptionV6 {
				return append(good(t), wire.OptionV6{Code: wire.OptV6RapidCommit, Data: []byte{1}})
			},
			"option 14 is malformed", 1, true},
		{"the Solicit did not ask", false, uint32(capXIDSolicit),
			func(t *testing.T) []wire.OptionV6 { return append(good(t), wire.RapidCommitOption()) },
			"the Solicit did not ask for it", 1, true},
		{"a plain Reply to a Solicit that did not ask", false, uint32(capXIDSolicit),
			good, "a Reply arrived while soliciting: ignored", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, sol := solicit6(t, rc6Params(tc.on))
			s, acts := m.Step(at(2), 0, receivedV6(t, wire.MsgReply, tc.xid, tc.opts(t)...))
			if s != State6Selecting {
				t.Fatalf("the machine moved to %s on a Reply it must discard", s)
			}
			if hasSendV6(acts, wire.MsgRequest6) {
				t.Error("a Request went out")
			}
			if _, held := m.Lease(); held {
				t.Error("a lease was taken")
			}
			if !rc6Says(acts, tc.say) {
				t.Errorf("not journalled as %q:%s", tc.say, rc6Journal(acts))
			}
			rc6Counters(t, m, 0, tc.refused)
			if rc6Cancelled(acts, Timer6Retransmit) {
				t.Error("the Solicit's retransmission was cancelled")
			}
			_, acts = m.Step(at(3), 0, TimerFired(Timer6Retransmit))
			if again := mustSendV6(t, acts, wire.MsgSolicit); again.XID != sol.XID {
				t.Errorf("the exchange did not survive: Solicit xid %06x, want %06x", again.XID, sol.XID)
			}
		})
	}
}

func TestARapid6ReplyAfterTheRequestIsNotASecondLease(t *testing.T) {
	m, sol := solicit6(t, rc6Params(true))
	s, acts := m.Step(at(2), capXIDRequest, advertise(t, sol.XID, 255))
	if s != State6Requesting {
		t.Fatalf("the Advertise left the machine in %s", s)
	}
	req := mustSendV6(t, acts, wire.MsgRequest6)

	s, acts = m.Step(at(3), 0, rc6Reply14(t, sol.XID))
	if s != State6Requesting {
		t.Fatalf("a Reply+14 for the Solicit's xid moved the machine to %s", s)
	}
	if !rc6Says(acts, "does not match the outstanding") {
		t.Errorf("the stale Reply was not journalled by admit:%s", rc6Journal(acts))
	}
	rc6Counters(t, m, 0, 1)

	// The Reply to the Request carries 14 as well: it is the ordinary answer.
	s, _ = m.Step(at(4), 0, rc6Reply14(t, req.XID))
	if s != State6DAD {
		t.Fatalf("the Reply to the Request left the machine in %s", s)
	}
	rc6Counters(t, m, 0, 1)
	s, acts = m.Step(at(5), 0, DADResult(addr6(rc6Addr), false))
	if s != State6Bound || rc6Acquired(acts) != 1 {
		t.Fatalf("state %s with %d acquisitions", s, rc6Acquired(acts))
	}
	// And a second copy of it, or a late Solicit-xid one, makes no second lease.
	for _, xid := range []uint32{req.XID, sol.XID} {
		s, acts = m.Step(at(6), 0, rc6Reply14(t, xid))
		if s != State6Bound || rc6Acquired(acts) != 0 || rc6Cancelled(acts, Timer6Renew) {
			t.Errorf("a late Reply+14 (xid %06x) changed state to %s or the lease:%s", xid, s, rc6Journal(acts))
		}
	}
	rc6Counters(t, m, 0, 3)
}

func TestALateAdvertiseOrReply6AfterARapidLeaseIsDropped(t *testing.T) {
	m, sol := solicit6(t, rc6Params(true))
	m.Step(at(2), 0, rc6Reply14(t, sol.XID))
	for _, state := range []State6{State6DAD, State6Bound} {
		if m.State() != state {
			t.Fatalf("state %s, want %s", m.State(), state)
		}
		s, acts := m.Step(at(3), capXIDRequest, advertise(t, sol.XID, 255))
		if s != state || hasSendV6(acts, wire.MsgRequest6) {
			t.Errorf("a late Advertise in %s moved the machine to %s or sent a Request", state, s)
		}
		s, acts = m.Step(at(3), 0, rc6Reply14(t, sol.XID))
		if s != state || rc6Acquired(acts) != 0 {
			t.Errorf("a late Reply in %s moved the machine to %s", state, s)
		}
		for _, a := range acts {
			if a.Kind == ActStartDAD {
				t.Errorf("a late Reply in %s started a second DAD", state)
			}
		}
		if state == State6DAD {
			m.Step(at(4), 0, DADResult(addr6(rc6Addr), false))
		}
	}
	rc6Counters(t, m, 1, 2)
}

func TestAPlainAdvertise6ToARapidSolicitLeadsToRequestAndReply(t *testing.T) {
	m, sol := solicit6(t, rc6Params(true))
	if s, acts := m.Step(at(2), capXIDRequest, advertise(t, sol.XID, 0)); s != State6Selecting || hasSendV6(acts, wire.MsgRequest6) {
		t.Fatalf("a preference-0 Advertise ended the collection window early (state %s)", s)
	}
	s, acts := m.Step(at(3), capXIDRequest, TimerFired(Timer6Retransmit))
	if s != State6Requesting {
		t.Fatalf("the window ending left the machine in %s, want %s", s, State6Requesting)
	}
	req := mustSendV6(t, acts, wire.MsgRequest6)
	if n, _ := rc6OnTheWire(t, req); n != 0 {
		t.Errorf("the Request carries %d option 14", n)
	}
	if s, _ = m.Step(at(4), 0, reply(t, req.XID, rc6Addr)); s != State6DAD {
		t.Fatalf("the Reply to the Request left the machine in %s", s)
	}
	if s, _ = m.Step(at(5), 0, DADResult(addr6(rc6Addr), false)); s != State6Bound {
		t.Fatalf("DAD left the machine in %s", s)
	}
	rc6Counters(t, m, 0, 0)
}

func TestAnAdvertise6CarryingOption14IsAnAdvertise(t *testing.T) {
	m, sol := solicit6(t, rc6Params(true))
	adv := receivedV6(t, wire.MsgAdvertise, sol.XID,
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{rc6Addr, 300, 300}}),
		optPreference(255), wire.RapidCommitOption())
	s, acts := m.Step(at(2), capXIDRequest, adv)
	if s != State6Requesting || !hasSendV6(acts, wire.MsgRequest6) {
		t.Fatalf("an Advertise with option 14 left the machine in %s with no Request", s)
	}
	if _, held := m.Lease(); held {
		t.Error("an Advertise gave a lease")
	}
	rc6Counters(t, m, 0, 0)
}

func TestARapid6ReplyThatGivesNoAddressIsNotALease(t *testing.T) {
	// What dnsmasq sends a Solicit with option 14 when it has no address: a
	// Reply with option 14 and a message-level NoAddrsAvail, no IA_NA.
	withNone := func(t *testing.T) []wire.OptionV6 {
		return []wire.OptionV6{optClientID(capDUID), optServerID(testServerDUID),
			wire.RapidCommitOption(), optStatus(wire.StatusNoAddrsAvail)}
	}
	inIA := func(t *testing.T) []wire.OptionV6 {
		return []wire.OptionV6{optClientID(capDUID), optServerID(testServerDUID), wire.RapidCommitOption(),
			optIANA(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoAddrsAvail))}
	}
	zero := func(t *testing.T) []wire.OptionV6 {
		return []wire.OptionV6{optClientID(capDUID), optServerID(testServerDUID), wire.RapidCommitOption(),
			optIANA(t, capIAID, 150, 240, []iaAddrSpec{{rc6Addr, 0, 0}})}
	}
	for _, tc := range []struct {
		name    string
		opts    func(*testing.T) []wire.OptionV6
		refusal bool
	}{
		{"message-level NoAddrsAvail", withNone, true},
		{"IA-level NoAddrsAvail", inIA, true},
		{"an address with a valid lifetime of 0", zero, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, sol := solicit6(t, rc6Params(true))
			s, acts := m.Step(at(2), capXIDRequest, receivedV6(t, wire.MsgReply, sol.XID, tc.opts(t)...))
			if s != State6Selecting {
				t.Fatalf("the machine moved to %s\n%s", s, rc6Journal(acts))
			}
			if _, held := m.Lease(); held {
				t.Error("a lease was taken")
			}
			if hasSendV6(acts, wire.MsgRequest6) || hasSendV6(acts, wire.MsgSolicit) {
				t.Errorf("the Reply made the client send at once:%s", rc6Journal(acts))
			}
			if _, ok := rc6Armed(acts, Timer6Retransmit); ok || rc6Cancelled(acts, Timer6Retransmit) {
				t.Error("the Solicit's schedule was touched")
			}
			if tc.refusal && rc6Refusals(acts, wire.StatusNoAddrsAvail) != 1 {
				t.Errorf("the NoAddrsAvail refusal was reported %d times, want 1", rc6Refusals(acts, wire.StatusNoAddrsAvail))
			}
			rc6Counters(t, m, 0, 1)
			// The Solicit goes on at its own pace, with its own xid, and a
			// later Advertise from another server is still requested.
			if _, acts = m.Step(at(3), 0, TimerFired(Timer6Retransmit)); mustSendV6(t, acts, wire.MsgSolicit).XID != sol.XID {
				t.Error("the Solicit changed its transaction id")
			}
			if s, acts = m.Step(at(4), capXIDRequest, advertise(t, sol.XID, 255)); s != State6Requesting || !hasSendV6(acts, wire.MsgRequest6) {
				t.Errorf("a later Advertise left the machine in %s", s)
			}
		})
	}
}

func TestARapid6NotOnLinkIsNotAnsweredWithTheSameHint(t *testing.T) {
	p := rc6Params(true)
	p.Hint = addr6(rc6Addr)
	m, sol := solicit6(t, p)
	hinted := func(msg *wire.MessageV6) bool {
		ia, ok := msg.Options.First(wire.OptV6IANA)
		return ok && bytes.Contains(ia, addr6(rc6Addr).AsSlice())
	}
	if !hinted(sol) {
		t.Fatal("the first Solicit carries no hint, so this test shows nothing")
	}
	s, acts := m.Step(at(2), 0, receivedV6(t, wire.MsgReply, sol.XID,
		optClientID(capDUID), optServerID(testServerDUID), wire.RapidCommitOption(), optStatus(wire.StatusNotOnLink)))
	if s != State6Init {
		t.Fatalf("NotOnLink left the machine in %s, want a restarted discovery", s)
	}
	if rc6Refusals(acts, wire.StatusNotOnLink) != 1 {
		t.Errorf("NotOnLink reported %d times", rc6Refusals(acts, wire.StatusNotOnLink))
	}
	rc6Counters(t, m, 0, 1)
	_, acts = m.Step(at(3), capXIDRequest, TimerFired(Timer6Delay))
	second := mustSendV6(t, acts, wire.MsgSolicit)
	if hinted(second) {
		t.Error("the restarted Solicit hints the address the server just said is not on this link")
	}
	// A second NotOnLink, to the Solicit that carried no hint, does not make
	// the machine forget the first: the third Solicit still carries none.
	m.Step(at(4), 0, receivedV6(t, wire.MsgReply, second.XID,
		optClientID(capDUID), optServerID(testServerDUID), wire.RapidCommitOption(), optStatus(wire.StatusNotOnLink)))
	_, acts = m.Step(at(5), capXIDSolicit, TimerFired(Timer6Delay))
	if hinted(mustSendV6(t, acts, wire.MsgSolicit)) {
		t.Error("a second NotOnLink made the machine hint the refused address again")
	}
}

// TestRapid6CountersCountOnlyReplies: the counter is about Replies carrying
// option 14. An Advertise with the option, discarded or late, adds nothing, and
// a Reply with the option twice is still a Reply with option 14
// (claymore666/docker-net-dhcp#926).
func TestRapid6CountersCountOnlyReplies(t *testing.T) {
	good := []wire.OptionV6{
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{rc6Addr, 300, 300}}),
		optPreference(255), wire.RapidCommitOption(),
	}
	m, sol := solicit6(t, rc6Params(true))
	m.Step(at(2), 0, receivedV6(t, wire.MsgAdvertise, sol.XID+1, good...))
	rc6Counters(t, m, 0, 0)
	twice := append(append([]wire.OptionV6{}, good...), wire.RapidCommitOption())
	m.Step(at(3), 0, receivedV6(t, wire.MsgReply, sol.XID+1, twice...))
	rc6Counters(t, m, 0, 1)

	m, sol = solicit6(t, rc6Params(true))
	m.Step(at(2), 0, rc6Reply14(t, sol.XID))
	for _, state := range []State6{State6DAD, State6Bound} {
		if m.State() != state {
			t.Fatalf("state %s, want %s", m.State(), state)
		}
		m.Step(at(3), 0, receivedV6(t, wire.MsgAdvertise, sol.XID, good...))
		rc6Counters(t, m, 1, 0)
		if state == State6DAD {
			m.Step(at(4), 0, DADResult(addr6(rc6Addr), false))
		}
	}
}

func TestARapid6LeaseReplaysFromTheJournal(t *testing.T) {
	p := rc6Params(true)
	m := newMachine6(t, p)
	var entries []JournalEntry6
	step := func(now Instant, rnd uint64, ev Event) State6 {
		from := m.State()
		to, acts := m.Step(now, rnd, ev)
		entries = append(entries, NewJournalEntry6(uint64(len(entries)), now, rnd, ev, from, to, acts))
		return to
	}
	step(at(0), 0, Simple(EvStart))
	step(at(1), capXIDSolicit, TimerFired(Timer6Delay))
	step(at(2), 0, rc6Reply14(t, uint32(capXIDSolicit)))
	if step(at(3), 0, DADResult(addr6(rc6Addr), false)) != State6Bound {
		t.Fatal("the recorded run did not bind")
	}
	res, err := Replay6(p, entries)
	if err != nil {
		t.Fatalf("Replay6: %v", err)
	}
	live, _ := m.Lease()
	if res.State != State6Bound || !res.Held || res.Lease.Start != live.Start ||
		len(res.Lease.Addrs) != 1 || res.Lease.Addrs[0] != live.Addrs[0] || res.Steps != 4 {
		t.Errorf("replay: state %s held %t lease %+v steps %d; recorded lease %+v", res.State, res.Held, res.Lease, res.Steps, live)
	}
	// The flag is the replay's seed: the same journal against a client that
	// never asked does not reproduce the exchange.
	if _, err := Replay6(rc6Params(false), entries); err == nil {
		t.Error("the journal replayed against a client that never asked for Rapid Commit")
	}
}

// TestARapid6ReplyWithInfiniteLifetimesIsTheLeaseAnOrdinaryReplyGives: the
// all-ones lifetime is infinity (RFC 8415 section 7.7), and a rapid Reply
// carrying it binds exactly as the ordinary Reply does
// (claymore666/docker-net-dhcp#926).
func TestARapid6ReplyWithInfiniteLifetimesIsTheLeaseAnOrdinaryReplyGives(t *testing.T) {
	forever := []iaAddrSpec{{rc6Addr, 0xFFFFFFFF, 0xFFFFFFFF}}
	rapid, sol := solicit6(t, rc6Params(true))
	rapid.Step(at(2), 0, rc6RapidWith(t, sol.XID, forever))
	rapid.Step(at(3), 0, DADResult(addr6(rc6Addr), false))

	plain, _ := solicit6(t, rc6Params(false))
	plain.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	plain.Step(at(3), 0, receivedV6(t, wire.MsgReply, uint32(capXIDRequest),
		optClientID(capDUID), optServerID(testServerDUID), optIANA(t, capIAID, 0xFFFFFFFF, 0xFFFFFFFF, forever)))
	plain.Step(at(4), 0, DADResult(addr6(rc6Addr), false))

	rl, rheld := rapid.Lease()
	pl, pheld := plain.Lease()
	if rapid.State() != State6Bound || plain.State() != State6Bound || !rheld || !pheld {
		t.Fatalf("rapid %s (held %t), ordinary %s (held %t)", rapid.State(), rheld, plain.State(), pheld)
	}
	if rl.Addrs[0] != pl.Addrs[0] || rl.Addrs[0].Valid != Infinite || rl.T1 != pl.T1 || rl.T2 != pl.T2 {
		t.Errorf("rapid lease %+v, ordinary lease %+v", rl, pl)
	}
}

func rc6RapidWith(t *testing.T, xid uint32, addrs []iaAddrSpec) Event {
	t.Helper()
	return receivedV6(t, wire.MsgReply, xid, optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 0xFFFFFFFF, 0xFFFFFFFF, addrs), wire.RapidCommitOption())
}

// TestANotOnLinkAfterTheRequestKeepsTheConfiguredHint: only a Reply to the
// Solicit remembers a refused hint. A NotOnLink to a Request is the base's
// transition and the restarted Solicit still asks, whether or not the client
// asked for Rapid Commit (claymore666/docker-net-dhcp#926).
func TestANotOnLinkAfterTheRequestKeepsTheConfiguredHint(t *testing.T) {
	for _, rapid := range []bool{false, true} {
		p := rc6Params(rapid)
		p.Hint = addr6(rc6Addr)
		m, sol := solicit6(t, p)
		_, acts := m.Step(at(2), capXIDRequest, advertise(t, sol.XID, 255))
		req := mustSendV6(t, acts, wire.MsgRequest6)
		s, _ := m.Step(at(3), 0, receivedV6(t, wire.MsgReply, req.XID,
			optClientID(capDUID), optServerID(testServerDUID), optStatus(wire.StatusNotOnLink)))
		if s != State6Init {
			t.Fatalf("rapid=%t: NotOnLink to the Request left the machine in %s", rapid, s)
		}
		_, acts = m.Step(at(4), capXIDSolicit, TimerFired(Timer6Delay))
		again := mustSendV6(t, acts, wire.MsgSolicit)
		ia, ok := again.Options.First(wire.OptV6IANA)
		if !ok || !bytes.Contains(ia, addr6(rc6Addr).AsSlice()) {
			t.Errorf("rapid=%t: the Solicit after a NotOnLink to the Request lost the configured hint", rapid)
		}
	}
}
