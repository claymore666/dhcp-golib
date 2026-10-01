// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// IPv6-Only Preferred, option 108, RFC 8925 (claymore666/docker-net-dhcp#1027).
// The wire assertions read the message after wire.Encode and wire.Decode. The
// fixtures come from fakes_test.go alone, so this file builds when its
// neighbours are switched off.

const (
	v6oAddr   = "192.168.99.50"
	v6oServer = "192.168.99.1"
)

func v6oParams() Params {
	p := testParams()
	p.IPv6OnlyPreferred = true
	return p
}

func v6oWire(t *testing.T, m *wire.Message) *wire.Message {
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

// v6oSelecting starts p at 10 s and returns the machine in SELECTING with the
// DISCOVER it sent (claymore666/docker-net-dhcp#1027).
func v6oSelecting(t *testing.T, p Params) (*Machine, *wire.Message) {
	t.Helper()
	m := newMachine(t, p)
	_, acts := m.Step(at(10), 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	if m.State() != StateSelecting {
		t.Fatalf("fixture reached %s, want SELECTING", m.State())
	}
	return m, disc
}

// v6oOffer is an OFFER answering disc that carries option 108 with the value (claymore666/docker-net-dhcp#1027).
func v6oOffer(disc *wire.Message, secs uint32) *wire.Message {
	o := offerFor(disc, v6oAddr, v6oServer)
	o.Options[wire.OptIPv6OnlyPreferred] = wire.EncodeIPv6OnlyPreferred(secs)
	return o
}

// v6oAck is an ACK answering req that carries option 108 with the value (claymore666/docker-net-dhcp#1027).
func v6oAck(req *wire.Message, secs uint32) *wire.Message {
	a := ackFor(req, v6oAddr, v6oServer, 3600)
	a.Options[wire.OptIPv6OnlyPreferred] = wire.EncodeIPv6OnlyPreferred(secs)
	return a
}

// v6oBound walks p to BOUND on a plain OFFER and ACK, returning the machine
// and the REQUEST that was answered (claymore666/docker-net-dhcp#1027).
func v6oBound(t *testing.T, p Params) (*Machine, *wire.Message) {
	t.Helper()
	m, disc := v6oSelecting(t, p)
	_, acts := m.Step(at(12), 2, received(t, offerFor(disc, v6oAddr, v6oServer)))
	req := mustSend(t, acts, wire.MsgRequest)
	m.Step(at(13), 3, received(t, ackFor(req, v6oAddr, v6oServer, 3600)))
	if m.State() != StateBound {
		t.Fatalf("fixture reached %s, want BOUND", m.State())
	}
	return m, req
}

func v6oRestartTimer(acts []Action) (Duration, bool) {
	for _, a := range acts {
		if a.Kind == ActSetTimer && a.Timer == TimerRestart {
			return a.After, true
		}
	}
	return 0, false
}

func v6oFailedReason(acts []Action) (Reason, bool) {
	a, ok := find(acts, ActFailed)
	return a.Reason, ok
}

func v6oJournal(acts []Action) string {
	var sb strings.Builder
	for _, a := range acts {
		if a.Kind == ActJournal {
			sb.WriteString(a.Note)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// v6oStep steps m and appends the journal entry the manager would write (claymore666/docker-net-dhcp#1027).
func v6oStep(m *Machine, es *[]JournalEntry, now Instant, rnd uint64, ev Event) []Action {
	from := m.State()
	to, acts := m.Step(now, rnd, ev)
	*es = append(*es, NewJournalEntry(uint64(len(*es)), now, rnd, ev, from, to, acts))
	return acts
}

// v6oCount108 is how many times option 108 appears in a decoded message's
// parameter request list (claymore666/docker-net-dhcp#1027).
func v6oCount108(msg *wire.Message) int {
	n := 0
	for _, b := range msg.Options[wire.OptParameterList] {
		if wire.OptionCode(b) == wire.OptIPv6OnlyPreferred {
			n++
		}
	}
	return n
}

// v6oAssertWait checks the whole action list of a step that must have started
// the wait: nothing sent, INIT, the reason, the restart timer, nothing held (claymore666/docker-net-dhcp#1027).
func v6oAssertWait(t *testing.T, m *Machine, acts []Action, wantWait Duration) {
	t.Helper()
	if n := count(acts, ActSend); n != 0 {
		t.Errorf("the wait sent %d message(s): %v", n, RenderActions(acts))
	}
	if m.State() != StateInit {
		t.Errorf("state %s, want INIT", m.State())
	}
	if r, ok := v6oFailedReason(acts); !ok || r != ReasonIPv6OnlyPreferred {
		t.Errorf("failed reason %v present=%v, want %v", r, ok, ReasonIPv6OnlyPreferred)
	}
	if d, ok := v6oRestartTimer(acts); !ok || d != wantWait {
		t.Errorf("restart timer %v present=%v, want %v", d, ok, wantWait)
	}
	if _, held := m.Lease(); held {
		t.Error("a lease is held during the wait")
	}
}

// TestIPv6OnlyPreferredIsOffByDefaultAndSendsNothing: the zero Params value
// and DefaultParams put no option 108 in the list, and the same Params with
// the flag on does, once, after the default list's entries
// (claymore666/docker-net-dhcp#1027).
func TestIPv6OnlyPreferredIsOffByDefaultAndSendsNothing(t *testing.T) {
	if DefaultParams(testCHAddr).IPv6OnlyPreferred {
		t.Fatal("DefaultParams turns IPv6-Only Preferred on")
	}
	if listsCode(optionBytes(DefaultParameterList()), wire.OptIPv6OnlyPreferred) {
		t.Fatal("DefaultParameterList names option 108")
	}
	_, off := v6oSelecting(t, testParams())
	if n := v6oCount108(v6oWire(t, off)); n != 0 {
		t.Fatalf("a client with the flag false listed option 108 %d time(s)", n)
	}
	_, on := v6oSelecting(t, v6oParams())
	got := v6oWire(t, on).Options[wire.OptParameterList]
	want := optionBytes(DefaultParameterList())
	if len(got) != len(want)+1 || string(got[:len(want)]) != string(want) || got[len(got)-1] != byte(wire.OptIPv6OnlyPreferred) {
		t.Fatalf("the preservation control: list %v, want %v then 108", got, want)
	}
}

func optionBytes(l []wire.OptionCode) []byte {
	b := make([]byte, len(l))
	for i, c := range l {
		b[i] = byte(c)
	}
	return b
}

// TestOption108IsOnEveryRequestListAndOnNoTerminalMessage drives the DISCOVER,
// its retransmission and the four REQUEST senders, then the DECLINE and the
// RELEASE, which carry no list (claymore666/docker-net-dhcp#1027).
func TestOption108IsOnEveryRequestListAndOnNoTerminalMessage(t *testing.T) {
	m, disc := v6oSelecting(t, v6oParams())
	lists := map[string]*wire.Message{"discover": v6oWire(t, disc)}
	_, acts := m.Step(at(14), 2, TimerFired(TimerRetransmit))
	lists["discover-retransmit"] = v6oWire(t, mustSend(t, acts, wire.MsgDiscover))
	_, acts = m.Step(at(15), 3, received(t, offerFor(disc, v6oAddr, v6oServer)))
	req := mustSend(t, acts, wire.MsgRequest)
	lists["selecting"] = v6oWire(t, req)
	m.Step(at(16), 4, received(t, ackFor(req, v6oAddr, v6oServer, 3600)))
	t1, _ := m.lease.RenewAt()
	_, acts = m.Step(t1, 5, TimerFired(TimerRenew))
	lists["renewing"] = v6oWire(t, mustSend(t, acts, wire.MsgRequest))
	t2, _ := m.lease.RebindAt()
	_, acts = m.Step(t2, 6, TimerFired(TimerRebind))
	lists["rebinding"] = v6oWire(t, mustSend(t, acts, wire.MsgRequest))

	rp := resumeParams(testRebootAddr, at(3600), true)
	rp.IPv6OnlyPreferred = true
	rm := newMachine(t, rp)
	_, acts = rm.Step(0, 7, Simple(EvStart))
	lists["init-reboot"] = v6oWire(t, mustSend(t, acts, wire.MsgRequest))

	if len(lists) != 6 {
		t.Fatalf("drove %d senders, want 6", len(lists))
	}
	for name, msg := range lists {
		if n := v6oCount108(msg); n != 1 {
			t.Errorf("the %s message lists option 108 %d time(s), want 1", name, n)
		}
	}

	for _, ev := range []EventKind{EvConflictDetected, EvRelease} {
		bm, _ := v6oBound(t, v6oParams())
		_, acts := bm.Step(at(30), 8, Simple(ev))
		want := wire.MsgDecline
		if ev == EvRelease {
			want = wire.MsgRelease
		}
		msg := v6oWire(t, mustSend(t, acts, want))
		if v6oCount108(msg) != 0 {
			t.Errorf("%s carries option 108 in its list", want)
		}
	}
}

// TestAParameterListNamingOption108NeedsTheFlag: a caller list naming 108 on
// a client that did not set the flag would send the option RFC 8925 section
// 3.2 forbids; with the flag the code is sent once wherever the caller put it,
// and appended when the caller did not (claymore666/docker-net-dhcp#1027).
func TestAParameterListNamingOption108NeedsTheFlag(t *testing.T) {
	list := []wire.OptionCode{wire.OptSubnetMask, wire.OptIPv6OnlyPreferred, wire.OptRouter}
	p := testParams()
	p.ParameterList = list
	if _, err := New(p); !errors.Is(err, ErrBadIPv6OnlyPreferred) {
		t.Fatalf("New with 108 listed and the flag false = %v, want ErrBadIPv6OnlyPreferred", err)
	}

	p.IPv6OnlyPreferred = true
	_, disc := v6oSelecting(t, p)
	got := v6oWire(t, disc).Options[wire.OptParameterList]
	if string(got) != string(optionBytes(list)) {
		t.Errorf("custom list with 108 in it: %v, want %v untouched", got, list)
	}

	p.ParameterList = []wire.OptionCode{wire.OptSubnetMask, wire.OptRouter}
	_, disc = v6oSelecting(t, p)
	got = v6oWire(t, disc).Options[wire.OptParameterList]
	if string(got) != string([]byte{byte(wire.OptSubnetMask), byte(wire.OptRouter), byte(wire.OptIPv6OnlyPreferred)}) {
		t.Errorf("custom list without 108: %v, want 108 appended once", got)
	}

	p.IPv6OnlyPreferred = false
	_, disc = v6oSelecting(t, p)
	if v6oCount108(v6oWire(t, disc)) != 0 {
		t.Error("a custom list on a client with the flag false gained option 108")
	}
}

// TestAnOfferWith108WaitsInsteadOfRequesting: RFC 8925 section 3.2 says the
// client "SHOULD NOT" request the address; the whole action list holds no
// message of any kind (claymore666/docker-net-dhcp#1027).
func TestAnOfferWith108WaitsInsteadOfRequesting(t *testing.T) {
	m, disc := v6oSelecting(t, v6oParams())
	_, acts := m.Step(at(12), 2, received(t, v6oOffer(disc, 1800)))
	v6oAssertWait(t, m, acts, 1800*Second)
	for _, k := range []ActionKind{ActSend, ActLeaseAcquired, ActLeaseLost} {
		if count(acts, k) != 0 {
			t.Errorf("the wait carries %d action(s) of kind %v", count(acts, k), k)
		}
	}
	if c := m.IPv6OnlyCounters(); c != (IPv6OnlyCounters{Waited: 1}) {
		t.Errorf("counters %+v, want Waited 1 only", c)
	}
	if !strings.Contains(v6oJournal(acts), "IPv6-only preferred") {
		t.Errorf("the journal does not say why the machine is idle: %q", v6oJournal(acts))
	}
}

// TestTheWaitIsNeverShorterThanThreeHundredSeconds: RFC 8925 section 3.2 reads
// the value, floored at MIN_V6ONLY_WAIT of section 3.4
// (claymore666/docker-net-dhcp#1027).
func TestTheWaitIsNeverShorterThanThreeHundredSeconds(t *testing.T) {
	for _, tc := range []struct {
		secs uint32
		want Duration
	}{
		{0, 300 * Second},
		{10, 300 * Second},
		{299, 300 * Second},
		{300, 300 * Second},
		{301, 301 * Second},
		{1800, 1800 * Second},
		{86400, 86400 * Second},
	} {
		t.Run(fmt.Sprint(tc.secs), func(t *testing.T) {
			m, disc := v6oSelecting(t, v6oParams())
			_, acts := m.Step(at(12), 2, received(t, v6oOffer(disc, tc.secs)))
			v6oAssertWait(t, m, acts, tc.want)
		})
	}
	if MinV6OnlyWait != 300*Second {
		t.Fatalf("MinV6OnlyWait = %v", MinV6OnlyWait)
	}
}

// TestTheWaitEndsInAFreshDiscover: when the restart timer fires the machine
// begins a new acquisition, a DISCOVER with its own transaction that carries
// nothing from the OFFER that paused it (claymore666/docker-net-dhcp#1027).
func TestTheWaitEndsInAFreshDiscover(t *testing.T) {
	m, disc := v6oSelecting(t, v6oParams())
	_, acts := m.Step(at(12), 2, received(t, v6oOffer(disc, 300)))
	d, _ := v6oRestartTimer(acts)
	to, acts := m.Step(at(12)+Instant(d), 0x77, TimerFired(TimerRestart))
	if to != StateSelecting {
		t.Fatalf("state %s after the wait, want SELECTING", to)
	}
	again := mustSend(t, acts, wire.MsgDiscover)
	if again.XID == disc.XID {
		t.Error("the DISCOVER after the wait reuses the first transaction id")
	}
	for _, c := range []wire.OptionCode{wire.OptRequestedIP, wire.OptServerID} {
		if _, ok := again.Options[c]; ok {
			t.Errorf("the DISCOVER after the wait carries option %d", c)
		}
	}
	if v6oCount108(v6oWire(t, again)) != 1 {
		t.Error("the DISCOVER after the wait does not ask for option 108 again")
	}
}

// TestALinkUpEndsTheWaitEarly: RFC 8925 section 3.2, "or until a network
// attachment event". The link-up event is INIT's own and the park lands there
// (claymore666/docker-net-dhcp#1027).
func TestALinkUpEndsTheWaitEarly(t *testing.T) {
	m, disc := v6oSelecting(t, v6oParams())
	m.Step(at(12), 2, received(t, v6oOffer(disc, 1800)))
	to, acts := m.Step(at(20), 3, Simple(EvLinkUp))
	if to != StateSelecting {
		t.Fatalf("state %s after the link came up, want SELECTING", to)
	}
	again := mustSend(t, acts, wire.MsgDiscover)
	if again.XID == disc.XID {
		t.Error("the DISCOVER after the link event reuses the first transaction id")
	}
	if !v6oHasCancel(acts, TimerRestart) {
		t.Errorf("the wait timer is still armed after the link event: %v", RenderActions(acts))
	}
}

func v6oHasCancel(acts []Action, id TimerID) bool {
	for _, a := range acts {
		if a.Kind == ActCancelTimer && a.Timer == id {
			return true
		}
	}
	return false
}

// TestAnOfferWith108AndNoAddressStillWaits: RFC 8925 section 3.3 says a server
// SHOULD answer a client that listed 108 with yiaddr 0.0.0.0, which the usable
// address check would discard before the option is read; the same offer
// without 108 is still discarded (claymore666/docker-net-dhcp#1027).
func TestAnOfferWith108AndNoAddressStillWaits(t *testing.T) {
	m, disc := v6oSelecting(t, v6oParams())
	off := v6oOffer(disc, 300)
	off.YIAddr = offerFor(disc, "0.0.0.0", v6oServer).YIAddr
	delete(off.Options, wire.OptServerID)
	_, acts := m.Step(at(12), 2, received(t, off))
	v6oAssertWait(t, m, acts, 300*Second)

	m, disc = v6oSelecting(t, v6oParams())
	plain := offerFor(disc, "0.0.0.0", v6oServer)
	_, acts = m.Step(at(12), 2, received(t, plain))
	if m.State() != StateSelecting || count(acts, ActSend) != 0 ||
		!strings.Contains(v6oJournal(acts), "without a usable yiaddr") {
		t.Errorf("the control: an unusable offer without 108 gave %s, %v", m.State(), RenderActions(acts))
	}
}

// TestAClientWithoutTheFlagIgnoresOption108: RFC 8925 section 3.2, "MUST
// ignore". The OFFER is requested as usual, in SELECTING and in the REBOOTING
// ACK, and nothing is counted (claymore666/docker-net-dhcp#1027).
func TestAClientWithoutTheFlagIgnoresOption108(t *testing.T) {
	m, disc := v6oSelecting(t, testParams())
	_, acts := m.Step(at(12), 2, received(t, v6oOffer(disc, 300)))
	mustSend(t, acts, wire.MsgRequest)
	if m.State() != StateRequesting {
		t.Errorf("state %s, want REQUESTING", m.State())
	}
	if c := m.IPv6OnlyCounters(); c != (IPv6OnlyCounters{}) {
		t.Errorf("counters %+v for a client that did not ask", c)
	}

	rp := resumeParams(testRebootAddr, at(3600), true)
	rm := newMachine(t, rp)
	_, acts = rm.Step(0, 1, Simple(EvStart))
	req := mustSend(t, acts, wire.MsgRequest)
	rm.Step(at(1), 2, received(t, v6oAck(req, 300)))
	if rm.State() != StateBound {
		t.Errorf("a REBOOTING ACK with 108 on a client without the flag: %s, want BOUND", rm.State())
	}
}

// TestAMalformedOption108IsTreatedAsAbsentAndCounted: any length but 4 reads
// as no option, in an OFFER and in a REBOOTING ACK, and a well-formed zero is
// not malformed (claymore666/docker-net-dhcp#1027).
func TestAMalformedOption108IsTreatedAsAbsentAndCounted(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 5, 8} {
		t.Run(fmt.Sprint("offer-", n), func(t *testing.T) {
			m, disc := v6oSelecting(t, v6oParams())
			off := offerFor(disc, v6oAddr, v6oServer)
			off.Options[wire.OptIPv6OnlyPreferred] = make([]byte, n)
			_, acts := m.Step(at(12), 2, received(t, off))
			mustSend(t, acts, wire.MsgRequest)
			if m.State() != StateRequesting {
				t.Errorf("state %s, want REQUESTING", m.State())
			}
			if _, ok := v6oRestartTimer(acts); ok {
				t.Error("a malformed option armed the wait")
			}
			if c := m.IPv6OnlyCounters(); c != (IPv6OnlyCounters{Malformed: 1}) {
				t.Errorf("counters %+v, want Malformed 1 only", c)
			}
		})
		t.Run(fmt.Sprint("reboot-", n), func(t *testing.T) {
			rp := resumeParams(testRebootAddr, at(3600), true)
			rp.IPv6OnlyPreferred = true
			m := newMachine(t, rp)
			_, acts := m.Step(0, 1, Simple(EvStart))
			req := mustSend(t, acts, wire.MsgRequest)
			ack := ackFor(req, testRebootAddr, v6oServer, 3600)
			ack.Options[wire.OptIPv6OnlyPreferred] = make([]byte, n)
			m.Step(at(1), 2, received(t, ack))
			if m.State() != StateBound {
				t.Errorf("state %s, want BOUND", m.State())
			}
			if c := m.IPv6OnlyCounters(); c != (IPv6OnlyCounters{Malformed: 1}) {
				t.Errorf("counters %+v, want Malformed 1 only", c)
			}
		})
	}
	m, disc := v6oSelecting(t, v6oParams())
	_, acts := m.Step(at(12), 2, received(t, v6oOffer(disc, 0)))
	v6oAssertWait(t, m, acts, 300*Second)
	if c := m.IPv6OnlyCounters(); c.Malformed != 0 {
		t.Errorf("a four-octet zero counted as malformed: %+v", c)
	}
}

// TestAnAckWith108IsAnOrdinaryAckWhereTheLeaseStands: RFC 8925 section 3.2,
// "SHOULD continue to use the assigned IPv4 address", in REQUESTING, BOUND,
// RENEWING and REBINDING (claymore666/docker-net-dhcp#1027).
func TestAnAckWith108IsAnOrdinaryAckWhereTheLeaseStands(t *testing.T) {
	t.Run("requesting", func(t *testing.T) {
		m, disc := v6oSelecting(t, v6oParams())
		_, acts := m.Step(at(12), 2, received(t, offerFor(disc, v6oAddr, v6oServer)))
		req := mustSend(t, acts, wire.MsgRequest)
		_, acts = m.Step(at(13), 3, received(t, v6oAck(req, 1800)))
		if m.State() != StateBound || count(acts, ActLeaseAcquired) != 1 {
			t.Errorf("state %s, acquired %d: %v", m.State(), count(acts, ActLeaseAcquired), RenderActions(acts))
		}
		if _, ok := v6oRestartTimer(acts); ok {
			t.Error("the ACK armed the wait")
		}
		if c := m.IPv6OnlyCounters(); c != (IPv6OnlyCounters{Ignored: 1}) {
			t.Errorf("counters %+v, want Ignored 1 only", c)
		}
	})
	t.Run("bound", func(t *testing.T) {
		m, req := v6oBound(t, v6oParams())
		before, _ := m.Lease()
		_, acts := m.Step(at(20), 4, received(t, v6oAck(req, 1800)))
		after, held := m.Lease()
		if m.State() != StateBound || !held || after.Addr != before.Addr || after.Start != before.Start || after.LeaseTime != before.LeaseTime || after.ServerID != before.ServerID {
			t.Errorf("state %s held=%v: the lease changed", m.State(), held)
		}
		if count(acts, ActLeaseLost) != 0 || count(acts, ActSend) != 0 {
			t.Errorf("an ACK in BOUND acted: %v", RenderActions(acts))
		}
		if c := m.IPv6OnlyCounters(); c != (IPv6OnlyCounters{Ignored: 1}) {
			t.Errorf("counters %+v, want Ignored 1 only", c)
		}
	})
	t.Run("bound, a message that is no ACK", func(t *testing.T) {
		m, req := v6oBound(t, v6oParams())
		_, acts := m.Step(at(20), 4, received(t, v6oOffer(req, 1800)))
		if m.State() != StateBound || count(acts, ActLeaseLost) != 0 {
			t.Errorf("an unsolicited OFFER with 108 moved BOUND: %s", m.State())
		}
		if c := m.IPv6OnlyCounters(); c != (IPv6OnlyCounters{}) {
			t.Errorf("counters %+v, want none: only an ACK is kept", c)
		}
	})
	for _, name := range []string{"renewing", "rebinding"} {
		t.Run(name, func(t *testing.T) {
			m, _ := v6oBound(t, v6oParams())
			t1, _ := m.lease.RenewAt()
			_, acts := m.Step(t1, 5, TimerFired(TimerRenew))
			if name == "rebinding" {
				t2, _ := m.lease.RebindAt()
				_, acts = m.Step(t2, 6, TimerFired(TimerRebind))
			}
			req := mustSend(t, acts, wire.MsgRequest)
			if m.State().String() != strings.ToUpper(name) {
				t.Fatalf("fixture reached %s", m.State())
			}
			_, acts = m.Step(t1+at(500), 7, received(t, v6oAck(req, 1800)))
			if m.State() != StateBound || count(acts, ActLeaseRenewed) != 1 {
				t.Errorf("state %s, renewed %d: %v", m.State(), count(acts, ActLeaseRenewed), RenderActions(acts))
			}
			if _, held := m.Lease(); !held || count(acts, ActLeaseLost) != 0 {
				t.Error("the lease did not stand")
			}
			if c := m.IPv6OnlyCounters(); c != (IPv6OnlyCounters{Ignored: 1}) {
				t.Errorf("counters %+v, want Ignored 1 only", c)
			}
		})
	}
}

// TestAnAckWith108InRebootingStartsTheWait: RFC 8925 section 3.2 for
// INIT-REBOOT, whatever address the ACK carries, and the DISCOVER after the
// wait is the full one, with no remembered address
// (claymore666/docker-net-dhcp#1027).
func TestAnAckWith108InRebootingStartsTheWait(t *testing.T) {
	rp := resumeParams(testRebootAddr, at(3600), true)
	rp.IPv6OnlyPreferred = true
	m := newMachine(t, rp)
	_, acts := m.Step(0, 1, Simple(EvStart))
	req := mustSend(t, acts, wire.MsgRequest)
	if m.State() != StateRebooting {
		t.Fatalf("fixture reached %s, want REBOOTING", m.State())
	}
	ack := v6oAck(req, 100)
	ack.YIAddr = offerFor(req, "0.0.0.0", v6oServer).YIAddr
	_, acts = m.Step(at(1), 2, received(t, ack))
	v6oAssertWait(t, m, acts, 300*Second)
	if !v6oHasCancel(acts, TimerRetransmit) {
		t.Error("the INIT-REBOOT retransmission timer is still armed during the wait")
	}
	_, acts = m.Step(at(301), 3, TimerFired(TimerRestart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	if _, ok := disc.Options[wire.OptRequestedIP]; ok {
		t.Error("the DISCOVER after the wait still asks for the remembered address")
	}
	if c := m.IPv6OnlyCounters(); c != (IPv6OnlyCounters{Waited: 1}) {
		t.Errorf("counters %+v, want Waited 1 only", c)
	}
}

// TestARapidCommitAckWith108InSelectingWaits: with both flags on, an ACK that
// carries 80 and 108 is the server's "IPv6 only", not a two-message lease; the
// same ACK without 108 is still taken (claymore666/docker-net-dhcp#1027).
func TestARapidCommitAckWith108InSelectingWaits(t *testing.T) {
	p := v6oParams()
	p.RapidCommit = true
	rapid := func(disc *wire.Message, with108 bool) *wire.Message {
		a := ackFor(disc, v6oAddr, v6oServer, 3600)
		a.Options[wire.OptRapidCommit] = wire.EncodeRapidCommit()
		if with108 {
			a.Options[wire.OptIPv6OnlyPreferred] = wire.EncodeIPv6OnlyPreferred(300)
		}
		return a
	}
	m, disc := v6oSelecting(t, p)
	got := v6oWire(t, disc)
	if _, ok := got.Options[wire.OptRapidCommit]; !ok || v6oCount108(got) != 1 {
		t.Fatalf("the DISCOVER lacks option 80 or 108: %v", got.Options)
	}
	_, acts := m.Step(at(12), 2, received(t, rapid(disc, true)))
	v6oAssertWait(t, m, acts, 300*Second)
	if rc := m.RapidCommitCounters(); rc != (RapidCommitCounters{}) {
		t.Errorf("Rapid Commit counters %+v, want none: the ACK was neither taken nor refused", rc)
	}

	m, disc = v6oSelecting(t, p)
	m.Step(at(12), 2, received(t, rapid(disc, false)))
	if m.State() != StateBound || m.RapidCommitCounters().Accepted != 1 {
		t.Errorf("the control: an ACK with option 80 only gave %s, %+v", m.State(), m.RapidCommitCounters())
	}
}

// TestAPlainAckInSelectingWith108IsWaitedOnToo: an ACK answering a DISCOVER
// carries the server's answer whether or not it has option 80
// (claymore666/docker-net-dhcp#1027).
func TestAPlainAckInSelectingWith108IsWaitedOnToo(t *testing.T) {
	m, disc := v6oSelecting(t, v6oParams())
	_, acts := m.Step(at(12), 2, received(t, v6oAck(disc, 300)))
	v6oAssertWait(t, m, acts, 300*Second)
}

// TestTheWaitTimerIsArmedAfterEverythingIsCancelled: toInitIdle cancels every
// timer, so the restart timer must be set after it, once, and the
// retransmission timer must be among the cancelled
// (claymore666/docker-net-dhcp#1027).
func TestTheWaitTimerIsArmedAfterEverythingIsCancelled(t *testing.T) {
	m, disc := v6oSelecting(t, v6oParams())
	_, acts := m.Step(at(12), 2, received(t, v6oOffer(disc, 300)))
	setAt, lastCancel, sets := -1, -1, 0
	for i, a := range acts {
		switch {
		case a.Kind == ActSetTimer:
			sets++
			if a.Timer == TimerRestart {
				setAt = i
			}
		case a.Kind == ActCancelTimer:
			lastCancel = i
		}
	}
	if sets != 1 || setAt < 0 {
		t.Fatalf("%d timer(s) set, restart at %d: %v", sets, setAt, RenderActions(acts))
	}
	if lastCancel < 0 || lastCancel > setAt {
		t.Errorf("a cancel (%d) follows the restart timer (%d): %v", lastCancel, setAt, RenderActions(acts))
	}
	if !v6oHasCancel(acts, TimerRetransmit) {
		t.Error("the DISCOVER retransmission timer is not cancelled")
	}
}

// TestAStopDuringTheWaitCancelsTheRestartTimer (claymore666/docker-net-dhcp#1027).
func TestAStopDuringTheWaitCancelsTheRestartTimer(t *testing.T) {
	m, disc := v6oSelecting(t, v6oParams())
	m.Step(at(12), 2, received(t, v6oOffer(disc, 1800)))
	to, acts := m.Step(at(20), 3, Simple(EvStop))
	if to != StateStopped || !v6oHasCancel(acts, TimerRestart) {
		t.Fatalf("state %s, restart cancelled=%v: %v", to, v6oHasCancel(acts, TimerRestart), RenderActions(acts))
	}
	_, acts = m.Step(at(1812), 4, TimerFired(TimerRestart))
	if count(acts, ActSend) != 0 || m.State() != StateStopped {
		t.Errorf("a late restart timer after Stop acted: %s, %v", m.State(), RenderActions(acts))
	}
}

// TestAStartDuringTheWaitBeginsAFreshAcquisition: Start in INIT is documented
// as restarting the acquisition, so it ends the wait as a link event does and
// leaves no second timer behind (claymore666/docker-net-dhcp#1027).
func TestAStartDuringTheWaitBeginsAFreshAcquisition(t *testing.T) {
	m, disc := v6oSelecting(t, v6oParams())
	m.Step(at(12), 2, received(t, v6oOffer(disc, 1800)))
	to, acts := m.Step(at(20), 3, Simple(EvStart))
	if to != StateSelecting {
		t.Fatalf("state %s, want SELECTING", to)
	}
	if again := mustSend(t, acts, wire.MsgDiscover); again.XID == disc.XID {
		t.Error("the DISCOVER after Start reuses the first transaction id")
	}
	if !v6oHasCancel(acts, TimerRestart) {
		t.Error("the wait timer is still armed after Start")
	}
	if _, ok := v6oRestartTimer(acts); ok {
		t.Error("Start armed a second restart timer")
	}
}

// TestMessagesDuringTheWaitChangeNothing: a second OFFER with 108 while idle
// neither extends the wait nor counts as one, and an OFFER with another
// transaction id never starts it (claymore666/docker-net-dhcp#1027).
func TestMessagesDuringTheWaitChangeNothing(t *testing.T) {
	m, disc := v6oSelecting(t, v6oParams())
	m.Step(at(12), 2, received(t, v6oOffer(disc, 300)))
	_, acts := m.Step(at(30), 3, received(t, v6oOffer(disc, 1800)))
	if _, ok := v6oRestartTimer(acts); ok || count(acts, ActSend) != 0 || m.State() != StateInit {
		t.Errorf("a second OFFER in the wait acted: %s, %v", m.State(), RenderActions(acts))
	}
	if c := m.IPv6OnlyCounters(); c != (IPv6OnlyCounters{Waited: 1}) {
		t.Errorf("counters %+v, want the one wait only", c)
	}

	m, disc = v6oSelecting(t, v6oParams())
	stray := v6oOffer(disc, 300)
	stray.XID = disc.XID + 1
	_, acts = m.Step(at(12), 2, received(t, stray))
	if m.State() != StateSelecting || count(acts, ActSend) != 0 || m.IPv6OnlyCounters().Waited != 0 {
		t.Errorf("an OFFER for another transaction acted: %s, %v", m.State(), RenderActions(acts))
	}
}

// TestTheCountersAreSeparateAndACopy (claymore666/docker-net-dhcp#1027).
func TestTheCountersAreSeparateAndACopy(t *testing.T) {
	m, disc := v6oSelecting(t, v6oParams())
	bad := offerFor(disc, v6oAddr, v6oServer)
	bad.Options[wire.OptIPv6OnlyPreferred] = []byte{1, 2}
	_, acts := m.Step(at(12), 2, received(t, bad))
	req := mustSend(t, acts, wire.MsgRequest)
	m.Step(at(13), 3, received(t, v6oAck(req, 300)))
	m.Step(at(14), 4, Simple(EvLinkDown))
	_, acts = m.Step(at(15), 5, Simple(EvLinkUp))
	disc = mustSend(t, acts, wire.MsgDiscover)
	m.Step(at(16), 6, received(t, v6oOffer(disc, 300)))
	want := IPv6OnlyCounters{Waited: 1, Ignored: 1, Malformed: 1}
	got := m.IPv6OnlyCounters()
	if got != want {
		t.Fatalf("counters %+v, want %+v", got, want)
	}
	got.Waited = 99
	if m.IPv6OnlyCounters() != want {
		t.Error("IPv6OnlyCounters returned the machine's own storage")
	}
}

// TestReasonIPv6OnlyPreferredHasItsOwnName (claymore666/docker-net-dhcp#1027).
func TestReasonIPv6OnlyPreferredHasItsOwnName(t *testing.T) {
	if got := ReasonIPv6OnlyPreferred.String(); got != "ipv6-only-preferred" {
		t.Errorf("String() = %q", got)
	}
	for r := ReasonNone; r < ReasonIPv6OnlyPreferred; r++ {
		if r.String() == ReasonIPv6OnlyPreferred.String() {
			t.Errorf("reason %d shares the name", r)
		}
	}
}

// TestAJournalWrittenDuringTheWaitReplaysIntoTheSameWait: Replay compares the
// rendered actions, which carry the reason and the timer's duration, so a
// replay that came back BOUND or without the timer diverges. The recorded
// OFFER still carries 108 in its bytes, and a client without the flag cannot
// reproduce the run (claymore666/docker-net-dhcp#1027).
func TestAJournalWrittenDuringTheWaitReplaysIntoTheSameWait(t *testing.T) {
	p := v6oParams()
	m := newMachine(t, p)
	var es []JournalEntry
	acts := v6oStep(m, &es, at(10), 0xA1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	acts = v6oStep(m, &es, at(12), 0xA2, received(t, v6oOffer(disc, 10)))
	v6oAssertWait(t, m, acts, 300*Second)

	ev, err := es[1].Event()
	if err != nil {
		t.Fatalf("the OFFER entry does not decode: %v", err)
	}
	if secs, ok, err := ev.Msg.Options.IPv6OnlyPreferred(); err != nil || !ok || secs != 10 {
		t.Fatalf("the journalled OFFER lost option 108: %d/%v/%v", secs, ok, err)
	}
	var sawTimer, sawReason bool
	for _, line := range es[1].Actions {
		sawTimer = sawTimer || strings.Contains(line, "SetTimer restart after 300s")
		sawReason = sawReason || strings.Contains(line, "Failed ipv6-only-preferred")
	}
	if !sawTimer || !sawReason {
		t.Fatalf("the OFFER entry does not hold the wait: %q", es[1].Actions)
	}

	got, err := Replay(p, es)
	if err != nil {
		t.Fatalf("the run does not replay under the params it ran with: %v", err)
	}
	if got.State != StateInit || got.Held {
		t.Fatalf("the replay reached %+v, want INIT with nothing held", got)
	}

	v6oStep(m, &es, at(312), 0xA3, TimerFired(TimerRestart))
	got, err = Replay(p, es)
	if err != nil || got.State != StateSelecting {
		t.Fatalf("the run through the wait's end replays to %+v, %v", got, err)
	}

	if _, err := Replay(testParams(), es[:2]); !errors.Is(err, ErrReplayDiverged) {
		t.Fatalf("Replay with the flag false = %v, want ErrReplayDiverged", err)
	}
}
