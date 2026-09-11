// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// TestNewRefusesAnUnsendableHostname is defeat row H, and it is the observer
// that was RED against the tree before this change: Params.Hostname carried no
// refusal at all, so a name that wire.Encode cannot put in a single option was
// accepted by New and then refused on EVERY outgoing message — a client that
// looks like a broken transport once the send budget runs out.
//
// It is the shape wire/values.go's length bound was moved out of encodeName to
// fix for option 81, surviving in option 12.
func TestNewRefusesAnUnsendableHostname(t *testing.T) {
	for _, tc := range []struct {
		name  string
		host  string
		valid bool
	}{
		{"ordinary", "container-a", true},
		{"an underscore is not RFC 1035 preferred syntax and is not refused", "my_container", true},
		{"dotted", "a.b.example.test", true},
		{"empty means the option is not sent", "", true},
		{"255 octets is what one option carries", strings.Repeat("a", 255), true},
		{"256 octets is one too many", strings.Repeat("a", 256), false},
		{"a NUL ends the name in every consumer that stores it", "a\x00b", false},
		{"a newline is a lease-file injection", "a\nb", false},
		{"a space separates the fields of the file the server writes", "a b", false},
		{"a byte over 0x7e is not in RFC 1035's character set", "caf\xc3\xa9", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testParams()
			p.Hostname = tc.host
			m, err := New(p)
			if tc.valid && err != nil {
				t.Fatalf("New refused %q: %v", tc.host, err)
			}
			if !tc.valid {
				if err == nil {
					t.Fatalf("New accepted %q", tc.host)
				}
				return
			}
			// The other half of the row: a name New accepts must survive the
			// encoder on the message it produces. Asserting on New alone would
			// leave the very defect the row names — accepted here, refused on
			// the wire — untouched.
			_, acts := m.Step(0, 1, Simple(EvStart))
			disc := mustSend(t, acts, wire.MsgDiscover)
			if _, err := wire.Encode(disc); err != nil {
				t.Fatalf("New accepted %q and the DISCOVER it produces cannot be encoded: %v", tc.host, err)
			}
		})
	}
}

// hostnameOf returns what option 12 carried in a message, and whether it was
// there at all. The two are different answers and a test that folded them
// together could not tell "no name" from "the empty name".
func hostnameOf(msg *wire.Message) (string, bool) {
	v, ok := msg.Options[wire.OptHostName]
	return string(v), ok
}

// TestAHostnameInBoundIsSentAsAnEarlyRenewal is the whole of
// docker-net-dhcp#961's library half, and it asserts on the BYTES of the
// message rather than on the machine's opinion of what it did.
//
// RFC 2131 section 4.4.5 is the permission — "A client MAY choose to renew or
// extend its lease prior to T1" — and section 4.3.2's DHCPREQUEST-generated-
// during-RENEWING bullet is the shape: "'server identifier' MUST NOT be filled
// in, 'requested IP address' option MUST NOT be filled in, 'ciaddr' MUST be
// filled in with client's IP address".
//
// THE STATE IS PART OF THE ASSERTION. A DHCPREQUEST sent while the machine
// stayed in BOUND would have its DHCPACK thrown away, so the last two steps
// here — the ACK, and the expiry timer moving — are what distinguish a name
// that reached the server from a name that reached it and left the lease
// unrenewable.
func TestAHostnameInBoundIsSentAsAnEarlyRenewal(t *testing.T) {
	m := machineIn(t, StateBound)
	held, ok := m.Lease()
	if !ok {
		t.Fatal("the BOUND fixture holds no lease")
	}

	st, acts := m.Step(at(10), 0xF00D, SetHostname("late-name"))
	if st != StateRenewing {
		t.Fatalf("after SetHostname in BOUND: %s, want RENEWING — a DHCPREQUEST sent from BOUND has its DHCPACK discarded (RFC 2131 4.4.5 is a RENEWAL)", st)
	}
	if n := count(acts, ActSend); n != 1 {
		t.Fatalf("SetHostname emitted %d sends, want 1: %v", n, RenderActions(acts))
	}
	req := mustSend(t, acts, wire.MsgRequest)

	if got, ok := hostnameOf(req); !ok || got != "late-name" {
		t.Fatalf("the DHCPREQUEST carries option 12 %q (present=%v), want %q", got, ok, "late-name")
	}
	if req.CIAddr != held.Addr.Addr() {
		t.Fatalf("ciaddr = %s, want the held address %s (RFC 2131 4.3.2 MUST)", req.CIAddr, held.Addr.Addr())
	}
	if _, ok := req.Options[wire.OptRequestedIP]; ok {
		t.Fatal("the renewal carries option 50; RFC 2131 4.3.2 makes it MUST NOT in RENEWING")
	}
	if _, ok := req.Options[wire.OptServerID]; ok {
		t.Fatal("the renewal carries option 54; RFC 2131 4.3.2 makes it MUST NOT in RENEWING")
	}
	send, _ := find(acts, ActSend)
	if send.Dest.Broadcast || send.Dest.Addr != held.ServerID {
		t.Fatalf("the renewal went to %s, want a unicast to %s (RFC 2131 4.4.5)", send.Dest, held.ServerID)
	}
	if _, err := wire.Encode(req); err != nil {
		t.Fatalf("the renewal cannot be encoded: %v", err)
	}

	// The ACK, and the half a request sent from BOUND would have lost.
	st, acts = m.Step(at(11), 0xBEEF, received(t, ackFor(req, held.Addr.Addr().String(), held.ServerID.String(), 7200)))
	if st != StateBound {
		t.Fatalf("after the DHCPACK: %s, want BOUND", st)
	}
	armed := false
	for _, a := range acts {
		if a.Kind == ActSetTimer && a.Timer == TimerExpire {
			armed = true
		}
	}
	if !armed {
		t.Fatalf("the DHCPACK answering the early renewal did not re-arm the expiry timer; it was discarded: %v", RenderActions(acts))
	}
}

// TestAHostnameSetTwiceSendsOneMessage is defeat row L. The question the
// machine asks is whether the SERVER has been told, not whether the value
// changed, so a caller re-applying a name on every event produces no traffic.
func TestAHostnameSetTwiceSendsOneMessage(t *testing.T) {
	m := machineIn(t, StateBound)

	_, acts := m.Step(at(10), 1, SetHostname("same"))
	if n := count(acts, ActSend); n != 1 {
		t.Fatalf("the first SetHostname emitted %d sends, want 1", n)
	}
	req := mustSend(t, acts, wire.MsgRequest)
	held, _ := m.Lease()
	m.Step(at(11), 2, received(t, ackFor(req, held.Addr.Addr().String(), held.ServerID.String(), 7200)))
	if m.State() != StateBound {
		t.Fatalf("after the ACK: %s, want BOUND", m.State())
	}

	_, acts = m.Step(at(12), 3, SetHostname("same"))
	if n := count(acts, ActSend); n != 0 {
		t.Fatalf("a second SetHostname with the same name emitted %d sends, want 0: %v", n, RenderActions(acts))
	}
	if m.State() != StateBound {
		t.Fatalf("a second SetHostname with the same name moved the machine to %s", m.State())
	}
}

// TestAHostnameArrivingBeforeTheLeaseGoesOutAtTheBind is defeat row K.
//
// The name arrives while the client is still acquiring, so there is no lease to
// renew and nothing is sent. The DHCPREQUEST of that acquisition had already
// gone, so the server has not been told — and the moment there IS a lease, the
// early renewal carries it. Without this the name would wait for T1.
func TestAHostnameArrivingBeforeTheLeaseGoesOutAtTheBind(t *testing.T) {
	m := machineIn(t, StateRequesting)

	_, acts := m.Step(at(5), 1, SetHostname("arrived-late"))
	if n := count(acts, ActSend); n != 0 {
		t.Fatalf("SetHostname in REQUESTING emitted %d sends, want 0: %v", n, RenderActions(acts))
	}
	if m.Hostname() != "arrived-late" {
		t.Fatalf("the name was not recorded in REQUESTING: %q", m.Hostname())
	}

	// The ACK for the REQUEST that went out before the name existed.
	st, acts := m.Step(at(6), 2, received(t, ackFor(&wire.Message{XID: m.xid, CHAddr: testCHAddr},
		"192.168.99.50", "192.168.99.1", 3600)))
	if st != StateRenewing {
		t.Fatalf("after the DHCPACK: %s, want RENEWING — the bind must carry the name that arrived while acquiring", st)
	}
	if _, ok := find(acts, ActLeaseAcquired); !ok {
		t.Fatalf("the lease was never announced: %v", RenderActions(acts))
	}
	var req *wire.Message
	for _, a := range acts {
		if a.Kind == ActSend {
			req = a.Msg
		}
	}
	if req == nil {
		t.Fatalf("nothing was sent at the bind: %v", RenderActions(acts))
	}
	if got, ok := hostnameOf(req); !ok || got != "arrived-late" {
		t.Fatalf("the message sent at the bind carries option 12 %q (present=%v), want %q", got, ok, "arrived-late")
	}
}

// TestAnOrdinaryAcquisitionSendsNoExtraMessage is the preservation control for
// the row above: the check at the bind must fire only when the server has NOT
// been told, or every acquisition renews itself the moment it completes.
func TestAnOrdinaryAcquisitionSendsNoExtraMessage(t *testing.T) {
	p := testParams()
	p.Hostname = "from-the-start"
	m := newMachine(t, p)

	_, acts := m.Step(0, 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	_, acts = m.Step(at(1), 2, received(t, offerFor(disc, "192.168.99.50", "192.168.99.1")))
	req := mustSend(t, acts, wire.MsgRequest)
	if got, _ := hostnameOf(req); got != "from-the-start" {
		t.Fatalf("the acquisition's DHCPREQUEST carries option 12 %q", got)
	}

	st, acts := m.Step(at(2), 3, received(t, ackFor(req, "192.168.99.50", "192.168.99.1", 3600)))
	if st != StateBound {
		t.Fatalf("an ordinary acquisition ended in %s, want BOUND", st)
	}
	if n := count(acts, ActSend); n != 0 {
		t.Fatalf("an ordinary acquisition sent %d extra messages at the bind: %v", n, RenderActions(acts))
	}
}

// TestAHostnameDuringARenewalResendsTheOpenTransaction: a DHCPREQUEST is
// already in flight carrying the old name, so the new one goes out as a
// retransmission of THAT transaction. Section 4.4.5 measures the lease from
// the moment the request was sent and sendRenewal re-stamps that on every
// attempt, so whichever copy the server answers gives the same answer.
func TestAHostnameDuringARenewalResendsTheOpenTransaction(t *testing.T) {
	for _, st := range []State{StateRenewing, StateRebinding} {
		t.Run(st.String(), func(t *testing.T) {
			m := machineIn(t, st)
			xid := m.xid

			next, acts := m.Step(at(3000), 7, SetHostname("mid-renewal"))
			if next != st {
				t.Fatalf("SetHostname in %s moved to %s", st, next)
			}
			if n := count(acts, ActSend); n != 1 {
				t.Fatalf("SetHostname in %s emitted %d sends, want 1: %v", st, n, RenderActions(acts))
			}
			req := mustSend(t, acts, wire.MsgRequest)
			if req.XID != xid {
				t.Fatalf("the resend opened a new transaction (xid 0x%x, was 0x%x); it is a retransmission", req.XID, xid)
			}
			if got, ok := hostnameOf(req); !ok || got != "mid-renewal" {
				t.Fatalf("the resent DHCPREQUEST carries option 12 %q (present=%v)", got, ok)
			}
			send, _ := find(acts, ActSend)
			if st == StateRebinding && !send.Dest.Broadcast {
				t.Fatalf("the REBINDING resend went to %s, want a broadcast (RFC 2131 4.4.5)", send.Dest)
			}
			if st == StateRenewing && send.Dest.Broadcast {
				t.Fatalf("the RENEWING resend was broadcast, want a unicast to the server (RFC 2131 4.4.5)")
			}
		})
	}
}

// TestAHostnameRenewalThatIsNAKedLosesTheLease is defeat row G, pinned by name
// because it is a COST and not a defect: moving BOUND to RENEWING for a name
// means a server that has repudiated the binding says so now instead of at T1.
// A client that had stayed in BOUND would have kept an address the server has
// already given away.
func TestAHostnameRenewalThatIsNAKedLosesTheLease(t *testing.T) {
	m := machineIn(t, StateBound)
	_, acts := m.Step(at(10), 1, SetHostname("provokes-a-nak"))
	req := mustSend(t, acts, wire.MsgRequest)

	st, acts := m.Step(at(11), 2, received(t, nakFor(req, "192.168.99.1", "lease not found")))
	if _, ok := m.Lease(); ok {
		t.Fatalf("the lease survived a DHCPNAK in %s", st)
	}
	lost, ok := find(acts, ActLeaseLost)
	if !ok {
		t.Fatalf("the DHCPNAK produced no LeaseLost: %v", RenderActions(acts))
	}
	if lost.Reason != ReasonNak {
		t.Fatalf("LeaseLost carries %s, want %s", lost.Reason, ReasonNak)
	}
}

// TestAnFqdnClientIgnoresAHostname is defeat row D. RFC 4702 section 3.1: a
// client sending option 81 "MUST NOT also send the Host Name option", so a
// name given to such a client is one the machine can never put on the wire —
// and an announcing DHCPREQUEST would be a renewal that changed nothing.
func TestAnFqdnClientIgnoresAHostname(t *testing.T) {
	p := testParams()
	p.FQDN = FQDN{Name: "host.example.test."}
	m := newMachine(t, p)

	_, acts := m.Step(0, 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	_, acts = m.Step(at(1), 2, received(t, offerFor(disc, "192.168.99.50", "192.168.99.1")))
	req := mustSend(t, acts, wire.MsgRequest)
	m.Step(at(2), 3, received(t, ackFor(req, "192.168.99.50", "192.168.99.1", 3600)))
	if m.State() != StateBound {
		t.Fatalf("fixture is in %s, want BOUND", m.State())
	}

	st, acts := m.Step(at(10), 4, SetHostname("ignored"))
	if st != StateBound {
		t.Fatalf("SetHostname on an FQDN client moved to %s", st)
	}
	if n := count(acts, ActSend); n != 0 {
		t.Fatalf("SetHostname on an FQDN client sent %d messages: %v", n, RenderActions(acts))
	}
	if m.Hostname() != "" {
		t.Fatalf("an FQDN client recorded the name %q it can never send", m.Hostname())
	}

	// And the option is still not there when the client does send: the
	// assertion is on the wire, not on the stored field.
	_, acts = m.Step(at(1800), 5, TimerFired(TimerRenew))
	ren := mustSend(t, acts, wire.MsgRequest)
	if _, ok := hostnameOf(ren); ok {
		t.Fatal("an FQDN client put option 12 on the wire beside option 81 (RFC 4702 3.1)")
	}
	if _, ok := ren.Options[wire.OptFQDN]; !ok {
		t.Fatal("the FQDN client stopped sending option 81")
	}
}

// TestAMachineRefusesAnUnsendableHostnameAtRuntime is defeat row H's other
// half: New and the running client apply the SAME rule, so a name that could
// not be started with cannot be switched to either.
func TestAMachineRefusesAnUnsendableHostnameAtRuntime(t *testing.T) {
	m := machineIn(t, StateBound)
	if _, err := New(func() Params { p := testParams(); p.Hostname = "a b"; return p }()); err == nil {
		t.Fatal("New accepted a name with a space; this test is comparing against nothing")
	}

	st, acts := m.Step(at(10), 1, SetHostname("a b"))
	if st != StateBound {
		t.Fatalf("a refused name moved the machine to %s", st)
	}
	if n := count(acts, ActSend); n != 0 {
		t.Fatalf("a refused name sent %d messages: %v", n, RenderActions(acts))
	}
	if m.Hostname() != "" {
		t.Fatalf("a refused name was recorded: %q", m.Hostname())
	}
}

// TestParamsIsNotMovedByASetter is defeat row A stated as an invariant: Params
// is the value a replay is built from, so it must say what the machine STARTED
// with however many names the run went through. Hostname is the other reader.
func TestParamsIsNotMovedByASetter(t *testing.T) {
	p := testParams()
	p.Hostname = "at-start"
	m := newMachine(t, p)
	m.Step(0, 1, Simple(EvStart))
	m.Step(at(1), 2, SetHostname("at-runtime"))

	if got := m.Params().Hostname; got != "at-start" {
		t.Fatalf("Params().Hostname = %q after a setter; a replay built from it would send %q from the first DHCPDISCOVER", got, got)
	}
	if got := m.Hostname(); got != "at-runtime" {
		t.Fatalf("Hostname() = %q, want the name the client is now sending", got)
	}
}

// stepAndRecord drives one Step and appends the journal entry for it, through
// NewJournalEntry — the one place the journal's shape is defined. A recorder
// that built entries its own way would be a probe derived differently from its
// subject and could replay perfectly while the manager's journal did not.
func stepAndRecord(m *Machine, es *[]JournalEntry, now Instant, rnd uint64, ev Event) []Action {
	from := m.State()
	to, acts := m.Step(now, rnd, ev)
	*es = append(*es, NewJournalEntry(uint64(len(*es)), now, rnd, ev, from, to, acts))
	return acts
}

// TestAHostnameSetAfterStartReplaysFromTheStartParams is defeat rows A and B
// together, and it is the reason the name is a journalled EVENT rather than a
// write into Params.
//
// ROW B IS WHY THE ASSERTION IS ON BYTES. Replay compares RENDERED actions, and
// a send is rendered through wire.Message.Summary, which prints the option
// COUNT and never the contents — so a replay that dropped the name produces the
// identical line and Replay returns no error. The only thing that can see it is
// option 12 of the message the replayed machine emitted.
func TestAHostnameSetAfterStartReplaysFromTheStartParams(t *testing.T) {
	start := testParams()
	start.Hostname = "at-start"

	m := newMachine(t, start)
	var es []JournalEntry
	acts := stepAndRecord(m, &es, 0, 0xA1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	acts = stepAndRecord(m, &es, at(1), 0xA2, received(t, offerFor(disc, "192.168.99.50", "192.168.99.1")))
	req := mustSend(t, acts, wire.MsgRequest)
	stepAndRecord(m, &es, at(2), 0xA3, received(t, ackFor(req, "192.168.99.50", "192.168.99.1", 3600)))
	acts = stepAndRecord(m, &es, at(10), 0xA4, SetHostname("at-runtime"))
	if _, ok := hostnameOf(mustSend(t, acts, wire.MsgRequest)); !ok {
		t.Fatal("the recorded run did not send the new name; there is nothing for the replay to reproduce")
	}

	if _, err := Replay(start, es); err != nil {
		t.Fatalf("the run does not replay against the params it started with: %v", err)
	}

	// The byte assertion Replay cannot make. A fresh machine on the START
	// params, fed the recorded events, must emit the same option 12 the run
	// emitted — which it can only do if the journal carried the name.
	rp := newMachine(t, start)
	var last *wire.Message
	for _, e := range es {
		ev, err := e.Event()
		if err != nil {
			t.Fatalf("entry %d: %v", e.Seq, err)
		}
		_, ra := rp.Step(e.Now, e.Rnd, ev)
		for _, a := range ra {
			if a.Kind == ActSend {
				last = a.Msg
			}
		}
	}
	if last == nil {
		t.Fatal("the replay sent nothing")
	}
	got, ok := hostnameOf(last)
	if !ok || got != "at-runtime" {
		t.Fatalf("the replayed DHCPREQUEST carries option 12 %q (present=%v), want %q — the journal lost the name", got, ok, "at-runtime")
	}
	if rp.Hostname() != "at-runtime" {
		t.Fatalf("the replayed machine's name is %q", rp.Hostname())
	}

	// The control the doc bound rests on: replaying under the name the run
	// ENDED with is a different client, and must not quietly succeed.
	ended := testParams()
	ended.Hostname = "at-runtime"
	if _, err := Replay(ended, es); err == nil {
		t.Fatal("the journal replayed against the name the run ended with; Params would then not be the replay seed at all")
	}
}

// TestAHostnameArrivingWhileProbingGoesOutAtTheAnnouncement is defeat row K in
// the state it is most likely to happen in.
//
// ConflictWait is the DEFAULT mode (D22) and RFC 5227 section 1.1's arithmetic
// puts a client in PROBING for a mean of five and a half seconds after the
// DHCPACK — which is exactly the window a name fetched from an API lands in.
// There is no lease to renew there and nothing is sent; the check at the bind
// is what keeps the name from waiting for T1.
func TestAHostnameArrivingWhileProbingGoesOutAtTheAnnouncement(t *testing.T) {
	m := machineIn(t, StateProbing)

	_, acts := m.Step(at(3), 11, SetHostname("named-while-probing"))
	if n := count(acts, ActSend); n != 0 {
		t.Fatalf("SetHostname in PROBING sent %d DHCP messages, want 0 — nothing is held yet: %v", n, RenderActions(acts))
	}

	// Drive RFC 5227's schedule to its end, the way the ACD tests do: the
	// delay comes from the machine's own arming, so the loop cannot drift from
	// the schedule it is standing on.
	//
	// The schedule was armed by the DHCPACK that produced this fixture, so the
	// first firing is due now and each later delay comes from the machine's
	// own arming rather than from a number written here.
	now := at(3)
	var delay Duration
	var sent *wire.Message
	for step := 0; step < 12 && sent == nil; step++ {
		now = now.Add(delay)
		_, acts = m.Step(now, uint64(step*7919+3), TimerFired(TimerACD))
		for _, a := range acts {
			if a.Kind == ActSend {
				sent = a.Msg
			}
		}
		next, ok := armedACD(acts)
		if !ok {
			break
		}
		delay = next
	}
	if m.State() != StateRenewing {
		t.Fatalf("after the probe window the machine is %s, want RENEWING — the name recorded while probing was never sent", m.State())
	}
	if sent == nil {
		t.Fatal("nothing was sent when the probe window ended")
	}
	if got, ok := hostnameOf(sent); !ok || got != "named-while-probing" {
		t.Fatalf("the message sent at the announcement carries option 12 %q (present=%v)", got, ok)
	}
}

// TestAHostnameOnALeaseWithNoServerIdentifierWaitsForT2 drives the one lease
// shape where "sent at once" is not what happens. RFC 2131 section 4.4.5
// unicasts the renewal to the server, and a DHCPACK that carried no option 54
// leaves nothing to unicast to, so the machine stays in BOUND and the name
// goes out in the broadcast DHCPREQUEST at T2. The doc on announceHostname and
// on lease.Manager.SetHostname both say so; this is what holds them to it.
func TestAHostnameOnALeaseWithNoServerIdentifierWaitsForT2(t *testing.T) {
	m := bound(t, testParams(), func(ack *wire.Message) {
		delete(ack.Options, wire.OptServerID)
	})
	if m.lease.ServerID.IsValid() && !m.lease.ServerID.IsUnspecified() {
		t.Fatalf("fixture lease still carries a server identifier %s", m.lease.ServerID)
	}

	st, acts := m.Step(at(10), 0xF00D, SetHostname("late-name"))
	if st != StateBound {
		t.Fatalf("state = %s, want BOUND: there is no server to unicast the early renewal to", st)
	}
	if _, ok := find(acts, ActSend); ok {
		t.Fatalf("a renewal went out with no server to send it to:\n%v", RenderActions(acts))
	}
	if !journalHas(acts, "no message was sent") {
		t.Fatalf("nothing in the journal says the name was recorded and not sent:\n%v", RenderActions(acts))
	}
	if m.Hostname() != "late-name" {
		t.Fatalf("Hostname() = %q, want the name that was recorded", m.Hostname())
	}

	// T2, where the same DHCPREQUEST is broadcast and needs no server
	// identifier. This is where the name reaches the server.
	t2, ok := m.lease.RebindAt()
	if !ok {
		t.Fatal("the fixture's lease has no T2")
	}
	_, acts = m.Step(t2, 0x22, TimerFired(TimerRebind))
	req := mustSend(t, acts, wire.MsgRequest)
	if got, ok := hostnameOf(req); !ok || got != "late-name" {
		t.Fatalf("the broadcast DHCPREQUEST at T2 carries option 12 %q (present=%v), want %q", got, ok, "late-name")
	}
}

// TestAnEmptyHostnameStopsTheOptionAndSendsNothing is the other half of the
// setter, and the half that must NOT produce a message. DHCP has no message
// that withdraws a name: a DHCPREQUEST whose only difference is an absent
// option 12 leaves the server's table exactly as it was, so spending an early
// renewal — and the DHCPNAK risk that comes with leaving BOUND — on one buys
// nothing. What an empty name does is take the option off the next message
// this machine builds, which is measured here at T1.
func TestAnEmptyHostnameStopsTheOptionAndSendsNothing(t *testing.T) {
	p := testParams()
	p.Hostname = "first-name"
	m := bound(t, p, nil)

	st, acts := m.Step(at(10), 0xF00D, SetHostname(""))
	if st != StateBound {
		t.Fatalf("state = %s, want BOUND: clearing a name is not a request the server can answer", st)
	}
	if _, ok := find(acts, ActSend); ok {
		t.Fatalf("clearing the name sent a message:\n%v", RenderActions(acts))
	}
	if m.Hostname() != "" {
		t.Fatalf("Hostname() = %q, want the empty name that was just set", m.Hostname())
	}

	acts = renew(t, m)
	req := mustSend(t, acts, wire.MsgRequest)
	if got, ok := hostnameOf(req); ok {
		t.Fatalf("the renewal still carries option 12 %q; an empty name takes it off the next message", got)
	}
}

// TestTheRenewTimerLeftOverByAnEarlyRenewalIsIgnored closes the one thing the
// early renewal leaves behind. T1 is armed when the lease is taken, and a name
// that arrives before T1 moves the machine into RENEWING without it firing, so
// the timer is still pending in a state that is already renewing. RFC 2131
// section 4.4.5's retransmission schedule is what carries the transaction from
// there, and a second entry into RENEWING would restart it — so the stale
// timer must do nothing, and the DHCPACK that ends the transaction is what
// re-arms all three deadlines.
func TestTheRenewTimerLeftOverByAnEarlyRenewalIsIgnored(t *testing.T) {
	m := machineIn(t, StateBound)
	held, _ := m.Lease()
	t1, ok := held.RenewAt()
	if !ok {
		t.Fatal("the BOUND fixture's lease has no T1")
	}

	if st, _ := m.Step(at(10), 0xF00D, SetHostname("late-name")); st != StateRenewing {
		t.Fatalf("state = %s, want RENEWING", st)
	}
	st, acts := m.Step(t1, 0x33, TimerFired(TimerRenew))
	if st != StateRenewing {
		t.Fatalf("the stale T1 moved the machine to %s", st)
	}
	if _, ok := find(acts, ActSend); ok {
		t.Fatalf("the stale T1 sent a second renewal:\n%v", RenderActions(acts))
	}
	if _, ok := timerSet(acts, TimerRetransmit); ok {
		t.Fatalf("the stale T1 restarted the retransmission schedule:\n%v", RenderActions(acts))
	}
	if _, ok := m.Lease(); !ok {
		t.Fatal("the stale T1 cost the lease")
	}
}

// TestAHostnameSetBeforeTheClientStartsGoesOutInTheFirstDiscover drives the
// STOPPED arm. A caller that has the name before it has a client should not
// have to choose between Params and the setter, and the machine has no message
// to put it in yet — so it is recorded, and the first DHCPDISCOVER carries it.
func TestAHostnameSetBeforeTheClientStartsGoesOutInTheFirstDiscover(t *testing.T) {
	m := machineIn(t, StateStopped)

	st, acts := m.Step(at(1), 0xF00D, SetHostname("named-before-start"))
	if st != StateStopped {
		t.Fatalf("state = %s, want STOPPED: there is nothing to send from", st)
	}
	if _, ok := find(acts, ActSend); ok {
		t.Fatalf("a stopped machine sent something:\n%v", RenderActions(acts))
	}

	_, acts = m.Step(at(2), 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	if got, ok := hostnameOf(disc); !ok || got != "named-before-start" {
		t.Fatalf("the first DHCPDISCOVER carries option 12 %q (present=%v), want %q", got, ok, "named-before-start")
	}
}

// TestAHostnameSetDuringTheDesyncWaitGoesOutInTheDiscover drives the INIT arm,
// through the door a default client actually sits behind: RFC 2131 section
// 4.4.1's startup delay, which DefaultParams sets to between one and ten
// seconds. Nothing is in flight for that whole window, so a name arriving in
// it has to ride the DHCPDISCOVER that ends the wait.
func TestAHostnameSetDuringTheDesyncWaitGoesOutInTheDiscover(t *testing.T) {
	p := testParams()
	p.DesyncMin, p.DesyncMax = 4*Second, 4*Second
	m := newMachine(t, p)

	st, acts := m.Step(at(0), 1, Simple(EvStart))
	if st != StateInit {
		t.Fatalf("state = %s, want INIT: the desync wait has not elapsed", st)
	}
	if _, ok := find(acts, ActSend); ok {
		t.Fatalf("the DHCPDISCOVER went out before the desync wait:\n%v", RenderActions(acts))
	}
	delay, ok := timerSet(acts, TimerDesync)
	if !ok {
		t.Fatalf("no desync timer was armed:\n%v", RenderActions(acts))
	}

	if st, acts = m.Step(at(1), 0xF00D, SetHostname("named-while-waiting")); st != StateInit {
		t.Fatalf("state = %s, want INIT", st)
	}
	if _, ok := find(acts, ActSend); ok {
		t.Fatalf("the name sent a message of its own from INIT:\n%v", RenderActions(acts))
	}

	_, acts = m.Step(at(0).Add(delay), 2, TimerFired(TimerDesync))
	disc := mustSend(t, acts, wire.MsgDiscover)
	if got, ok := hostnameOf(disc); !ok || got != "named-while-waiting" {
		t.Fatalf("the DHCPDISCOVER carries option 12 %q (present=%v), want %q", got, ok, "named-while-waiting")
	}
}

// TestAHostnameSetWhileRebootingGoesOutInTheNextRequest drives the REBOOTING
// arm, which every client handed a remembered lease passes through (RFC 2131
// section 3.2). The DHCPREQUEST for the remembered address has already gone by
// the time the name arrives, so what carries it is the retransmission of that
// same request.
func TestAHostnameSetWhileRebootingGoesOutInTheNextRequest(t *testing.T) {
	m := machineIn(t, StateRebooting)

	st, acts := m.Step(at(10), 0xF00D, SetHostname("named-while-rebooting"))
	if st != StateRebooting {
		t.Fatalf("state = %s, want REBOOTING", st)
	}
	if _, ok := find(acts, ActSend); ok {
		t.Fatalf("the name sent a message of its own from REBOOTING:\n%v", RenderActions(acts))
	}

	_, acts = m.Step(at(11), 2, TimerFired(TimerRetransmit))
	req := mustSend(t, acts, wire.MsgRequest)
	if got, ok := hostnameOf(req); !ok || got != "named-while-rebooting" {
		t.Fatalf("the retransmitted DHCPREQUEST carries option 12 %q (present=%v), want %q", got, ok, "named-while-rebooting")
	}
	if _, ok := req.Options[wire.OptServerID]; ok {
		t.Fatal("the INIT-REBOOT request carries option 54; RFC 2131 4.3.2 makes it MUST NOT")
	}
}
