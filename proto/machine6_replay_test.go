// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// record6 drives a Machine6 through a script, recording a journal as it goes.
type record6 struct {
	m       *Machine6
	entries []JournalEntry6
	seq     uint64
}

func newRecord6(t *testing.T, p Params6) *record6 {
	t.Helper()
	return &record6{m: newMachine6(t, p)}
}

func (r *record6) step(now Instant, rnd uint64, ev Event) (State6, []Action) {
	from := r.m.State()
	to, acts := r.m.Step(now, rnd, ev)
	r.entries = append(r.entries, NewJournalEntry6(r.seq, now, rnd, ev, from, to, acts))
	r.seq++
	return to, acts
}

// TestReplay6ReproducesARecordedExchange is the v6 half of the support
// workflow design §4.3 names: a captured exchange replayed offline, with no
// network and no root, reaching the same state through the same actions.
//
// THE EXCHANGE RECORDED IS THE ONE DRIVEN BY THE CAPTURED dnsmasq BYTES, so
// what the replay reproduces is a real server's answers and not a script this
// package wrote for itself.
func TestReplay6ReproducesARecordedExchange(t *testing.T) {
	p := testParams6()
	r := newRecord6(t, p)

	r.step(at(0), 0, Simple(EvStart))
	r.step(at(1), capXIDSolicit, TimerFired(Timer6Delay))
	r.step(at(2), capXIDRequest, receivedCaptured(t, capAdvertise6))
	r.step(at(3), 0, receivedCaptured(t, capReply6))
	if s, _ := r.step(at(4), 0, DADResult(addr6(dnsmasqLeasedAddr), false)); s != State6Bound {
		t.Fatalf("the recorded run did not bind: %s", s)
	}

	res, err := Replay6(p, r.entries)
	if err != nil {
		t.Fatalf("Replay6: %v", err)
	}
	if res.State != State6Bound {
		t.Errorf("the replay ended in %s, want %s", res.State, State6Bound)
	}
	if !res.Held || len(res.Lease.Addrs) != 1 || res.Lease.Addrs[0].Addr.String() != dnsmasqLeasedAddr {
		t.Errorf("the replay holds %v, want %s", res.Lease.Addrs, dnsmasqLeasedAddr)
	}
	if res.Steps != len(r.entries) {
		t.Errorf("the replay ran %d steps, the recording has %d", res.Steps, len(r.entries))
	}
}

// TestReplay6ReportsADivergence is the guarantee the replay exists to give:
// a recording that the current code no longer reproduces is a FINDING and not
// a quietly different answer.
//
// The mutation below is the smallest one that changes nothing visible in the
// final state — a different rnd on the step that draws the transaction id —
// and it must still be caught, because the actions diverge even though the
// machine ends up bound either way.
func TestReplay6ReportsADivergence(t *testing.T) {
	p := testParams6()
	r := newRecord6(t, p)
	r.step(at(0), 0, Simple(EvStart))
	r.step(at(1), capXIDSolicit, TimerFired(Timer6Delay))

	t.Run("a changed rnd", func(t *testing.T) {
		mutated := append([]JournalEntry6(nil), r.entries...)
		mutated[1].Rnd = capXIDSolicit ^ 0xff
		_, err := Replay6(p, mutated)
		var d Divergence
		if !asDivergence(err, &d) {
			t.Fatalf("Replay6 = %v, want a Divergence", err)
		}
		if !strings.HasPrefix(d.Field, "action") {
			t.Errorf("the divergence is on %q; a different transaction id changes the Solicit that goes out", d.Field)
		}
	})

	t.Run("a changed to-state", func(t *testing.T) {
		mutated := append([]JournalEntry6(nil), r.entries...)
		mutated[1].To = State6Bound
		_, err := Replay6(p, mutated)
		var d Divergence
		if !asDivergence(err, &d) {
			t.Fatalf("Replay6 = %v, want a Divergence", err)
		}
		if d.Field != "to-state" {
			t.Errorf("the divergence is on %q, want to-state", d.Field)
		}
		if d.Recorded != State6Bound.String() || d.Replayed != State6Selecting.String() {
			t.Errorf("Divergence{Recorded: %q, Replayed: %q}, want %q and %q",
				d.Recorded, d.Replayed, State6Bound, State6Selecting)
		}
	})

	t.Run("a changed from-state", func(t *testing.T) {
		mutated := append([]JournalEntry6(nil), r.entries...)
		mutated[1].From = State6Renewing
		_, err := Replay6(p, mutated)
		var d Divergence
		if !asDivergence(err, &d) {
			t.Fatalf("Replay6 = %v, want a Divergence", err)
		}
		if d.Field != "from-state" {
			t.Errorf("the divergence is on %q, want from-state", d.Field)
		}
	})
}

// TestReplay6ReportsUndecodableBytes is the other failure a recording can
// carry: the octets were truncated on their way into the record.
func TestReplay6ReportsUndecodableBytes(t *testing.T) {
	p := testParams6()
	r := newRecord6(t, p)
	r.step(at(0), 0, Simple(EvStart))
	r.step(at(1), capXIDSolicit, TimerFired(Timer6Delay))
	r.step(at(2), capXIDRequest, receivedCaptured(t, capAdvertise6))

	mutated := append([]JournalEntry6(nil), r.entries...)
	mutated[2].Raw = mutated[2].Raw[:2]
	if _, err := Replay6(p, mutated); err == nil {
		t.Fatal("Replay6 accepted a recording whose message bytes cannot be decoded")
	}
}

func asDivergence(err error, out *Divergence) bool {
	d, ok := err.(Divergence)
	if ok {
		*out = d
	}
	return ok
}

// TestReplay6StepsOverARing2Note is the JournalEntry6.Note contract.
//
// RFC 9915 §14.1's refused send is recorded in the journal with the count
// rather than dropped silently — and it happens between
// two Steps, in ring 2, with no event and no transition. THE MUTANT THIS KILLS
// is a Replay6 that treats such a line as a Step: it reads From as the zero
// State6, finds the machine somewhere else, and reports a divergence that says
// the machine is broken when what actually happened is that the journal
// carried two kinds of line.
//
// The control is the same journal without the note, which must replay to the
// same place: a skip that also dropped a real entry would pass the first half
// of this test and fail the comparison.
func TestReplay6StepsOverARing2Note(t *testing.T) {
	p := testParams6()
	r := newRecord6(t, p)
	r.step(at(0), 1, Simple(EvStart))
	r.step(at(1), 2, TimerFired(Timer6Delay))

	clean := r.entries
	if len(clean) < 2 {
		t.Fatalf("the recorder captured %d entries, want at least 2", len(clean))
	}

	withNote := []JournalEntry6{clean[0], {
		Kind:   EvActionFailed,
		Reason: "RFC 9915 §14.1 rate limit: SOLICIT refused, 1 refused on this interface so far",
		Note:   true,
	}}
	withNote = append(withNote, clean[1:]...)

	got, err := Replay6(p, withNote)
	if err != nil {
		t.Fatalf("a journal carrying one ring-2 note did not replay: %v", err)
	}
	want, err := Replay6(p, clean)
	if err != nil {
		t.Fatalf("the same journal without the note did not replay: %v", err)
	}
	if got.State != want.State {
		t.Errorf("with the note the replay ended in %s, without it in %s", got.State, want.State)
	}
	if got.Steps != want.Steps {
		t.Errorf("with the note %d steps were replayed, without it %d: the note was counted as a Step", got.Steps, want.Steps)
	}
	if got.Steps != len(clean) {
		t.Errorf("replayed %d of %d real entries", got.Steps, len(clean))
	}
}

// TestReplay6TellsAHintedSolicitFromAnUnhintedOne is the property the v6
// journal did not have, and it is the one that decides whether a replay can
// see this milestone's own defect.
//
// A JournalEntry6's Actions are rendered strings. Until this round
// wire.MessageV6.Summary listed option CODES only, so a Solicit asking for a
// particular address and one asking for nothing rendered to the identical
// line — "SOLICIT xid=1a2b3c client-id ia-na oro elapsed-time to ff02::1:2"
// for both. Replay6 compares those strings, so the journal of a client that
// re-hinted an address it had declined replayed CLEAN through a machine that
// does not: the one difference between the defect and the fix was the one
// thing the record could not show. MEASURED by review at d78c1eb.
//
// THE ONE VARIABLE IS THE DECLINED SET. The recording machine has declined
// nothing and hints; the replaying machine is built from the same parameters
// with that address already declined — the machine a restart produces. A
// divergence here is the replay reporting "this recording was made by a client
// that asked for an address this configuration will not ask for", which is
// exactly what a support workflow is for.
func TestReplay6TellsAHintedSolicitFromAnUnhintedOne(t *testing.T) {
	p := testParams6()
	p.Hint = addr6(dnsmasqLeasedAddr)

	r := newRecord6(t, p)
	r.step(at(0), 0, Simple(EvStart))
	if _, acts := r.step(at(1), capXIDSolicit, TimerFired(Timer6Delay)); len(acts) == 0 {
		t.Fatal("the recorded Solicit produced no actions")
	}

	t.Run("the same configuration replays clean", func(t *testing.T) {
		if _, err := Replay6(p, r.entries); err != nil {
			t.Fatalf("Replay6 with the recording machine's own parameters: %v", err)
		}
	})

	t.Run("a machine that has declined the hint diverges", func(t *testing.T) {
		restarted := p
		restarted.Declined = []netip.Addr{addr6(dnsmasqLeasedAddr)}
		_, err := Replay6(restarted, r.entries)
		var d Divergence
		if !asDivergence(err, &d) {
			t.Fatalf("Replay6 = %v, want a Divergence: the recorded Solicit asked for %s and the replaying machine will not",
				err, dnsmasqLeasedAddr)
		}
		if !strings.HasPrefix(d.Field, "action") {
			t.Errorf("the divergence is on %q, want an action: the two machines differ in what their Solicit ASKS FOR", d.Field)
		}
		if !strings.Contains(d.Recorded, dnsmasqLeasedAddr) {
			t.Errorf("the recorded action %q does not name the address it asked for, so the journal line cannot tell the two Solicits apart", d.Recorded)
		}
		if strings.Contains(d.Replayed, dnsmasqLeasedAddr) {
			t.Errorf("the replayed action %q names the declined address", d.Replayed)
		}
	})
}

// TestOneJournalCarriesBothTheRouterSourceAndTheDestination is the merge of
// #814 and #925 at the one declaration both of them widened. Each round added
// a field to JournalEntry6 — the advertisement's source address here, the
// received message's destination there — and each round's own tests pass on a
// merge product that kept only its own half, because a test that never makes
// the other field non-zero cannot see it go missing. The diff shows nothing
// either: the text that collides is the text neither side changed.
//
// ONE JOURNAL WITH BOTH IN IT IS THE ONLY FIXTURE THAT SEES IT. The recording
// below takes a lease from a server that sent a reconfigure key, hears one
// advertisement, and is then reconfigured on a unicast destination, so one
// entry carries a source, a later one carries a destination, and the two
// fields are non-zero in the same journal and never on the same entry.
func TestOneJournalCarriesBothTheRouterSourceAndTheDestination(t *testing.T) {
	p := testParams6()
	r := newRecord6(t, p)
	r.step(at(0), 0, Simple(EvStart))
	r.step(at(1), capXIDSolicit, TimerFired(Timer6Delay))
	r.step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	r.step(at(3), 0, replyWithKey(t, uint32(capXIDRequest), dnsmasqLeasedAddr, testReconfKey))
	r.step(at(4), 0, DADResult(addr6(dnsmasqLeasedAddr), false))

	raw := raWithOptions("fd00::53", netip.MustParsePrefix("2001:db8:1::/48"))
	ra := mustRA(t, raw)
	ra.Router = netip.MustParseAddr("fe80::abcd")
	r.step(at(5), 0, RouterAdvertRaw(ra, raw))

	if s, _ := r.step(at(10), 7, goodReconfigure(t, wire.MsgRenew, 1)); s != State6Renewing {
		t.Fatalf("the recorded run did not act on the Reconfigure: %s", s)
	}

	// Both fields are in this one journal, on entries of different kinds.
	var srcs, dsts int
	for _, e := range r.entries {
		if e.RASrc.IsValid() {
			srcs++
			if e.Kind != EvRouterAdvert {
				t.Errorf("entry %d is a %s and carries a router source", e.Seq, e.Kind)
			}
		}
		if e.Dst.IsValid() {
			dsts++
			if e.Kind != EvReceived {
				t.Errorf("entry %d is a %s and carries a destination", e.Seq, e.Kind)
			}
		}
	}
	if srcs == 0 || dsts == 0 {
		t.Fatalf("the journal carries %d router source(s) and %d destination(s); the fixture has to make both non-zero", srcs, dsts)
	}

	live := r.m.Router()
	res, err := Replay6(p, r.entries)
	if err != nil {
		t.Fatalf("Replay6: %v", err)
	}
	if res.State != State6Renewing {
		t.Errorf("the replay ended in %s, want %s", res.State, State6Renewing)
	}

	// The destination half: dropping it diverges, which is #925's own control.
	noDst := append([]JournalEntry6(nil), r.entries...)
	last := noDst[len(noDst)-1]
	last.Dst = netip.Addr{}
	noDst[len(noDst)-1] = last
	if _, err := Replay6(p, noDst); err == nil {
		t.Error("the same journal with the destination dropped replayed clean")
	}

	// The source half: the table is not part of what Replay6 compares, so it
	// is rebuilt from the journal's own events. Dropping the source leaves the
	// states identical and the table without its router.
	rebuild := func(entries []JournalEntry6) RouterObservation {
		t.Helper()
		again := newMachine6(t, p)
		for _, e := range entries {
			ev, err := e.Event()
			if err != nil {
				t.Fatalf("entry %d: %v", e.Seq, err)
			}
			again.Step(e.Now, e.Rnd, ev)
		}
		return again.Router()
	}
	if got := rebuild(r.entries); got.String() != live.String() {
		t.Errorf("the replayed observation is\n  %s\nand the recorded one is\n  %s", got, live)
	}
	noSrc := append([]JournalEntry6(nil), r.entries...)
	for i, e := range noSrc {
		if e.Kind == EvRouterAdvert {
			e.RASrc = netip.Addr{}
			noSrc[i] = e
		}
	}
	if got := rebuild(noSrc); got.String() == live.String() {
		t.Error("the same journal with the advertisement's source dropped rebuilt the same table")
	}
}
