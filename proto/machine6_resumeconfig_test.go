package proto

import (
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// What the caller remembered from the run before: RFC 3646's two lists,
// beside the address and the lifetimes Resume6 already carried.
var (
	rememberedDNS    = []netip.Addr{addr6("fd00:99::1"), addr6("fd00:99::2")}
	rememberedSearch = []string{"lan.example", "example"}
)

func resumeWithConfig() *Resume6 {
	return &Resume6{
		Addrs:      []Addr6{{Addr: addr6(dnsmasqLeasedAddr), Preferred: 300 * Second, Valid: 300 * Second}},
		ServerDUID: append([]byte(nil), testServerDUID...),
		T1:         150 * Second,
		T2:         240 * Second,
		DNS:        append([]netip.Addr(nil), rememberedDNS...),
		Search:     append([]string(nil), rememberedSearch...),
	}
}

func acquiredLease6(t *testing.T, acts []Action) Lease6 {
	t.Helper()
	for _, a := range acts {
		if a.Kind == ActLeaseAcquired {
			return a.Lease6
		}
	}
	t.Fatalf("nothing was acquired: %v", acts)
	return Lease6{}
}

func assertCarriesRememberedConfig(t *testing.T, l Lease6, how string) {
	t.Helper()
	if len(l.DNS) != len(rememberedDNS) {
		t.Fatalf("the %s lease carries %d DNS server(s), want the %d that were remembered: %v",
			how, len(l.DNS), len(rememberedDNS), l.DNS)
	}
	for i := range rememberedDNS {
		if l.DNS[i] != rememberedDNS[i] {
			t.Errorf("the %s lease's DNS server %d is %v, want %v", how, i, l.DNS[i], rememberedDNS[i])
		}
	}
	if len(l.Search) != len(rememberedSearch) {
		t.Fatalf("the %s lease carries %d search domain(s), want the %d that were remembered: %v",
			how, len(l.Search), len(rememberedSearch), l.Search)
	}
	for i := range rememberedSearch {
		if l.Search[i] != rememberedSearch[i] {
			t.Errorf("the %s lease's search domain %d is %q, want %q", how, i, l.Search[i], rememberedSearch[i])
		}
	}
}

// TestAConfirmedResumeKeepsTheConfigurationItWasGiven is RFC 9915 §18.2.3
// read for what it says about the OTHER half of a binding.
//
// §18.2.3, on the Confirm that goes unanswered: "the client SHOULD continue to
// use any leases, using the last known lifetimes for those leases, and SHOULD
// continue to use any other previously obtained configuration parameters." A
// Reply to a Confirm carries a Status Code and nothing else, so nothing later
// in the exchange supplies the RFC 3646 lists; without them on the Resume6 a
// resumed client has no resolver at all, which is what the plugin's chassis
// had to close from its own record.
//
// THE OBSERVER IS THE ANNOUNCED LEASE, not the Resume6 handed in: a machine
// that stored the lists and did not put them on the lease it announces looks
// identical from the caller's side to one that dropped them.
func TestAConfirmedResumeKeepsTheConfigurationItWasGiven(t *testing.T) {
	p := testParams6()
	p.Resume = resumeWithConfig()

	m := newMachine6(t, p)
	if s, _ := m.Step(at(0), 0, Simple(EvStart)); s != State6Init {
		t.Fatalf("EvStart left the machine in %s", s)
	}
	s, acts := m.Step(at(1), capXIDSolicit, TimerFired(Timer6Delay))
	if s != State6Confirming {
		t.Fatalf("a live resume left the machine in %s, want %s", s, State6Confirming)
	}
	conf := mustSendV6(t, acts, wire.MsgConfirm)

	if s, _ := m.Step(at(2), 3, receivedV6(t, wire.MsgReply, conf.XID,
		optClientID(capDUID), optServerID(testServerDUID), optStatus(wire.StatusSuccess))); s != State6DAD {
		t.Fatalf("a confirming Reply left the machine in %s", s)
	}
	s, acts = m.Step(at(3), 3, DADResult(addr6(dnsmasqLeasedAddr), false))
	if s != State6Bound {
		t.Fatalf("a clean DAD verdict left the machine in %s", s)
	}
	assertCarriesRememberedConfig(t, acquiredLease6(t, acts), "confirmed")
}

// TestAnUnansweredConfirmKeepsTheConfigurationToo is §18.2.3's silence path,
// and it is the arm the sentence quoted above is actually written about.
//
// The machine reaches CNF_MAX_RD with no Reply and continues with the
// remembered binding. A version that carried the lists only on the confirmed
// path would pass the test above and leave a client that lost its server
// without a resolver — which is the case where losing one hurts most.
func TestAnUnansweredConfirmKeepsTheConfigurationToo(t *testing.T) {
	p := testParams6()
	p.Resume = resumeWithConfig()

	m := newMachine6(t, p)
	m.Step(at(0), 0, Simple(EvStart))
	if s, _ := m.Step(at(1), capXIDSolicit, TimerFired(Timer6Delay)); s != State6Confirming {
		t.Fatal("the machine is not confirming")
	}

	// §7.6: CNF_MAX_RD is ten seconds, measured from the first Confirm. Step
	// the retransmission timer past it.
	var (
		acts []Action
		s    State6
	)
	for sec := int64(2); sec <= 40; sec++ {
		s, acts = m.Step(at(sec), uint64(sec), TimerFired(Timer6Retransmit))
		if s != State6Confirming {
			break
		}
	}
	if s != State6DAD {
		t.Fatalf("the Confirm exchange ended in %s, want %s: §18.2.3 continues with the remembered leases", s, State6DAD)
	}
	s, acts = m.Step(at(60), 3, DADResult(addr6(dnsmasqLeasedAddr), false))
	if s != State6Bound {
		t.Fatalf("a clean DAD verdict left the machine in %s", s)
	}
	assertCarriesRememberedConfig(t, acquiredLease6(t, acts), "unconfirmed")
}

// TestResume6CloneReachesTheConfigurationLists is Clone's own obligation.
//
// Resume6 is the one pointer in Params6, and New6 clones it so that a caller
// holding the value it passed in cannot move the remembered binding out from
// under a machine that has already decided to confirm it. Two new slices are
// two new ways to do exactly that.
func TestResume6CloneReachesTheConfigurationLists(t *testing.T) {
	r := resumeWithConfig()
	c := r.Clone()

	r.DNS[0] = addr6("fd00:99::dead")
	r.Search[0] = "moved.example"

	if c.DNS[0] != rememberedDNS[0] {
		t.Errorf("the clone's DNS server followed the original to %v", c.DNS[0])
	}
	if c.Search[0] != rememberedSearch[0] {
		t.Errorf("the clone's search domain followed the original to %q", c.Search[0])
	}
}

// TestAMachineDoesNotFollowTheCallersRememberedLists is the same obligation
// one level up, where it is the machine and not the test that holds the copy.
func TestAMachineDoesNotFollowTheCallersRememberedLists(t *testing.T) {
	p := testParams6()
	res := resumeWithConfig()
	p.Resume = res

	m := newMachine6(t, p)
	// The caller reuses its own slices for something else after handing them
	// over. Nothing forbids it and nothing tells the machine.
	res.DNS[0] = addr6("fd00:99::dead")
	res.Search[0] = "moved.example"

	m.Step(at(0), 0, Simple(EvStart))
	_, acts := m.Step(at(1), capXIDSolicit, TimerFired(Timer6Delay))
	conf := mustSendV6(t, acts, wire.MsgConfirm)
	m.Step(at(2), 3, receivedV6(t, wire.MsgReply, conf.XID,
		optClientID(capDUID), optServerID(testServerDUID), optStatus(wire.StatusSuccess)))
	_, acts = m.Step(at(3), 3, DADResult(addr6(dnsmasqLeasedAddr), false))

	assertCarriesRememberedConfig(t, acquiredLease6(t, acts), "confirmed")
}
