package lease

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// TestAV6ManagerAcquiresThroughEveryPort is the v6 counterpart of the v4
// acquisition test, and it drives the WHOLE ring: the DHCPv6 transport, the
// Neighbor Discovery port, the duplicate address detection interlock, the
// timers and the journal.
//
// EVERY ASSERTION IS ON WHAT LEFT THE HOST OR ON WHAT THE CALLER WAS TOLD, and
// never on the manager's own counters — the fake server decodes the payload it
// was handed, so lastSent6 reads the bytes.
func TestAV6ManagerAcquiresThroughEveryPort(t *testing.T) {
	r := newRig6(t, testParams6(), answerNormally6(t))

	e := r.acquire6(t)
	if e.Family != FamilyV6 {
		t.Errorf("the event names family %s, want %s", e.Family, FamilyV6)
	}
	if got := e.Lease.Addr.String(); got != test6Addr+"/128" {
		t.Errorf("acquired %s, want %s/128 — RFC 9915 §21.6 carries an address and no prefix length", got, test6Addr)
	}
	if !sameBytes(e.Lease.ServerDUID, test6ServerDUID) {
		t.Errorf("the lease names the server %x, want %x", e.Lease.ServerDUID, test6ServerDUID)
	}
	if e.Lease.ServerID.IsValid() {
		t.Error("the v6 lease carries a v4 ServerID; exactly one of the two is set per family")
	}
	if e.Lease.IAID != test6IAID {
		t.Errorf("the lease names IAID %d, want %d", e.Lease.IAID, test6IAID)
	}
	if len(e.Lease.DNS) != 1 || e.Lease.DNS[0].String() != test6DNS {
		t.Errorf("the lease carries DNS %v, want %s", e.Lease.DNS, test6DNS)
	}
	if len(e.Lease.DomainSearch) != 1 || e.Lease.DomainSearch[0] != test6Search {
		t.Errorf("the lease carries the search list %v, want %s", e.Lease.DomainSearch, test6Search)
	}
	if e.DAD != proto.DADPassed {
		t.Errorf("the Acquired event reports duplicate address detection as %s, want %s: RFC 9915 §18.2.10.1 leaves no window in which a v6 caller holds an unchecked address", e.DAD, proto.DADPassed)
	}
	if e.ACD != proto.ACDIdle {
		t.Errorf("a v6 event reports the RFC 5227 phase %s; that check is not run here", e.ACD)
	}

	// The wall-clock deadlines are ordered the way the protocol orders them.
	if !e.Lease.Renew.Before(e.Lease.Rebind) {
		t.Errorf("T1 %s is not before T2 %s", e.Lease.Renew, e.Lease.Rebind)
	}
	if !e.Lease.Rebind.Before(e.Lease.Expire) {
		t.Errorf("T2 %s is not before the valid lifetime %s", e.Lease.Rebind, e.Lease.Expire)
	}
	if !e.Lease.Preferred.Equal(e.Lease.Valid) {
		t.Errorf("preferred %s and valid %s differ; the fixture sends 300 for both", e.Lease.Preferred, e.Lease.Valid)
	}

	// The exchange that produced it, read off the wire.
	sent := r.server.sentMessages()
	if len(sent) < 2 {
		t.Fatalf("the server saw %d message(s), want a Solicit and a Request", len(sent))
	}
	if sent[0].Type != wire.MsgSolicit || sent[1].Type != wire.MsgRequest6 {
		t.Fatalf("the exchange was %s then %s, want SOLICIT then REQUEST", sent[0].Type, sent[1].Type)
	}
	// Every message went to All_DHCP_Relay_Agents_and_Servers: RFC 9915
	// removed RFC 3315's Server Unicast option, so there is no unicast
	// destination for a v6 client to use.
	for i, d := range r.server.destinations() {
		if d.Addr != wire.AllDHCPRelayAgentsAndServers {
			t.Errorf("message %d went to %s, want %s", i, d.Addr, wire.AllDHCPRelayAgentsAndServers)
		}
	}
}

// TestTheV6ManagerSolicitsARouterAtStart is design section A.3.3's interlock 1
// seen from ring 2: the Router Solicitation goes out and nothing waits for the
// answer.
func TestTheV6ManagerSolicitsARouterAtStart(t *testing.T) {
	r := newRig6(t, testParams6(), answerNormally6(t))
	r.acquire6(t)

	pkts := r.nd.sentPackets()
	if len(pkts) == 0 {
		t.Fatal("no Router Solicitation went out (RFC 4861 §6.3.7)")
	}
	rs := pkts[0]
	if rs.Dst != wire.AllRoutersMulticast {
		t.Errorf("the Router Solicitation went to %s, want %s", rs.Dst, wire.AllRoutersMulticast)
	}
	if rs.Src.String() != "fe80::e849:4eff:fee5:31ed" {
		t.Errorf("the Router Solicitation's source is %s, want the interface's own link-local address", rs.Src)
	}
	if len(rs.Body) == 0 || rs.Body[0] != wire.ICMPv6RouterSolicit {
		t.Fatalf("the frame is not a Router Solicitation: % x", rs.Body)
	}
	// The lease was acquired without any Router Advertisement arriving, which
	// is interlock 1's whole content.
	if r.mgr.Router().Seen {
		t.Error("the manager reports a router observation with no Router Advertisement delivered")
	}
}

// TestARouterAdvertisementReachesRing1AndTheCaller drives the ND port inbound.
func TestARouterAdvertisementReachesRing1AndTheCaller(t *testing.T) {
	r := newRig6(t, testParams6(), answerNormally6(t))
	r.acquire6(t)

	r.nd.inject(raManagedOther)
	r.journal.waitAppended(t, "the Router Advertisement", func(e proto.JournalEntry6) bool {
		return e.Kind == proto.EvRouterAdvert
	})

	obs := r.mgr.Router()
	if !obs.Seen || !obs.Managed || !obs.Other {
		t.Errorf("the manager reports %+v, want M and O both set", obs)
	}
	if got := r.mgr.Stats().RouterAdvertsSeen; got != 1 {
		t.Errorf("RouterAdvertsSeen = %d, want 1", got)
	}

	// A frame that is not a Router Advertisement is counted and dropped.
	before := r.mgr.Stats()
	r.nd.inject([]byte{136, 0, 0, 0, 0, 0, 0, 0})
	r.nd.inject(raManagedOther)
	r.journal.waitAppended(t, "the second Router Advertisement", func(e proto.JournalEntry6) bool {
		return e.Kind == proto.EvRouterAdvert
	})
	after := r.mgr.Stats()
	if after.NDIgnored != before.NDIgnored+1 {
		t.Errorf("NDIgnored went from %d to %d; a Neighbor Advertisement is not this ring's to read", before.NDIgnored, after.NDIgnored)
	}
	if after.NDSeen != before.NDSeen+2 {
		t.Errorf("NDSeen went from %d to %d, want two more frames", before.NDSeen, after.NDSeen)
	}
}

// raManagedOther is a Router Advertisement with M and O both set.
var raManagedOther = []byte{
	134, 0, 0, 0,
	64, 0xC0, 0x07, 0x08,
	0, 0, 0, 0,
	0, 0, 0, 0,
}

// TestTheV6ManagerReportsTheStatelessConfiguration drives RFC 9915 §18.2.6
// through the manager: an M=0 O=1 Router Advertisement while soliciting turns
// the exchange into an Information-request, whose Reply is a Configured event
// and NOT a lease.
func TestTheV6ManagerReportsTheStatelessConfiguration(t *testing.T) {
	answered := make(chan struct{}, 1)
	behaviour := func(req *wire.MessageV6, _ int) []*wire.MessageV6 {
		if req.Type != wire.MsgInformationRequest {
			return nil
		}
		search, err := wire.EncodeDomainSearch([]string{test6Search})
		if err != nil {
			t.Errorf("EncodeDomainSearch: %v", err)
			return nil
		}
		dns := netip.MustParseAddr(test6DNS).As16()
		select {
		case answered <- struct{}{}:
		default:
		}
		return []*wire.MessageV6{{
			Type: wire.MsgReply, XID: req.XID,
			Options: wire.OptionsV6{
				optV6(wire.OptV6ClientID, test6DUID),
				optV6(wire.OptV6ServerID, test6ServerDUID),
				optV6(wire.OptV6DNSServers, dns[:]),
				optV6(wire.OptV6DomainList, search),
				// 60 seconds, which is OUTSIDE §21.23's bounds on purpose:
				// IRT_MINIMUM is 600. A fixture inside the bounds cannot
				// tell the reported value from the raw one, and this test
				// is the ring-2 end of that fact.
				optV6(wire.OptV6InfoRefresh, []byte{0, 0, 0, 60}),
			},
		}}
	}
	r := newRig6(t, testParams6(), behaviour)

	r.nd.inject(raOtherOnly)

	// The switch happens inside the Router Advertisement's own dispatch, so
	// settling on it is enough to say whether the Information-request went
	// out. Asserting that BEFORE reading the event is what turns "interlock 1
	// does not fire" from a hang on nextEvent into a failure. MEASURED: the
	// mutant that deletes the SELECTING6 arm of the switch was scored HUNG.
	r.settle(t)
	if got := lastSent6(t, r, wire.MsgInformationRequest); got == nil {
		t.Fatal("M=0 O=1 arrived while soliciting and no Information-request left the host: design §A.3.3 interlock 1")
	}

	e := r.nextEvent(t)
	if e.Kind != Configured {
		t.Fatalf("the first event is %s, want configured", e.Kind)
	}
	if e.Lease.Addr.IsValid() {
		t.Errorf("a configured event carries the address %s; §18.2.6's exchange has none", e.Lease.Addr)
	}
	if len(e.Config.DNS) != 1 || e.Config.DNS[0].String() != test6DNS {
		t.Errorf("the configuration carries DNS %v, want %s", e.Config.DNS, test6DNS)
	}
	if len(e.Config.Search) != 1 || e.Config.Search[0] != test6Search {
		t.Errorf("the configuration carries the search list %v, want %s", e.Config.Search, test6Search)
	}
	// The fake clock does not move unless a test moves it, and this one does
	// not, so the instant the configuration names is exactly now + the bound.
	if want := r.clock.Wall().Add(600 * time.Second); !e.Config.Refresh.Equal(want) {
		t.Errorf("the configuration says the client asks again at %s, want %s: the Reply sent 60 seconds and §21.23 says \"A client MUST use the refresh time IRT_MINIMUM if it receives the option with a value less than IRT_MINIMUM.\"",
			e.Config.Refresh, want)
	}
	if got := r.mgr.Stats().ConfiguredEvents; got != 1 {
		t.Errorf("ConfiguredEvents = %d, want 1", got)
	}
	<-answered
	if got := lastSent6(t, r, wire.MsgInformationRequest); got == nil {
		t.Fatal("no Information-request left the host")
	}
}

// raOtherOnly is M=0, O=1: RFC 4861 §4.2's "other configuration information is
// available via DHCPv6", with no addresses.
var raOtherOnly = []byte{
	134, 0, 0, 0,
	64, 0x40, 0x07, 0x08,
	0, 0, 0, 0,
	0, 0, 0, 0,
}

// TestADuplicateAddressDeclinesAndNeverAcquires is D22's shape at ring 2: the
// caller is never told Acquired for an address the check found in use.
func TestADuplicateAddressDeclinesAndNeverAcquires(t *testing.T) {
	r := newRig6(t, testParams6(), answerNormally6(t))
	r.settleDAD(t, test6Addr, true)

	// settle rather than waitSent: a client that dropped the address without
	// declining it sends nothing, and a barrier waiting for the Decline would
	// HANG on exactly that defect instead of naming it. MEASURED — the mutant
	// that replaces declineAll with a bare restartDiscovery was scored HUNG.
	r.settle(t)
	if _, held := r.mgr.Lease(); held {
		t.Error("the manager holds a lease for an address duplicate address detection found in use")
	}
	dec := findSent6(r, wire.MsgDecline6)
	if dec == nil {
		t.Fatal("no Decline left the host (§18.2.10.1 makes it a MUST)")
	}
	declined, err := dec.Options.IANAs()
	if err != nil || len(declined) != 1 {
		t.Fatalf("the Decline's IA_NA: %v %v", declined, err)
	}
	addrs, err := declined[0].Options.Addrs()
	if err != nil || len(addrs) != 1 || addrs[0].Addr.String() != test6Addr {
		t.Fatalf("the Decline names %v, want the address the check refused, %s", addrs, test6Addr)
	}
}

// TestAV6ManagerRefusesTheWrongPorts is the Config validation, as a table.
func TestAV6ManagerRefusesTheWrongPorts(t *testing.T) {
	p := testParams6()
	base := func() Config {
		return Config{
			Params6:     &p,
			TransportV6: newFakeServer6(silent6),
			ND:          newFakeND(),
			Clock:       newFakeClock(),
			Timers:      newFakeTimers(),
			Entropy:     &fakeEntropy{},
		}
	}
	for _, tc := range []struct {
		name  string
		spoil func(*Config)
		want  error
	}{
		{"no v6 transport", func(c *Config) { c.TransportV6 = nil }, ErrNoTransportV6},
		{"no Neighbor Discovery port", func(c *Config) { c.ND = nil }, ErrNoND},
		{"no clock", func(c *Config) { c.Clock = nil }, ErrNoClock},
		{"no timers", func(c *Config) { c.Timers = nil }, ErrNoTimers},
		{"no entropy", func(c *Config) { c.Entropy = nil }, ErrNoEntropy},
		{"a v4 transport beside Params6", func(c *Config) { c.Transport = newFakeServer(answerNormally) }, ErrBothFamilies},
		{"a v4 resume beside Params6", func(c *Config) { c.Resume = &Lease{} }, ErrBothFamilies},
		{
			"a resume with no usable address",
			func(c *Config) { c.Resume6 = &Lease{} },
			ErrResume6NoAddr,
		},
		{
			"a v4 address in the v6 resume",
			func(c *Config) { c.Resume6 = &Lease{Addr: netip.MustParsePrefix("192.168.99.5/24")} },
			ErrResume6NoAddr,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.spoil(&cfg)
			mgr, err := NewManager(cfg)
			if !errors.Is(err, tc.want) {
				t.Fatalf("NewManager = %v, %v; want %v", mgr, err, tc.want)
			}
			if mgr != nil {
				t.Error("a refused Config still produced a manager")
			}
		})
	}

	t.Run("the control", func(t *testing.T) {
		mgr, err := NewManager(base())
		if err != nil || mgr == nil {
			t.Fatalf("NewManager on a good Config = %v, %v", mgr, err)
		}
		if !mgr.v6() {
			t.Error("a Config with Params6 built a v4 manager")
		}
	})
}

// TestAResumedV6LeaseConfirms is design section A.3.3's interlock 3 through
// ring 2, and it is where the wall-clock crossing is checked: the record's
// deadlines become the remaining lifetimes ring 1 works in.
func TestAResumedV6LeaseConfirms(t *testing.T) {
	clk := newFakeClock()
	now := clk.Wall()
	remembered := Lease{
		Addr:       netip.MustParsePrefix(test6Addr + "/128"),
		ServerDUID: append([]byte(nil), test6ServerDUID...),
		IAID:       test6IAID,
		Preferred:  now.Add(120e9),
		Valid:      now.Add(240e9),
		Expire:     now.Add(240e9),
		Renew:      now.Add(60e9),
		Rebind:     now.Add(180e9),
	}
	r := newRig6On(t, clk, testParams6(), answerNormally6(t), withResume6(remembered))

	r.waitSent(t, wire.MsgConfirm)
	conf := findSent6(r, wire.MsgConfirm)
	if conf == nil {
		t.Fatal("no Confirm left the host (§18.2.12)")
	}
	if findSent6(r, wire.MsgSolicit) != nil {
		t.Error("a Solicit went out beside the Confirm; a client with remembered addresses confirms them")
	}
	if _, ok := conf.Options.First(wire.OptV6ServerID); ok {
		t.Error("the Confirm carries a Server Identifier; §18.2.3 lists none")
	}
	ias, err := conf.Options.IANAs()
	if err != nil || len(ias) != 1 {
		t.Fatalf("the Confirm's IA_NA: %v %v", ias, err)
	}
	addrs, err := ias[0].Options.Addrs()
	if err != nil || len(addrs) != 1 || addrs[0].Addr.String() != test6Addr {
		t.Fatalf("the Confirm asks about %v, want the remembered %s", addrs, test6Addr)
	}
}

// findSent6 returns the first message of this type the server saw, or nil.
func findSent6(r *rig6, want wire.MessageTypeV6) *wire.MessageV6 {
	for _, m := range r.server.sentMessages() {
		if m.Type == want {
			return m
		}
	}
	return nil
}

func sameBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
