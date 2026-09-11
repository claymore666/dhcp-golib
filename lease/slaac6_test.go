// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/proto"
)

// slaacRAPrefix is the prefix the fixture advertises and slaacRAAddr the
// address RFC 4291 Appendix A forms from it and the rig's own link hardware
// address. Its interface identifier is the one the rig's link-local address
// already carries, which is what a real link would look like.
const (
	slaacRAPrefix = "2001:db8:77::"
	slaacRAAddr   = "2001:db8:77:0:e849:4eff:fee5:31ed"
)

// raWithAutonomousPrefix is a Router Advertisement with M and O clear carrying
// one Prefix Information option with the Autonomous flag set, built from RFC
// 4861 §4.6.2's field diagram because this library has no encoder for one.
func raWithAutonomousPrefix(valid, preferred uint32) []byte {
	out := []byte{
		134, 0, 0, 0,
		64, 0x00, 0x07, 0x08,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
	o := make([]byte, 32)
	o[0], o[1], o[2] = 3, 4, 64
	o[3] = 0xC0 // L and A
	o[4], o[5], o[6], o[7] = byte(valid>>24), byte(valid>>16), byte(valid>>8), byte(valid)
	o[8], o[9], o[10], o[11] = byte(preferred>>24), byte(preferred>>16), byte(preferred>>8), byte(preferred)
	copy(o[16:], netip.MustParseAddr(slaacRAPrefix).AsSlice())
	return append(out, o...)
}

// TestAnAddressFormedFromAnAdvertisementReachesTheCaller is defeat row R-17 at
// the ring that owns the answer: ring 1's stateless autoconfiguration counters
// are mirrored into Stats at every Step, the way RouterTableEntriesDropped is,
// and the lease itself reaches the caller as an ordinary acquisition.
//
// THE COUNTERS ARE ASSERTED BESIDE THE EVENT AND NEVER INSTEAD OF IT. A
// counter is the machine's own account of itself; the acquisition event and
// the addresses it carries are what a caller acts on.
func TestAnAddressFormedFromAnAdvertisementReachesTheCaller(t *testing.T) {
	p := testParams6()
	p.Mode = proto.Mode6SLAAC
	p.LinkAddr = mustHex("ea494ee531ed")
	r := newRig6(t, p, silent6)

	r.nd.injectFrom(raWithAutonomousPrefix(86400, 14400), raRouter)
	// NO SEPARATE BARRIER FOR THE ADVERTISEMENT. Forming the address and
	// asking for the check happen in the SAME Step as the advertisement, so a
	// wait for the advertisement's journal entry would consume the very entry
	// settleDAD then waits for.
	r.settleDAD(t, slaacRAAddr, false)
	e := r.takeEvent(t)
	if e.Kind != Acquired {
		t.Fatalf("the first event is %s, want acquired", e.Kind)
	}
	// THE ADVERTISED PREFIX LENGTH CROSSES THE RING BOUNDARY. RFC 9915
	// §18.2.10.1's "MUST NOT be used to form an implicit prefix with a length
	// other than 128" binds an IA Address option, which carries no length; RFC
	// 4862 §5.5.3 d's option carries one, and it is the only thing on the link
	// that says which addresses are reachable without a router. A caller given
	// a /128 would re-derive it from the router observation instead.
	if got := e.Lease.Addr.String(); got != slaacRAAddr+"/64" {
		t.Fatalf("the acquired lease carries %s, want %s/64", got, slaacRAAddr)
	}
	if len(e.Lease.Addrs) != 1 || e.Lease.Addrs[0].Addr.Addr().String() != slaacRAAddr {
		t.Fatalf("the acquired lease's address list is %v, want the one formed address", e.Lease.Addrs)
	}
	if got := e.Lease.Addrs[0].Addr.Bits(); got != 64 {
		t.Errorf("the formed address is reported as a /%d, want the advertised /64", got)
	}
	if !e.Lease.SLAAC {
		t.Error("the acquired lease does not say it was formed rather than granted")
	}
	// A formed lease has no renewal schedule, and the caller can see that
	// rather than wait for a T1 that is never coming.
	if !e.Lease.Renew.IsZero() || !e.Lease.Rebind.IsZero() {
		t.Errorf("the formed lease carries T1 %s and T2 %s", e.Lease.Renew, e.Lease.Rebind)
	}
	// NOTHING WAS SENT TO A SERVER. The whole acquisition came off the link.
	if got := len(r.server.sentMessages()); got != 0 {
		t.Errorf("%d DHCPv6 message(s) were sent for an address no server granted", got)
	}

	st := r.mgr.Stats()
	if st.SLAACAddressesFormed != 1 {
		t.Errorf("Stats.SLAACAddressesFormed is %d, want 1", st.SLAACAddressesFormed)
	}
	if st.SLAACAddressesConflicted != 0 || st.SLAACAddressesExpired != 0 {
		t.Errorf("Stats reports %d conflict(s) and %d expiry on a clean acquisition", st.SLAACAddressesConflicted, st.SLAACAddressesExpired)
	}
	if st.DADChecksStarted != 1 {
		t.Errorf("Stats.DADChecksStarted is %d, want 1: a formed address is checked like any other", st.DADChecksStarted)
	}

	// A prefix this client cannot use is accounted under its own reason, so
	// "the router advertises something and you got nothing" is a number.
	refused := raWithAutonomousPrefix(86400, 14400)
	refused[19] &^= 0x40 // clear the Autonomous flag, RFC 4862 §5.5.3 a
	r.nd.injectFrom(refused, raRouter)
	waitRA(t, r, "the advertisement whose prefix rule a refuses")
	r.settle(t)
	if got := r.mgr.Stats().SLAACPrefixesIgnored; got != 1 {
		t.Errorf("Stats.SLAACPrefixesIgnored is %d, want 1", got)
	}
	if got := r.mgr.Stats().SLAACAddressesFormed; got != 1 {
		t.Errorf("a refused prefix formed an address: %d", got)
	}
}

// slaacRAAddr2 is the address a second autonomous prefix forms from the same
// link hardware address.
const slaacRAAddr2 = "2001:db8:78:0:e849:4eff:fee5:31ed"

// TestEveryRememberedAddressComesBack is the ring-2 half of defeat row R-16,
// and it is a row the row itself did not reach: ring 1 rebuilds RFC 4862
// §5.5.3's list from proto.Resume6.Addrs, and ring 2 was filling that list
// with ONE address however many the caller remembered.
//
// MEASURED on the base tree: Config.Resume6 is a lease.Lease, whose Addr is a
// single prefix, so a formed lease holding two addresses came back as one. The
// first advertisement after the restart then found the second prefix "not
// equal to the prefix of an address already in the list" and formed it again,
// which is the same address configured twice with two origins.
func TestEveryRememberedAddressComesBack(t *testing.T) {
	clk := newFakeClock()
	now := clk.Wall()
	p := testParams6()
	p.Mode = proto.Mode6SLAAC
	p.LinkAddr = mustHex("ea494ee531ed")

	remembered := Lease{
		Addr:  netip.MustParsePrefix(slaacRAAddr + "/128"),
		SLAAC: true,
		Addrs: []Addr6{
			{Addr: netip.MustParsePrefix(slaacRAAddr + "/128"), Preferred: now.Add(3600e9), Valid: now.Add(7200e9)},
			// A DIFFERENT PAIR OF LIFETIMES on purpose: §5.5.3 gives every
			// address its own two lifetimes, and a rig whose addresses shared
			// them could not tell a per-address deadline from the lease's.
			{Addr: netip.MustParsePrefix(slaacRAAddr2 + "/128"), Preferred: now.Add(1800e9), Valid: now.Add(3600e9)},
		},
		Preferred: now.Add(3600e9),
		Valid:     now.Add(7200e9),
		Expire:    now.Add(7200e9),
	}
	r := newRig6On(t, clk, p, silent6, withResume6(remembered))

	// BOTH remembered addresses are checked, and neither is formed a second
	// time by the advertisement that formed them originally.
	// ONE REQUEST BARRIER FOR BOTH ADDRESSES. Both checks are started in the
	// SAME Step, so there is one journal entry carrying both StartDAD
	// actions; waiting a second time would wait for an entry that is never
	// written. The two answers are then stepped one at a time.
	r.waitDADRequested(t, slaacRAAddr)
	r.mgr.ReportDADResult(netip.MustParseAddr(slaacRAAddr), false)
	r.waitDADStepped(t)
	r.mgr.ReportDADResult(netip.MustParseAddr(slaacRAAddr2), false)
	r.waitDADStepped(t)
	e := r.takeEvent(t)
	if e.Kind != Acquired {
		t.Fatalf("the first event is %s, want acquired", e.Kind)
	}
	if len(e.Lease.Addrs) != 2 {
		t.Fatalf("the resumed lease carries %v, want both remembered addresses", e.Lease.Addrs)
	}
	if !e.Lease.SLAAC {
		t.Error("the resumed lease does not say it was formed rather than granted")
	}
	// EACH ADDRESS CARRIES ITS OWN DEADLINES. The two were remembered with
	// different lifetimes, so a list that copied one address's deadlines onto
	// the other reads as equal here.
	byAddr := map[string]Addr6{}
	for _, a := range e.Lease.Addrs {
		byAddr[a.Addr.Addr().String()] = a
	}
	for _, want := range []struct {
		addr             string
		preferred, valid int64
	}{
		{slaacRAAddr, 3600, 7200},
		{slaacRAAddr2, 1800, 3600},
	} {
		got, ok := byAddr[want.addr]
		if !ok {
			t.Fatalf("%s is not in the reported list %v", want.addr, e.Lease.Addrs)
		}
		if d := got.Preferred.Sub(now).Seconds(); int64(d) != want.preferred {
			t.Errorf("%s is preferred for %vs, want %ds", want.addr, d, want.preferred)
		}
		if d := got.Valid.Sub(now).Seconds(); int64(d) != want.valid {
			t.Errorf("%s is valid for %vs, want %ds", want.addr, d, want.valid)
		}
	}

	r.nd.injectFrom(raWithAutonomousPrefix(86400, 14400), raRouter)
	waitRA(t, r, "the advertisement that formed the remembered addresses")
	r.settle(t)
	if got := r.mgr.Stats().SLAACAddressesFormed; got != 0 {
		t.Errorf("Stats.SLAACAddressesFormed is %d; every address came from the restart", got)
	}
	held, ok := r.mgr.Lease()
	if !ok || len(held.Addrs) != 2 {
		t.Errorf("the held lease carries %v (%v), want both addresses", held.Addrs, ok)
	}
}
