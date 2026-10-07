// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

const infinity6 uint32 = 0xffffffff

// bindIA6 binds a fresh machine on an IA_NA built from t1, t2 and specs, with
// the Request at t+2s and the bind at t+4s as bind6 does, and returns the
// actions of the step that entered BOUND.
func bindIA6(t *testing.T, t1, t2 uint32, specs []iaAddrSpec) (*Machine6, []Action) {
	t.Helper()
	m, _ := solicit6(t, testParams6())
	if s, _ := m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255)); s != State6Requesting {
		t.Fatalf("a preference-255 Advertise left the machine in %s", s)
	}
	s, acts := m.Step(at(3), 0, receivedV6(t, wire.MsgReply, uint32(capXIDRequest),
		optClientID(capDUID), optServerID(testServerDUID), optIANA(t, capIAID, t1, t2, specs)))
	for i := 0; s == State6DAD && i < len(specs); i++ {
		s, acts = m.Step(at(4), 0, DADResult(netip.MustParseAddr(specs[i].addr), false))
	}
	if s != State6Bound {
		t.Fatalf("the Reply left the machine in %s, want %s", s, State6Bound)
	}
	return m, acts
}

// TestAnInfiniteT1AndT2ArmNoRenewalTimer is RFC 9915 §21.4: "the client MUST
// use the values in the T1 and T2 fields for the T1 and T2 times, unless
// values in those fields are 0", with "the value 0xffffffff is taken to mean
// 'infinity'" (dhcp-golib#78). Only zero is the client's choice (§14.2).
func TestAnInfiniteT1AndT2ArmNoRenewalTimer(t *testing.T) {
	for _, c := range []struct {
		name                string
		t1, t2              uint32
		wantRenew, wantRebd Duration
		hasRenew, hasRebd   bool
	}{
		{name: "both infinite", t1: infinity6, t2: infinity6},
		{name: "T1 finite and T2 infinite", t1: 1000, t2: infinity6, wantRenew: 1000*Second - 2*Second, hasRenew: true},
		// T1 infinite beside a finite T2 is discarded at the IA (§21.4), so the
		// mixed shape that survives is T1 infinite with T2 zero: T2 is the
		// client's choice, 0.8 of the preferred lifetime.
		{name: "T1 infinite and T2 zero", t1: infinity6, t2: 0, wantRebd: 2880*Second - 2*Second, hasRebd: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, acts := bindIA6(t, c.t1, c.t2, []iaAddrSpec{{dnsmasqLeasedAddr, 3600, 7200}})
			d, ok := timerSet(acts, Timer6Renew)
			if ok != c.hasRenew || (ok && d != c.wantRenew) {
				t.Errorf("renew timer = %s armed=%v, want %s armed=%v", d, ok, c.wantRenew, c.hasRenew)
			}
			d, ok = timerSet(acts, Timer6Rebind)
			if ok != c.hasRebd || (ok && d != c.wantRebd) {
				t.Errorf("rebind timer = %s armed=%v, want %s armed=%v", d, ok, c.wantRebd, c.hasRebd)
			}
			if d, ok := timerSet(acts, Timer6Expire); !ok || d != 7200*Second-2*Second {
				t.Errorf("expire timer = %s armed=%v, want the valid lifetime from the Request", d, ok)
			}
		})
	}
}

// TestAZeroT1AndT2ChooseFromTheAddressesStillPreferred is RFC 9915 §14.2 ("the
// client MUST choose a time") with §21.4's 0.5 and 0.8 of "the shortest
// preferred lifetime of the addresses in the IA that the server is willing to
// extend": a deprecated address, preferred 0, is not one (dhcp-golib#78).
func TestAZeroT1AndT2ChooseFromTheAddressesStillPreferred(t *testing.T) {
	const live = "fd00:99::184"
	for _, c := range []struct {
		name      string
		specs     []iaAddrSpec
		renew     Duration
		rebind    Duration
		hasRenew  bool
		hasRebind bool
	}{
		{
			name:  "a deprecated address beside a live one",
			specs: []iaAddrSpec{{dnsmasqLeasedAddr, 0, 7200}, {live, 3600, 7200}},
			renew: 1800*Second - 2*Second, rebind: 2880*Second - 2*Second, hasRenew: true, hasRebind: true,
		},
		{
			name:  "the live address first and the deprecated one second",
			specs: []iaAddrSpec{{live, 3600, 7200}, {dnsmasqLeasedAddr, 0, 7200}},
			renew: 1800*Second - 2*Second, rebind: 2880*Second - 2*Second, hasRenew: true, hasRebind: true,
		},
		{
			name:  "every address deprecated: the choice is taken from the valid lifetime",
			specs: []iaAddrSpec{{dnsmasqLeasedAddr, 0, 7200}},
			renew: 3600*Second - 2*Second, rebind: 5760*Second - 2*Second, hasRenew: true, hasRebind: true,
		},
		{
			name:  "a deprecated address beside one with an infinite preferred lifetime",
			specs: []iaAddrSpec{{dnsmasqLeasedAddr, 0, 7200}, {live, infinity6, infinity6}},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, acts := bindIA6(t, 0, 0, c.specs)
			d, ok := timerSet(acts, Timer6Renew)
			if ok != c.hasRenew || (ok && d != c.renew) {
				t.Errorf("renew timer = %s armed=%v, want %s armed=%v", d, ok, c.renew, c.hasRenew)
			}
			d, ok = timerSet(acts, Timer6Rebind)
			if ok != c.hasRebind || (ok && d != c.rebind) {
				t.Errorf("rebind timer = %s armed=%v, want %s armed=%v", d, ok, c.rebind, c.hasRebind)
			}
			if d, ok := timerSet(acts, Timer6Expire); !ok || d != 7200*Second-2*Second {
				t.Errorf("expire timer = %s armed=%v, want the valid lifetime from the Request", d, ok)
			}
		})
	}
}

// TestADeprecatedAddressStillEndsThePreferredWindow pins PreferredUntil as the
// moment the first address deprecates: the renewal choice skips a preferred
// lifetime of 0, the deprecation report must not (dhcp-golib#78).
func TestADeprecatedAddressStillEndsThePreferredWindow(t *testing.T) {
	l := Lease6{Start: at(1000), Addrs: []Addr6{
		{Addr: addr6(dnsmasqLeasedAddr), Preferred: 0, Valid: 7200 * Second},
		{Addr: addr6("fd00:99::184"), Preferred: 3600 * Second, Valid: 7200 * Second},
	}}
	if _, ok := l.PreferredUntil(); ok {
		t.Error("PreferredUntil reports a moment although an address is deprecated already")
	}
}

// TestThePrefixGroupFollowsTheSameRules is the IA_PD side of the two tests
// above: the prefix group has its own aggregate in groupDeadlines, and an
// IA_PD takes §14.2 and §21.21's T1 and T2 the same way (dhcp-golib#78).
func TestThePrefixGroupFollowsTheSameRules(t *testing.T) {
	for _, c := range []struct {
		name          string
		l             Lease6
		renew, rebind Instant
		hasRenew      bool
		hasRebind     bool
	}{
		{
			name: "a deprecated prefix beside a live one",
			l: split6Lease(0, 0, split6Prefix(pr6First, 0, 410*Second),
				split6Prefix("2001:db8:1:200::/64", 310*Second, 410*Second)),
			renew: at(10 + 150), rebind: at(10 + 240), hasRenew: true, hasRebind: true,
		},
		{
			name:  "every prefix deprecated takes the choice from the valid lifetime",
			l:     split6Lease(0, 0, split6Prefix(pr6First, 0, 410*Second)),
			renew: at(10 + 200), rebind: at(10 + 320), hasRenew: true, hasRebind: true,
		},
		{
			name: "a prefix already past its preferred lifetime when the Reply arrived is deprecated",
			l: split6Lease(0, 0, split6Prefix(pr6First, 5*Second, 410*Second),
				split6Prefix("2001:db8:1:200::/64", 310*Second, 410*Second)),
			renew: at(10 + 150), rebind: at(10 + 240), hasRenew: true, hasRebind: true,
		},
		{
			// the wire cannot send this (§21.22 discards a preferred
			// lifetime above the valid one); the type can hold it
			name: "an infinite preferred lifetime beside a finite valid one arms nothing",
			l:    split6Lease(0, 0, split6Prefix(pr6First, Infinite, 410*Second)),
		},
		{
			name: "an infinite T1 and T2 arm nothing for the prefix",
			l:    split6Lease(Infinite, Infinite, split6Prefix(pr6First, 310*Second, 410*Second)),
		},
		{
			name:   "T1 infinite and T2 zero keeps T1 and chooses T2",
			l:      split6Lease(Infinite, 0, split6Prefix(pr6First, 310*Second, 410*Second)),
			rebind: at(10 + 240), hasRebind: true,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, pd := c.l.groupDeadlines()
			if pd.HasRenew != c.hasRenew || pd.HasRebind != c.hasRebind ||
				(c.hasRenew && pd.Renew != c.renew) || (c.hasRebind && pd.Rebind != c.rebind) {
				t.Errorf("IA_PD renew %v/%v rebind %v/%v, want %v/%v and %v/%v",
					pd.Renew, pd.HasRenew, pd.Rebind, pd.HasRebind, c.renew, c.hasRenew, c.rebind, c.hasRebind)
			}
		})
	}
}

// TestALeaseWithAnInfiniteTimeStillOrdersTheOthers keeps §21.4's ordering and
// the expiry on the shapes the fix lets through (dhcp-golib#78).
func TestALeaseWithAnInfiniteTimeStillOrdersTheOthers(t *testing.T) {
	addr := addr6(dnsmasqLeasedAddr)
	for _, c := range []struct{ t1, t2 Duration }{{Infinite, Infinite}, {1000 * Second, Infinite}, {Infinite, 0}, {0, Infinite}} {
		l := Lease6{Start: at(1000), T1: c.t1, T2: c.t2, Addrs: []Addr6{{Addr: addr, Preferred: 3600 * Second, Valid: 7200 * Second}}}
		d := l.Deadlines()
		if (c.t1 == Infinite) == d.HasRenew {
			t.Errorf("T1 %s T2 %s: HasRenew = %v", c.t1, c.t2, d.HasRenew)
		}
		if (c.t2 == Infinite) == d.HasRebind {
			t.Errorf("T1 %s T2 %s: HasRebind = %v", c.t1, c.t2, d.HasRebind)
		}
		if d.HasRenew && d.HasRebind && !d.Renew.Before(d.Rebind) {
			t.Errorf("T1 %s T2 %s: renew %s is not before rebind %s", c.t1, c.t2, d.Renew, d.Rebind)
		}
		if !d.HasExpire || d.Expire != at(1000).Add(7200*Second) {
			t.Errorf("T1 %s T2 %s: expiry %v/%v", c.t1, c.t2, d.Expire, d.HasExpire)
		}
	}
}

// TestAnInfinitePreferredLifetimeBesideADeprecatedAddressArmsNoRenewal drives
// Lease6 directly for the shape the wire cannot produce (§21.6 discards a
// preferred lifetime above the valid one): an infinite preferred lifetime with
// a finite valid one stays "never", and does not fall back to the valid
// lifetime the way an IA with nothing left to extend does (dhcp-golib#78).
func TestAnInfinitePreferredLifetimeBesideADeprecatedAddressArmsNoRenewal(t *testing.T) {
	l := Lease6{Start: at(1000), Addrs: []Addr6{
		{Addr: addr6(dnsmasqLeasedAddr), Preferred: 0, Valid: 7200 * Second},
		{Addr: addr6("fd00:99::184"), Preferred: Infinite, Valid: 7200 * Second},
	}}
	if d := l.Deadlines(); d.HasRenew || d.HasRebind {
		t.Errorf("renew %v/%v rebind %v/%v, want neither", d.Renew, d.HasRenew, d.Rebind, d.HasRebind)
	}
}

// TestAPrefixDeprecatedAtTheExchangeStartIsNotOneTheServerWillExtend drives
// the boundary of the prefix group through Step: a prefix-only Renew Reply
// with T1 and T2 of 0 whose deprecated prefix has its preferred lifetime end
// exactly where the prefix timers count from (dhcp-golib#78, RFC 9915 §21.4:
// 0.5 and 0.8 of the prefixes "the server is willing to extend"). The choice
// comes from the live prefix alone.
func TestAPrefixDeprecatedAtTheExchangeStartIsNotOneTheServerWillExtend(t *testing.T) {
	m, _ := split6Bound(t)
	_, acts := m.Step(at(10), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	if s, _ := m.Step(at(11), 0, split6Reply(t, ren.XID, pr6Server, optIAPD(t, capIAID, 0, 0, []pd6Spec{
		{pr6First, 0, 300}, {"2001:db8:1:200::/64", 200, 300}}))); s != State6Bound {
		t.Fatalf("the prefix-only Reply left the machine in %s, want %s", s, State6Bound)
	}
	l, _ := m.Lease()
	_, pd := l.groupDeadlines()
	if !pd.HasRenew || pd.Renew != at(10+100) || !pd.HasRebind || pd.Rebind != at(10+160) {
		t.Errorf("IA_PD renew %v/%v rebind %v/%v, want at(110) and at(170): 0.5 and 0.8 of the live prefix's 200 s counted from the Renew at 10",
			pd.Renew, pd.HasRenew, pd.Rebind, pd.HasRebind)
	}
}

// TestATimeClampedToTheValidLifetimeStillArmsWhenEveryPrefixIsDeprecated pins
// the T2 clamp where the choice is taken from the valid lifetime (RFC 9915
// §18.2.5: Rebind ends when the valid lifetimes expire, dhcp-golib#78).
func TestATimeClampedToTheValidLifetimeStillArmsWhenEveryPrefixIsDeprecated(t *testing.T) {
	l := split6Lease(0, 500*Second, split6Prefix(pr6First, 0, 410*Second))
	_, pd := l.groupDeadlines()
	if !pd.HasRenew || pd.Renew != at(10+200) || !pd.HasRebind || pd.Rebind != at(10+320) {
		t.Errorf("IA_PD renew %v/%v rebind %v/%v, want at(210) and at(330): a T2 of 500 s past the 400 s of valid lifetime left at the prefix start is 0.8 of 400 s",
			pd.Renew, pd.HasRenew, pd.Rebind, pd.HasRebind)
	}
}
