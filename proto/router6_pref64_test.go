// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// nat64A to nat64C are the NAT64 prefixes the fixtures use
// (claymore666/docker-net-dhcp#1028).
const (
	nat64A = "2001:db8:1::/96"
	nat64B = "2001:db8:2::/96"
	nat64C = "64:ff9b::/96"
)

// withPREF64 is advert plus decoded PREF64 entries, for the cases that are
// about the table and not the decoder (claymore666/docker-net-dhcp#1028).
func withPREF64(from string, routerLifetime uint16, entries ...wire.PREF64) *wire.RouterAdvert {
	ra := advert(from, routerLifetime)
	ra.PREF64 = entries
	return ra
}

func nat64(prefix string, lifetime uint32) wire.PREF64 {
	return wire.PREF64{Prefix: netip.MustParsePrefix(prefix), Lifetime: lifetime}
}

func prefixTexts(in []netip.Prefix) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, p.String())
	}
	return out
}

// raWithPREF64Bytes is a Router Advertisement built from bytes, so the option
// reaches the table through the decoder the way a frame does. The router
// address is stamped on as ring 2 does.
// (claymore666/docker-net-dhcp#1028)
func raWithPREF64Bytes(t *testing.T, from string, routerLifetime uint16, options ...[]byte) *wire.RouterAdvert {
	t.Helper()
	raw := []byte{134, 0, 0, 0, 64, 0, byte(routerLifetime >> 8), byte(routerLifetime), 0, 0, 0, 0, 0, 0, 0, 0}
	for _, o := range options {
		raw = append(raw, o...)
	}
	ra := mustRA(t, raw)
	ra.Router = netip.MustParseAddr(from)
	return ra
}

func TestAPREF64PrefixLivesForItsScaledLifetimeTimesEight(t *testing.T) {
	var tab routerTable
	// Scaled Lifetime 75 is 600 s: a table that forgot RFC 8781 §4.1's
	// multiplication would hold it for 75 s.
	// (claymore666/docker-net-dhcp#1028)
	tab.observe(at(0), raWithPREF64Bytes(t, "fe80::1", 9000,
		pref64Bytes(75, 0, netip.MustParsePrefix(nat64A))))

	if got := prefixTexts(observation(t, &tab, at(599)).PREF64); !equalStrings(got, []string{nat64A}) {
		t.Errorf("one second before its lifetime ran out the list is %v", got)
	}
	got := observation(t, &tab, at(600))
	if len(got.PREF64) != 0 {
		t.Errorf("at its lifetime the list is still %v", prefixTexts(got.PREF64))
	}
	if len(got.Routers) != 1 {
		t.Errorf("the prefix's expiry took the router with it: %v", addrTexts(got.Routers))
	}
}

func TestAPREF64PrefixOutlivesARouterWhoseLifetimeWentToZero(t *testing.T) {
	var tab routerTable
	tab.observe(at(0), withPREF64("fe80::1", 1800, nat64(nat64A, 1600)))
	tab.observe(at(10), advert("fe80::1", 0))
	got := observation(t, &tab, at(11))
	if len(got.Routers) != 0 {
		t.Fatalf("the router that said lifetime 0 is still a default router: %v", addrTexts(got.Routers))
	}
	if !equalStrings(prefixTexts(got.PREF64), []string{nat64A}) {
		t.Errorf("the router's lifetime 0 took its prefix: %v", prefixTexts(got.PREF64))
	}

	// A router whose first advertisement already says lifetime 0 and carries
	// a PREF64 names a prefix nobody would have to be a default router for.
	// (claymore666/docker-net-dhcp#1028)
	var fresh routerTable
	fresh.observe(at(0), withPREF64("fe80::2", 0, nat64(nat64B, 800)))
	if got := prefixTexts(observation(t, &fresh, at(1)).PREF64); !equalStrings(got, []string{nat64B}) {
		t.Errorf("a prefix from a router with lifetime 0 is %v", got)
	}
	if got := observation(t, &fresh, at(801)).PREF64; len(got) != 0 {
		t.Errorf("that prefix outlived its own lifetime: %v", prefixTexts(got))
	}
}

func TestAWithdrawnPREF64IsGoneAtOnceAndAWithdrawalOfNothingChangesNothing(t *testing.T) {
	var tab routerTable
	tab.observe(at(0), withPREF64("fe80::1", 1800, nat64(nat64A, 600), nat64(nat64B, 600)))

	// Same advertisement withdraws one and introduces a third: wire order
	// decides nothing here, the withdrawal must not cost its siblings.
	// (claymore666/docker-net-dhcp#1028)
	tab.observe(at(1), withPREF64("fe80::1", 1800, nat64(nat64A, 0), nat64(nat64C, 600)))
	if got := prefixTexts(observation(t, &tab, at(2)).PREF64); !equalStrings(got, []string{nat64C, nat64B}) {
		t.Errorf("after the withdrawal the list is %v, want %s and %s", got, nat64C, nat64B)
	}

	refused, evicted, ignored := tab.refused, tab.evicted, tab.optIgnored
	tab.observe(at(3), withPREF64("fe80::1", 1800, nat64(nat64A, 0)))
	if got := prefixTexts(observation(t, &tab, at(4)).PREF64); !equalStrings(got, []string{nat64C, nat64B}) {
		t.Errorf("a withdrawal of a prefix never held changed the list to %v", got)
	}
	if tab.refused != refused || tab.evicted != evicted || tab.optIgnored != ignored {
		t.Errorf("a withdrawal of nothing moved a counter: refused %d evicted %d ignored %d",
			tab.refused-refused, tab.evicted-evicted, tab.optIgnored-ignored)
	}
}

func TestAnAdvertisementWithNoPREF64LeavesTheListAlone(t *testing.T) {
	var tab routerTable
	tab.observe(at(0), withPREF64("fe80::1", 1800, nat64(nat64A, 600)))
	// RFC 4861 §6.3.4: "the receipt of a Router Advertisement MUST NOT
	// invalidate all information received in a previous advertisement or from
	// another source."
	// (claymore666/docker-net-dhcp#1028)
	tab.observe(at(1), advert("fe80::1", 1800))
	tab.observe(at(2), advert("fe80::2", 1800))
	if got := prefixTexts(observation(t, &tab, at(3)).PREF64); !equalStrings(got, []string{nat64A}) {
		t.Errorf("advertisements without the option changed the list to %v", got)
	}
}

func TestTheSameBitsWithTwoPrefixLengthsAreTwoEntries(t *testing.T) {
	var tab routerTable
	// One advertisement per PLC, the bytes of RFC 8781 §4's diagram: the /96
	// and the /64 cut from the same twelve octets are different prefixes.
	// (claymore666/docker-net-dhcp#1028)
	cut := netip.MustParsePrefix("2001:db8:1:2:3:4::/96")
	tab.observe(at(0), raWithPREF64Bytes(t, "fe80::1", 1800, pref64Bytes(75, 0, cut)))
	tab.observe(at(1), raWithPREF64Bytes(t, "fe80::1", 1800, pref64Bytes(150, 1, cut)))
	got := observation(t, &tab, at(2))
	if !equalStrings(prefixTexts(got.PREF64), []string{"2001:db8:1:2::/64", "2001:db8:1:2:3:4::/96"}) {
		t.Fatalf("the list is %v, want the /64 and the /96", prefixTexts(got.PREF64))
	}

	// Refreshing one must leave the other's deadline alone: the /96 was heard
	// for 600 s at 0, the /64 for 1200 s at 1.
	// (claymore666/docker-net-dhcp#1028)
	tab.observe(at(500), raWithPREF64Bytes(t, "fe80::1", 1800, pref64Bytes(75, 1, cut)))
	if got := prefixTexts(observation(t, &tab, at(601)).PREF64); !equalStrings(got, []string{"2001:db8:1:2::/64"}) {
		t.Errorf("the /96 had to expire at 600 s whatever happened to the /64: %v", got)
	}
}

func TestARefreshThatShortensTheLifetimeIsHonoured(t *testing.T) {
	var tab routerTable
	tab.observe(at(0), withPREF64("fe80::1", 1800, nat64(nat64A, 600)))
	// RFC 4861 §6.3.4: "the most recently received information is considered
	// authoritative", so 80 s replaces 600 s and is not the larger of the two.
	// (claymore666/docker-net-dhcp#1028)
	tab.observe(at(10), withPREF64("fe80::1", 1800, nat64(nat64A, 80)))
	if got := observation(t, &tab, at(89)).PREF64; len(got) != 1 {
		t.Fatalf("before the shortened lifetime ran out the list is %v", prefixTexts(got))
	}
	if got := observation(t, &tab, at(90)).PREF64; len(got) != 0 {
		t.Errorf("the refresh that said 80 s was taken as the larger of the two: %v", prefixTexts(got))
	}
}

func TestAPREF64PrefixWithHostBitsSetIsHeldMaskedAndWithdrawnUnderEitherSpelling(t *testing.T) {
	var tab routerTable
	dirty := netip.PrefixFrom(netip.MustParseAddr("2001:db8:1::ff"), 96)
	clean := dirty.Masked()
	tab.observe(at(0), withPREF64("fe80::1", 1800, wire.PREF64{Prefix: dirty, Lifetime: 600}))
	tab.observe(at(1), withPREF64("fe80::1", 1800, wire.PREF64{Prefix: clean, Lifetime: 600}))
	got := observation(t, &tab, at(2)).PREF64
	if len(got) != 1 || got[0] != clean {
		t.Fatalf("the list is %v, want one entry %s", prefixTexts(got), clean)
	}
	tab.observe(at(3), withPREF64("fe80::1", 1800, wire.PREF64{Prefix: dirty, Lifetime: 0}))
	if got := observation(t, &tab, at(4)).PREF64; len(got) != 0 {
		t.Errorf("a withdrawal spelled with host bits missed the entry: %v", prefixTexts(got))
	}
}

func TestAPREF64WithNoPrefixIsAnIgnoredOptionAndNotAnEntry(t *testing.T) {
	var tab routerTable
	tab.observe(at(0), withPREF64("fe80::1", 1800, wire.PREF64{Lifetime: 600}))
	if got := observation(t, &tab, at(1)).PREF64; len(got) != 0 {
		t.Errorf("the zero prefix became an entry: %v", prefixTexts(got))
	}
	if tab.optIgnored != 1 || tab.refused != 0 || tab.evicted != 0 {
		t.Errorf("ignored %d refused %d evicted %d, want 1 0 0", tab.optIgnored, tab.refused, tab.evicted)
	}
}

func TestAPrefixLengthCodeOfSixOrSevenNeverReachesTheTable(t *testing.T) {
	m := newMachine6(t, testParams6())
	good := netip.MustParsePrefix("2001:db8:5::/64")
	ra := raWithPREF64Bytes(t, "fe80::1", 1800,
		pref64Bytes(75, 6, netip.MustParsePrefix(nat64A)),
		pref64Bytes(75, 1, good),
		pref64Bytes(75, 7, netip.MustParsePrefix(nat64B)))
	if ra.IgnoredOptions != 2 {
		t.Fatalf("the decoder counted %d refused options, the fixture needs 2", ra.IgnoredOptions)
	}
	m.Step(at(0), 1, RouterAdvert(ra))

	got := m.Router()
	if !equalStrings(prefixTexts(got.PREF64), []string{good.String()}) {
		t.Errorf("the observation holds %v, want only the /64 beside the two refused options", prefixTexts(got.PREF64))
	}
	if m.RouterTableDrops() != 0 || m.RouterTableEvictions() != 0 {
		t.Errorf("a refused option was counted as a full list: drops %d evictions %d", m.RouterTableDrops(), m.RouterTableEvictions())
	}
}

func TestAFullPREF64ListEvictsTheEntryThatExpiresFirstAndCountsIt(t *testing.T) {
	var tab routerTable
	for i := range maxRouterPref64 {
		// lifetimes 500, 400, 300, 200: the last one heard expires first.
		// (claymore666/docker-net-dhcp#1028)
		tab.observe(at(0), withPREF64("fe80::1", 1800,
			nat64(fmt.Sprintf("2001:db8:%x::/96", i+1), uint32(500-100*i))))
	}
	if got := len(observation(t, &tab, at(1)).PREF64); got != maxRouterPref64 {
		t.Fatalf("%d entries before the flood, want the cap %d", got, maxRouterPref64)
	}

	// A refresh of a held prefix on a full list makes no room and takes none.
	// (claymore666/docker-net-dhcp#1028)
	tab.observe(at(2), withPREF64("fe80::1", 1800, nat64("2001:db8:1::/96", 500)))
	if tab.evicted != 0 {
		t.Errorf("a refresh on a full list evicted %d entries", tab.evicted)
	}

	// The prefix that expires first is the fourth (200 s), not the newest
	// arrival and not the first one heard.
	// (claymore666/docker-net-dhcp#1028)
	tab.observe(at(3), withPREF64("fe80::1", 1800, nat64("2001:db8:ff::/96", 50)))
	got := prefixTexts(observation(t, &tab, at(4)).PREF64)
	want := []string{"2001:db8:1::/96", "2001:db8:2::/96", "2001:db8:3::/96", "2001:db8:ff::/96"}
	if !equalStrings(got, want) {
		t.Errorf("the list is %v, want %v", got, want)
	}
	if tab.evicted != 1 || tab.refused != 0 {
		t.Errorf("evicted %d refused %d, want 1 0: a full PREF64 list evicts", tab.evicted, tab.refused)
	}
}

func TestAFullPREF64ListOfEqualsEvictsTheOneHeardLast(t *testing.T) {
	var tab routerTable
	for i := range maxRouterPref64 {
		tab.observe(at(0), withPREF64("fe80::1", 1800, nat64(fmt.Sprintf("2001:db8:%x::/96", i+1), 600)))
	}
	tab.observe(at(0), withPREF64("fe80::1", 1800, nat64("2001:db8:ff::/96", 600)))
	got := prefixTexts(observation(t, &tab, at(1)).PREF64)
	want := []string{"2001:db8:1::/96", "2001:db8:2::/96", "2001:db8:3::/96", "2001:db8:ff::/96"}
	if !equalStrings(got, want) {
		t.Errorf("the list is %v, want %v: on a tie the entry heard last goes", got, want)
	}
}

func TestThePREF64CapHoldsAtLeastTwoForARenumbering(t *testing.T) {
	if maxRouterPref64 < 2 {
		t.Errorf("maxRouterPref64 is %d; RFC 8781 §5 names renumbering from one prefix to another, which is two", maxRouterPref64)
	}
}

func TestThePREF64ListIsACopyAndNotTheTablesOwnStorage(t *testing.T) {
	var tab routerTable
	tab.observe(at(0), withPREF64("fe80::1", 1800, nat64(nat64A, 600), nat64(nat64B, 600)))
	first := observation(t, &tab, at(1))
	first.PREF64[0] = netip.MustParsePrefix("2001:db8:dead::/96")
	first.PREF64 = append(first.PREF64[:0], first.PREF64...)

	second := observation(t, &tab, at(2))
	if !equalStrings(prefixTexts(second.PREF64), []string{nat64A, nat64B}) {
		t.Errorf("an edit of one observation reached the next: %v", prefixTexts(second.PREF64))
	}
	if &first.PREF64[0] == &second.PREF64[0] {
		t.Error("two observations share one backing array")
	}
}

func TestThePREF64OrderIsTheSameWhateverOrderTheyArrivedIn(t *testing.T) {
	forward := []string{"2001:db8:2::/96", "2001:db8:1::/64", "64:ff9b::/96", "2001:db8:1::/96"}
	var a, b routerTable
	for i, p := range forward {
		a.observe(at(int64(i)), withPREF64("fe80::1", 1800, nat64(p, 600)))
		b.observe(at(int64(i)), withPREF64("fe80::1", 1800, nat64(forward[len(forward)-1-i], 600)))
	}
	got := prefixTexts(observation(t, &a, at(10)).PREF64)
	want := []string{"64:ff9b::/96", "2001:db8:1::/64", "2001:db8:1::/96", "2001:db8:2::/96"}
	if !equalStrings(got, want) {
		t.Errorf("the list is %v, want address then length: %v", got, want)
	}
	if other := prefixTexts(observation(t, &b, at(10)).PREF64); !equalStrings(other, got) {
		t.Errorf("the reverse arrival order gave %v, the forward one %v", other, got)
	}
}

func TestAnAdvertisementWithNoSourceAddressHoldsNoPREF64(t *testing.T) {
	var tab routerTable
	ra := withPREF64("fe80::1", 1800, nat64(nat64A, 600))
	ra.Router = netip.Addr{}
	if tab.observe(at(0), ra) {
		t.Error("the table took an advertisement with no source address")
	}
	if got := observation(t, &tab, at(1)).PREF64; len(got) != 0 {
		t.Errorf("a frame with no source held %v", prefixTexts(got))
	}
}

func TestThePREF64ListIsAgedByAnyStepAndNotOnlyByAnAdvertisement(t *testing.T) {
	m := newMachine6(t, testParams6())
	m.Step(at(0), 1, RouterAdvert(raWithPREF64Bytes(t, "fe80::1", 9000, pref64Bytes(10, 0, netip.MustParsePrefix(nat64A)))))
	if got := m.Router().PREF64; len(got) != 1 {
		t.Fatalf("the advertisement held %v", prefixTexts(got))
	}
	m.Step(at(81), 2, TimerFired(Timer6Retransmit))
	got := m.Router()
	if len(got.PREF64) != 0 {
		t.Errorf("an 80 s prefix is still reported at 81 s: %v", prefixTexts(got.PREF64))
	}
	if len(got.Routers) != 1 {
		t.Errorf("the prefix's expiry took the router: %s", got)
	}
}

func TestTheObservationNamesItsNAT64Prefixes(t *testing.T) {
	var tab routerTable
	tab.observe(at(0), withPREF64("fe80::1", 1800, nat64(nat64A, 600)))
	obs := observation(t, &tab, at(1))
	obs.Seen = true
	if s := obs.String(); !strings.Contains(s, nat64A) {
		t.Errorf("the observation's text %q does not name %s", s, nat64A)
	}
}

func TestAWithdrawnPREF64FreesItsSlotInTheSameAdvertisement(t *testing.T) {
	var tab routerTable
	full := advert("fe80::1", 1800)
	for i := range maxRouterPref64 {
		full.PREF64 = append(full.PREF64, nat64(fmt.Sprintf("2001:db8:%x::/96", i+1), 600))
	}
	tab.observe(at(0), full)
	if got := observation(t, &tab, at(1)).PREF64; len(got) != maxRouterPref64 {
		t.Fatalf("%d prefix(es) before the withdrawal, want the cap %d", len(got), maxRouterPref64)
	}
	evicted := tab.evicted

	// The withdrawal comes first, the order RFC 8781 §4.1's options are walked
	// in; a withdrawn entry that kept its slot would be evicted to make room
	// and counted as an eviction that never happened
	// (claymore666/docker-net-dhcp#1028).
	tab.observe(at(2), withPREF64("fe80::1", 1800,
		nat64("2001:db8:1::/96", 0), nat64(nat64C, 600)))

	got := prefixTexts(observation(t, &tab, at(3)).PREF64)
	want := []string{nat64C, "2001:db8:2::/96", "2001:db8:3::/96", "2001:db8:4::/96"}
	if !equalStrings(got, want) {
		t.Errorf("the list after a swap is %v, want %v", got, want)
	}
	if tab.evicted != evicted {
		t.Errorf("a withdrawal followed by an addition counted %d eviction(s)", tab.evicted-evicted)
	}
}

func TestOneRoutersWithdrawalOfAPREF64TakesItForTheLinkUntilAnotherAdvertisesIt(t *testing.T) {
	var tab routerTable
	tab.observe(at(0), withPREF64("fe80::1", 1800, nat64(nat64A, 600)))
	tab.observe(at(1), withPREF64("fe80::2", 1800, nat64(nat64A, 600)))

	// The list belongs to the link and not to a router (RFC 8781 §5.1), and the
	// most recent information is authoritative (RFC 4861 §6.3.4): the first
	// router's withdrawal removes the prefix although the second still
	// advertises it (claymore666/docker-net-dhcp#1028).
	tab.observe(at(2), withPREF64("fe80::1", 1800, nat64(nat64A, 0)))
	if got := observation(t, &tab, at(3)).PREF64; len(got) != 0 {
		t.Errorf("after one router withdrew it the list is still %v", prefixTexts(got))
	}

	tab.observe(at(4), withPREF64("fe80::2", 1800, nat64(nat64A, 600)))
	if got := prefixTexts(observation(t, &tab, at(5)).PREF64); !equalStrings(got, []string{nat64A}) {
		t.Errorf("the next advertisement from the other router left the list %v", got)
	}
}
