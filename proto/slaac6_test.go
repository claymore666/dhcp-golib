// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// The RFC 4862 §5.5.3 rules, driven one at a time against the table that holds
// them. Every test here reads the FORMED ADDRESS or the built lease; the
// counters are asserted beside that evidence and never instead of it.

// TestTheFormedAddressIsRFC4291AppendixAsOwnOctets is defeat row R-1 and R-37.
//
// It asserts SIXTEEN OCTETS and not "an address was formed", because every
// wrong way to build this address still produces an address: the MAC placed
// verbatim in the low 48 bits, the 0xff 0xfe pair inserted at the wrong offset,
// the universal/local bit set instead of inverted, the identifier overlapping
// the prefix.
//
// RFC 4291 Appendix A, for the 48-bit case: "This is to insert two octets,
// with hexadecimal values of 0xFF and 0xFE ... in the middle of the 48-bit MAC
// (between the company_id and vendor-supplied id)", and for both cases "The
// only change is inverting the value of the universal/local bit." The appendix
// gives bit diagrams and no numeric example, so the expectations below are
// hand-computed from those diagrams and written out octet by octet.
//
// BOTH POLARITIES OF THE u BIT ARE DRIVEN. A fixture whose MAC is globally
// scoped (u = 0) cannot tell an inversion from a set, and one that is locally
// administered (u = 1, which is what a container runtime invents) cannot tell
// an inversion from a clear. A doubled inversion is invisible to either alone.
func TestTheFormedAddressIsRFC4291AppendixAsOwnOctets(t *testing.T) {
	for _, c := range []struct {
		name   string
		hw     net.HardwareAddr
		prefix string
		plen   uint8
		want   string
	}{
		{
			// Globally scoped EUI-48: the u bit is 0 and the identifier's
			// first octet must come back with it at 1.
			name:   "an EUI-48 with universal scope",
			hw:     net.HardwareAddr{0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e},
			prefix: "2001:db8:1::",
			plen:   64,
			want:   "2001:db8:1:0:21b:21ff:fe3c:4d5e",
		},
		{
			// Locally administered EUI-48: the u bit is 1 and must come back
			// at 0. 0x02 ^ 0x02 == 0x00, which is also the octet a wrong
			// implementation that CLEARS the bit would produce, so the case
			// above is what separates the two.
			name:   "an EUI-48 that is locally administered",
			hw:     net.HardwareAddr{0x02, 0x42, 0xac, 0x11, 0x00, 0x02},
			prefix: "2001:db8:1::",
			plen:   64,
			want:   "2001:db8:1:0:42:acff:fe11:2",
		},
		{
			// An EUI-64 goes in whole: no 0xff 0xfe is inserted, and only the
			// u bit moves.
			name:   "an EUI-64",
			hw:     net.HardwareAddr{0x00, 0x1b, 0x21, 0xaa, 0xbb, 0x3c, 0x4d, 0x5e},
			prefix: "2001:db8:1::",
			plen:   64,
			want:   "2001:db8:1:0:21b:21aa:bb3c:4d5e",
		},
		{
			// §5.5.3 d's diagram is "link prefix" then "interface
			// identifier", so nothing a router puts in the low 64 bits
			// survives. A router that advertises 2001:db8:1::dead:beef/64 has
			// advertised 2001:db8:1::/64 with rubbish in the half it does not
			// own.
			name:   "a prefix carrying host bits below its own length",
			hw:     net.HardwareAddr{0x02, 0x42, 0xac, 0x11, 0x00, 0x02},
			prefix: "2001:db8:1::dead:beef",
			plen:   64,
			want:   "2001:db8:1:0:42:acff:fe11:2",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := SLAACAddress(netip.MustParseAddr(c.prefix), c.plen, c.hw)
			if err != nil {
				t.Fatalf("SLAACAddress: %v", err)
			}
			want := netip.MustParseAddr(c.want)
			if got != want {
				t.Fatalf("formed %s, want %s\n got octets %x\nwant octets %x",
					got, want, got.As16(), want.As16())
			}
		})
	}
}

// TestALinkAddressOfAnotherLengthFormsNoIdentifier is R-37's other half: RFC
// 4291 Appendix A covers the EUI-48 and the EUI-64, and this library forms
// nothing from anything else — not a zero identifier, which would collide on
// every endpoint of the link.
func TestALinkAddressOfAnotherLengthFormsNoIdentifier(t *testing.T) {
	for _, n := range []int{0, 1, 4, 5, 7, 9, 16, 20} {
		hw := make(net.HardwareAddr, n)
		if _, err := ModifiedEUI64(hw); err == nil {
			t.Errorf("a link address of %d octet(s) formed an interface identifier", n)
		}
		if _, err := SLAACAddress(netip.MustParseAddr("2001:db8::"), 64, hw); err == nil {
			t.Errorf("a link address of %d octet(s) formed an address", n)
		}
	}
	for _, n := range []int{6, 8} {
		if _, err := ModifiedEUI64(make(net.HardwareAddr, n)); err != nil {
			t.Errorf("a link address of %d octet(s) is RFC 4291 Appendix A's own case and was refused: %v", n, err)
		}
	}
}

// TestAPrefixLengthThatDoesNotSumTo128FormsNothing is defeat row R-2.
//
// The rule is RFC 4862 §5.5.3 d: "If the sum of the prefix length and
// interface identifier length does not equal 128 bits, the Prefix Information
// option MUST be ignored." Written as `PrefixLen == 64` it is identical today
// and wrong the moment an identifier of another length exists, so the test
// reads IIDBits and drives the lengths either side of the sum.
func TestAPrefixLengthThatDoesNotSumTo128FormsNothing(t *testing.T) {
	fits := uint8(128 - IIDBits)
	for _, plen := range []uint8{0, 1, 48, fits - 1, fits + 1, 96, 127, 128} {
		if plen == fits {
			continue
		}
		var tab slaacTable
		formed, _, why := tab.applyPIO(at(0), wire.PrefixInfo{
			PrefixLen: plen, Autonomous: true,
			Prefix:        netip.MustParseAddr("2001:db8:1::"),
			ValidLifetime: 86400, PreferredLifetime: 14400,
		}, testLinkAddr6)
		if formed {
			t.Errorf("a /%d prefix formed an address; %d + %d is not 128", plen, plen, IIDBits)
		}
		if why != SLAACIgnoreBadLength {
			t.Errorf("a /%d prefix was refused as %q, want the length rule", plen, why)
		}
	}
	var tab slaacTable
	formed, _, why := tab.applyPIO(at(0), wire.PrefixInfo{
		PrefixLen: fits, Autonomous: true,
		Prefix:        netip.MustParseAddr("2001:db8:1::"),
		ValidLifetime: 86400, PreferredLifetime: 14400,
	}, testLinkAddr6)
	if !formed || why != SLAACIgnoreNone {
		t.Fatalf("a /%d prefix, which is the length that sums to 128, formed=%v why=%q", fits, formed, why)
	}

	// THE RULE IS A SUM AND NOT THE NUMBER 64, driven at identifier lengths
	// this library does not use. MEASURED: written inline against IIDBits, the
	// mutant `pi.PrefixLen != 64` survives, because the two agree for every
	// input while the constant is 64. Nothing about the option can separate
	// them; only the rule itself can.
	for _, c := range []struct {
		prefixLen, iidBits int
		want               bool
	}{
		{64, 64, true}, {48, 80, true}, {80, 48, true}, {0, 128, true}, {128, 0, true},
		{64, 48, false}, {48, 64, false}, {63, 64, false}, {65, 64, false}, {127, 0, false},
	} {
		if got := lengthsSumTo128(c.prefixLen, c.iidBits); got != c.want {
			t.Errorf("a /%d prefix with a %d-bit identifier: got %v, want %v", c.prefixLen, c.iidBits, got, c.want)
		}
	}
}

// TestEachIgnoreRuleIsChargedByName is defeat rows R-3 and R-40: one Prefix
// Information option per rule, each breaking THAT rule only, asserting the
// reason by name. A rule that short-circuited another would charge the wrong
// counter, and a single "ignored" total could not tell.
func TestEachIgnoreRuleIsChargedByName(t *testing.T) {
	for _, c := range []struct {
		name string
		pi   wire.PrefixInfo
		want SLAACIgnore
	}{
		{
			// a: "If the Autonomous flag is not set, silently ignore the
			// Prefix Information option."
			name: "rule a, the Autonomous flag is clear",
			pi:   wire.PrefixInfo{PrefixLen: 64, Prefix: netip.MustParseAddr("2001:db8:1::"), ValidLifetime: 86400, PreferredLifetime: 14400},
			want: SLAACIgnoreNotAutonomous,
		},
		{
			// b: "If the prefix is the link-local prefix, silently ignore the
			// Prefix Information option."
			name: "rule b, the link-local prefix",
			pi:   wire.PrefixInfo{PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("fe80::"), ValidLifetime: 86400, PreferredLifetime: 14400},
			want: SLAACIgnoreLinkLocal,
		},
		{
			// RFC 4291 §2.5.6 makes the link-local prefix fe80::/10, so "the
			// link-local prefix" is a RANGE and not one address. MEASURED:
			// with fe80:: as the only case, the mutant that compares for
			// equality with fe80:: survives, and a router advertising
			// fe80:0:0:1::/64 would have an address formed from it.
			name: "rule b, a link-local prefix that is not fe80:: itself",
			pi:   wire.PrefixInfo{PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("fe80:0:0:1::"), ValidLifetime: 86400, PreferredLifetime: 14400},
			want: SLAACIgnoreLinkLocal,
		},
		{
			// The far end of fe80::/10, which a /64 or a /128 comparison both
			// miss.
			name: "rule b, the top of fe80::/10",
			pi:   wire.PrefixInfo{PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("febf:ffff:ffff:ffff::"), ValidLifetime: 86400, PreferredLifetime: 14400},
			want: SLAACIgnoreLinkLocal,
		},
		{
			// c: "If the preferred lifetime is greater than the valid
			// lifetime, silently ignore the Prefix Information option."
			name: "rule c, preferred greater than valid",
			pi:   wire.PrefixInfo{PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("2001:db8:1::"), ValidLifetime: 600, PreferredLifetime: 601},
			want: SLAACIgnorePreferredOverValid,
		},
		{
			name: "rule d, the lengths do not sum to 128",
			pi:   wire.PrefixInfo{PrefixLen: 48, Autonomous: true, Prefix: netip.MustParseAddr("2001:db8:1::"), ValidLifetime: 86400, PreferredLifetime: 14400},
			want: SLAACIgnoreBadLength,
		},
		{
			// d: "and if the Valid Lifetime is not 0, form an address". R-21.
			name: "rule d, a prefix this client does not hold with a valid lifetime of zero",
			pi:   wire.PrefixInfo{PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("2001:db8:1::"), ValidLifetime: 0, PreferredLifetime: 0},
			want: SLAACIgnoreValidZero,
		},
		{
			name: "not an IPv6 prefix at all",
			pi:   wire.PrefixInfo{PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("::ffff:192.0.2.0"), ValidLifetime: 86400, PreferredLifetime: 14400},
			want: SLAACIgnoreBadLength,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			var tab slaacTable
			formed, changed, why := tab.applyPIO(at(0), c.pi, testLinkAddr6)
			if formed || changed || len(tab.entries) != 0 {
				t.Fatalf("%s formed %d address(es)", c.name, len(tab.entries))
			}
			if why != c.want {
				t.Fatalf("charged to %q, want %q", why, c.want)
			}
		})
	}

	// AND WHICH RULE IS CHARGED WHEN TWO ARE BROKEN. §5.5.3's rules are a
	// list in order, so an option that is neither autonomous nor of a usable
	// length is refused by a, the first one that applies.
	var tab slaacTable
	_, _, why := tab.applyPIO(at(0), wire.PrefixInfo{
		PrefixLen: 48, Prefix: netip.MustParseAddr("fe80::"),
		ValidLifetime: 600, PreferredLifetime: 601,
	}, testLinkAddr6)
	if why != SLAACIgnoreNotAutonomous {
		t.Errorf("an option breaking four rules was charged to %q; §5.5.3's rules are a list in order and a is first", why)
	}
	// And one that is autonomous but link-local AND badly sized is charged to
	// b, which comes before d.
	tab = slaacTable{}
	_, _, why = tab.applyPIO(at(0), wire.PrefixInfo{
		PrefixLen: 48, Autonomous: true, Prefix: netip.MustParseAddr("fe80::"),
		ValidLifetime: 86400, PreferredLifetime: 14400,
	}, testLinkAddr6)
	if why != SLAACIgnoreLinkLocal {
		t.Errorf("a link-local prefix of an unusable length was charged to %q, want the link-local rule", why)
	}
}

// TestEveryIgnoreReasonIsDeclaredCountedAndNamed is the enumeration guard for
// the reasons, the D-1 shape applied to SLAACIgnore: a reason added to the
// constant block and not to AllSLAACIgnores shrinks every domain built from
// it, and one added past numSLAACIgnore would index outside the counter array.
func TestEveryIgnoreReasonIsDeclaredCountedAndNamed(t *testing.T) {
	seen := map[SLAACIgnore]int{}
	for _, r := range AllSLAACIgnores() {
		seen[r]++
		if r == SLAACIgnoreNone {
			t.Error("AllSLAACIgnores carries the zero value, which means the option was used")
		}
	}
	for i := 1; i < int(numSLAACIgnore); i++ {
		r := SLAACIgnore(i)
		if seen[r] != 1 {
			t.Errorf("%d is a declared reason and appears %d time(s) in AllSLAACIgnores()", i, seen[r])
		}
		if s := r.String(); s == "" || strings.HasPrefix(s, "slaac-ignore(") {
			t.Errorf("reason %d has no name of its own: %q", i, s)
		}
	}
	if got, want := len(seen), int(numSLAACIgnore)-1; got != want {
		t.Errorf("AllSLAACIgnores names %d reason(s) and the constant block declares %d", got, want)
	}
	// The counter array is sized by numSLAACIgnore, so every declared reason
	// has a slot and the totals add up.
	var c SLAACCounters
	for i := 1; i < int(numSLAACIgnore); i++ {
		c.Ignored[i] = uint64(i)
	}
	var want uint64
	for i := 1; i < int(numSLAACIgnore); i++ {
		want += uint64(i)
	}
	if got := c.IgnoredTotal(); got != want {
		t.Errorf("IgnoredTotal is %d, want %d: a reason is outside the sum", got, want)
	}
	if strings.HasPrefix(SLAACIgnore(numSLAACIgnore).String(), "slaac-ignore(") == false {
		t.Error("a value past the last declared reason is named, so the block and numSLAACIgnore have parted company")
	}
}

// TestPrefixEqualityIsMaskedAndLengthAware is defeat row R-23, and it is
// §5.5.3 d's own definition: "where "equal" means the two prefix lengths are
// the same and the first prefix-length bits of the prefixes are identical".
func TestPrefixEqualityIsMaskedAndLengthAware(t *testing.T) {
	var tab slaacTable
	first := wire.PrefixInfo{
		PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("2001:db8:1::"),
		ValidLifetime: 86400, PreferredLifetime: 14400,
	}
	if formed, _, _ := tab.applyPIO(at(0), first, testLinkAddr6); !formed {
		t.Fatal("the first advertisement formed nothing")
	}

	// Same prefix bits, host bits set: the SAME prefix, so the entry is
	// refreshed and no second address is formed.
	dirty := first
	dirty.Prefix = netip.MustParseAddr("2001:db8:1::dead:beef")
	dirty.ValidLifetime, dirty.PreferredLifetime = 100000, 20000
	formed, changed, why := tab.applyPIO(at(int64(Second)*0+1), dirty, testLinkAddr6)
	if formed {
		t.Error("a prefix advertised with host bits set formed a SECOND address; §5.5.3 d compares the first prefix-length bits")
	}
	if why != SLAACIgnoreNone || !changed {
		t.Errorf("the refresh was refused (%q) or reported no change (%v)", why, changed)
	}
	if len(tab.entries) != 1 {
		t.Fatalf("the table holds %d entries, want 1", len(tab.entries))
	}

	// Same bits, DIFFERENT length: not equal, so it is a new prefix — and a
	// /48 is refused by d's 128-bit rule, which is what it must be refused
	// by, not by silently updating the /64.
	before := tab.entries[0]
	short := first
	short.PrefixLen = 48
	formed, _, why = tab.applyPIO(at(2), short, testLinkAddr6)
	if formed || why != SLAACIgnoreBadLength {
		t.Errorf("a /48 with the same bits as the held /64 was formed=%v why=%q; the lengths differ so it is not the same prefix", formed, why)
	}
	if tab.entries[0] != before {
		t.Error("a /48 advertisement changed the held /64's entry")
	}
}

// TestTheTwoHourRuleUsesRemainingLifetimeAndTheKernelsOwnNumbers is defeat
// rows R-5 and R-6.
//
// §5.5.3 e, quoted because every wrong version of this passes an ordinary
// refresh: "1. If the received Valid Lifetime is greater than 2 hours or
// greater than RemainingLifetime, set the valid lifetime of the corresponding
// address to the advertised Valid Lifetime. 2. If RemainingLifetime is less
// than or equal to 2 hours, ignore the Prefix Information option with regards
// to the valid lifetime ... 3. Otherwise, reset the valid lifetime of the
// corresponding address to 2 hours."
//
// THE ORACLE IS LINUX. Design note M-1 phases 2c-2e measured Linux 6.12 under
// `unshare -Urn` doing exactly this: an address with 86400 seconds left,
// re-advertised with a valid lifetime of 0, came back with 7199 seconds — 2
// hours less the one second the measurement itself took — and advertised with
// 0 again a second later came back with 7198, still counting down rather than
// reset. Those two numbers are what separates rule 3 from rule 2.
func TestTheTwoHourRuleUsesRemainingLifetimeAndTheKernelsOwnNumbers(t *testing.T) {
	var tab slaacTable
	pi := wire.PrefixInfo{
		PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("2001:db8:1::"),
		ValidLifetime: 86400, PreferredLifetime: 14400,
	}
	if formed, _, _ := tab.applyPIO(at(0), pi, testLinkAddr6); !formed {
		t.Fatal("the first advertisement formed nothing")
	}

	// Phase 2c/2d: remaining 86400, advertised valid 0. Rule 1 does not fire
	// (0 is neither greater than 2 hours nor greater than 86400), rule 2 does
	// not fire (86400 > 2 hours), so rule 3 resets it to 2 hours. The kernel
	// said 7199 with one second of its own latency; a pure machine with an
	// exact clock says 7200.
	pi.ValidLifetime, pi.PreferredLifetime = 0, 0
	if _, changed, why := tab.applyPIO(at(1), pi, testLinkAddr6); why != SLAACIgnoreNone || !changed {
		t.Fatalf("the refresh was refused (%q) or reported no change (%v)", why, changed)
	}
	if got := tab.entries[0].remaining(at(1)); got != TwoHours {
		t.Fatalf("a valid lifetime of 0 against 86400 remaining left %s, want %s (rule 3)", got, TwoHours)
	}
	if got := tab.entries[0].remainingPreferred(at(1)); got != 0 {
		t.Errorf("the preferred lifetime is %s, want 0: §5.5.3 e's closing note says it is ALWAYS reset", got)
	}
	// One second after the reset is where Linux was read: 7199.
	if got, want := tab.entries[0].remaining(at(2)), TwoHours-Second; got != want {
		t.Fatalf("one second after the reset %s is left, want %s (Linux measured 7199s)", got, want)
	}

	// Phase 2e: advertise 0 again at that instant. RemainingLifetime is now
	// 7199, which is <= 2 hours, so rule 1 does not fire and rule 2 IGNORES
	// the option with regard to the valid lifetime: the deadline does not
	// move and the address keeps counting down. Linux, read one second later
	// again, measured 7198.
	if _, _, why := tab.applyPIO(at(2), pi, testLinkAddr6); why != SLAACIgnoreNone {
		t.Fatalf("the second refresh was refused: %q", why)
	}
	if got, want := tab.entries[0].remaining(at(3)), TwoHours-2*Second; got != want {
		t.Fatalf("a second valid lifetime of 0 left %s, want %s (rule 2 ignores it; Linux measured 7198s)", got, want)
	}
	// And with no advertisement at all the deadline is still the same
	// instant: rule 2 ignored the option rather than freezing the countdown.
	if got, want := tab.entries[0].remaining(at(6)), TwoHours-5*Second; got != want {
		t.Fatalf("the address stopped counting down: %s left at t+5, want %s", got, want)
	}
}

// TestRuleOneIsTriedFirstAndItsArmsAreADisjunction is the other half of R-5,
// and it is the order a tree that asked "is RemainingLifetime <= 2 hours"
// first would get wrong: such a tree refuses a router's legitimate extension
// of a nearly-expired prefix, which is the common case after a renumbering.
func TestRuleOneIsTriedFirstAndItsArmsAreADisjunction(t *testing.T) {
	// Arm 1: the advertised valid lifetime is greater than 2 hours. It is
	// taken whatever RemainingLifetime is — here 60 seconds, well inside the
	// two-hour window rule 2 would otherwise claim.
	t.Run("arm 1, greater than two hours, against a nearly expired address", func(t *testing.T) {
		tab := heldFor(t, 60, 60)
		pi := wire.PrefixInfo{
			PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("2001:db8:1::"),
			ValidLifetime: 86400, PreferredLifetime: 14400,
		}
		if _, _, why := tab.applyPIO(at(1), pi, testLinkAddr6); why != SLAACIgnoreNone {
			t.Fatalf("refused: %q", why)
		}
		if got, want := tab.entries[0].remaining(at(1)), 86400*Second; got != want {
			t.Fatalf("the extension left %s, want %s: rule 1 is tried FIRST and 86400 is greater than 2 hours", got, want)
		}
	})

	// Arm 2: the advertised valid lifetime is LESS than 2 hours and greater
	// than RemainingLifetime. Rule 1 still fires — its two arms are an "or" —
	// and a tree that wrote "and" would fall through to rule 2 and ignore a
	// router that just extended the address.
	t.Run("arm 2, less than two hours but greater than what is left", func(t *testing.T) {
		tab := heldFor(t, 60, 60)
		pi := wire.PrefixInfo{
			PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("2001:db8:1::"),
			ValidLifetime: 600, PreferredLifetime: 300,
		}
		if _, _, why := tab.applyPIO(at(1), pi, testLinkAddr6); why != SLAACIgnoreNone {
			t.Fatalf("refused: %q", why)
		}
		if got, want := tab.entries[0].remaining(at(1)), 600*Second; got != want {
			t.Fatalf("the extension left %s, want %s: rule 1's arms are a disjunction", got, want)
		}
	})

	// Neither arm: the advertised lifetime is under 2 hours AND under what is
	// left, with more than 2 hours left. That is rule 3's "otherwise", which
	// is the case the test above pins at exactly 2 hours.
	t.Run("neither arm, with more than two hours left", func(t *testing.T) {
		tab := heldFor(t, 86400, 14400)
		pi := wire.PrefixInfo{
			PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("2001:db8:1::"),
			ValidLifetime: 600, PreferredLifetime: 300,
		}
		if _, _, why := tab.applyPIO(at(1), pi, testLinkAddr6); why != SLAACIgnoreNone {
			t.Fatalf("refused: %q", why)
		}
		if got := tab.entries[0].remaining(at(1)); got != TwoHours {
			t.Fatalf("left %s, want %s (rule 3)", got, TwoHours)
		}
	})

	// And rule 2 proper: under 2 hours advertised, under what is left, and
	// what is left is inside the window.
	t.Run("rule 2, inside the window, the option is ignored", func(t *testing.T) {
		tab := heldFor(t, 3600, 1800)
		pi := wire.PrefixInfo{
			PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("2001:db8:1::"),
			ValidLifetime: 300, PreferredLifetime: 120,
		}
		if _, _, why := tab.applyPIO(at(10), pi, testLinkAddr6); why != SLAACIgnoreNone {
			t.Fatalf("refused: %q", why)
		}
		if got, want := tab.entries[0].remaining(at(10)), 3590*Second; got != want {
			t.Fatalf("left %s, want %s: rule 2 ignores the advertised valid lifetime", got, want)
		}
		// R-6: the PREFERRED lifetime moved in the same step, which is the
		// closing note's "regardless of whether the valid lifetime is also
		// reset or ignored".
		if got, want := tab.entries[0].remainingPreferred(at(10)), 120*Second; got != want {
			t.Fatalf("the preferred lifetime is %s, want %s: rule 2 ignored it too", got, want)
		}
	})
}

// TestTheTwoHourConstantIsTwoHours pins the constant itself, because every
// test above is expressed in terms of it and would pass against 2 minutes or
// 7200 milliseconds.
func TestTheTwoHourConstantIsTwoHours(t *testing.T) {
	if TwoHours != 7200*Second {
		t.Fatalf("TwoHours is %s, want two hours (RFC 4862 §5.5.3 e)", TwoHours)
	}
	if TwoHours.Seconds() != 7200 {
		t.Fatalf("TwoHours is %d seconds, want 7200", TwoHours.Seconds())
	}
}

// TestEachAddressKeepsItsOwnLifetimeOrigin is defeat row R-7: the clock the
// two-hour rule reads is the ADDRESS's own origin, not the lease's start. Two
// prefixes refreshed an hour apart from one origin would give the second a
// RemainingLifetime an hour wrong, which is a rule-2-versus-rule-3 difference.
func TestEachAddressKeepsItsOwnLifetimeOrigin(t *testing.T) {
	var tab slaacTable
	a := wire.PrefixInfo{PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("2001:db8:1::"), ValidLifetime: 86400, PreferredLifetime: 14400}
	b := wire.PrefixInfo{PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("2001:db8:2::"), ValidLifetime: 86400, PreferredLifetime: 14400}
	if formed, _, _ := tab.applyPIO(at(0), a, testLinkAddr6); !formed {
		t.Fatal("prefix A formed nothing")
	}
	if formed, _, _ := tab.applyPIO(at(0), b, testLinkAddr6); !formed {
		t.Fatal("prefix B formed nothing")
	}

	// A is refreshed at t=0 with 10000; B is refreshed an hour later with the
	// same number. If they shared an origin, B would come back an hour short.
	a.ValidLifetime, a.PreferredLifetime = 10000, 5000
	b.ValidLifetime, b.PreferredLifetime = 10000, 5000
	tab.applyPIO(at(0), a, testLinkAddr6)
	tab.applyPIO(at(3600), b, testLinkAddr6)

	now := at(3600)
	if got, want := tab.entries[0].remaining(now), (10000-3600)*Second; got != want {
		t.Errorf("prefix A has %s left, want %s", got, want)
	}
	if got, want := tab.entries[1].remaining(now), 10000*Second; got != want {
		t.Errorf("prefix B has %s left, want %s: it was refreshed at this instant and carries its own origin", got, want)
	}
}

// TestTwoAutonomousPrefixesFormTwoAddresses is defeat row R-4 at the table:
// the record holds a LIST, and first-wins is the shape this closes.
func TestTwoAutonomousPrefixesFormTwoAddresses(t *testing.T) {
	var tab slaacTable
	for _, p := range []string{"2001:db8:1::", "2001:db8:2::", "2001:db8:3::"} {
		formed, _, why := tab.applyPIO(at(0), wire.PrefixInfo{
			PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr(p),
			ValidLifetime: 86400, PreferredLifetime: 14400,
		}, testLinkAddr6)
		if !formed || why != SLAACIgnoreNone {
			t.Fatalf("%s formed=%v why=%q", p, formed, why)
		}
	}
	if len(tab.entries) != 3 {
		t.Fatalf("three autonomous prefixes formed %d address(es)", len(tab.entries))
	}
	l := tab.lease(at(0), 7)
	if len(l.Addrs) != 3 {
		t.Fatalf("the lease carries %d address(es), want 3", len(l.Addrs))
	}
	// And in the order the prefixes were heard, which is what a chassis that
	// must name one of them reads.
	for i, want := range []string{
		"2001:db8:1::42:acff:fe11:2",
		"2001:db8:2::42:acff:fe11:2",
		"2001:db8:3::42:acff:fe11:2",
	} {
		if got := l.Addrs[i].Addr; got != netip.MustParseAddr(want) {
			t.Errorf("address %d is %s, want %s: the list is in wire order", i, got, want)
		}
	}
	if !l.SLAAC {
		t.Error("the lease does not say it was formed rather than granted")
	}
}

// TestTheFormedSetIsCapped is defeat row R-22: a router that advertises more
// prefixes than this client will hold gets the cap, and the NEW prefix is the
// one refused, which is the router table's rule in L1 for the same reason.
func TestTheFormedSetIsCapped(t *testing.T) {
	var tab slaacTable
	for i := 0; i < MaxSLAACAddresses+4; i++ {
		formed, _, why := tab.applyPIO(at(0), wire.PrefixInfo{
			PrefixLen: 64, Autonomous: true,
			Prefix:        netip.MustParseAddr(fmt.Sprintf("2001:db8:%d::", i+1)),
			ValidLifetime: 86400, PreferredLifetime: 14400,
		}, testLinkAddr6)
		switch {
		case i < MaxSLAACAddresses:
			if !formed || why != SLAACIgnoreNone {
				t.Fatalf("prefix %d, inside the cap, formed=%v why=%q", i, formed, why)
			}
		default:
			if formed {
				t.Errorf("prefix %d formed an address past the cap of %d", i, MaxSLAACAddresses)
			}
			if why != SLAACIgnoreCapReached {
				t.Errorf("prefix %d past the cap was charged to %q", i, why)
			}
		}
	}
	if len(tab.entries) != MaxSLAACAddresses {
		t.Fatalf("the table holds %d entries, want the cap of %d", len(tab.entries), MaxSLAACAddresses)
	}
	// A HELD prefix is still refreshed at the cap: the cap refuses new
	// entries, not advertisements about the ones already held.
	_, _, why := tab.applyPIO(at(1), wire.PrefixInfo{
		PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("2001:db8:1::"),
		ValidLifetime: 100000, PreferredLifetime: 50000,
	}, testLinkAddr6)
	if why != SLAACIgnoreNone {
		t.Errorf("a HELD prefix was refused at the cap: %q", why)
	}
	if got, want := tab.entries[0].remaining(at(1)), 100000*Second; got != want {
		t.Errorf("the held entry has %s left, want %s", got, want)
	}
}

// TestAnInfiniteLifetimeIsASentinelAndNeverAnInstant is defeat row R-42.
//
// proto.Duration carries Infinite as -1 and not as a large number, so every
// comparison in §5.5.3 e has to name it: `valid > TwoHours` is FALSE for an
// infinite lifetime written as a plain greater-than, which would send a
// router's 0xffffffff straight into rule 3 and clamp it to two hours.
func TestAnInfiniteLifetimeIsASentinelAndNeverAnInstant(t *testing.T) {
	if !durGreater(Infinite, TwoHours) {
		t.Error("Infinite does not compare greater than two hours")
	}
	if durGreater(TwoHours, Infinite) {
		t.Error("two hours compares greater than Infinite")
	}
	if durGreater(Infinite, Infinite) {
		t.Error("Infinite compares greater than itself")
	}

	// Rule 1 arm 1 with an infinite advertised lifetime, against an address
	// with a finite one.
	tab := heldFor(t, 3600, 1800)
	pi := wire.PrefixInfo{
		PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("2001:db8:1::"),
		ValidLifetime: 0xffffffff, PreferredLifetime: 0xffffffff,
	}
	if _, _, why := tab.applyPIO(at(1), pi, testLinkAddr6); why != SLAACIgnoreNone {
		t.Fatalf("an infinite lifetime was refused: %q", why)
	}
	if !tab.entries[0].valid.IsInfinite() || !tab.entries[0].preferred.IsInfinite() {
		t.Fatalf("the entry holds valid=%s preferred=%s, want both infinite", tab.entries[0].valid, tab.entries[0].preferred)
	}
	if tab.entries[0].expired(farFuture) || tab.entries[0].deprecated(farFuture) {
		t.Error("an infinite lifetime ran out")
	}
	// And it contributes NO instant: an infinite lifetime added to an origin
	// is an instant in the past, which would arm a timer that fires forever.
	if ts, ok := tab.next(at(1)); ok {
		t.Errorf("a table of nothing but infinite lifetimes produced the instant %v", ts)
	}

	// WHY next's OWN INFINITE GUARD CANNOT BE DRIVEN, stated rather than left
	// as a surviving mutant. Infinite is -1, so an origin plus an infinite
	// lifetime is one nanosecond BEFORE that origin, and every origin in this
	// table is at or before now — an entry's start is stamped at the instant
	// it is formed or refreshed. next's "at or before now" filter therefore
	// absorbs the sentinel, and deleting the guard changes nothing TODAY.
	// MEASURED: the mutant that deletes it SURVIVES.
	//
	// The guard stays because that absorption is an accident of the
	// REPRESENTATION and not the rule. These two assertions are what make a
	// change of representation — Infinite as a large positive number, say —
	// go red here, rather than arm a timer three hundred years out.
	if Infinite >= 0 {
		t.Fatalf("Infinite is %d: next's filter no longer absorbs it and its own guard is the only thing left", Infinite)
	}
	if got := at(100).Add(Infinite); got >= at(100) {
		t.Fatalf("an origin plus an infinite lifetime is %v, which is not before the origin %v", got, at(100))
	}

	// Rule c at both polarities of infinity: an infinite PREFERRED lifetime
	// against a finite valid one is "preferred greater than valid" and is
	// refused; an infinite valid one against a finite preferred is not.
	var fresh slaacTable
	_, _, why := fresh.applyPIO(at(0), wire.PrefixInfo{
		PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("2001:db8:9::"),
		ValidLifetime: 3600, PreferredLifetime: 0xffffffff,
	}, testLinkAddr6)
	if why != SLAACIgnorePreferredOverValid {
		t.Errorf("an infinite preferred lifetime against a finite valid one was charged to %q", why)
	}
	fresh = slaacTable{}
	formed, _, why := fresh.applyPIO(at(0), wire.PrefixInfo{
		PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("2001:db8:9::"),
		ValidLifetime: 0xffffffff, PreferredLifetime: 3600,
	}, testLinkAddr6)
	if !formed || why != SLAACIgnoreNone {
		t.Errorf("an infinite valid lifetime against a finite preferred one was formed=%v why=%q", formed, why)
	}
	// And the instant it produces is the PREFERRED one, alone.
	ts, ok := fresh.next(at(0))
	if !ok || ts != at(3600) {
		t.Errorf("the next moment is %v (%v), want the preferred deadline at %v", ts, ok, at(3600))
	}
}

// TestThePreferredLifetimeNeverOutlivesTheValidOneAfterTheRules is defeat row
// R-25, and it is the row whose answer CHANGED under measurement.
//
// The row was written expecting the state "preferred greater than valid after
// §5.5.3 e" to be reachable and to be left unclamped. Driving it says the
// state is not reachable at all, and the reason is in the rules rather than in
// a clamp: c refuses any option whose preferred lifetime is greater than its
// valid one, rule 1 sets the valid lifetime to that same advertised value,
// rule 2 is reached only when the advertised valid lifetime is not greater
// than RemainingLifetime and sets the valid lifetime to RemainingLifetime, and
// rule 3 is reached only when the advertised valid lifetime is not greater
// than two hours and sets it to two hours. In each arm the valid lifetime ends
// at or above the preferred one.
//
// So the guarantee is an INVARIANT rather than a clamp, and a clamp added
// later would be undetectable without this. It is driven over a grid rather
// than one case, because one case selects one arm.
//
// The second half is what the invariant buys: the next moment §5.5.4 has to
// act on is the EARLIER of the two deadlines, so an expiry is never scheduled
// before the deprecation it follows.
func TestThePreferredLifetimeNeverOutlivesTheValidOneAfterTheRules(t *testing.T) {
	held := [][2]uint32{{100, 50}, {3600, 1800}, {7000, 100}, {86400, 14400}, {0xffffffff, 14400}}
	adv := [][2]uint32{{0, 0}, {50, 50}, {600, 300}, {6000, 6000}, {7200, 7200}, {86400, 86400}, {0xffffffff, 0xffffffff}}
	arms := map[string]int{}
	for _, h := range held {
		for _, a := range adv {
			tab := heldFor(t, h[0], h[1])
			before := tab.entries[0].remaining(at(10))
			if _, _, why := tab.applyPIO(at(10), wire.PrefixInfo{
				PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("2001:db8:1::"),
				ValidLifetime: a[0], PreferredLifetime: a[1],
			}, testLinkAddr6); why != SLAACIgnoreNone {
				t.Fatalf("held %v, advertised %v: refused as %q", h, a, why)
			}
			e := tab.entries[0]
			if durGreater(e.preferred, e.valid) {
				t.Errorf("held %v, advertised %v: left preferred=%s greater than valid=%s", h, a, e.preferred, e.valid)
			}
			// Which arm ran, so a grid that exercised one of them would be
			// visible as a grid that proves less than it claims.
			switch {
			case e.valid == SecondsToDuration(a[0]):
				arms["rule 1"]++
			case e.valid == before:
				arms["rule 2"]++
			case e.valid == TwoHours:
				arms["rule 3"]++
			}

			// The next moment is the earliest deadline STILL AHEAD. An
			// infinite lifetime contributes no instant at all, and a
			// preferred lifetime of zero has already arrived — the address is
			// deprecated at this instant — so the moment left to wait for is
			// the expiry.
			var want Instant
			have := false
			for _, d := range []Duration{e.preferred, e.valid} {
				if d.IsInfinite() {
					continue
				}
				ts := at(10).Add(d)
				if ts <= at(10) {
					continue
				}
				if !have || ts < want {
					want, have = ts, true
				}
			}
			ts, ok := tab.next(at(10))
			if ok != have {
				t.Fatalf("held %v, advertised %v: next reported %v with preferred=%s valid=%s", h, a, ok, e.preferred, e.valid)
			}
			if have && ts != want {
				t.Errorf("held %v, advertised %v: the next moment is %v, want the earlier deadline %v", h, a, ts, want)
			}
			if e.preferred == 0 && !e.deprecated(at(10)) {
				t.Errorf("held %v, advertised %v: a preferred lifetime of zero left the address preferred", h, a)
			}
		}
	}
	for _, arm := range []string{"rule 1", "rule 2", "rule 3"} {
		if arms[arm] == 0 {
			t.Errorf("the grid never reached %s of §5.5.3 e, so it proves nothing about it", arm)
		}
	}
}

// TestExpiryDropsOnlyTheAddressesWhoseValidLifetimeRanOut is the table half of
// defeat row R-9.
func TestExpiryDropsOnlyTheAddressesWhoseValidLifetimeRanOut(t *testing.T) {
	var tab slaacTable
	for i, v := range []uint32{100, 200, 300} {
		tab.applyPIO(at(0), wire.PrefixInfo{
			PrefixLen: 64, Autonomous: true,
			Prefix:        netip.MustParseAddr(fmt.Sprintf("2001:db8:%d::", i+1)),
			ValidLifetime: v, PreferredLifetime: v / 2,
		}, testLinkAddr6)
	}
	gone := tab.expire(at(150))
	if len(gone) != 1 || gone[0] != netip.MustParseAddr("2001:db8:1::42:acff:fe11:2") {
		t.Fatalf("expire returned %v, want the one address whose 100 seconds ran out", gone)
	}
	if len(tab.entries) != 2 {
		t.Fatalf("the table holds %d entries, want 2", len(tab.entries))
	}
	if got := tab.counts.Expired; got != 1 {
		t.Errorf("the expiry counter is %d, want 1", got)
	}
	if gone := tab.expire(at(1000)); len(gone) != 2 || len(tab.entries) != 0 {
		t.Fatalf("the remaining two did not expire: %v, %d left", gone, len(tab.entries))
	}
}

// heldFor is a table holding one address for the given lifetimes, formed at
// instant zero.
func heldFor(t *testing.T, valid, preferred uint32) *slaacTable {
	t.Helper()
	tab := &slaacTable{}
	formed, _, why := tab.applyPIO(at(0), wire.PrefixInfo{
		PrefixLen: 64, Autonomous: true, Prefix: netip.MustParseAddr("2001:db8:1::"),
		ValidLifetime: valid, PreferredLifetime: preferred,
	}, testLinkAddr6)
	if !formed || why != SLAACIgnoreNone {
		t.Fatalf("the fixture formed nothing: formed=%v why=%q", formed, why)
	}
	return tab
}

// farFuture is an instant beyond any lifetime a router can advertise and
// INSIDE the int64 nanosecond count Instant is. L1 lost a day to an at(1<<40)
// that overflowed the same arithmetic and made an expiry test pass by
// wrapping.
var farFuture = at(4_000_000_000)

// TestLease6EqualComparesEveryFieldItConfigures is defeat row R-49.
//
// Equal is what tells ActLeaseRenewed from ActLeaseChanged, so a field it
// ignores is a reconfiguration the caller never hears about. SLAAC is one of
// those fields: two leases can name the same address with the same lifetimes
// and still differ in where the address came from, which is the difference
// between a lease with a renewal schedule and one with none (Deadlines reads
// the same field).
func TestLease6EqualComparesEveryFieldItConfigures(t *testing.T) {
	base := Lease6{
		IAID: 7,
		Addrs: []Addr6{{
			Addr:      netip.MustParseAddr("2001:db8:1::5"),
			Preferred: 100 * Second,
			Valid:     200 * Second,
		}},
		ServerDUID: []byte{1, 2, 3},
		T1:         50 * Second,
		T2:         80 * Second,
		DNS:        []netip.Addr{netip.MustParseAddr("2001:db8:1::1")},
		Search:     []string{"example.test"},
		Start:      at(1),
	}
	renewed := base
	renewed.Start = at(4000)
	if !base.Equal(renewed) {
		t.Fatal("a renewal of the same addresses reads as a changed lease")
	}

	for _, tc := range []struct {
		name string
		mut  func(*Lease6)
	}{
		{"iaid", func(l *Lease6) { l.IAID = 8 }},
		{"address", func(l *Lease6) { l.Addrs = []Addr6{{Addr: netip.MustParseAddr("2001:db8:1::6")}} }},
		{"address count", func(l *Lease6) { l.Addrs = nil }},
		{"server duid", func(l *Lease6) { l.ServerDUID = []byte{9} }},
		{"t1", func(l *Lease6) { l.T1 = 51 * Second }},
		{"t2", func(l *Lease6) { l.T2 = 81 * Second }},
		{"dns", func(l *Lease6) { l.DNS = []netip.Addr{netip.MustParseAddr("2001:db8:1::2")} }},
		{"search", func(l *Lease6) { l.Search = []string{"other.test"} }},
		{"origin", func(l *Lease6) { l.SLAAC = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := base
			tc.mut(&other)
			if base.Equal(other) {
				t.Fatalf("a changed %s reads as the same lease", tc.name)
			}
		})
	}
}
