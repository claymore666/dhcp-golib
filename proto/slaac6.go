// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/claymore666/dhcp-golib/wire"
)

// Stateless address autoconfiguration, RFC 4862 §5.5.3 and §5.5.4: what this
// client forms from a Prefix Information option, and what later
// advertisements do to what it formed.
//
// IT IS A SECOND ADDRESS SOURCE BESIDE THE IA_NA AND NOT A SECOND MACHINE.
// §5.5.3 is written per Prefix Information option — "For each
// Prefix-Information option in the Router Advertisement:" — and a client on a
// link with two autonomous prefixes ends with two addresses, each with its own
// pair of lifetimes and its own expiry. So the table below is keyed on the
// PREFIX, every rule is applied per entry, and the lease the machine reports
// is the whole set. One entry per prefix is the decision recorded against
// question Q2 of the v2.2 IPv6 design; the first-wins alternative would have
// left a container on a ULA-plus-GUA link holding whichever of the two its
// router happened to list first.
//
// NOTHING HERE READS A CLOCK. Every function takes the Instant its caller was
// handed, which is ring 1's rule and is what makes the two-hour rule testable:
// its whole content is a comparison against a remaining lifetime, and a
// remaining lifetime computed from a clock of its own could not be driven to a
// boundary.

// Mode6 is what the caller wants this endpoint to get its IPv6 address from.
//
// THE ZERO VALUE IS DHCPv6, which is what this library did before this field
// existed. A zero value meaning "off" would turn DHCPv6 off for every caller
// that had not been updated, and no test naming any of the new symbols below
// could see it happen: the machine would simply stop soliciting.
type Mode6 uint8

// The four modes. They are the chassis's four option values, so that the
// option a user writes and the value the machine switches on are one
// enumeration rather than two that must be kept in agreement.
const (
	// Mode6DHCP is RFC 9915 alone: Solicit, Request, Renew. A Router
	// Advertisement is observed for its flags and its router, and its Prefix
	// Information options form nothing.
	Mode6DHCP Mode6 = iota

	// Mode6SLAAC is RFC 4862 alone: no Solicit is ever sent, whatever the M
	// flag says. An Information-request still goes out when the router sets
	// M or O, because that exchange carries no address — RFC 9915 §18.2.6 —
	// and it is the only way a SLAAC-only client gets a resolver from DHCPv6.
	Mode6SLAAC

	// Mode6Auto lets the router decide, once, on the FIRST advertisement it
	// sends: M=1 is DHCPv6 (RFC 4861 §4.2, "addresses are available via
	// Dynamic Host Configuration Protocol"), M=0 is stateless address
	// autoconfiguration. The decision is not revisited, because a machine
	// that re-decided on every advertisement would abandon a held address
	// when a router changed a flag.
	Mode6Auto

	// Mode6Off is the chassis's fourth option value, and New6 REFUSES it.
	//
	// It is declared so the chassis has one name for the value rather than a
	// private constant of its own, and it is refused rather than implemented
	// because a machine in this mode would have to be proved inert against
	// every event that can reach it. Not building one is the stronger
	// statement and it is the one a compiler can hold.
	Mode6Off
)

func (m Mode6) String() string {
	switch m {
	case Mode6DHCP:
		return "dhcp"
	case Mode6SLAAC:
		return "slaac"
	case Mode6Auto:
		return "auto"
	case Mode6Off:
		return "off"
	default:
		return fmt.Sprintf("mode6(%d)", uint8(m))
	}
}

// AllModes6 is every declared Mode6, so a test enumerating them reads one
// place. Mode6Off is in it: it is declared, and the test that drives New6's
// answer for each mode needs the value that is refused as much as the three
// that are not.
func AllModes6() []Mode6 { return []Mode6{Mode6DHCP, Mode6SLAAC, Mode6Auto, Mode6Off} }

// formsAddresses reports whether this mode can form an address from a Prefix
// Information option. Mode6Auto's answer depends on what the router said and
// is the machine's, not this function's.
func (m Mode6) formsAddresses() bool { return m == Mode6SLAAC || m == Mode6Auto }

// The errors New6 answers a Params6 whose mode it will not run.
var (
	// ErrMode6Off is Params6.Mode set to Mode6Off. See Mode6Off.
	ErrMode6Off = errors.New("proto: Params6.Mode is off: a machine in that mode has nothing to do, so none is built")
	// ErrBadMode6 is a Params6.Mode outside the declared set. Refused rather
	// than defaulted: a mode that fell through a switch would turn an
	// option typo into a client that silently does something else.
	ErrBadMode6 = errors.New("proto: Params6.Mode is not a declared mode")
	// ErrNoLinkAddr is a Params6 in a mode that forms addresses with no
	// usable Params6.LinkAddr. An interface identifier is formed FROM the
	// link address, so an absent one would form the same address on every
	// node of the link.
	ErrNoLinkAddr = errors.New("proto: Params6.LinkAddr is required when Params6.Mode forms addresses")
)

// TwoHours is RFC 4862 §5.5.3 e's constant, the one the whole rule is about:
// "If the received Valid Lifetime is greater than 2 hours or greater than
// RemainingLifetime, set the valid lifetime of the corresponding address to
// the advertised Valid Lifetime."
const TwoHours = 7200 * Second

// MaxSLAACAddresses is how many prefixes this client will hold addresses for.
//
// AT THE CAP THE NEW PREFIX IS REFUSED and the held ones keep their places,
// which is the rule the router table states for its own lists and is the same
// rule for the same reason: what a client heard first on a flooded link is at
// least a prefix that was advertised, and evicting the oldest would hand the
// link to whoever advertises most. The price is the one the router table pays
// too — a renumbering that adds a ninth prefix is refused until one of the
// eight reaches its own valid lifetime.
const MaxSLAACAddresses = 8

// IIDBits is the length in bits of the interface identifier this client
// forms. RFC 4862 §5.5.3 d makes the length the thing the prefix is checked
// against — "If the sum of the prefix length and interface identifier length
// does not equal 128 bits, the Prefix Information option MUST be ignored" —
// and the same section says an implementation "should not assume a particular
// constant. Rather, it should expect any lengths of interface identifiers".
//
// BOUND, STATED: this client forms exactly one kind of identifier, RFC 4291
// Appendix A's modified EUI-64, which is 64 bits from either an EUI-48 or an
// EUI-64 link address. So the constant is 64 here and the rule is nonetheless
// written as the SUM, because the two are the same number today and different
// questions, and the sum is the one §5.5.3 asks.
const IIDBits = 64

// lengthsSumTo128 is RFC 4862 §5.5.3 d's condition, quoted: "If the sum of the
// prefix length and interface identifier length does not equal 128 bits, the
// Prefix Information option MUST be ignored."
//
// IT TAKES THE IDENTIFIER LENGTH AS AN ARGUMENT so that the rule can be driven
// at lengths this library does not use. MEASURED by this change's own mutant
// campaign: written inline against IIDBits, the mutant `pi.PrefixLen != 64`
// SURVIVED, and it survived because it is a NO-OP — the two expressions agree
// for every input while the constant is 64. A test cannot separate them. What
// a test CAN separate is the rule from a rule about the number 64, and that is
// what this function makes reachable.
func lengthsSumTo128(prefixLen, iidBits int) bool { return prefixLen+iidBits == 128 }

// SLAACIgnore is why a Prefix Information option formed nothing.
//
// IT IS AN ENUMERATION AND NOT A COUNT, because the reasons need different
// things from an operator: a link with no autonomous prefix is a router to
// configure, a prefix of the wrong length is a prefix to fix, and a client at
// its cap is a client to look at. One number holding all of them answers none
// of the three.
type SLAACIgnore uint8

// The reasons, each the rule of RFC 4862 §5.5.3 that refused the option.
const (
	// SLAACIgnoreNone is not a reason; it is the zero value, meaning the
	// option was used.
	SLAACIgnoreNone SLAACIgnore = iota
	// SLAACIgnoreNotAutonomous is rule a: "If the Autonomous flag is not set,
	// silently ignore the Prefix Information option."
	SLAACIgnoreNotAutonomous
	// SLAACIgnoreLinkLocal is rule b: "If the prefix is the link-local
	// prefix, silently ignore the Prefix Information option."
	SLAACIgnoreLinkLocal
	// SLAACIgnorePreferredOverValid is rule c: "If the preferred lifetime is
	// greater than the valid lifetime, silently ignore the Prefix Information
	// option."
	SLAACIgnorePreferredOverValid
	// SLAACIgnoreBadLength is rule d's 128-bit condition.
	SLAACIgnoreBadLength
	// SLAACIgnoreValidZero is rule d's other condition: "and if the Valid
	// Lifetime is not 0, form an address". A prefix this client does not hold,
	// advertised with a valid lifetime of zero, forms nothing. It is NOT a
	// withdrawal: §5.5.3 e's rules are what withdraw a HELD address, and they
	// do not let a single advertisement do it (see applyPIO).
	SLAACIgnoreValidZero
	// SLAACIgnoreCapReached is MaxSLAACAddresses.
	SLAACIgnoreCapReached
	// SLAACIgnoreLinkAddr is a link address no interface identifier can be
	// formed from. Unreachable through New6, which refuses such a Params6,
	// and handled anyway for Machine6.Step's reason.
	SLAACIgnoreLinkAddr
	// SLAACIgnoreModeDHCP is the one reason that is not a rule of RFC 4862
	// §5.5.3: the option was eligible and this client's address comes from
	// DHCPv6, so nothing was formed from it. It is counted rather than passed
	// over because a link whose router advertises an autonomous prefix to a
	// client configured for DHCPv6 is a configuration worth being able to see
	// from outside.
	SLAACIgnoreModeDHCP
	// SLAACIgnoreDuplicate is an address this client already formed once and
	// duplicate address detection found in use (RFC 4862 §5.4.5). The address
	// a prefix forms is a function of that prefix and this link's hardware
	// address, so forming it again produces the same address and the same
	// answer. A router repeats its advertisement every few seconds (RFC 4861
	// §6.2.1), so without this the refusal is charged once per advertisement
	// for as long as the other node holds the address.
	SLAACIgnoreDuplicate

	// numSLAACIgnore is one past the last reason, which is what sizes
	// SLAACCounters.Ignored. It is written here, immediately after the block,
	// so that a reason added below it does not compile.
	numSLAACIgnore
)

func (r SLAACIgnore) String() string {
	switch r {
	case SLAACIgnoreNone:
		return "used"
	case SLAACIgnoreNotAutonomous:
		return "the Autonomous flag is not set (RFC 4862 §5.5.3 a)"
	case SLAACIgnoreLinkLocal:
		return "the prefix is the link-local prefix (RFC 4862 §5.5.3 b)"
	case SLAACIgnorePreferredOverValid:
		return "the preferred lifetime is greater than the valid lifetime (RFC 4862 §5.5.3 c)"
	case SLAACIgnoreBadLength:
		return "the prefix length and the interface identifier length do not sum to 128 bits (RFC 4862 §5.5.3 d)"
	case SLAACIgnoreValidZero:
		return "the prefix is not held and its valid lifetime is 0 (RFC 4862 §5.5.3 d)"
	case SLAACIgnoreCapReached:
		return "this client already holds the addresses it will hold (RFC 4862 §5.5.3 d, this client's cap)"
	case SLAACIgnoreLinkAddr:
		return "no interface identifier can be formed from this link address (RFC 4291 Appendix A)"
	case SLAACIgnoreModeDHCP:
		return "this client's address comes from DHCPv6"
	case SLAACIgnoreDuplicate:
		return "the address this prefix forms is in use on the link (RFC 4862 §5.4.5)"
	default:
		return fmt.Sprintf("slaac-ignore(%d)", uint8(r))
	}
}

// AllSLAACIgnores is every reason a Prefix Information option was not used, so
// the counters and the tests enumerate the domain from one place.
func AllSLAACIgnores() []SLAACIgnore {
	return []SLAACIgnore{
		SLAACIgnoreNotAutonomous, SLAACIgnoreLinkLocal,
		SLAACIgnorePreferredOverValid, SLAACIgnoreBadLength,
		SLAACIgnoreValidZero, SLAACIgnoreCapReached, SLAACIgnoreLinkAddr,
		SLAACIgnoreModeDHCP, SLAACIgnoreDuplicate,
	}
}

// SLAACCounters is what the machine did with the Prefix Information options it
// was given. Ring 2 mirrors it at every Step, the way it mirrors the router
// table's drops.
//
// Formed counts ADDRESSES, Ignored counts OPTIONS, and Conflicts counts
// addresses another node answered for. Their sum is not the number of options
// seen: an option that refreshed a held address is none of the three.
type SLAACCounters struct {
	Formed     uint64
	Refreshed  uint64
	Deprecated uint64
	Expired    uint64
	Conflicts  uint64
	Fallbacks  uint64

	// Ignored is indexed BY SLAACIgnore, so a reason added to the enumeration
	// widens this array rather than needing a line here. numSLAACIgnore is
	// what makes that true and
	// TestEveryIgnoreReasonIsDeclaredCountedAndNamed is what holds the two to
	// each other.
	Ignored [numSLAACIgnore]uint64
}

// IgnoredTotal is every option refused by any rule.
func (c SLAACCounters) IgnoredTotal() uint64 {
	var n uint64
	for _, r := range AllSLAACIgnores() {
		n += c.Ignored[r]
	}
	return n
}

// SLAACAddress is RFC 4862 §5.5.3 d's formation, "combining the advertised
// prefix with an interface identifier of the link", with RFC 4291 Appendix A's
// modified EUI-64 as the identifier.
//
// IT IS EXPORTED BECAUSE THE PROOF IS OUTSIDE THIS PACKAGE. The runtime test
// that watches a real router advertise a prefix and a real kernel answer a
// Neighbor Solicitation has to name the address it expects, and deriving it a
// second time in the test would be one fact derived twice, with the looser
// derivation deciding.
//
// IT IS NOT wire.LinkLocalFromMAC, which says of itself that it is for
// fixtures and tests only and that the product never forms an address. This is
// the product's, it takes a prefix rather than assuming fe80::/64, and it
// refuses what that helper does not: a prefix whose length plus IIDBits is not
// 128, and a link address of a length Appendix A does not cover.
func SLAACAddress(prefix netip.Addr, prefixLen uint8, hw []byte) (netip.Addr, error) {
	if !prefix.Is6() || prefix.Is4In6() {
		return netip.Addr{}, fmt.Errorf("proto: %s is not an IPv6 prefix", prefix)
	}
	if !lengthsSumTo128(int(prefixLen), IIDBits) {
		return netip.Addr{}, fmt.Errorf("proto: prefix length %d plus interface identifier length %d is not 128 (RFC 4862 §5.5.3 d)", prefixLen, IIDBits)
	}
	iid, err := ModifiedEUI64(hw)
	if err != nil {
		return netip.Addr{}, err
	}
	out := prefix.As16()
	// THE HOST BITS OF THE ADVERTISED PREFIX DO NOT SURVIVE. §5.5.3 d's
	// diagram is "link prefix" in the high 128-N bits and "interface
	// identifier" in the low N, so every bit the identifier covers comes from
	// the identifier — a router that advertises 2001:db8::dead:beef/64 has
	// advertised 2001:db8::/64 with rubbish in the part it does not own.
	for i := 0; i < 8; i++ {
		out[8+i] = iid[i]
	}
	return netip.AddrFrom16(out), nil
}

// ModifiedEUI64 is RFC 4291 Appendix A's identifier, from an EUI-48 (six
// octets, the ordinary Ethernet address) or an EUI-64 (eight).
//
// From the EUI-48: "insert two octets, with hexadecimal values of 0xFF and
// 0xFE, in the middle of the 48-bit MAC (between the company_id and vendor
// supplied id)". From either: "the IPv6 interface identifier is formed by
// inverting the 'u' bit (universal/local bit in IEEE EUI-64 terminology)".
// Appendix A's own worked example is the one the tests pin.
func ModifiedEUI64(hw []byte) ([8]byte, error) {
	var iid [8]byte
	switch len(hw) {
	case 6:
		iid[0], iid[1], iid[2] = hw[0], hw[1], hw[2]
		iid[3], iid[4] = 0xff, 0xfe
		iid[5], iid[6], iid[7] = hw[3], hw[4], hw[5]
	case 8:
		copy(iid[:], hw)
	default:
		return iid, fmt.Errorf("proto: a link address of %d octets is neither an EUI-48 nor an EUI-64 (RFC 4291 Appendix A)", len(hw))
	}
	// THE INVERSION IS UNCONDITIONAL, in both directions. Appendix A says
	// "inverting the 'u' bit", not "setting" it: a locally administered
	// address, whose u bit is 0, produces an identifier whose u bit is 1, and
	// the Ethernet addresses a container runtime invents are exactly that
	// kind. A test using one polarity only cannot tell an inversion from a
	// set, and cannot see a doubled one either.
	iid[0] ^= 0x02
	return iid, nil
}

// linkLocalPrefix is RFC 4291 §2.5.6's fe80::/10, which is the prefix RFC 4862
// §5.5.3 b names: "If the prefix is the link-local prefix, silently ignore the
// Prefix Information option."
var linkLocalPrefix = netip.MustParsePrefix("fe80::/10")

// slaacEntry is one prefix this client holds an address for.
//
// THE TWO LIFETIMES ARE DURATIONS FROM start AND NOT INSTANTS, which is the
// shape Addr6 already has and is what makes the per-prefix clock right: each
// entry's start moves when THAT entry's lifetimes are reset, so two prefixes
// refreshed an hour apart have two origins and RemainingLifetime is each one's
// own. A single origin on the lease would have made the second prefix's
// remaining lifetime a function of the first prefix's last advertisement.
type slaacEntry struct {
	prefix netip.Prefix
	addr   netip.Addr

	start     Instant
	preferred Duration
	valid     Duration

	// deprecationCharged says RFC 4862 §5.5.4's change of phase has already
	// been counted and journalled for THIS address.
	//
	// IT IS NOT slaacPhases. That record is what the CALLER was last told, and
	// it is read by enterBoundSLAAC to tell a renewal from a change; writing it
	// on a path that announced nothing would make the next announcement look
	// like a renewal and swallow the change. This one is what the MACHINE has
	// already charged, it belongs to the entry, it goes when the entry goes,
	// and refresh clears it because §5.5.3 e's closing note resets the
	// preferred lifetime, which makes the address preferred again.
	deprecationCharged bool

	// tentative is set while duplicate address detection has not answered for
	// this address. A router repeats its advertisement every few seconds
	// (RFC 4861 §6.2.1), and without this the repeat would start a second
	// check for an address already being checked.
	tentative bool
}

// remaining is RFC 4862 §5.5.3 e's "RemainingLifetime", "the remaining time to
// the valid lifetime expiration of the previously autoconfigured address".
func (e slaacEntry) remaining(now Instant) Duration {
	if e.valid.IsInfinite() {
		return Infinite
	}
	d := e.start.Add(e.valid).Sub(now)
	if d < 0 {
		return 0
	}
	return d
}

// remainingPreferred is the same for the preferred lifetime, and zero means
// §5.5.4's "A preferred address becomes deprecated when its preferred lifetime
// expires."
func (e slaacEntry) remainingPreferred(now Instant) Duration {
	if e.preferred.IsInfinite() {
		return Infinite
	}
	d := e.start.Add(e.preferred).Sub(now)
	if d < 0 {
		return 0
	}
	return d
}

func (e slaacEntry) deprecated(now Instant) bool {
	return !e.preferred.IsInfinite() && e.start.Add(e.preferred) <= now
}

func (e slaacEntry) expired(now Instant) bool {
	return !e.valid.IsInfinite() && e.start.Add(e.valid) <= now
}

// durGreater is ">" over Durations in which Infinite is larger than every
// finite value.
//
// IT IS A FUNCTION AND NOT AN OPERATOR BECAUSE Infinite IS -1. The sentinel is
// a specific comparable value rather than a large one (see Infinite), so every
// comparison in RFC 4862 §5.5.3's rules has to say what it means by it, and a
// raw `a > b` gets the infinite cases exactly backwards.
func durGreater(a, b Duration) bool {
	switch {
	case a.IsInfinite() && b.IsInfinite():
		return false
	case a.IsInfinite():
		return true
	case b.IsInfinite():
		return false
	default:
		return a > b
	}
}

// slaacTable is the list §5.5.3 calls "the list of addresses associated with
// the interface", holding only the ones this client configured by stateless
// autoconfiguration. A DHCPv6 address is not in it and is never touched by
// these rules: §5.5.3 e is scoped to "an address configured by stateless
// autoconfiguration in the list".
type slaacTable struct {
	entries []slaacEntry
	counts  SLAACCounters

	// refused is every address duplicate address detection found in use, kept
	// for the life of the machine. §5.4.5 ends the address and this library
	// has no second identifier to try (RFC 4941's temporary addresses are not
	// implemented), so the same prefix would form the same address again on
	// the router's next advertisement, and the check would answer the same
	// way. It is cleared by a stop, with the rest of the table.
	refused map[netip.Addr]bool
}

// refuse records an address as in use on the link, so no later advertisement
// of the prefix that formed it forms it again.
func (t *slaacTable) refuse(a netip.Addr) {
	if t.refused == nil {
		t.refused = map[netip.Addr]bool{}
	}
	t.refused[a] = true
}

// find is §5.5.3 d's equality test, quoted in full because the whole of
// renumbering turns on it: "where "equal" means the two prefix lengths are the
// same and the first prefix-length bits of the prefixes are identical". So the
// comparison is masked and length-aware, and a router that advertises host
// bits inside the prefix updates the entry it meant rather than forming a
// second address.
func (t *slaacTable) find(p netip.Prefix) int {
	p = p.Masked()
	for i := range t.entries {
		if t.entries[i].prefix == p {
			return i
		}
	}
	return -1
}

// applyPIO runs RFC 4862 §5.5.3 over one Prefix Information option and reports
// which rule decided, whether an address was formed, and whether anything the
// caller reports changed.
//
// THE RULES ARE IN THE SECTION'S OWN ORDER, and that is load-bearing twice
// over. a, b and c come before d and e, so an option refused by c never
// reaches e's "always reset the preferred lifetime" — a held address is not
// touched by an advertisement the section says to ignore. And inside e, rule 1
// is tried FIRST and its two arms are a disjunction: a tree that asked "is
// RemainingLifetime <= 2 hours" before rule 1 would refuse a router's
// legitimate extension of a nearly-expired prefix, which is the common case
// after a renumbering.
func (t *slaacTable) applyPIO(now Instant, pi wire.PrefixInfo, hw []byte) (formed bool, changed bool, why SLAACIgnore) {
	if !pi.Autonomous {
		return false, false, SLAACIgnoreNotAutonomous
	}
	if !pi.Prefix.Is6() || pi.Prefix.Is4In6() {
		// Not an IPv6 prefix at all, so no length of identifier can make the
		// sum 128. Unreachable through wire.DecodeRouterAdvert, which reads
		// sixteen octets, and given its own arm rather than folded into the
		// link-local one, which would name the wrong rule.
		return false, false, SLAACIgnoreBadLength
	}
	if linkLocalPrefix.Contains(pi.Prefix) {
		return false, false, SLAACIgnoreLinkLocal
	}
	preferred := SecondsToDuration(pi.PreferredLifetime)
	valid := SecondsToDuration(pi.ValidLifetime)
	if durGreater(preferred, valid) {
		return false, false, SLAACIgnorePreferredOverValid
	}

	p := netip.PrefixFrom(pi.Prefix, int(pi.PrefixLen))
	if !p.IsValid() {
		return false, false, SLAACIgnoreBadLength
	}
	if i := t.find(p); i >= 0 {
		return false, t.refresh(now, i, preferred, valid), SLAACIgnoreNone
	}

	if !lengthsSumTo128(int(pi.PrefixLen), IIDBits) {
		return false, false, SLAACIgnoreBadLength
	}
	// §5.5.3 d: "and if the Valid Lifetime is not 0, form an address". A
	// prefix this client does not hold and whose valid lifetime is zero is a
	// prefix that would be invalid the instant it was formed.
	if valid == 0 {
		return false, false, SLAACIgnoreValidZero
	}
	if len(t.entries) >= MaxSLAACAddresses {
		return false, false, SLAACIgnoreCapReached
	}
	addr, err := SLAACAddress(pi.Prefix, pi.PrefixLen, hw)
	if err != nil {
		return false, false, SLAACIgnoreLinkAddr
	}
	if t.refused[addr] {
		return false, false, SLAACIgnoreDuplicate
	}
	t.entries = append(t.entries, slaacEntry{
		prefix:    p.Masked(),
		addr:      addr,
		start:     now,
		preferred: preferred,
		valid:     valid,
		tentative: true,
	})
	t.counts.Formed++
	return true, true, SLAACIgnoreNone
}

// refresh is §5.5.3 e for an entry this client already holds, and it reports
// whether anything a caller can see moved.
func (t *slaacTable) refresh(now Instant, i int, preferred, valid Duration) bool {
	e := &t.entries[i]
	before := *e
	remaining := e.remaining(now)

	// "Note that the preferred lifetime of the corresponding address is always
	// reset to the Preferred Lifetime in the received Prefix Information
	// option, regardless of whether the valid lifetime is also reset or
	// ignored." It is written before the three rules for that reason: none of
	// their branches may skip it.
	e.preferred = preferred

	switch {
	case durGreater(valid, TwoHours) || durGreater(valid, remaining):
		// e 1: "set the valid lifetime of the corresponding address to the
		// advertised Valid Lifetime."
		e.valid = valid
	case !durGreater(remaining, TwoHours):
		// e 2: "If RemainingLifetime is less than or equal to 2 hours, ignore
		// the Prefix Information option with regards to the valid lifetime".
		// The deadline is unchanged, which with a moving origin means the
		// lifetime is what is left of it.
		//
		// §5.5.3 e 2's other arm — "unless the Router Advertisement from which
		// this option was obtained has been authenticated (e.g., via Secure
		// Neighbor Discovery [RFC3971])" — is UNREACHABLE HERE and is stated
		// rather than implemented: this library has no RFC 3971, so no
		// advertisement it ever sees is authenticated.
		e.valid = remaining
	default:
		// e 3: "Otherwise, reset the valid lifetime of the corresponding
		// address to 2 hours."
		e.valid = TwoHours
	}
	e.start = now
	// A reset preferred lifetime makes the address preferred again, so the
	// next time it runs out is a new change of phase and is charged again.
	//
	// THE QUESTION IS ASKED AGAINST THE NEW ORIGIN, and that is the whole of
	// it: §5.5.3 e's note resets the lifetime, and the origin moves with it,
	// so asking before `e.start = now` answers for the lifetime that just
	// ended. Every repeat that arrives later than the old preferred lifetime
	// reads "still deprecated" there and leaves the charge standing, which
	// costs the SECOND deprecation its counter and its journal line.
	if !e.deprecated(now) {
		e.deprecationCharged = false
	}
	t.counts.Refreshed++

	// WHAT COUNTS AS A CHANGE IS THE DEADLINE AND THE PHASE, not the stored
	// numbers: the origin moves on every refresh, so two Durations that differ
	// can name the same instant and a comparison of the fields alone would
	// report a change on every advertisement a router repeats.
	return before.start.Add(before.preferred) != e.start.Add(e.preferred) ||
		before.start.Add(before.valid) != e.start.Add(e.valid) ||
		before.preferred.IsInfinite() != e.preferred.IsInfinite() ||
		before.valid.IsInfinite() != e.valid.IsInfinite()
}

// next is the earliest instant at which §5.5.4 has something to say about any
// held address: a preferred lifetime that has not yet run out, or a valid one.
//
// AN INFINITE LIFETIME CONTRIBUTES NO INSTANT AT ALL rather than a distant
// one. Instant is a monotonic nanosecond count in an int64 and Infinite is a
// sentinel, not a number; adding it to an origin produces an instant one
// nanosecond BEFORE that origin.
//
// THE CHECK IS IN consider AND NOWHERE ELSE, which is one derivation instead
// of two. MEASURED by this change's own mutant campaign: with the check
// written at the two call sites, removing both of them SURVIVED — the
// sentinel's instant lands in the past and the "at or before now" filter
// below drops it anyway. Two guards for one fact, and the outer one could be
// deleted with nothing going red. Here there is one site, so the mutant that
// deletes it has nowhere to be written and the filter's own test covers it.
func (t *slaacTable) next(now Instant) (Instant, bool) {
	var best Instant
	have := false
	consider := func(origin Instant, d Duration) {
		if d.IsInfinite() {
			return
		}
		ts := origin.Add(d)
		if ts <= now {
			return
		}
		if !have || ts < best {
			best, have = ts, true
		}
	}
	for _, e := range t.entries {
		consider(e.start, e.preferred)
		consider(e.start, e.valid)
	}
	return best, have
}

// expire drops every address whose valid lifetime has run out, §5.5.4: "An
// address (and its association with an interface) becomes invalid when its
// valid lifetime expires.  An invalid address MUST NOT be used as a source
// address in outgoing communications".
func (t *slaacTable) expire(now Instant) []netip.Addr {
	var gone []netip.Addr
	kept := t.entries[:0]
	for _, e := range t.entries {
		if e.expired(now) {
			gone = append(gone, e.addr)
			t.counts.Expired++
			continue
		}
		kept = append(kept, e)
	}
	t.entries = kept
	return gone
}

// drop removes one address, which is what a duplicate found by RFC 4862 §5.4
// leaves this client with: the identifier is the link's own hardware address,
// so §5.5.3 offers no second candidate to try.
func (t *slaacTable) drop(a netip.Addr) bool {
	for i := range t.entries {
		if t.entries[i].addr == a {
			t.entries = append(t.entries[:i], t.entries[i+1:]...)
			return true
		}
	}
	return false
}

// settle marks an address no longer tentative.
func (t *slaacTable) settle(a netip.Addr) {
	for i := range t.entries {
		if t.entries[i].addr == a {
			t.entries[i].tentative = false
			return
		}
	}
}

// tentativeAddrs is every address whose duplicate address detection has not
// answered, in the order the prefixes were first heard.
func (t *slaacTable) tentativeAddrs() []netip.Addr {
	var out []netip.Addr
	for _, e := range t.entries {
		if e.tentative {
			out = append(out, e.addr)
		}
	}
	return out
}

// lease is the whole held set as a Lease6, with every lifetime expressed from
// the instant the lease is stamped.
//
// ORDER IS WIRE ORDER AND STAYS WIRE ORDER: the entries are appended as their
// prefixes are first heard and are never sorted, so index 0 is the first
// autonomous prefix the first advertisement carried. A chassis that must name
// one address of several as the endpoint's main one reads that index, and a
// map iteration here would have made it a different address per process.
func (t *slaacTable) lease(now Instant, iaid uint32) Lease6 {
	l := Lease6{IAID: iaid, Start: now, SLAAC: true}
	for _, e := range t.entries {
		l.Addrs = append(l.Addrs, Addr6{
			Addr:      e.addr,
			Preferred: e.remainingPreferred(now),
			Valid:     e.remaining(now),
			PrefixLen: e.prefix.Bits(),
		})
	}
	return l
}

// phases is which held addresses are deprecated, keyed on the address, so a
// caller can tell a lifetime refresh from RFC 4862 §5.5.4's change of phase
// without diffing two sets of durations.
func (t *slaacTable) phases(now Instant) map[netip.Addr]bool {
	out := make(map[netip.Addr]bool, len(t.entries))
	for _, e := range t.entries {
		out[e.addr] = e.deprecated(now)
	}
	return out
}

// phasesDiffer reports whether the set of addresses or any address's phase
// changed between two snapshots.
func phasesDiffer(a, b map[netip.Addr]bool) bool {
	if len(a) != len(b) {
		return true
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || v != w {
			return true
		}
	}
	return false
}
