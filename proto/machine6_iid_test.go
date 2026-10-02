// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// stableAddr is the address the machine must form on prefix at counter: the
// prefix's upper 64 bits, then the vector-checked StablePrivacyIID
// (dhcp-golib#54).
func stableAddr(prefix string, counter uint8) netip.Addr {
	p := netip.MustParsePrefix(prefix)
	iid := StablePrivacyIID(p, testIIDNetIface, testIIDNetworkID, counter, testIIDSecret)
	b := p.Masked().Addr().As16()
	copy(b[8:], iid[:])
	return netip.AddrFrom16(b)
}

// stableStart is a stable-privacy machine that has seen one advertisement of
// prefixes, with every action and journal line it produced so far
// (dhcp-golib#54).
func stableStart(t *testing.T, p Params6, at0 int64, prefixes ...[]byte) (*Machine6, []Action) {
	t.Helper()
	m := newMachine6(t, p)
	_, a1 := m.Step(at(at0), 0, Simple(EvStart))
	_, a2 := m.Step(at(at0+1), 0, raEvent6(t, ra6(false, false, prefixes...)))
	return m, append(a1, a2...)
}

func dadTargets(acts []Action) []netip.Addr {
	var out []netip.Addr
	for _, a := range acts {
		if a.Kind == ActStartDAD {
			out = append(out, a.Target)
		}
	}
	return out
}

func TestAStablePrivacyAddressIsTheHashAndNotTheLinkAddress(t *testing.T) {
	_, acts := stableStart(t, testParams6Stable(), 0, pio(testSLAACPrefix, 64, true, 86400, 14400))
	want := netip.MustParseAddr("2001:db8:1::9c3:7179:74cd:959e")
	if want != stableAddr("2001:db8:1::/64", 0) {
		t.Fatalf("the test's own address %s disagrees with the vector", stableAddr("2001:db8:1::/64", 0))
	}
	got := dadTargets(acts)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("duplicate address detection runs on %v, want [%s].%s", got, want, journalLines(acts))
	}
	if got[0] == netip.MustParseAddr(testSLAACAddr) {
		t.Fatal("stable-privacy mode formed the modified EUI-64 address")
	}
}

func TestOnePrefixFormsOneStableAddressAndTwoPrefixesTwo(t *testing.T) {
	// The same /64 with host bits left in the advertised prefix field: RFC
	// 4862 §5.5.3 forms from the prefix length's bits only
	// (dhcp-golib#54).
	_, a := stableStart(t, testParams6Stable(), 0, pio("2001:db8:1::", 64, true, 86400, 14400))
	_, b := stableStart(t, testParams6Stable(), 0, pio("2001:db8:1::ffff", 64, true, 86400, 14400))
	if ta, tb := dadTargets(a), dadTargets(b); len(ta) != 1 || len(tb) != 1 || ta[0] != tb[0] {
		t.Fatalf("one /64 advertised two ways formed %v and %v", ta, tb)
	}
	_, two := stableStart(t, testParams6Stable(), 0,
		pio("2001:db8:1::", 64, true, 86400, 14400),
		pio("2001:db8:2::", 64, true, 86400, 14400))
	got := dadTargets(two)
	want := []netip.Addr{stableAddr("2001:db8:1::/64", 0), stableAddr("2001:db8:2::/64", 0)}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("two prefixes formed %v, want %v", got, want)
	}
	if x, y := got[0].As16(), got[1].As16(); [8]byte(x[8:]) == [8]byte(y[8:]) {
		t.Errorf("two prefixes share an interface identifier: %v", got)
	}
}

func TestADuplicateStableAddressIsRetriedAtTheNextCounter(t *testing.T) {
	m, _ := stableStart(t, testParams6Stable(), 0, pio(testSLAACPrefix, 64, true, 86400, 14400))
	c0, c1 := stableAddr("2001:db8:1::/64", 0), stableAddr("2001:db8:1::/64", 1)
	s, acts := m.Step(at(2), 0, DADResult(c0, true))
	if s != State6DAD {
		t.Fatalf("a duplicate with retries left put the machine in %s, want %s.%s", s, State6DAD, journalLines(acts))
	}
	if got := dadTargets(acts); len(got) != 1 || got[0] != c1 {
		t.Fatalf("after the duplicate, duplicate address detection runs on %v, want [%s].%s", got, c1, journalLines(acts))
	}
	for _, k := range []ActionKind{ActFailed, ActLeaseAcquired, ActLeaseChanged} {
		if _, ok := find(acts, k); ok {
			t.Errorf("%s reached the caller before the retried address was checked", k)
		}
	}
	if !strings.Contains(journalLines(acts), "DAD_Counter 1") {
		t.Errorf("the journal does not name the retry.%s", journalLines(acts))
	}
	s, acts = m.Step(at(3), 0, DADResult(c1, false))
	if s != State6Bound {
		t.Fatalf("a clean retried address left the machine in %s.%s", s, journalLines(acts))
	}
	acq, ok := find(acts, ActLeaseAcquired)
	if !ok || len(acq.Lease6.Addrs) != 1 || acq.Lease6.Addrs[0].Addr != c1 {
		t.Fatalf("the announced lease is %+v, want the one address %s.%s", acq.Lease6.Addrs, c1, journalLines(acts))
	}
	if got := m.SLAACCounters().Conflicts; got != 1 {
		t.Errorf("the conflict counter is %d, want 1", got)
	}
}

// RFC 7217 §6: "hosts MUST NOT automatically fall back to employing other
// algorithms for generating Interface Identifiers" (dhcp-golib#54).
func TestTheFourthDuplicateRefusesThePrefixAndNeverFallsBackToEUI64(t *testing.T) {
	m, all := stableStart(t, testParams6Stable(), 0, pio(testSLAACPrefix, 64, true, 86400, 14400))
	for c := uint8(0); c < IDGenRetries; c++ {
		_, acts := m.Step(at(2+int64(c)), 0, DADResult(stableAddr("2001:db8:1::/64", c), true))
		all = append(all, acts...)
		if got := dadTargets(acts); len(got) != 1 || got[0] != stableAddr("2001:db8:1::/64", c+1) {
			t.Fatalf("after the duplicate at DAD_Counter %d the check runs on %v, want the counter %d address.%s", c, got, c+1, journalLines(acts))
		}
	}
	s, acts := m.Step(at(9), 0, DADResult(stableAddr("2001:db8:1::/64", IDGenRetries), true))
	all = append(all, acts...)
	if got := dadTargets(acts); len(got) != 0 {
		t.Fatalf("a fifth address was tried after IDGEN_RETRIES: %v", got)
	}
	f, ok := find(acts, ActFailed)
	if !ok || f.Reason != ReasonConflict {
		t.Fatalf("the spent prefix ended with %+v, want a %s failure.%s", f, ReasonConflict, journalLines(acts))
	}
	if s != State6Discovering {
		t.Errorf("the machine is in %s, want %s", s, State6Discovering)
	}
	if got := m.SLAACCounters().Conflicts; got != 4 {
		t.Errorf("the conflict counter is %d, want 4", got)
	}

	ignored := m.SLAACCounters().Ignored[SLAACIgnoreDuplicate]
	_, acts = m.Step(at(20), 0, raEvent6(t, ra6(false, false, pio(testSLAACPrefix, 64, true, 86400, 14400))))
	all = append(all, acts...)
	if got := dadTargets(acts); len(got) != 0 {
		t.Errorf("the router's next advertisement formed %v on the spent prefix", got)
	}
	if got := m.SLAACCounters().Ignored[SLAACIgnoreDuplicate]; got != ignored+1 {
		t.Errorf("the repeat was charged %d to SLAACIgnoreDuplicate, want 1", got-ignored)
	}
	eui := netip.MustParseAddr(testSLAACAddr)
	for _, a := range dadTargets(all) {
		if a == eui {
			t.Fatalf("the modified EUI-64 address %s was formed", eui)
		}
	}
	if _, held := m.Lease(); held {
		t.Error("the machine holds a lease on a spent prefix")
	}
}

func TestTheDADCounterIsPerPrefix(t *testing.T) {
	m, _ := stableStart(t, testParams6Stable(), 0,
		pio("2001:db8:1::", 64, true, 86400, 14400),
		pio("2001:db8:2::", 64, true, 86400, 14400))
	a0, a1, b0 := stableAddr("2001:db8:1::/64", 0), stableAddr("2001:db8:1::/64", 1), stableAddr("2001:db8:2::/64", 0)
	m.Step(at(2), 0, DADResult(a0, true))
	_, acts := m.Step(at(2), 0, DADResult(b0, false))
	if got := dadTargets(acts); len(got) != 1 || got[0] != a1 {
		t.Fatalf("after a duplicate on one prefix the check runs on %v, want [%s].%s", got, a1, journalLines(acts))
	}
	s, acts := m.Step(at(3), 0, DADResult(a1, false))
	if s != State6Bound {
		t.Fatalf("the machine is in %s.%s", s, journalLines(acts))
	}
	got := m.SLAACAddrs()
	if len(got) != 2 || !(got[0] == a1 && got[1] == b0 || got[0] == b0 && got[1] == a1) {
		t.Fatalf("the machine holds %v, want %s and the untouched prefix's %s", got, a1, b0)
	}
}

func TestAnEUI64DuplicateIsNotRetried(t *testing.T) {
	m := newMachine6(t, testParams6SLAAC())
	m.Step(at(0), 0, Simple(EvStart))
	m.Step(at(1), 0, raEvent6(t, ra6(false, false, pio(testSLAACPrefix, 64, true, 86400, 14400))))
	_, acts := m.Step(at(2), 0, DADResult(netip.MustParseAddr(testSLAACAddr), true))
	if got := dadTargets(acts); len(got) != 0 {
		t.Errorf("EUI-64 mode tried %v after its one identifier was in use", got)
	}
	if f, ok := find(acts, ActFailed); !ok || f.Reason != ReasonConflict {
		t.Errorf("the duplicate ended with %+v, want a %s failure.%s", f, ReasonConflict, journalLines(acts))
	}
}

func TestTheDADCounterOutlivesThePrefixsAddress(t *testing.T) {
	m, _ := stableStart(t, testParams6Stable(), 0,
		pio("2001:db8:1::", 64, true, 100, 100),
		pio("2001:db8:2::", 64, true, 900, 900))
	a0, a1, b0 := stableAddr("2001:db8:1::/64", 0), stableAddr("2001:db8:1::/64", 1), stableAddr("2001:db8:2::/64", 0)
	m.Step(at(2), 0, DADResult(a0, true))
	m.Step(at(2), 0, DADResult(b0, false))
	if s, acts := m.Step(at(3), 0, DADResult(a1, false)); s != State6Bound {
		t.Fatalf("the machine is in %s.%s", s, journalLines(acts))
	}
	_, acts := m.Step(at(102), 0, TimerFired(Timer6SLAAC))
	if got := m.SLAACAddrs(); len(got) != 1 || got[0] != b0 {
		t.Fatalf("after the first prefix's valid lifetime the machine holds %v, want [%s].%s", got, b0, journalLines(acts))
	}
	_, acts = m.Step(at(103), 0, raEvent6(t, ra6(false, false, pio("2001:db8:1::", 64, true, 100, 100))))
	if got := dadTargets(acts); len(got) != 1 || got[0] != a1 {
		t.Fatalf("the prefix advertised again formed %v, want the counter 1 address %s.%s", got, a1, journalLines(acts))
	}
}

// The counter is not persisted, so a restart counts from 0 and its first
// re-formed address is the refused one; it is skipped (dhcp-golib#54).
func TestAResumedRetriedAddressFoundInUseSkipsToTheNextCounter(t *testing.T) {
	p := testParams6Stable()
	c1, c2 := stableAddr("2001:db8:1::/64", 1), stableAddr("2001:db8:1::/64", 2)
	p.Resume = &Resume6{Addrs: []Addr6{{Addr: c1, Preferred: 10000 * Second, Valid: 20000 * Second}}}
	m := newMachine6(t, p)
	if s, acts := m.Step(at(0), 0, Simple(EvStart)); s != State6DAD {
		t.Fatalf("a restart with a remembered address left the machine in %s.%s", s, journalLines(acts))
	}
	_, acts := m.Step(at(1), 0, DADResult(c1, true))
	if got := dadTargets(acts); len(got) != 1 || got[0] != c2 {
		t.Fatalf("the remembered address in use was followed by %v, want [%s].%s", got, c2, journalLines(acts))
	}
}

func TestTheIdentifierSecretIsNeverJournalled(t *testing.T) {
	m, all := stableStart(t, testParams6Stable(), 0, pio(testSLAACPrefix, 64, true, 86400, 14400))
	for c := uint8(0); c <= IDGenRetries; c++ {
		_, acts := m.Step(at(2+int64(c)), 0, DADResult(stableAddr("2001:db8:1::/64", c), true))
		all = append(all, acts...)
	}
	text := journalLines(all)
	for _, form := range []string{hex.EncodeToString(testIIDSecret), fmt.Sprint(testIIDSecret), fmt.Sprintf("% x", testIIDSecret), string(testIIDSecret)} {
		if strings.Contains(text, form) {
			t.Errorf("the journal carries the secret as %q.%s", form, text)
		}
	}
}

// The Auto fallback forms from the deferred prefixes through the same
// identifier choice, and stable-privacy mode needs no link address there
// either (dhcp-golib#54).
func TestTheAutoFallbackFormsTheStableAddressWithOrWithoutALinkAddress(t *testing.T) {
	for _, c := range []struct {
		name string
		hw   []byte
	}{
		{"with a link address", testLinkAddr6},
		{"without one", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := testParams6Stable()
			p.Mode = Mode6Auto
			p.LinkAddr = c.hw
			m := newMachine6(t, p)
			m.Step(at(0), 0, Simple(EvStart))
			_, acts := m.Step(at(1), 0, raEvent6(t, ra6(true, false, pio(testSLAACPrefix, 64, true, 86400, 14400))))
			d, ok := timerSet(acts, Timer6AutoFallback)
			if !ok {
				t.Fatalf("no fallback deadline was armed.%s", journalLines(acts))
			}
			_, acts = m.Step(at(2), 0, TimerFired(Timer6Delay))
			mustSendV6(t, acts, wire.MsgSolicit)

			_, acts = m.Step(at(1).Add(d), 0, TimerFired(Timer6AutoFallback))
			want := stableAddr("2001:db8:1::/64", 0)
			if got := dadTargets(acts); len(got) != 1 || got[0] != want {
				t.Fatalf("the fallback runs duplicate address detection on %v, want [%s].%s", got, want, journalLines(acts))
			}
			if n := m.SLAACCounters().Ignored[SLAACIgnoreLinkAddr]; n != 0 {
				t.Errorf("%d prefix(es) were charged to the link address in stable-privacy mode", n)
			}
		})
	}
}
