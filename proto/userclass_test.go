// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// Option 77 on the wire, RFC 3004 section 4 (claymore666/docker-net-dhcp#1120).
// Every assertion reads the message after wire.Encode and wire.Decode: the
// bytes a server parses, not a field this package holds.

func userClassParams(classes ...[]byte) Params {
	p := testParams()
	p.UserClass = classes
	return p
}

func userClassRep(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

// TestNewValidatesTheUserClassAgainstRFC3004Section4 holds the length rules at
// their boundaries: a wrapped one-octet Len is a valid option naming other
// classes (claymore666/docker-net-dhcp#1120).
func TestNewValidatesTheUserClassAgainstRFC3004Section4(t *testing.T) {
	for _, tc := range []struct {
		name    string
		classes [][]byte
		ok      bool
	}{
		{"nil sends nothing", nil, true},
		{"empty sends nothing", [][]byte{}, true},
		{"one short instance", [][]byte{[]byte("tier")}, true},
		{"one octet is the smallest instance", [][]byte{{'a'}}, true},
		{"a zero octet inside an instance is data", [][]byte{{'a', 0, 'b'}}, true},
		{"254 octets fill Len with the one length octet", [][]byte{userClassRep('a', 254)}, true},
		{"255 octets do not fit Len", [][]byte{userClassRep('a', 255)}, false},
		{"an empty instance is refused, UC_Len must be non-zero", [][]byte{{}}, false},
		{"an empty instance among others is refused, not dropped", [][]byte{{'a'}, {}, {'b'}}, false},
		{"a nil instance is refused", [][]byte{nil}, false},
		{"sum 253 and two instances is 255", [][]byte{userClassRep('a', 127), userClassRep('b', 126)}, true},
		{"sum 254 and two instances is 256", [][]byte{userClassRep('a', 127), userClassRep('b', 127)}, false},
		{"sum 255 and two instances is 257", [][]byte{userClassRep('a', 127), userClassRep('b', 128)}, false},
		{"three instances at exactly 255", [][]byte{userClassRep('a', 100), userClassRep('b', 100), userClassRep('c', 52)}, true},
		{"three instances one over 255", [][]byte{userClassRep('a', 100), userClassRep('b', 100), userClassRep('c', 53)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verr := userClassParams(tc.classes...).validate()
			if (verr == nil) != tc.ok {
				t.Fatalf("validate() = %v, want an error: %v", verr, !tc.ok)
			}
			m, err := New(userClassParams(tc.classes...))
			if tc.ok {
				if err != nil {
					t.Fatalf("New refused a list option 77 can carry: %v", err)
				}
				if m == nil {
					t.Fatal("New returned no machine and no error")
				}
				return
			}
			if err == nil {
				t.Fatal("New accepted a list option 77 cannot carry")
			}
			if !errors.Is(err, ErrBadUserClass) {
				t.Fatalf("error %v does not name ErrBadUserClass", err)
			}
			if !errors.Is(err, wire.ErrBadOptionValue) {
				t.Fatalf("error %v does not carry the codec's reason", err)
			}
		})
	}
}

// userClassSends returns the five messages that may carry option 77 after a
// wire round trip: DISCOVER, the SELECTING, T1, T2 and INIT-REBOOT REQUESTs
// (claymore666/docker-net-dhcp#1120).
func userClassSends(t *testing.T, classes ...[]byte) map[string]*wire.Message {
	t.Helper()
	out := map[string]*wire.Message{}

	p := userClassParams(classes...)
	m := newMachine(t, p)
	_, acts := m.Step(at(0), 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	out["discover"] = encoded(t, disc)
	_, acts = m.Step(at(1), 2, received(t, offerFor(disc, testLeaseAddr, testServerID)))
	req := mustSend(t, acts, wire.MsgRequest)
	out["selecting request"] = encoded(t, req)
	if _, acts = m.Step(at(2), 3, received(t, ackFor(req, testLeaseAddr, testServerID, 3600))); m.State() != StateBound {
		t.Fatalf("fixture did not reach BOUND: %s\n%v", m.State(), RenderActions(acts))
	}
	t1, _ := m.lease.RenewAt()
	_, acts = m.Step(t1, 0x11, TimerFired(TimerRenew))
	out["renewing request"] = encoded(t, mustSend(t, acts, wire.MsgRequest))
	t2, _ := m.lease.RebindAt()
	_, acts = m.Step(t2, 0x22, TimerFired(TimerRebind))
	out["rebinding request"] = encoded(t, mustSend(t, acts, wire.MsgRequest))

	rp := resumeParams(testRebootAddr, at(3600), true)
	rp.UserClass = classes
	rm := newMachine(t, rp)
	_, acts = rm.Step(0, 0xC0FFEE, Simple(EvStart))
	out["init-reboot request"] = encoded(t, mustSend(t, acts, wire.MsgRequest))
	return out
}

// TestUserClassIsOnTheDiscoverAndOnEveryRequestByteForByte drives all five
// senders, so option 77 on some of them only is red (claymore666/docker-net-dhcp#1120).
func TestUserClassIsOnTheDiscoverAndOnEveryRequestByteForByte(t *testing.T) {
	for _, tc := range []struct {
		name    string
		classes [][]byte
		want    []byte
	}{
		{"one instance", [][]byte{[]byte("vip-tier")}, append([]byte{8}, "vip-tier"...)},
		{"a zero octet inside the instance", [][]byte{{'a', 0x00, 'b'}}, []byte{3, 'a', 0x00, 'b'}},
		{"instances stay separate", [][]byte{[]byte("foo"), []byte("bar")}, []byte{3, 'f', 'o', 'o', 3, 'b', 'a', 'r'}},
		{"the longest instance", [][]byte{userClassRep('z', 254)}, append([]byte{254}, userClassRep('z', 254)...)},
		{"the longest list", [][]byte{userClassRep('a', 127), userClassRep('b', 126)},
			append(append([]byte{127}, userClassRep('a', 127)...), append([]byte{126}, userClassRep('b', 126)...)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, msg := range userClassSends(t, tc.classes...) {
				got, ok := msg.Options[wire.OptUserClass]
				if !ok {
					t.Errorf("%s carries no option 77", name)
					continue
				}
				if !bytes.Equal(got, tc.want) {
					t.Errorf("%s option 77 = %x, want %x", name, got, tc.want)
				}
				back, present, err := msg.Options.UserClass()
				if err != nil || !present || len(back) != len(tc.classes) {
					t.Errorf("%s option 77 does not decode to the %d instance(s) sent: %v/%v/%v",
						name, len(tc.classes), back, present, err)
					continue
				}
				for i := range back {
					if !bytes.Equal(back[i], tc.classes[i]) {
						t.Errorf("%s instance %d = %x, want %x", name, i, back[i], tc.classes[i])
					}
				}
			}
		})
	}
}

// userClassBound reaches BOUND with p from fakes_test.go fixtures only, so this
// file builds when its neighbours are switched off
// (claymore666/docker-net-dhcp#1120).
func userClassBound(t *testing.T, p Params) *Machine {
	t.Helper()
	m := newMachine(t, p)
	_, acts := m.Step(0, 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	_, acts = m.Step(at(1), 2, received(t, offerFor(disc, "192.168.99.50", "192.168.99.1")))
	req := mustSend(t, acts, wire.MsgRequest)
	m.Step(at(2), 3, received(t, ackFor(req, "192.168.99.50", "192.168.99.1", 3600)))
	if m.State() != StateBound {
		t.Fatalf("fixture reached %s, want BOUND", m.State())
	}
	return m
}

// TestADeclineAndAReleaseCarryNoUserClass: RFC 2131 Table 5 does not list
// option 77 for either. The machine has no DHCPINFORM builder, so that message
// is absent by construction (claymore666/docker-net-dhcp#1120).
func TestADeclineAndAReleaseCarryNoUserClass(t *testing.T) {
	// Every option base() adds is on, so a DECLINE without option 77 is not
	// clean for want of a host name. The fixtures live in fakes_test.go, which a
	// disabled test file does not take along (claymore666/docker-net-dhcp#1120).
	p := userClassParams([]byte("vip-tier"))
	p.Hostname = "container-a"
	p.VendorClass = "docker-net-dhcp"
	p.ClientID = []byte{0xFF, 0x01, 0x02, 0x03}
	p.RequestedLease = 3600 * Second
	p.Broadcast = true

	t.Run("decline", func(t *testing.T) {
		m := userClassBound(t, p)
		_, acts := m.Step(at(10), 0xFEED, Simple(EvConflictDetected))
		msg := encoded(t, mustSend(t, acts, wire.MsgDecline))
		if _, ok := msg.Options[wire.OptUserClass]; ok {
			t.Error("DHCPDECLINE carries option 77")
		}
	})
	t.Run("release", func(t *testing.T) {
		m := userClassBound(t, p)
		_, acts := m.Step(at(10), 0xFEED, Simple(EvRelease))
		msg := encoded(t, mustSend(t, acts, wire.MsgRelease))
		if _, ok := msg.Options[wire.OptUserClass]; ok {
			t.Error("DHCPRELEASE carries option 77")
		}
	})
	t.Run("the preservation control: the same Params still send it on the DISCOVER", func(t *testing.T) {
		m := newMachine(t, p)
		_, acts := m.Step(0, 1, Simple(EvStart))
		msg := encoded(t, mustSend(t, acts, wire.MsgDiscover))
		if _, ok := msg.Options[wire.OptUserClass]; !ok {
			t.Error("the fixture's DISCOVER carries no option 77, so the two checks above prove nothing")
		}
	})
}

// TestANilAndAnEmptyUserClassSendNothing: nil, empty and the defaults never
// produce the zero-length option 77 RFC 3004 section 4 forbids
// (claymore666/docker-net-dhcp#1120).
func TestANilAndAnEmptyUserClassSendNothing(t *testing.T) {
	for name, p := range map[string]Params{
		"nil":           userClassParams(nil...),
		"empty":         userClassParams([][]byte{}...),
		"DefaultParams": DefaultParams(testCHAddr),
	} {
		t.Run(name, func(t *testing.T) {
			p.DesyncMin, p.DesyncMax = 0, 0
			if got := newMachine(t, p).Params().UserClass; len(got) != 0 {
				t.Errorf("Params().UserClass = %q for a client with none", got)
			}
			for what, msg := range userClassFirstTwo(t, p) {
				if v, ok := msg.Options[wire.OptUserClass]; ok {
					t.Errorf("%s carries option 77 = %x for a client with no user class", what, v)
				}
			}
		})
	}
}

// TestNoUserClassStaysNilThroughParams: nil in, nil out, so New(m.Params())
// builds the same machine (claymore666/docker-net-dhcp#1120).
func TestNoUserClassStaysNilThroughParams(t *testing.T) {
	if got := newMachine(t, userClassParams()).Params().UserClass; got != nil {
		t.Fatalf("Params().UserClass = %#v for a client built with none, want nil", got)
	}
}

// userClassFirstTwo is the DISCOVER and SELECTING REQUEST of any Params (claymore666/docker-net-dhcp#1120).
func userClassFirstTwo(t *testing.T, p Params) map[string]*wire.Message {
	t.Helper()
	m := newMachine(t, p)
	_, acts := m.Step(at(0), 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	out := map[string]*wire.Message{"discover": encoded(t, disc)}
	_, acts = m.Step(at(1), 2, received(t, offerFor(disc, testLeaseAddr, testServerID)))
	out["request"] = encoded(t, mustSend(t, acts, wire.MsgRequest))
	return out
}

// TestACallerCannotEditTheUserClassAfterNew: the list is copied to the depth
// of its instances, on the way in and out (claymore666/docker-net-dhcp#1120).
func TestACallerCannotEditTheUserClassAfterNew(t *testing.T) {
	inner := []byte("vip-tier")
	list := [][]byte{inner}
	m := newMachine(t, userClassParams(list...))

	inner[0] = 'X'
	list[0] = []byte("swapped")
	list = append(list, []byte("extra"))
	_ = list

	got := m.Params().UserClass
	if len(got) != 1 || string(got[0]) != "vip-tier" {
		t.Fatalf("Params().UserClass = %q after the caller edited its own list", got)
	}
	got[0][0] = 'Y'
	if again := m.Params().UserClass; string(again[0]) != "vip-tier" {
		t.Fatalf("an edit of the list Params returned reached the machine: %q", again)
	}

	_, acts := m.Step(0, 1, Simple(EvStart))
	first := mustSend(t, acts, wire.MsgDiscover)
	msg := encoded(t, first)
	want := append([]byte{8}, "vip-tier"...)
	if !bytes.Equal(msg.Options[wire.OptUserClass], want) {
		t.Fatalf("option 77 = %q, want %q", msg.Options[wire.OptUserClass], want)
	}

	// The same for the message the machine handed out: a receiver that edits
	// its option 77 must not change the next one (claymore666/docker-net-dhcp#1120).
	first.Options[wire.OptUserClass][1] = 'Z'
	_, acts = m.Step(at(1), 2, received(t, offerFor(first, testLeaseAddr, testServerID)))
	next := encoded(t, mustSend(t, acts, wire.MsgRequest))
	if !bytes.Equal(next.Options[wire.OptUserClass], want) {
		t.Fatalf("an edit of a sent message reached the next one: %q, want %q", next.Options[wire.OptUserClass], want)
	}
}

// TestUserClassDoesNotChangeTheParameterRequestList: option 77 is sent, not
// asked for (claymore666/docker-net-dhcp#1120).
func TestUserClassDoesNotChangeTheParameterRequestList(t *testing.T) {
	with := userClassFirstTwo(t, userClassParams([]byte("vip-tier")))["discover"]
	without := userClassFirstTwo(t, userClassParams())["discover"]
	if !bytes.Equal(with.Options[wire.OptParameterList], without.Options[wire.OptParameterList]) {
		t.Fatalf("parameter request list %x with a user class, %x without",
			with.Options[wire.OptParameterList], without.Options[wire.OptParameterList])
	}
	if strings.Contains(string(with.Options[wire.OptParameterList]), string([]byte{byte(wire.OptUserClass)})) {
		t.Fatal("the parameter request list asks for option 77")
	}
}
