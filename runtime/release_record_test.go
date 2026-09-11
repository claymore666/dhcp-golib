// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package runtime

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/lease"
)

// The fixture these cases vary one field of at a time.
const (
	relHostSrc4 = "192.168.99.2"
	relAddr4    = "192.168.99.84"
	relServer4  = "192.168.99.1"
	relHostSrc6 = "fe80::9"
	relAddr6    = "fd00:99::53"
	relIface    = "cli0"
	relIAID     = uint32(0x0a0b0c0d)
)

var (
	relDUID       = []byte{0x00, 0x03, 0x00, 0x01, 0x02, 0x42, 0xc0, 0xa8, 0x63, 0x54}
	relServerDUID = []byte{0x00, 0x01, 0x00, 0x01, 0x2b, 0x00, 0x00, 0x01, 0xaa, 0xbb}
)

func relRec4() lease.Record {
	return lease.Record{
		ID: "rec-4", Scope: "net-a", Family: lease.FamilyV4,
		CHAddr:   []byte{0x02, 0x42, 0xc0, 0xa8, 0x63, 0x54},
		Identity: []byte{0xff, 0x01, 0x02, 0x03},
		Lease: lease.Lease{
			Addr:     netip.MustParsePrefix(relAddr4 + "/24"),
			ServerID: netip.MustParseAddr(relServer4),
		},
	}
}

func relRec6() lease.Record {
	return lease.Record{
		ID: "rec-6", Scope: "net-a", Family: lease.FamilyV6,
		Identity: binary.BigEndian.AppendUint32(append([]byte(nil), relDUID...), relIAID),
		Lease: lease.Lease{
			Addr:       netip.MustParsePrefix(relAddr6 + "/128"),
			ServerDUID: append([]byte(nil), relServerDUID...),
			IAID:       relIAID,
		},
	}
}

// relFake is the transport seam, and it counts CALLS rather than recording the
// last one.
//
// A refusal that returns an error is not the same claim as a refusal that
// sends nothing, and only the second one is what a server sees. A test
// asserting "an error came back" passes for a sender that refused loudly after
// having already put a malformed datagram on the wire.
type relFake struct {
	calls   int
	src     netip.AddrPort
	dst     netip.AddrPort
	iface   string
	payload []byte
	err     error
}

func (f *relFake) send(src, dst netip.AddrPort, iface string, payload []byte) error {
	f.calls++
	f.src, f.dst, f.iface = src, dst, iface
	f.payload = append([]byte(nil), payload...)
	return f.err
}

func relCfg4() ReleaseConfig {
	return ReleaseConfig{Source: netip.MustParseAddr(relHostSrc4), Rand: NewEntropySeeded(1)}
}

func relCfg6() ReleaseConfig {
	return ReleaseConfig{Interface: relIface, Source: netip.MustParseAddr(relHostSrc6), Rand: NewEntropySeeded(1)}
}

// TestARefusedReleaseReachesTheTransportZeroTimes is the assertion the error
// value cannot make.
//
// Every row here is a release that must not happen: a record that names no
// server has nowhere to unicast to, and RFC 2131 section 4.4.4 gives it no
// broadcast fallback — "The client unicasts DHCPRELEASE messages to the
// server" is the whole sentence, and broadcast is what the same paragraph
// gives the DHCPDECLINE. A sender that shouted such a release at the segment,
// or unicast it to 0.0.0.0, and then returned an error would satisfy a test
// that only reads the error.
func TestARefusedReleaseReachesTheTransportZeroTimes(t *testing.T) {
	cases := []struct {
		name string
		rec  lease.Record
		cfg  ReleaseConfig
		want error
	}{
		{"no source address", relRec4(), ReleaseConfig{Rand: NewEntropySeeded(1)}, ErrReleaseNoSource},
		{"a v6 source for a v4 record", relRec4(),
			ReleaseConfig{Source: netip.MustParseAddr(relHostSrc6), Interface: relIface, Rand: NewEntropySeeded(1)},
			ErrReleaseSourceFamily},
		{"a v4 source for a v6 record", relRec6(),
			ReleaseConfig{Source: netip.MustParseAddr(relHostSrc4), Interface: relIface, Rand: NewEntropySeeded(1)},
			ErrReleaseSourceFamily},
		{"a v6 release with no interface", relRec6(),
			ReleaseConfig{Source: netip.MustParseAddr(relHostSrc6), Rand: NewEntropySeeded(1)},
			ErrReleaseNoInterface},
		{"the v6 source is the address being released", relRec6(),
			ReleaseConfig{Interface: relIface, Source: netip.MustParseAddr(relAddr6), Rand: NewEntropySeeded(1)},
			ErrReleaseSourceIsReleased},
		{"a record that names no server", func() lease.Record {
			r := relRec4()
			r.Lease.ServerID = netip.Addr{}
			return r
		}(), relCfg4(), lease.ErrReleaseNoServer},
		{"a record with no leased address", func() lease.Record {
			r := relRec4()
			r.Lease.Addr = netip.Prefix{}
			return r
		}(), relCfg4(), lease.ErrReleaseNoAddr},
		{"a record that never bound", lease.Record{}, relCfg4(), lease.ErrReleaseFamily},
		{"a v6 record whose two IAIDs disagree", func() lease.Record {
			r := relRec6()
			r.Lease.IAID = relIAID + 1
			return r
		}(), relCfg6(), lease.ErrReleaseIAIDMismatch},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &relFake{}
			err := sendReleaseWith(tc.rec, tc.cfg, f.send)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if f.calls != 0 {
				t.Errorf("the transport was called %d time(s) on a refusal", f.calls)
			}
		})
	}

	// THE OTHER DIRECTION, or every row above is satisfied by a function that
	// refuses everything and the check has one possible verdict.
	for _, ok := range []struct {
		name string
		rec  lease.Record
		cfg  ReleaseConfig
	}{
		{"v4", relRec4(), relCfg4()},
		{"v6", relRec6(), relCfg6()},
	} {
		t.Run("the complete "+ok.name+" record sends exactly one datagram", func(t *testing.T) {
			f := &relFake{}
			if err := sendReleaseWith(ok.rec, ok.cfg, f.send); err != nil {
				t.Fatalf("SendRelease: %v", err)
			}
			if f.calls != 1 {
				t.Errorf("the transport was called %d time(s), want exactly one", f.calls)
			}
		})
	}
}

// TestAV6ReleaseRefusesToComeFromTheAddressItIsReleasing is RFC 9915 section
// 18.2.7's second MUST NOT, refused rather than trusted:
//
//	"The client MUST NOT use any of the addresses it is releasing as the
//	source address in the Release message or in any subsequently transmitted
//	message."
//
// It has to be refused here because no outside evidence could ever catch it. A
// server acts on the Release either way — MEASURED against dnsmasq 2.91, the
// source address is not consulted at all — so a fixture that sent the
// forbidden shape would go green and the violation would ship.
//
// THE GUARD HAS A DIRECTION AND THE OPPOSITE FAILURE IS NAMED. Refusing a
// LEGAL send is the other way to be wrong, and it is not hypothetical: RFC
// 2131 has no such prohibition, and proto.Machine's own release depends on
// sending FROM the address it is giving back. So the v4 arm must accept
// exactly the configuration the v6 arm refuses, and it is driven here beside
// it rather than left to be assumed.
func TestAV6ReleaseRefusesToComeFromTheAddressItIsReleasing(t *testing.T) {
	f := &relFake{}
	cfg := relCfg6()
	cfg.Source = netip.MustParseAddr(relAddr6)
	if err := sendReleaseWith(relRec6(), cfg, f.send); !errors.Is(err, ErrReleaseSourceIsReleased) {
		t.Fatalf("error = %v, want %v", err, ErrReleaseSourceIsReleased)
	}
	if f.calls != 0 {
		t.Errorf("the forbidden Release reached the transport %d time(s)", f.calls)
	}

	// The v4 mirror: the same shape, and it must go.
	f4 := &relFake{}
	cfg4 := relCfg4()
	cfg4.Source = netip.MustParseAddr(relAddr4)
	if err := sendReleaseWith(relRec4(), cfg4, f4.send); err != nil {
		t.Fatalf("a v4 release sourced from the released address was refused: %v", err)
	}
	if f4.calls != 1 {
		t.Fatalf("the v4 release reached the transport %d time(s), want one", f4.calls)
	}
	if f4.src.Addr().String() != relAddr4 {
		t.Errorf("the v4 source = %s, want the caller's explicit choice %s", f4.src.Addr(), relAddr4)
	}
}

// TestTheReleaseDestinationIsTheRingsOwnServerPort holds ring 2's idea of
// where a release goes against ring 3's.
//
// The two numbers are declared twice — lease cannot import runtime, so it
// carries its own copies of 67 and 547 — and one fact derived twice has two
// answers the moment either moves. This is the second observer that makes the
// duplication safe rather than the comment that says it is.
func TestTheReleaseDestinationIsTheRingsOwnServerPort(t *testing.T) {
	f := &relFake{}
	if err := sendReleaseWith(relRec4(), relCfg4(), f.send); err != nil {
		t.Fatalf("v4: %v", err)
	}
	if f.dst.Port() != ServerPort {
		t.Errorf("the v4 destination port = %d, want runtime.ServerPort %d", f.dst.Port(), ServerPort)
	}
	if f.dst.Addr().String() != relServer4 {
		t.Errorf("the v4 destination = %s, want the record's server %s", f.dst.Addr(), relServer4)
	}

	f6 := &relFake{}
	if err := sendReleaseWith(relRec6(), relCfg6(), f6.send); err != nil {
		t.Fatalf("v6: %v", err)
	}
	if f6.dst.Port() != ServerPort6 {
		t.Errorf("the v6 destination port = %d, want runtime.ServerPort6 %d", f6.dst.Port(), ServerPort6)
	}
	if f6.dst.Addr() != AllDHCPRelayAgentsAndServers {
		t.Errorf("the v6 destination = %s, want %s", f6.dst.Addr(), AllDHCPRelayAgentsAndServers)
	}
}

// TestTheReleaseSourcePortDefaultsToTheClientPort pins both arms of the one
// field a caller changes when the host already runs a DHCP client of its own.
//
// RFC 2131 section 4.1 and RFC 9915 section 7.2 give a client 68 and 546, and
// that is what an unset field means. An explicit value is the escape for a
// host where those ports are taken, and it is a value the caller states rather
// than a fallback this package takes silently — a sender that quietly moved to
// an ephemeral port would work against dnsmasq and fail against a server that
// reads the source port, with nothing to say which happened.
func TestTheReleaseSourcePortDefaultsToTheClientPort(t *testing.T) {
	cases := []struct {
		name string
		rec  lease.Record
		cfg  ReleaseConfig
		want uint16
	}{
		{"v4 default", relRec4(), relCfg4(), ClientPort},
		{"v6 default", relRec6(), relCfg6(), ClientPort6},
		{"v4 explicit", relRec4(), func() ReleaseConfig { c := relCfg4(); c.SourcePort = 33333; return c }(), 33333},
		{"v6 explicit", relRec6(), func() ReleaseConfig { c := relCfg6(); c.SourcePort = 33334; return c }(), 33334},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &relFake{}
			if err := sendReleaseWith(tc.rec, tc.cfg, f.send); err != nil {
				t.Fatalf("SendRelease: %v", err)
			}
			if f.src.Port() != tc.want {
				t.Errorf("source port = %d, want %d", f.src.Port(), tc.want)
			}
			if f.iface != tc.cfg.Interface {
				t.Errorf("interface = %q, want the caller's %q", f.iface, tc.cfg.Interface)
			}
		})
	}
}

// TestAReleaseThatCouldNotBeWrittenIsReported is the fire-and-forget boundary.
//
// Forget refers to the REPLY and never to the error. RFC 2131 section 4.4.6 —
// "Note that the correct operation of DHCP does not depend on the transmission
// of DHCPRELEASE messages" — permits the release to fail; it does not permit
// the caller to be told it succeeded. A swallowed write error is a caller that
// closes its record while the address stays leased until its lifetime runs
// out, and there is nothing afterwards that could notice.
func TestAReleaseThatCouldNotBeWrittenIsReported(t *testing.T) {
	boom := errors.New("the parent link went away")
	f := &relFake{err: boom}
	err := sendReleaseWith(relRec4(), relCfg4(), f.send)
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want the transport's %v", err, boom)
	}
	if f.calls != 1 {
		t.Errorf("the transport was called %d time(s), want one", f.calls)
	}

	// The other direction: the same fixture with a write that succeeds must
	// report nothing, or this observer has one possible verdict.
	ok := &relFake{}
	if err := sendReleaseWith(relRec4(), relCfg4(), ok.send); err != nil {
		t.Errorf("a successful write was reported as %v", err)
	}
}

// TestTwoReleasesOfOneRecordCarryDifferentTransactionIDs is the one shape with
// no outside evidence at all in this fixture, so it is asserted on the bytes
// and the bound is stated rather than claimed away.
//
// Nothing here reads a reply, so a repeated transaction id changes no outcome
// this package can observe. It changes one somewhere else: two releases a
// second apart carrying one id are one datagram to anything that deduplicates
// on it.
func TestTwoReleasesOfOneRecordCarryDifferentTransactionIDs(t *testing.T) {
	first, second := &relFake{}, &relFake{}
	cfg := ReleaseConfig{Source: netip.MustParseAddr(relHostSrc4), Rand: NewEntropySeeded(7)}
	if err := sendReleaseWith(relRec4(), cfg, first.send); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := sendReleaseWith(relRec4(), cfg, second.send); err != nil {
		t.Fatalf("second: %v", err)
	}
	if string(first.payload) == string(second.payload) {
		t.Errorf("two releases of one record produced identical datagrams: % x", first.payload)
	}
}
