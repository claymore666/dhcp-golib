// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// The record a release is built from, in one place so that every case below
// varies ONE field of it. A per-case literal would let a case pass because it
// quietly differs in a second field nobody is looking at.
const (
	relAddr4   = "192.168.99.84"
	relServer4 = "192.168.99.1"
	relAddr6   = "fd00:99::53"
	relIAID    = uint32(0x0a0b0c0d)
)

var (
	relCHAddr     = []byte{0x02, 0x42, 0xc0, 0xa8, 0x63, 0x54}
	relIdentity4  = []byte{0xff, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}
	relDUID       = []byte{0x00, 0x03, 0x00, 0x01, 0x02, 0x42, 0xc0, 0xa8, 0x63, 0x54}
	relServerDUID = []byte{0x00, 0x01, 0x00, 0x01, 0x2b, 0x00, 0x00, 0x01, 0xaa, 0xbb}
)

// relIdentity6 is the DUID followed by the IAID, which is what a v6 record's
// Identity is: "the option 61 / DUID+IAID bytes AS SENT".
func relIdentity6() []byte {
	out := append([]byte(nil), relDUID...)
	return binary.BigEndian.AppendUint32(out, relIAID)
}

func relRecord4() Record {
	return Record{
		ID: "rec-4", Scope: "net-a", Family: FamilyV4,
		CHAddr:   append([]byte(nil), relCHAddr...),
		Identity: append([]byte(nil), relIdentity4...),
		Held:     true,
		Lease: Lease{
			Addr:     netip.MustParsePrefix(relAddr4 + "/24"),
			ServerID: netip.MustParseAddr(relServer4),
		},
	}
}

func relRecord6() Record {
	return Record{
		ID: "rec-6", Scope: "net-a", Family: FamilyV6,
		Identity: relIdentity6(),
		Held:     true,
		Lease: Lease{
			Addr:       netip.MustParsePrefix(relAddr6 + "/128"),
			ServerDUID: append([]byte(nil), relServerDUID...),
			IAID:       relIAID,
		},
	}
}

func mustBuild(t *testing.T, rec Record, xid uint32) ([]byte, netip.AddrPort) {
	t.Helper()
	payload, dst, err := BuildRelease(rec, xid)
	if err != nil {
		t.Fatalf("BuildRelease: %v", err)
	}
	return payload, dst
}

// TestAV4ReleaseCarriesTheRecordsAddressServerAndIdentity reads the ENCODED
// BYTES, not the struct the encoder was handed.
//
// Everything this datagram has to get right is invisible afterwards: nothing
// answers a DHCPRELEASE, nothing retransmits it and no state comes back, so a
// message with the wrong address in it behaves exactly like a correct one from
// this process's side. The bytes are the only place the difference exists
// before the server's log.
func TestAV4ReleaseCarriesTheRecordsAddressServerAndIdentity(t *testing.T) {
	payload, dst := mustBuild(t, relRecord4(), 0xC0FFEE01)

	msg, err := wire.Decode(payload)
	if err != nil {
		t.Fatalf("the datagram does not decode: %v", err)
	}
	if got, _ := msg.Type(); got != wire.MsgRelease {
		t.Errorf("message type = %s, want %s", got, wire.MsgRelease)
	}
	if msg.Op != wire.BootRequest {
		t.Errorf("op = %s, want %s", msg.Op, wire.BootRequest)
	}
	if msg.XID != 0xC0FFEE01 {
		t.Errorf("xid = %#x, want the caller's %#x", msg.XID, 0xC0FFEE01)
	}
	if msg.CIAddr.String() != relAddr4 {
		t.Errorf("ciaddr = %s, want the released address %s", msg.CIAddr, relAddr4)
	}
	if !bytes.Equal(msg.CHAddr, relCHAddr) {
		t.Errorf("chaddr = %x, want the record's %x", msg.CHAddr, relCHAddr)
	}
	if got, _ := msg.Addr4(wire.OptServerID); got.String() != relServer4 {
		t.Errorf("option 54 = %s, want the record's server %s", got, relServer4)
	}
	if !bytes.Equal(msg.Options[wire.OptClientID], relIdentity4) {
		t.Errorf("option 61 = %x, want the record's identity %x", msg.Options[wire.OptClientID], relIdentity4)
	}

	// Table 5 makes the requested-IP option a MUST NOT in a DHCPRELEASE. It is
	// the DHCPDECLINE that carries the address there, and a builder written by
	// copying the decline's shape reintroduces it.
	if v, ok := msg.Options[wire.OptRequestedIP]; ok {
		t.Errorf("the release carries option 50 = %x; Table 5 makes it a MUST NOT here", v)
	}

	// RFC 2131 section 4.4.4: "The client unicasts DHCPRELEASE messages to the
	// server." The destination is a value this function returns precisely so
	// that it can be asserted rather than inferred from where a socket went.
	if want := netip.AddrPortFrom(netip.MustParseAddr(relServer4), 67); dst != want {
		t.Errorf("destination = %s, want the server at %s", dst, want)
	}
}

// TestAV4ReleaseWithoutAnIdentityCarriesNoOptionSixtyOne is the ABSENCE half
// of RFC 2131 section 3.1(6), and it is the one assertion in this file that no
// server could ever make for us.
//
// "If the client used a 'client identifier' when it obtained the lease, it
// MUST use the same 'client identifier' in the DHCPRELEASE message" is
// conditional, and the condition is the whole requirement: a server looks a
// binding up by client-identifier and falls back to chaddr only for a lease
// that has none. An option 61 invented here is a lookup that succeeds on the
// wrong key.
//
// MEASURED against dnsmasq 2.91 while this path was being designed: a release
// carrying a MAC-derived option 61 closes a lease that was acquired WITHOUT
// one, because dnsmasq's fallback finds it by chaddr afterwards. So the
// fixture agrees with the defect, and these bytes are the only observer that
// does not.
func TestAV4ReleaseWithoutAnIdentityCarriesNoOptionSixtyOne(t *testing.T) {
	rec := relRecord4()
	rec.Identity = nil
	payload, _ := mustBuild(t, rec, 1)

	msg, err := wire.Decode(payload)
	if err != nil {
		t.Fatalf("the datagram does not decode: %v", err)
	}
	if v, ok := msg.Options[wire.OptClientID]; ok {
		t.Errorf("option 61 is present as %x on a record whose acquisition carried none", v)
	}

	// And on the wire, not only in the map: a zero-length option 61 decodes to
	// an empty value that a map lookup reports as present, but a builder that
	// wrote a code-61 TLV with no content would also be wrong, and the two
	// mistakes are the same size. So the encoded octets are walked as well.
	if optionPresent(t, payload, wire.OptClientID) {
		t.Errorf("the encoded datagram carries an option 61 TLV: % x", payload)
	}

	// The control on the other side of the branch, in the same test, so that a
	// mutant flipping the condition cannot live in the arm this case does not
	// drive.
	with, _ := mustBuild(t, relRecord4(), 1)
	if !optionPresent(t, with, wire.OptClientID) {
		t.Error("the same builder wrote no option 61 for a record that HAS an identity: this case now passes for the wrong reason")
	}
}

// optionPresent walks the encoded option area and reports whether code appears
// as a TLV, independently of wire.Decode's map.
//
// Two readings of one datagram, and the second one exists because the first
// cannot tell an absent option from a present empty one in every direction.
func optionPresent(t *testing.T, payload []byte, code wire.OptionCode) bool {
	t.Helper()
	const optionsStart = 240
	if len(payload) < optionsStart {
		t.Fatalf("the datagram is %d octets, shorter than the fixed header", len(payload))
	}
	b := payload[optionsStart:]
	for i := 0; i < len(b); {
		switch c := wire.OptionCode(b[i]); c {
		case wire.OptEnd:
			return false
		case wire.OptPad:
			i++
		default:
			if i+1 >= len(b) {
				t.Fatalf("option %s at %d has no length octet", c, i)
			}
			if c == code {
				return true
			}
			i += 2 + int(b[i+1])
		}
	}
	return false
}

// TestAReboundRecordReleasesTheAddressItHoldsNow is the renumbering shape.
//
// A record is one BINDING ATTEMPT and outlives a restart, so the address it
// folds to is not the address it started with. A builder that read an earlier
// field, a Params snapshot or a journal entry would release an address the
// server has since given to somebody else — and section 4.3.4 says what the
// server then does with it: "Upon receipt of a DHCPRELEASE message, the server
// marks the network address as not allocated."
func TestAReboundRecordReleasesTheAddressItHoldsNow(t *testing.T) {
	const first, second = "192.168.99.10", "192.168.99.211"

	rec, err := Fold(Record{}, RecordEvent{
		ID: "rec-rebind", Seq: 1, Op: OpCreate, Scope: "net-a", Family: FamilyV4,
		CHAddr: append([]byte(nil), relCHAddr...), Identity: append([]byte(nil), relIdentity4...),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if rec, err = Fold(rec, RecordEvent{ID: "rec-rebind", Seq: 2, Op: OpBind, Family: FamilyV4}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	for i, addr := range []string{first, second} {
		rec, err = Fold(rec, RecordEvent{
			ID: "rec-rebind", Seq: uint64(3 + i), Op: OpLease, Family: FamilyV4,
			Lease: &Lease{
				Addr:     netip.MustParsePrefix(addr + "/24"),
				ServerID: netip.MustParseAddr(relServer4),
			},
		})
		if err != nil {
			t.Fatalf("lease %s: %v", addr, err)
		}
	}

	payload, _ := mustBuild(t, rec, 1)
	msg, err := wire.Decode(payload)
	if err != nil {
		t.Fatalf("the datagram does not decode: %v", err)
	}
	if msg.CIAddr.String() != second {
		t.Errorf("ciaddr = %s, want the address the record holds now, %s", msg.CIAddr, second)
	}
	// Not merely "the new one is in ciaddr": the OLD one must be nowhere in
	// the datagram at all, because a builder that wrote it into sname, file or
	// an option would satisfy the line above.
	old := netip.MustParseAddr(first).As4()
	if bytes.Contains(payload, old[:]) {
		t.Errorf("the pre-rebind address %s appears in the datagram: % x", first, payload)
	}
}

// TestTheReleasedAddressIsTheHostAddressAndNotTheSubnet holds Lease.Addr's
// shape apart from its value. It is a netip.Prefix, and Masked().Addr() on it
// is the network base — a binding no server has ever held.
func TestTheReleasedAddressIsTheHostAddressAndNotTheSubnet(t *testing.T) {
	rec := relRecord4()
	rec.Lease.Addr = netip.MustParsePrefix("192.168.99.84/16")

	payload, _ := mustBuild(t, rec, 1)
	msg, err := wire.Decode(payload)
	if err != nil {
		t.Fatalf("the datagram does not decode: %v", err)
	}
	if msg.CIAddr.String() != "192.168.99.84" {
		t.Errorf("ciaddr = %s, want the host address %s and not the base Masked() would give", msg.CIAddr, relAddr4)
	}
}

// TestAV6ReleaseCarriesSectionEighteenTwoSevensThreeMustOptions is RFC 9915
// section 18.2.7 read as a checklist of MUSTs, each one its own assertion.
//
// "The client MUST include a Server Identifier option (see Section 21.3) in
// the Renew message, identifying the server that allocated the lease(s)." —
// the text says Renew inside the Release section and is quoted as written.
// "The client MUST include a Client Identifier option (see Section 21.2) to
// identify itself to the server."
// "The client MUST include an Elapsed Time option (see Section 21.9) to
// indicate how long the client has been trying to complete the current DHCP
// message exchange."
func TestAV6ReleaseCarriesSectionEighteenTwoSevensThreeMustOptions(t *testing.T) {
	payload, dst := mustBuild(t, relRecord6(), 0x00AABBCC)

	msg, err := wire.DecodeV6(payload)
	if err != nil {
		t.Fatalf("the datagram does not decode: %v", err)
	}
	if msg.Type != wire.MsgRelease6 {
		t.Errorf("message type = %s, want %s", msg.Type, wire.MsgRelease6)
	}

	cid, ok := msg.Options.First(wire.OptV6ClientID)
	if !ok {
		t.Fatal("no Client Identifier option; section 18.2.7 makes it a MUST")
	}
	// THE DUID ALONE. The record's Identity is the DUID and the IAID
	// concatenated, and a Client Identifier carrying both is a DUID no server
	// has ever seen — which section 11 leaves no way to detect, since a DUID
	// is opaque and compared only for equality.
	if !bytes.Equal(cid, relDUID) {
		t.Errorf("Client Identifier = %x, want the DUID alone %x", cid, relDUID)
	}
	iaidOctets := relIdentity6()[len(relDUID):]
	if bytes.Contains(cid, iaidOctets) {
		t.Errorf("the Client Identifier contains the IAID octets %x: %x", iaidOctets, cid)
	}

	sid, ok := msg.Options.First(wire.OptV6ServerID)
	if !ok {
		t.Fatal("no Server Identifier option; section 18.2.7 makes it a MUST")
	}
	if !bytes.Equal(sid, relServerDUID) {
		t.Errorf("Server Identifier = %x, want the record's %x", sid, relServerDUID)
	}

	el, ok := msg.Options.First(wire.OptV6ElapsedTime)
	if !ok {
		t.Fatal("no Elapsed Time option; section 18.2.7 makes it a MUST")
	}
	if len(el) != 2 || el[0] != 0 || el[1] != 0 {
		t.Errorf("Elapsed Time = %x, want 0: this exchange begins at this datagram", el)
	}

	// RFC 9915 section 7.2: "Servers and relay agents MUST listen for DHCP
	// messages on UDP port 547.  Therefore, clients MUST send DHCP messages to
	// UDP destination port 547."  Section 7.1 names the group.
	want := netip.AddrPortFrom(wire.AllDHCPRelayAgentsAndServers, 547)
	if dst != want {
		t.Errorf("destination = %s, want %s", dst, want)
	}
}

// TestAV6ReleaseNamesTheLeaseInsideTheIA is section 18.2.7's "The client
// includes options containing the IAs for the leases it is releasing in the
// "options" field.  The leases to be released MUST be included in the IAs."
//
// An IA_NA with the right IAID and nothing inside it is a Release that names
// no lease, and it is the shape a builder falls into by encoding the IA before
// it has the address. dnsmasq answers it with a per-IA status and leaves the
// binding alone, which from this side is indistinguishable from success.
func TestAV6ReleaseNamesTheLeaseInsideTheIA(t *testing.T) {
	payload, _ := mustBuild(t, relRecord6(), 1)
	msg, err := wire.DecodeV6(payload)
	if err != nil {
		t.Fatalf("the datagram does not decode: %v", err)
	}

	ias, err := msg.Options.IANAs()
	if err != nil {
		t.Fatalf("reading the IA_NA options: %v", err)
	}
	if len(ias) != 1 {
		t.Fatalf("the Release carries %d IA_NA option(s), want exactly one", len(ias))
	}
	if ias[0].IAID != relIAID {
		t.Errorf("IAID = %#x, want the record's %#x", ias[0].IAID, relIAID)
	}

	addrs, err := ias[0].Options.Addrs()
	if err != nil {
		t.Fatalf("reading the IA Address options: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("the IA_NA encloses %d IA Address option(s), want exactly one", len(addrs))
	}
	if addrs[0].Addr.String() != relAddr6 {
		t.Errorf("the released address = %s, want %s", addrs[0].Addr, relAddr6)
	}

	// The IAID is four octets in network byte order (section 21.4). A
	// byte-reversed one is a Release for a binding that does not exist, and
	// section 7.1's measurement says the server then leaves the lease alone.
	// This reads the field where it sits rather than trusting the decoder that
	// produced the struct above.
	wantIAID := binary.BigEndian.AppendUint32(nil, relIAID)
	if !bytes.Contains(payload, wantIAID) {
		t.Errorf("the big-endian IAID %x is not in the datagram: % x", wantIAID, payload)
	}
}

// TestAV6ReleaseUsesTheLowTwentyFourBitsOfTheTransactionID pins what the doc
// says about a three-octet field being handed a 32-bit value (section 8).
func TestAV6ReleaseUsesTheLowTwentyFourBitsOfTheTransactionID(t *testing.T) {
	payload, _ := mustBuild(t, relRecord6(), 0xAABBCCDD)
	msg, err := wire.DecodeV6(payload)
	if err != nil {
		t.Fatalf("the datagram does not decode: %v", err)
	}
	if msg.XID != 0xBBCCDD {
		t.Errorf("transaction-id = %#x, want the low 24 bits %#x", msg.XID, 0xBBCCDD)
	}

	// And that it is the CALLER's, which is what makes two releases in one
	// second two datagrams rather than one to anything that deduplicates.
	other, _ := mustBuild(t, relRecord6(), 0xAABBCCDE)
	if bytes.Equal(payload, other) {
		t.Error("two builds with different transaction ids produced identical datagrams")
	}
}

// TestBuildingAReleaseDoesNotWriteThroughTheRecord holds the one direction a
// build can damage its caller. Record is taken by value and its Identity,
// CHAddr and ServerDUID are slices, so the caller keeps every octet the
// builder can reach.
//
// It replaced a test that rewrote the record after the build and compared two
// datagrams. That could not fail: MEASURED in wire/codec.go and
// wire/dhcpv6.go, both encoders copy into a buffer they allocate, so a payload
// cannot alias an option's Data and the defensive copies this package used to
// make were unobservable. They are gone with the assertion that never ran.
func TestBuildingAReleaseDoesNotWriteThroughTheRecord(t *testing.T) {
	for _, mk := range []func() Record{relRecord4, relRecord6} {
		rec := mk()
		id := append([]byte(nil), rec.Identity...)
		ch := append([]byte(nil), rec.CHAddr...)
		duid := append([]byte(nil), rec.Lease.ServerDUID...)

		if _, _, err := BuildRelease(rec, 7); err != nil {
			t.Fatalf("BuildRelease: %v", err)
		}

		if !bytes.Equal(id, rec.Identity) {
			t.Errorf("the build rewrote the record's identity: % x became % x", id, rec.Identity)
		}
		if !bytes.Equal(ch, rec.CHAddr) {
			t.Errorf("the build rewrote the record's chaddr: % x became % x", ch, rec.CHAddr)
		}
		if !bytes.Equal(duid, rec.Lease.ServerDUID) {
			t.Errorf("the build rewrote the record's server DUID: % x became % x", duid, rec.Lease.ServerDUID)
		}
	}
}

// TestARecordThatCannotNameItsBindingIsRefused is the refusal set, one field
// removed at a time, and the reason it is a refusal rather than a best effort.
//
// A release nothing answers cannot be retried on a failure the sender did not
// notice. A DHCPRELEASE with a zero server identifier has nowhere to go, and
// RFC 2131 section 4.4.4 gives it no broadcast fallback — broadcast is what
// the same paragraph gives the DHCPDECLINE. A v6 Release missing its Client
// Identifier or its Server Identifier breaks a section 18.2.7 MUST. Every one
// of those, sent anyway, is a caller told the address is free.
func TestARecordThatCannotNameItsBindingIsRefused(t *testing.T) {
	cases := []struct {
		name string
		rec  func() Record
		want error
	}{
		{"a record that never bound", func() Record { return Record{} }, ErrReleaseFamily},
		{"v4 with no address", func() Record { r := relRecord4(); r.Lease.Addr = netip.Prefix{}; return r }, ErrReleaseNoAddr},
		{"v4 with no server", func() Record { r := relRecord4(); r.Lease.ServerID = netip.Addr{}; return r }, ErrReleaseNoServer},
		{"v4 holding the unspecified address", func() Record {
			r := relRecord4()
			r.Lease.Addr = netip.MustParsePrefix("0.0.0.0/32")
			return r
		}, ErrReleaseNoAddr},
		{"v4 with neither a client identifier nor a chaddr", func() Record {
			r := relRecord4()
			r.Identity = nil
			r.CHAddr = nil
			return r
		}, ErrReleaseNoIdentity},
		{"v4 whose server is the unspecified address", func() Record {
			r := relRecord4()
			r.Lease.ServerID = netip.IPv4Unspecified()
			return r
		}, ErrReleaseNoServer},
		{"v4 holding a v6 address", func() Record {
			r := relRecord4()
			r.Lease.Addr = netip.MustParsePrefix(relAddr6 + "/128")
			return r
		}, ErrReleaseNoAddr},
		{"v6 with no address", func() Record { r := relRecord6(); r.Lease.Addr = netip.Prefix{}; return r }, ErrReleaseNoAddr},
		{"v6 holding the unspecified address", func() Record {
			r := relRecord6()
			r.Lease.Addr = netip.MustParsePrefix("::/128")
			return r
		}, ErrReleaseNoAddr},
		{"v6 holding a v4-mapped address", func() Record {
			r := relRecord6()
			r.Lease.Addr = netip.PrefixFrom(netip.AddrFrom16(netip.MustParseAddr(relAddr4).As16()), 128)
			return r
		}, ErrReleaseNoAddr},
		{"v6 with no server DUID", func() Record { r := relRecord6(); r.Lease.ServerDUID = nil; return r }, ErrReleaseNoServer},
		{"v6 with no identity", func() Record { r := relRecord6(); r.Identity = nil; return r }, ErrReleaseNoIdentity},
		{"v6 with an identity that is only an IAID", func() Record {
			r := relRecord6()
			r.Identity = binary.BigEndian.AppendUint32(nil, relIAID)
			return r
		}, ErrReleaseNoIdentity},
		{"v6 whose two IAIDs disagree", func() Record { r := relRecord6(); r.Lease.IAID = relIAID + 1; return r }, ErrReleaseIAIDMismatch},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload, dst, err := BuildRelease(tc.rec(), 1)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if payload != nil || dst.IsValid() {
				t.Errorf("a refusal produced a datagram of %d octet(s) for %s", len(payload), dst)
			}
		})
	}

	// The other direction, once, or the whole table above is satisfied by a
	// function that refuses everything.
	if _, _, err := BuildRelease(relRecord4(), 1); err != nil {
		t.Errorf("the complete v4 record was refused: %v", err)
	}
	if _, _, err := BuildRelease(relRecord6(), 1); err != nil {
		t.Errorf("the complete v6 record was refused: %v", err)
	}
}

// TestTheTwoIAIDsAreComparedRatherThanChosenBetween is the "one fact derived
// twice" refusal on its own, because it is the only refusal here that exists
// to stop a SILENT choice rather than to stop a missing field.
//
// The record carries the IAID in two places: the trailing four octets of
// Identity, which are the bytes as sent, and Lease.IAID, which is the value
// the exchange ran with. A builder that reads either one alone works until
// they differ and then releases a binding that does not exist — which the
// server answers with a per-IA "no binding found" and no change to the lease,
// so the caller sees a success.
func TestTheTwoIAIDsAreComparedRatherThanChosenBetween(t *testing.T) {
	rec := relRecord6()
	rec.Identity = binary.BigEndian.AppendUint32(append([]byte(nil), relDUID...), 0xDEADBEEF)

	_, _, err := BuildRelease(rec, 1)
	if !errors.Is(err, ErrReleaseIAIDMismatch) {
		t.Fatalf("error = %v, want %v", err, ErrReleaseIAIDMismatch)
	}
	// Both values named, so the refusal tells an operator which of the two
	// records is wrong rather than that something is.
	for _, want := range []string{"3735928559", "168496141"} {
		if !containsText(err.Error(), want) {
			t.Errorf("the refusal %q does not name %s", err, want)
		}
	}
}

func containsText(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }
