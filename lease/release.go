// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/claymore666/dhcp-golib/wire"
)

// BuildRelease renders the one release datagram that gives a record's lease
// back, and the address it goes to. For a record whose prefixes came from
// another server (PrefixServerDUID) it is the IA_NA's datagram alone, and the
// IA_PD's is BuildReleases'.
//
// It is the RECORD path, and it exists beside proto.Machine's release because
// the two answer different questions. The machine releases a lease it is
// holding, from a client that is still bound, with a socket in the namespace
// the lease was acquired in. This builds a release for a lease whose namespace
// is GONE — the container was removed, the link went with it, and all that is
// left is the record. There is no machine to step and no client to stop.
//
// THE SOURCE ADDRESS IS NOT HERE. That is the difference, and it is the whole
// reason this is a second path rather than a widening of the first one: the
// machine pins the source to the released address, and a host sending on
// behalf of a container that no longer exists cannot. Who the datagram comes
// from is the caller's, and runtime.SendRelease is where it is supplied.
//
// ONE DATAGRAM, and that is a choice this library is allowed to make rather
// than a corner cut. RFC 9915 section 18.2.7: "Because Release messages may be
// lost, the client should retransmit the Release if no Reply is received.
// However, there are scenarios where the client may not wish to wait for the
// normal retransmission timeout before giving up (e.g., on power down).
// Implementations SHOULD retransmit one or more times but MAY choose to
// terminate the retransmission procedure early." A host giving back an address
// for a container that is already gone is that scenario. RFC 2131 section
// 4.4.6 says the same of v4 from the other side: "Note that the correct
// operation of DHCP does not depend on the transmission of DHCPRELEASE
// messages."
//
// xid is the transaction id, caller-supplied so that this stays a pure
// function of its inputs and a golden-bytes test is possible — the reason
// runtime.BuildIPv4UDP takes its ident. For a v6 record the low 24 octets'
// worth of bits are used, because RFC 9915 section 8's transaction-id field is
// three octets; nothing reads the reply here, so a truncated value costs
// nothing but is stated rather than left to be found.
//
// BOUND: this renders the DHCP payload and the destination. It does not build
// an IP or UDP header, does not resolve anything and does not know what the
// source will be.
//
// BOUND: it reads the record's binding and not the record's phase. Whether the
// lease is still held, has expired, or has been taken over by something else
// is the caller's question, and a record that was re-bound renders the address
// it holds now. Nothing here decides that a release is due.
func BuildRelease(rec Record, xid uint32) ([]byte, netip.AddrPort, error) {
	switch rec.Family {
	case FamilyV4:
		return buildRelease4(rec, xid)
	case FamilyV6:
		return buildRelease6(rec, xid)
	default:
		return nil, netip.AddrPort{}, fmt.Errorf("%w: %s", ErrReleaseFamily, rec.Family)
	}
}

// ReleaseDatagram is one datagram of a record's release and where it goes.
type ReleaseDatagram struct {
	Payload []byte
	Dest    netip.AddrPort
}

// BuildReleases is BuildRelease for every server that allocated the record's
// leases, RFC 8415 section 18.2.7: a second datagram, with xid+1 and the IA_PD
// alone, goes to PrefixServerDUID when it is set (claymore666/dhcp-golib#70).
func BuildReleases(rec Record, xid uint32) ([]ReleaseDatagram, error) {
	payload, dst, err := BuildRelease(rec, xid)
	if err != nil {
		return nil, err
	}
	out := []ReleaseDatagram{{Payload: payload, Dest: dst}}
	if rec.Family != FamilyV6 || !splitRecord(rec.Lease) {
		return out, nil
	}
	pd, err := releasePD(rec.Lease)
	if err != nil || pd == nil {
		return out, err
	}
	msg := &wire.MessageV6{
		Type: wire.MsgRelease6,
		XID:  (xid + 1) & (wire.MaxXID6 - 1),
		Options: wire.OptionsV6{
			{Code: wire.OptV6ClientID, Data: rec.Identity[:len(rec.Identity)-iaidLen]},
			{Code: wire.OptV6ServerID, Data: rec.Lease.PrefixServerDUID},
			*pd,
			{Code: wire.OptV6ElapsedTime, Data: []byte{0, 0}},
		},
	}
	payload, err = wire.EncodeV6(msg)
	if err != nil {
		return nil, err
	}
	return append(out, ReleaseDatagram{Payload: payload, Dest: dst}), nil
}

// splitRecord reports whether the record's prefixes name a server of their
// own, RFC 8415 section 18.2.7 (claymore666/dhcp-golib#70).
func splitRecord(l Lease) bool {
	return len(l.PrefixServerDUID) > 0 && !bytes.Equal(l.PrefixServerDUID, l.ServerDUID)
}

// The refusals BuildRelease returns, each its own value so that a caller can
// tell "this record was never going to work" from "this one lost a field".
//
// They are refusals and not best-effort datagrams for one reason: a release
// nothing answers cannot be retried on a failure the sender did not notice.
// A DHCPRELEASE carrying a zero server identifier, or broadcast because there
// was no server to unicast to, reaches a server that either ignores it or acts
// on the wrong binding, and in both cases the caller is told it succeeded.
var (
	// ErrReleaseFamily is a record whose family is neither v4 nor v6. A record
	// that never bound has no lease to give back.
	ErrReleaseFamily = errors.New("lease: a release needs a record in a known family")

	// ErrReleaseNoAddr is a record with no leased address, or one whose
	// address is in the other family.
	ErrReleaseNoAddr = errors.New("lease: the record carries no leased address to release")

	// ErrReleaseNoServer is a record that names no server.
	//
	// RFC 2131 section 4.4.4: "The client unicasts DHCPRELEASE messages to the
	// server." There is no broadcast fallback in that sentence — broadcast is
	// what the same paragraph gives DHCPDECLINE — so a record with no server
	// identifier has nowhere to send and is refused rather than shouted at the
	// segment. RFC 9915 section 18.2.7 makes the Server Identifier option a
	// MUST on the v6 side.
	ErrReleaseNoServer = errors.New("lease: the record names no server to release to")

	// ErrReleaseNoIdentity is a record that cannot name its client.
	//
	// On v6 that is an identity too short to carry a DUID and an IAID. RFC
	// 9915 section 18.2.7: "The client MUST include a Client Identifier option
	// (see Section 21.2) to identify itself to the server."
	//
	// On v4 it is a record with NEITHER a client identifier NOR a chaddr. RFC
	// 2131 section 3.1(6): "The client identifies the lease to be released
	// with its 'client identifier', or 'chaddr' and network address in the
	// DHCPRELEASE message." The sentence offers two terms and a record with
	// neither has no way to name the binding, so the datagram would go out
	// with a zero chaddr, an hlen of zero and no option 61, and the caller
	// would be told the address was given back.
	ErrReleaseNoIdentity = errors.New("lease: the record carries nothing that identifies the binding")

	// ErrReleaseIAIDMismatch is a v6 record whose two IAIDs disagree.
	//
	// The record stores the IAID twice — as the trailing four octets of
	// Identity, which is "the DUID and IAID as sent", and as Lease.IAID, which
	// is the value the exchange ran with. One fact derived twice has two
	// answers the moment either is written differently, and the looser
	// derivation would decide silently: a Release whose IAID is wrong is
	// answered by dnsmasq with a per-IA "no binding found" and leaves the
	// lease exactly where it was, which is indistinguishable from a release
	// nobody sent. So the two are compared and a disagreement is refused with
	// both values named.
	ErrReleaseIAIDMismatch = errors.New("lease: the record's two IAIDs disagree")
)

// releaseMessage is option 56's text, RFC 2131 Table 5's SHOULD. It is the
// only place a server's log can say why the client did it, and it says the
// host did it rather than the client so that the two paths are told apart in
// somebody else's log.
const releaseMessage = "released by the host from the lease record"

func buildRelease4(rec Record, xid uint32) ([]byte, netip.AddrPort, error) {
	addr := rec.Lease.Addr.Addr()
	if !addr.Is4() || addr.IsUnspecified() {
		return nil, netip.AddrPort{}, fmt.Errorf("%w: %s", ErrReleaseNoAddr, rec.Lease.Addr)
	}
	sid := rec.Lease.ServerID
	if !sid.Is4() || sid.IsUnspecified() {
		return nil, netip.AddrPort{}, fmt.Errorf("%w: option 54 is %s", ErrReleaseNoServer, sid)
	}

	if len(rec.Identity) == 0 && len(rec.CHAddr) == 0 {
		return nil, netip.AddrPort{}, fmt.Errorf("%w: no client identifier and no chaddr", ErrReleaseNoIdentity)
	}

	msg := &wire.Message{
		Op:      wire.BootRequest,
		HType:   wire.HTypeEthernet,
		XID:     xid,
		CHAddr:  rec.CHAddr,
		Options: wire.Options{},
	}
	msg.SetType(wire.MsgRelease)

	// RFC 2131 section 3.1(6): "The client identifies the lease to be released
	// with its 'client identifier', or 'chaddr' and network address in the
	// DHCPRELEASE message."  The address is the 'ciaddr' FIELD and not the
	// requested-IP option: Table 5 makes option 50 a MUST NOT in a
	// DHCPRELEASE, which is the other way round from a DHCPDECLINE.
	//
	// Addr() and not Masked(): Lease.Addr is a prefix, and its base address is
	// the subnet, which is a binding no server holds.
	msg.CIAddr = addr

	sv := sid.As4()
	msg.Options[wire.OptServerID] = sv[:]
	msg.Options[wire.OptMessage] = []byte(releaseMessage)

	// THE IDENTITY IS REPLAYED INCLUDING ITS ABSENCE. RFC 2131 section 3.1(6):
	// "If the client used a 'client identifier' when it obtained the lease, it
	// MUST use the same 'client identifier' in the DHCPRELEASE message." The
	// condition is the operative word. A server looks the binding up by
	// client-identifier first and falls back to chaddr for a lease that has
	// none, so an option 61 invented here is a lookup on a key the acquisition
	// never used.
	//
	// THE ABSENCE HAS OUTSIDE EVIDENCE, and it took a fixture built for it.
	// MEASURED against dnsmasq 2.91 in TestAReleaseIsLookedUpOnTheKeyTheAcquisitionUsed:
	// a neighbour holds a lease under exactly the identifier an invention
	// would produce, dnsmasq's lookup then lands on the neighbour's binding,
	// that binding's address is not the released one, and dnsmasq answers
	// "unknown lease" and gives nothing back. The encoded bytes are the first
	// observer and that test is the second.
	if len(rec.Identity) > 0 {
		msg.Options[wire.OptClientID] = rec.Identity
	}

	payload, err := wire.Encode(msg)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	return payload, netip.AddrPortFrom(sid, serverPort4), nil
}

// The ports the two families' servers listen on. RFC 2131 section 4.1 for the
// first and RFC 9915 section 7.2 for the second: "Servers and relay agents
// MUST listen for DHCP messages on UDP port 547.  Therefore, clients MUST send
// DHCP messages to UDP destination port 547."
//
// Ring 3 declares the same two numbers as runtime.ServerPort and
// runtime.ServerPort6 and cannot lend them downward. That is one fact derived
// twice, so it is CHECKED rather than left alone:
// TestTheReleaseDestinationIsTheRingsOwnServerPort holds the destination this
// package returns against ring 3's constants.
const (
	serverPort4 = 67
	serverPort6 = 547
)

// iaidLen is how many octets of a v6 Identity are the IAID: RFC 9915 section
// 21.4's IAID field is four.
const iaidLen = 4

func buildRelease6(rec Record, xid uint32) ([]byte, netip.AddrPort, error) {
	addr := rec.Lease.Addr.Addr()
	if !addr.Is6() || addr.Is4In6() || addr.IsUnspecified() {
		return nil, netip.AddrPort{}, fmt.Errorf("%w: %s", ErrReleaseNoAddr, rec.Lease.Addr)
	}
	if len(rec.Lease.ServerDUID) == 0 {
		return nil, netip.AddrPort{}, fmt.Errorf("%w: the server DUID is empty", ErrReleaseNoServer)
	}
	if len(rec.Identity) <= iaidLen {
		return nil, netip.AddrPort{}, fmt.Errorf("%w: %d octet(s), and %d of them are the IAID",
			ErrReleaseNoIdentity, len(rec.Identity), iaidLen)
	}

	duid := rec.Identity[:len(rec.Identity)-iaidLen]
	sent := binary.BigEndian.Uint32(rec.Identity[len(rec.Identity)-iaidLen:])
	if sent != rec.Lease.IAID {
		return nil, netip.AddrPort{}, fmt.Errorf("%w: Identity ends in %d and Lease.IAID is %d",
			ErrReleaseIAIDMismatch, sent, rec.Lease.IAID)
	}

	// §18.2.7: "The client includes options containing the IAs for the leases
	// it is releasing in the "options" field.  The leases to be released MUST
	// be included in the IAs." So the IA_NA carries the IA Address, and an
	// IA_NA with nothing in it is a Release that names no lease.
	//
	// The lifetimes are zero. §21.6's preferred and valid are what the client
	// is asking to keep, and it is asking to keep nothing.
	ia, err := wire.EncodeIAAddr(&wire.IAAddr{Addr: addr})
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	iana, err := wire.EncodeIANA(&wire.IANA{
		IAID:    rec.Lease.IAID,
		Options: wire.OptionsV6{{Code: wire.OptV6IAAddr, Data: ia}},
	})
	if err != nil {
		return nil, netip.AddrPort{}, err
	}

	opts := wire.OptionsV6{
		// §18.2.7's three MUST-include options, and the Client Identifier
		// is the DUID ALONE. The record's Identity is the DUID and the
		// IAID as sent, concatenated; the IAID belongs in the IA_NA above
		// and a Client Identifier carrying both is a DUID no server has
		// ever seen.
		{Code: wire.OptV6ClientID, Data: duid},
		{Code: wire.OptV6ServerID, Data: rec.Lease.ServerDUID},
		{Code: wire.OptV6IANA, Data: iana},
	}

	// A record that holds temporary addresses or a delegated prefix gives
	// them back in the same datagram, IA_TA then IA_PD after the IA_NA: the
	// leases to be released MUST be in the IAs (§18.2.7), and a server that
	// is never told keeps the rows until their valid lifetimes end
	// (dhcp-golib#60). Neither held, neither sent, and the datagram is the
	// one v1.4.0 built.
	ta, err := releaseTA(rec.Lease)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	if ta != nil {
		opts = append(opts, *ta)
	}
	pd, err := releasePD(rec.Lease)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	if pd != nil && !splitRecord(rec.Lease) {
		opts = append(opts, *pd)
	}

	// §21.9's elapsed time, "how long the client has been trying to
	// complete the current DHCP message exchange". This exchange begins at
	// this datagram, so it is zero, and there is no second datagram for it
	// to grow in.
	opts = append(opts, wire.OptionV6{Code: wire.OptV6ElapsedTime, Data: []byte{0, 0}})

	msg := &wire.MessageV6{
		Type:    wire.MsgRelease6,
		XID:     xid & (wire.MaxXID6 - 1),
		Options: opts,
	}

	payload, err := wire.EncodeV6(msg)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	// §7.1: "All_DHCP_Relay_Agents_and_Servers (ff02::1:2) A link-scoped
	// multicast address used by a client to communicate with neighboring
	// (i.e., on-link) relay agents and servers." §16 obsoleted the server's
	// unicast address, so a Release goes where every other client message
	// goes, and the server DUID rather than an address is what names the
	// server it is for.
	return payload, netip.AddrPortFrom(wire.AllDHCPRelayAgentsAndServers, serverPort6), nil
}

// releasePD is the IA_PD of a Release: the record's IAID and one IA Prefix per
// delegated prefix, lifetimes zero as in the IA_NA (RFC 8415 §18.2.7, §21.22).
// An entry that cannot be on the wire (invalid, not IPv6, v4-mapped, length 0)
// is left out rather than failing the Release of the address; no usable entry
// returns nil (dhcp-golib#60).
func releasePD(l Lease) (*wire.OptionV6, error) {
	ia := &wire.IAPD{IAID: l.IAID}
	for _, p := range l.Prefixes {
		pfx := p.Addr
		if !pfx.IsValid() || !pfx.Addr().Is6() || pfx.Addr().Is4In6() || pfx.Bits() < 1 {
			continue
		}
		v, err := wire.EncodeIAPrefix(&wire.IAPrefix{Prefix: pfx})
		if err != nil {
			return nil, err
		}
		ia.Options = append(ia.Options, wire.OptionV6{Code: wire.OptV6IAPrefix, Data: v})
	}
	if len(ia.Options) == 0 {
		return nil, nil
	}
	v, err := wire.EncodeIAPD(ia)
	if err != nil {
		return nil, err
	}
	return &wire.OptionV6{Code: wire.OptV6IAPD, Data: v}, nil
}

// releaseTA is the IA_TA of a Release: the record's IAID and one IA Address
// per temporary address, lifetimes zero (RFC 8415 §18.2.7, §21.5). An entry
// that cannot be on the wire (invalid, v4-mapped, unspecified) is left out
// rather than failing the Release of the stable address; none usable returns
// nil (dhcp-golib#60).
func releaseTA(l Lease) (*wire.OptionV6, error) {
	ia := &wire.IATA{IAID: l.IAID}
	for _, t := range l.TempAddrs {
		a := t.Addr.Addr()
		if !t.Addr.IsValid() || !a.Is6() || a.Is4In6() || a.IsUnspecified() {
			continue
		}
		v, err := wire.EncodeIAAddr(&wire.IAAddr{Addr: a})
		if err != nil {
			return nil, err
		}
		ia.Options = append(ia.Options, wire.OptionV6{Code: wire.OptV6IAAddr, Data: v})
	}
	if len(ia.Options) == 0 {
		return nil, nil
	}
	v, err := wire.EncodeIATA(ia)
	if err != nil {
		return nil, err
	}
	return &wire.OptionV6{Code: wire.OptV6IATA, Data: v}, nil
}
