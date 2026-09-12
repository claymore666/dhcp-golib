// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// RFC 9915 §18.2.11 on a real link, against a server written here.
//
// WHY NOT dnsmasq. MEASURED 2026-09-11 against the 2.91 sources: a
// case-insensitive grep for "reconfigure" over src/ returns exactly two lines,
// both in src/dhcp6-protocol.h — "#define DHCP6RECONFIGURE 10" and "#define
// OPTION6_RECONFIGURE_MSG 19". Two constants and no code: nothing builds the
// message, nothing sends it, and no log line mentions it. dnsmasq cannot
// reconfigure a client, so a proof that used it could only ever show the
// client doing nothing. The server below is the smallest thing that can send
// one.
//
// THE DIGEST IS COMPUTED HERE, BY HAND. §20.4.3's HMAC-MD5 is the whole of the
// authentication rule; a fixture that signed with wire.RKAPVerify's own
// helpers would prove that the library agrees with itself, which is the one
// thing an authentication proof must not rest on. rfc2104HMACMD5 below is
// RFC 2104's construction written out from the RFC.

const (
	// The lease the hand-built server hands out, inside the fixture prefix
	// and outside the range dnsmasq is configured to serve, so nothing else
	// on this link can be holding it.
	test6ReconfAddr = "fd00:99::5a"
	// T1 and T2 are long enough that no timer this test does not fire can
	// produce the Renew it is looking for.
	test6ReconfT1 = 3000
	test6ReconfT2 = 4000
	// test6ReconfWait is how long a step waits for a datagram that should
	// arrive. It bounds a failure rather than a success: every wait that
	// matters is for something the client sends immediately.
	test6ReconfWait = 20 * time.Second
	// test6ReconfSilence is how long the forged-Reconfigure proof waits to be
	// sure nothing came. It is the other direction and is deliberately much
	// shorter than a client's own T1.
	test6ReconfSilence = 2 * time.Second
)

// test6ReconfKey is §20.4.1's 128-bit reconfigure key this server hands the
// client and signs with.
var test6ReconfKey = []byte{
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
}

// test6ReconfServerDUID is the server's own DUID, a DUID-LL over a locally
// administered address.
var test6ReconfServerDUID = []byte{0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0xc0, 0x5e}

// ------------------------------------------------------------ RFC 2104 --

// rfc2104HMACMD5 is RFC 2104 §2, written out rather than called.
//
// RFC 2104: "(1) append zeros to the end of K to create a B byte string ...
// (2) XOR (bitwise exclusive-OR) the B byte string computed in step (1) with
// ipad; (3) append the stream of data 'text' to the B byte string resulting
// from step (2); (4) apply H to the stream generated in step (3); (5) XOR
// (bitwise exclusive-OR) the B byte string computed in step (1) with opad;
// (6) append the H result from step (4) to the B byte string resulting from
// step (5); (7) apply H to the stream generated in step (6) and output the
// result." B is 64 for MD5, ipad is the byte 0x36 repeated B times and opad
// the byte 0x5C repeated B times.
func rfc2104HMACMD5(key, text []byte) []byte {
	const b = 64
	k := make([]byte, b)
	if len(key) > b {
		sum := md5.Sum(key)
		copy(k, sum[:])
	} else {
		copy(k, key)
	}
	inner := make([]byte, 0, b+len(text))
	outerKey := make([]byte, b)
	for i := 0; i < b; i++ {
		inner = append(inner, k[i]^0x36)
		outerKey[i] = k[i] ^ 0x5c
	}
	inner = append(inner, text...)
	innerSum := md5.Sum(inner)
	outer := append(append([]byte(nil), outerKey...), innerSum[:]...)
	sum := md5.Sum(outer)
	return sum[:]
}

// reconfDigestSpan locates §20.4.1's 16-octet Value in an encoded message, by
// walking §21.1's option area the way §21.11's layout describes it: code,
// length, then protocol, algorithm, RDM, eight octets of replay detection,
// then the authentication information whose first octet is the Type.
func reconfDigestSpan(raw []byte) (int, int, error) {
	for i := 4; i+4 <= len(raw); {
		code := int(raw[i])<<8 | int(raw[i+1])
		n := int(raw[i+2])<<8 | int(raw[i+3])
		i += 4
		if n > len(raw)-i {
			return 0, 0, fmt.Errorf("option %d overruns the message", code)
		}
		if code == int(wire.OptV6Auth) {
			start := i + 3 + 8 + 1
			return start, start + md5.Size, nil
		}
		i += n
	}
	return 0, 0, fmt.Errorf("no Authentication option in %x", raw)
}

// ------------------------------------------------- the hand-built server --

// handBuiltV6Server is a DHCPv6 server that speaks exactly enough of RFC 9915
// to lease one address and then reconfigure the client that holds it.
type handBuiltV6Server struct {
	fd     int
	t      *testing.T
	replay uint64
}

// newHandBuiltV6Server binds UDP port 547 on the server end of the fixture
// link and joins §7.1's All_DHCP_Relay_Agents_and_Servers group, which is
// where a client's Solicit goes.
func newHandBuiltV6Server(t *testing.T) *handBuiltV6Server {
	t.Helper()
	iface, err := net.InterfaceByName(test6ServerIf)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", test6ServerIf, err)
	}
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_UDP)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		t.Fatalf("SO_REUSEADDR: %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet6{Port: 547}); err != nil {
		t.Fatalf("bind [::]:547: %v", err)
	}
	mreq := &syscall.IPv6Mreq{Interface: uint32(iface.Index)}
	copy(mreq.Multiaddr[:], netip.MustParseAddr("ff02::1:2").AsSlice())
	if err := syscall.SetsockoptIPv6Mreq(fd, syscall.IPPROTO_IPV6, syscall.IPV6_JOIN_GROUP, mreq); err != nil {
		t.Fatalf("joining ff02::1:2 on %s: %v", test6ServerIf, err)
	}
	s := &handBuiltV6Server{fd: fd, t: t}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	return s
}

// next reads one DHCPv6 message, returning the client address it came from.
// ok is false when the wait elapsed with nothing arriving.
func (s *handBuiltV6Server) next(within time.Duration) (*wire.MessageV6, *syscall.SockaddrInet6, bool) {
	s.t.Helper()
	tv := syscall.NsecToTimeval(int64(within))
	if err := syscall.SetsockoptTimeval(s.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		s.t.Fatalf("SO_RCVTIMEO: %v", err)
	}
	buf := make([]byte, 2048)
	for {
		n, from, err := syscall.Recvfrom(s.fd, buf, 0)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			return nil, nil, false
		}
		if err != nil {
			s.t.Fatalf("recvfrom: %v", err)
		}
		sa, ok := from.(*syscall.SockaddrInet6)
		if !ok {
			s.t.Fatalf("a datagram arrived from %T", from)
		}
		msg, derr := wire.DecodeV6(buf[:n])
		if derr != nil {
			// Not a failure: anything else on this link that speaks to port
			// 547 is the fixture's problem and not the client's.
			s.t.Logf("the hand-built server ignored %d octets it could not decode: %v", n, derr)
			continue
		}
		return msg, sa, true
	}
}

// send puts raw on the wire to one client.
func (s *handBuiltV6Server) send(to *syscall.SockaddrInet6, raw []byte) {
	s.t.Helper()
	if err := syscall.Sendto(s.fd, raw, 0, to); err != nil {
		s.t.Fatalf("sendto: %v", err)
	}
}

// answer builds and sends a message of type typ carrying opts, to to.
func (s *handBuiltV6Server) answer(to *syscall.SockaddrInet6, typ wire.MessageTypeV6, xid uint32, opts ...wire.OptionV6) {
	s.t.Helper()
	raw, err := wire.EncodeV6(&wire.MessageV6{Type: typ, XID: xid, Options: opts})
	if err != nil {
		s.t.Fatalf("EncodeV6(%s): %v", typ, err)
	}
	s.send(to, raw)
}

// leaseOptions is the IA_NA this server hands out.
func (s *handBuiltV6Server) leaseOptions(t *testing.T, req *wire.MessageV6) []wire.OptionV6 {
	t.Helper()
	cid, ok := req.Options.First(wire.OptV6ClientID)
	if !ok {
		t.Fatalf("the client sent a %s with no Client Identifier", req.Type)
	}
	ias, err := req.Options.IANAs()
	if err != nil || len(ias) == 0 {
		t.Fatalf("the client sent a %s with no usable IA_NA: %v", req.Type, err)
	}
	av, err := wire.EncodeIAAddr(&wire.IAAddr{
		Addr:              netip.MustParseAddr(test6ReconfAddr),
		PreferredLifetime: test6ReconfT2 + 1000,
		ValidLifetime:     test6ReconfT2 + 2000,
	})
	if err != nil {
		t.Fatalf("EncodeIAAddr: %v", err)
	}
	iav, err := wire.EncodeIANA(&wire.IANA{
		IAID: ias[0].IAID, T1: test6ReconfT1, T2: test6ReconfT2,
		Options: []wire.OptionV6{{Code: wire.OptV6IAAddr, Data: av}},
	})
	if err != nil {
		t.Fatalf("EncodeIANA: %v", err)
	}
	return []wire.OptionV6{
		{Code: wire.OptV6ClientID, Data: cid},
		{Code: wire.OptV6ServerID, Data: test6ReconfServerDUID},
		{Code: wire.OptV6IANA, Data: iav},
	}
}

// lease6 runs the Solicit/Advertise/Request/Reply exchange and returns the
// client's address and its DUID. The Reply carries §20.4.1's Type 1
// authentication information, which is §20.4.2's key selection: "The server
// selects a reconfigure key for a client during the Request/Reply,
// Solicit/Reply, or Information-request/Reply message exchange."
func (s *handBuiltV6Server) lease6(t *testing.T) (*syscall.SockaddrInet6, []byte) {
	t.Helper()
	sol, from, ok := s.next(test6ReconfWait)
	if !ok {
		t.Fatal("no Solicit reached the hand-built server")
	}
	if sol.Type != wire.MsgSolicit {
		t.Fatalf("the first message was a %s, want a Solicit", sol.Type)
	}
	// §21.20's announcement, read from the wire rather than from the client's
	// own report: this is the half of AcceptReconfigure a server can see.
	if accept, err := sol.Options.ReconfigureAccept(); err != nil || !accept {
		t.Fatalf("the Solicit carries no Reconfigure Accept option (%v, %v) — §18.2.1", accept, err)
	}
	s.answer(from, wire.MsgAdvertise, sol.XID, s.leaseOptions(t, sol)...)

	req, from, ok := s.next(test6ReconfWait)
	if !ok {
		t.Fatal("no Request reached the hand-built server")
	}
	if req.Type != wire.MsgRequest6 {
		t.Fatalf("the second message was a %s, want a Request", req.Type)
	}
	if accept, err := req.Options.ReconfigureAccept(); err != nil || !accept {
		t.Fatalf("the Request carries no Reconfigure Accept option (%v, %v) — §18.2.2", accept, err)
	}
	key, err := wire.EncodeRKAPAuth(wire.RKAPTypeKey, test6ReconfKey, 0)
	if err != nil {
		t.Fatalf("EncodeRKAPAuth: %v", err)
	}
	opts := append(s.leaseOptions(t, req), wire.OptionV6{Code: wire.OptV6Auth, Data: key})
	s.answer(from, wire.MsgReply, req.XID, opts...)

	cid, _ := req.Options.First(wire.OptV6ClientID)
	return from, append([]byte(nil), cid...)
}

// reconfigure sends one Reconfigure, signed with key. Passing a key other than
// the one the Reply carried produces §16.11's "fails authentication
// validation" without changing anything else about the message.
func (s *handBuiltV6Server) reconfigure(t *testing.T, to *syscall.SockaddrInet6, cid []byte, kind wire.MessageTypeV6, key []byte) {
	t.Helper()
	s.replay++
	mv, err := wire.EncodeReconfigureMessage(kind)
	if err != nil {
		t.Fatalf("EncodeReconfigureMessage: %v", err)
	}
	auth, err := wire.EncodeRKAPAuth(wire.RKAPTypeDigest, make([]byte, md5.Size), s.replay)
	if err != nil {
		t.Fatalf("EncodeRKAPAuth: %v", err)
	}
	raw, err := wire.EncodeV6(&wire.MessageV6{
		Type: wire.MsgReconfigure,
		XID:  0x00abcdef & (wire.MaxXID6 - 1),
		Options: []wire.OptionV6{
			{Code: wire.OptV6ClientID, Data: cid},
			{Code: wire.OptV6ServerID, Data: test6ReconfServerDUID},
			{Code: wire.OptV6ReconfMsg, Data: mv},
			{Code: wire.OptV6Auth, Data: auth},
		},
	})
	if err != nil {
		t.Fatalf("EncodeV6(Reconfigure): %v", err)
	}
	start, end, err := reconfDigestSpan(raw)
	if err != nil {
		t.Fatalf("locating the digest: %v", err)
	}
	// §20.4.3: "the client computes an HMAC-MD5 over the Reconfigure message,
	// with zeroes substituted for the HMAC-MD5 field". The field is already
	// zero here, so the octets signed are the octets sent apart from the
	// digest itself.
	copy(raw[start:end], rfc2104HMACMD5(key, raw))
	s.send(to, raw)
}

// -------------------------------------------------------------- proofs --

// TestAnAuthenticatedReconfigureMakesTheClientRenew is the runtime proof for
// #925: a server the client has never met in a test before sends it a signed
// Reconfigure, and the Renew §18.2.11 asks for is READ OFF THE WIRE by that
// server rather than out of the client's own counters.
func TestAnAuthenticatedReconfigureMakesTheClientRenew(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6ReconfigureAgainstHandBuiltServer(t)
		return
	}
	reexecInNamespaces(t)
}

func v6ReconfigureAgainstHandBuiltServer(t *testing.T) {
	wireUpV6(t)
	srv := newHandBuiltV6Server(t)

	c, _ := newV6Client(t)
	stop := runV6Client(t, c)
	defer stop()

	to, cid := srv.lease6(t)
	ev := awaitV6(t, c, lease.Acquired)
	if got := ev.Lease.Addr.Addr().String(); got != test6ReconfAddr {
		t.Fatalf("the client acquired %s, want %s", got, test6ReconfAddr)
	}

	// THE FORGED ONE FIRST, so the Renew that follows cannot be the delayed
	// answer to it. §16.11: a Reconfigure that "fails authentication
	// validation" is discarded.
	forged := append([]byte(nil), test6ReconfKey...)
	forged[0] ^= 0xff
	srv.reconfigure(t, to, cid, wire.MsgRenew, forged)
	if msg, _, ok := srv.next(test6ReconfSilence); ok {
		t.Fatalf("a Reconfigure signed with the wrong key produced a %s (§16.11)", msg.Type)
	}

	// And now the genuine one.
	srv.reconfigure(t, to, cid, wire.MsgRenew, test6ReconfKey)
	msg, from, ok := srv.next(test6ReconfWait)
	if !ok {
		t.Fatal("an authenticated Reconfigure produced nothing on the wire (§18.2.11)")
	}
	if msg.Type != wire.MsgRenew {
		t.Fatalf("the client answered the Reconfigure with a %s, want a Renew (§18.2.11)", msg.Type)
	}
	sid, ok2 := msg.Options.First(wire.OptV6ServerID)
	if !ok2 || !bytes.Equal(sid, test6ReconfServerDUID) {
		t.Errorf("the Renew names server %x, want %x (§18.2.4)", sid, test6ReconfServerDUID)
	}

	// The lease survives the exchange, which is what a Reconfigure is for.
	srv.answer(from, wire.MsgReply, msg.XID, srv.leaseOptions(t, msg)...)
	if ev := awaitV6(t, c, lease.Renewed); ev.Lease.Addr.Addr().String() != test6ReconfAddr {
		t.Errorf("the renewal ended on %s, want %s", ev.Lease.Addr.Addr(), test6ReconfAddr)
	}
}

// TestAClientThatDoesNotAcceptReconfigureAnnouncesNothingAndAnswersNothing is
// the inert-control half: with the switch off, the option the server looks for
// is absent AND the Reconfigure it sends anyway is ignored.
//
// A test that only drove the default-on path would pass against a library that
// had the flag wired to nothing at all.
func TestAClientThatDoesNotAcceptReconfigureAnnouncesNothingAndAnswersNothing(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6ReconfigureOffAgainstHandBuiltServer(t)
		return
	}
	reexecInNamespaces(t)
}

func v6ReconfigureOffAgainstHandBuiltServer(t *testing.T) {
	wireUpV6(t)
	srv := newHandBuiltV6Server(t)

	c, _ := newV6ClientWith(t, func(p *proto.Params6) { p.AcceptReconfigure = false })
	stop := runV6Client(t, c)
	defer stop()

	sol, from, ok := srv.next(test6ReconfWait)
	if !ok {
		t.Fatal("no Solicit reached the hand-built server")
	}
	if accept, err := sol.Options.ReconfigureAccept(); accept || err != nil {
		t.Fatalf("a client with AcceptReconfigure off still announced it (%v, %v) — §21.20", accept, err)
	}
	srv.answer(from, wire.MsgAdvertise, sol.XID, srv.leaseOptions(t, sol)...)

	req, from, ok := srv.next(test6ReconfWait)
	if !ok {
		t.Fatal("no Request reached the hand-built server")
	}
	if accept, err := req.Options.ReconfigureAccept(); accept || err != nil {
		t.Fatalf("a client with AcceptReconfigure off still announced it in the Request (%v, %v)", accept, err)
	}
	key, err := wire.EncodeRKAPAuth(wire.RKAPTypeKey, test6ReconfKey, 0)
	if err != nil {
		t.Fatalf("EncodeRKAPAuth: %v", err)
	}
	srv.answer(from, wire.MsgReply, req.XID, append(srv.leaseOptions(t, req), wire.OptionV6{Code: wire.OptV6Auth, Data: key})...)
	awaitV6(t, c, lease.Acquired)

	cid, _ := req.Options.First(wire.OptV6ClientID)
	srv.reconfigure(t, from, cid, wire.MsgRenew, test6ReconfKey)
	if msg, _, ok := srv.next(test6ReconfSilence); ok {
		t.Fatalf("a client that announced no Reconfigure Accept option answered a Reconfigure with a %s (§21.20)", msg.Type)
	}
}
