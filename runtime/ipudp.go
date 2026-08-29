package runtime

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// This file builds and parses the IPv4 and UDP headers by hand.
//
// It has to. A DHCP client's first message goes out over an interface the
// kernel has no address on, to a destination that is not routable, and it must
// carry source 0.0.0.0 — RFC 2131 section 4.1: "the client MUST set the IP
// source address to 0". No socket API will produce that packet, which is why
// the transport is AF_PACKET and why the two headers below are our problem.

// The ports. RFC 2131 section 4.1.
const (
	// ClientPort is the DHCP client port (bootpc).
	ClientPort = 68
	// ServerPort is the DHCP server port (bootps).
	ServerPort = 67
)

const (
	ipv4HeaderLen = 20
	udpHeaderLen  = 8
	protoUDP      = 17
	ipv4Version   = 4
)

// Errors from parsing a received frame. These are all "not for us" rather than
// "something is wrong": a raw socket sees every packet on the link, so the
// common case for each of these is a perfectly healthy packet belonging to
// somebody else.
var (
	ErrNotIPv4      = errors.New("runtime: not IPv4")
	ErrNotUDP       = errors.New("runtime: not UDP")
	ErrShortFrame   = errors.New("runtime: frame shorter than its headers")
	ErrWrongPort    = errors.New("runtime: not a DHCP client port")
	ErrFragmented   = errors.New("runtime: fragmented IPv4 datagram")
	ErrBadChecksum  = errors.New("runtime: bad checksum")
	ErrPayloadShort = errors.New("runtime: UDP length exceeds frame")
)

// BuildIPv4UDP wraps payload in a UDP datagram inside an IPv4 packet.
//
// The IPv4 header checksum is mandatory. The UDP checksum is optional over
// IPv4 (RFC 768 allows the all-zero "not computed" value) and this function
// computes it anyway: a zero checksum is legal and is also exactly what a
// broken implementation emits, so computing it costs nothing and removes a
// reading.
//
// The identification field is caller-supplied rather than generated here, so
// that the transport is a pure function of its inputs and a golden-bytes test
// is possible. RFC 6864 section 4.1 permits any value for a datagram that will
// not be fragmented, and these will not be: a DHCP message is far below any
// link MTU.
func BuildIPv4UDP(src, dst netip.Addr, sport, dport uint16, ident uint16, ttl uint8, payload []byte) ([]byte, error) {
	if !src.Is4() || !dst.Is4() {
		return nil, fmt.Errorf("%w: src %s dst %s", ErrNotIPv4, src, dst)
	}
	total := ipv4HeaderLen + udpHeaderLen + len(payload)
	if total > 0xFFFF {
		return nil, fmt.Errorf("runtime: datagram %d bytes exceeds IPv4 maximum", total)
	}
	s4, d4 := src.As4(), dst.As4()

	buf := make([]byte, total)
	buf[0] = ipv4Version<<4 | ipv4HeaderLen/4
	buf[1] = 0 // DSCP/ECN
	binary.BigEndian.PutUint16(buf[2:4], uint16(total))
	binary.BigEndian.PutUint16(buf[4:6], ident)
	binary.BigEndian.PutUint16(buf[6:8], 0) // no flags, no fragment offset
	buf[8] = ttl
	buf[9] = protoUDP
	// buf[10:12] is the header checksum, left zero while it is computed.
	copy(buf[12:16], s4[:])
	copy(buf[16:20], d4[:])
	binary.BigEndian.PutUint16(buf[10:12], checksum(buf[:ipv4HeaderLen]))

	u := buf[ipv4HeaderLen:]
	binary.BigEndian.PutUint16(u[0:2], sport)
	binary.BigEndian.PutUint16(u[2:4], dport)
	binary.BigEndian.PutUint16(u[4:6], uint16(udpHeaderLen+len(payload)))
	copy(u[udpHeaderLen:], payload)
	binary.BigEndian.PutUint16(u[6:8], udpChecksum(s4, d4, u))

	return buf, nil
}

// Datagram is one parsed UDP datagram.
//
// It is a struct rather than three return values because PartialChecksum has to
// travel with the payload: it is the difference between "this datagram was
// checked" and "this datagram could not be checked", and a caller that cannot
// see it cannot report it.
type Datagram struct {
	// Payload is the UDP payload. It aliases the frame passed in.
	Payload []byte
	// Src is the IPv4 source address of the frame.
	Src netip.Addr
	// PartialChecksum reports that the UDP checksum field held the
	// pseudo-header sum instead of a completed checksum, so the payload was
	// NOT verified. See acceptUDPChecksum.
	PartialChecksum bool
}

// ParseIPv4UDP extracts the UDP payload of a DHCP reply from a raw IPv4 frame.
//
// It returns ErrWrongPort for anything not addressed to the client port, which
// on a shared link is most of what arrives.
//
// Fragments are REFUSED rather than reassembled. Reassembly is a real piece of
// machinery with its own timers and its own denial-of-service surface, and a
// DHCP reply that arrives fragmented is a server doing something exotic. The
// bound is stated rather than hidden: a fragmented DHCP reply is dropped and
// the client retransmits until it gives up.
func ParseIPv4UDP(frame []byte) (Datagram, error) {
	if len(frame) < ipv4HeaderLen {
		return Datagram{}, ErrShortFrame
	}
	if frame[0]>>4 != ipv4Version {
		return Datagram{}, ErrNotIPv4
	}
	ihl := int(frame[0]&0x0F) * 4
	if ihl < ipv4HeaderLen || len(frame) < ihl {
		return Datagram{}, ErrShortFrame
	}
	if frame[9] != protoUDP {
		return Datagram{}, ErrNotUDP
	}
	// More-fragments set, or a non-zero fragment offset.
	if frame[6]&0x20 != 0 || (uint16(frame[6]&0x1F)<<8|uint16(frame[7])) != 0 {
		return Datagram{}, ErrFragmented
	}
	if checksum(frame[:ihl]) != 0 {
		return Datagram{}, fmt.Errorf("%w: IPv4 header", ErrBadChecksum)
	}

	// The IPv4 total-length field, not len(frame): a SOCK_DGRAM read can hand
	// back trailing link-layer padding, and a short DHCP reply on Ethernet is
	// padded to the 60-octet minimum frame more often than not. Trusting
	// len(frame) here makes the UDP checksum fail on exactly those replies.
	total := int(binary.BigEndian.Uint16(frame[2:4]))
	if total < ihl || total > len(frame) {
		return Datagram{}, ErrShortFrame
	}
	u := frame[ihl:total]
	if len(u) < udpHeaderLen {
		return Datagram{}, ErrShortFrame
	}
	if binary.BigEndian.Uint16(u[2:4]) != ClientPort {
		return Datagram{}, ErrWrongPort
	}
	ulen := int(binary.BigEndian.Uint16(u[4:6]))
	if ulen < udpHeaderLen || ulen > len(u) {
		return Datagram{}, ErrPayloadShort
	}
	u = u[:ulen]

	var s4, d4 [4]byte
	copy(s4[:], frame[12:16])
	copy(d4[:], frame[16:20])
	partial, ok := acceptUDPChecksum(s4, d4, u)
	if !ok {
		return Datagram{}, fmt.Errorf("%w: UDP", ErrBadChecksum)
	}
	return Datagram{
		Payload:         u[udpHeaderLen:],
		Src:             netip.AddrFrom4(s4),
		PartialChecksum: partial,
	}, nil
}

// acceptUDPChecksum decides whether a received datagram's checksum field lets
// it through, and reports whether the payload actually got checked.
//
// Three cases are accepted, and only the middle one is a verification:
//
//  1. Zero. RFC 768 reserves the all-zero value for "no checksum computed",
//     and it is legal over IPv4.
//
//  2. A correct checksum: the datagram plus its pseudo-header sums to 0xFFFF.
//
//  3. The pseudo-header sum ALONE. This is Linux's CHECKSUM_PARTIAL, and it
//     is not corruption: for a locally generated datagram the kernel writes
//     ~csum_tcpudp_magic(saddr, daddr, len, IPPROTO_UDP, 0) into the field —
//     the folded pseudo-header sum — and leaves completing it to the hardware.
//     An AF_PACKET reader on the far side of a veth pair, or on any local
//     delivery path, sees the frame BEFORE anything completes it.
//
//     MEASURED 2026-08-29 against dnsmasq 2.91 over a veth pair: every OFFER
//     and ACK arrived with checksum 0x24f6 where the completed value was
//     0x0074, and 0x24f6 is exactly the folded pseudo-header sum for that
//     source, destination and length. The captured frame is a fixture in
//     ipudp_test.go. Refusing this case does not produce a stricter client,
//     it produces a client that cannot lease from a server on the same host.
//
// Case 3 carries NO information about the payload, so it is exactly as trusted
// as case 1 — which is why it is reported rather than hidden. THE BOUND: a
// datagram whose payload is corrupt and whose checksum field happens to equal
// the pseudo-header sum is accepted. Nothing here can distinguish that from a
// kernel that has not finished the sum yet; the two are the same bytes.
func acceptUDPChecksum(src, dst [4]byte, u []byte) (partial, ok bool) {
	got := binary.BigEndian.Uint16(u[6:8])
	switch {
	case got == 0:
		return true, true
	case udpChecksumVerify(src, dst, u) == 0:
		return false, true
	case got == pseudoHeaderSum(src, dst, len(u)):
		return true, true
	default:
		return false, false
	}
}

// checksum is the one's-complement sum of 16-bit words, complemented (RFC 1071).
func checksum(b []byte) uint16 {
	return ^sum16(b, 0)
}

// sum16 folds b into sum as 16-bit big-endian words and returns the folded
// one's-complement sum. RFC 1071 section 4.1.
func sum16(b []byte, sum uint32) uint16 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		// An odd trailing byte is the HIGH byte of the final word: the
		// datagram is padded on the right with a zero, and that pad is not
		// transmitted.
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(sum)
}

// udpChecksum computes the UDP checksum over the pseudo-header and datagram.
// u must have its checksum field already zeroed.
func udpChecksum(src, dst [4]byte, u []byte) uint16 {
	c := ^pseudoSum(src, dst, u)
	// RFC 768: a computed checksum of zero is transmitted as all ones, because
	// zero is reserved to mean "no checksum".
	if c == 0 {
		return 0xFFFF
	}
	return c
}

// udpChecksumVerify sums a datagram whose checksum field is populated. A
// correct datagram sums to 0xFFFF, so the complement is zero.
func udpChecksumVerify(src, dst [4]byte, u []byte) uint16 {
	return ^pseudoSum(src, dst, u)
}

// pseudoHeaderSum is the folded one's-complement sum of the UDP pseudo-header
// alone — no payload. It is what Linux leaves in the checksum field of a
// datagram it has not finished checksumming; see acceptUDPChecksum.
func pseudoHeaderSum(src, dst [4]byte, ulen int) uint16 {
	return sum16(nil, pseudoBase(src, dst, ulen))
}

func pseudoBase(src, dst [4]byte, ulen int) uint32 {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(src[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dst[2:4]))
	sum += uint32(protoUDP)
	sum += uint32(ulen)
	return sum
}

func pseudoSum(src, dst [4]byte, u []byte) uint16 {
	return sum16(u, pseudoBase(src, dst, len(u)))
}
