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
func ParseIPv4UDP(frame []byte) (payload []byte, src netip.Addr, err error) {
	if len(frame) < ipv4HeaderLen {
		return nil, netip.Addr{}, ErrShortFrame
	}
	if frame[0]>>4 != ipv4Version {
		return nil, netip.Addr{}, ErrNotIPv4
	}
	ihl := int(frame[0]&0x0F) * 4
	if ihl < ipv4HeaderLen || len(frame) < ihl {
		return nil, netip.Addr{}, ErrShortFrame
	}
	if frame[9] != protoUDP {
		return nil, netip.Addr{}, ErrNotUDP
	}
	// More-fragments set, or a non-zero fragment offset.
	if frame[6]&0x20 != 0 || (uint16(frame[6]&0x1F)<<8|uint16(frame[7])) != 0 {
		return nil, netip.Addr{}, ErrFragmented
	}
	if checksum(frame[:ihl]) != 0 {
		return nil, netip.Addr{}, fmt.Errorf("%w: IPv4 header", ErrBadChecksum)
	}

	// The IPv4 total-length field, not len(frame): a SOCK_DGRAM read can hand
	// back trailing link-layer padding, and a short DHCP reply on Ethernet is
	// padded to the 60-octet minimum frame more often than not. Trusting
	// len(frame) here makes the UDP checksum fail on exactly those replies.
	total := int(binary.BigEndian.Uint16(frame[2:4]))
	if total < ihl || total > len(frame) {
		return nil, netip.Addr{}, ErrShortFrame
	}
	u := frame[ihl:total]
	if len(u) < udpHeaderLen {
		return nil, netip.Addr{}, ErrShortFrame
	}
	if binary.BigEndian.Uint16(u[2:4]) != ClientPort {
		return nil, netip.Addr{}, ErrWrongPort
	}
	ulen := int(binary.BigEndian.Uint16(u[4:6]))
	if ulen < udpHeaderLen || ulen > len(u) {
		return nil, netip.Addr{}, ErrPayloadShort
	}
	u = u[:ulen]

	var s4, d4 [4]byte
	copy(s4[:], frame[12:16])
	copy(d4[:], frame[16:20])
	// A zero UDP checksum means "not computed" (RFC 768) and is legal.
	if binary.BigEndian.Uint16(u[6:8]) != 0 && udpChecksumVerify(s4, d4, u) != 0 {
		return nil, netip.Addr{}, fmt.Errorf("%w: UDP", ErrBadChecksum)
	}
	return u[udpHeaderLen:], netip.AddrFrom4(s4), nil
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

func pseudoSum(src, dst [4]byte, u []byte) uint16 {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(src[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dst[2:4]))
	sum += uint32(protoUDP)
	sum += uint32(len(u))
	return sum16(u, sum)
}
