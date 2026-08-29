// Package wire is ring 0: the codec. Bytes to typed messages and back.
//
// Ring 0 is pure. It holds no clock, opens no socket and touches no ambient
// state; it is subject to the same import policy as ring 1 (see the T1 gate,
// internal/gates/t1), because ring 1 imports it and an impure ring 0 would
// make ring 1 impure transitively.
//
// # Scope at M1
//
// DHCPv4 only, and only what DISCOVER / OFFER / REQUEST / ACK / NAK need. The
// message struct carries every BOOTP field and every option, so a message that
// arrives with options this milestone does not interpret round-trips through
// the codec without loss — that is deliberate, and it is the reason Options is
// a byte map rather than a struct of parsed fields.
//
// # What the decoder is defensive about, and what it is not
//
// Defensive (each has a test): a truncated option header, an option whose
// length runs past the buffer, a message shorter than the fixed header, a
// missing END option, a bad magic cookie, option overload into 'file' and
// 'sname' (RFC 2131 section 4.1), and a repeated option code, whose values are
// concatenated (RFC 2131 section 4.1, RFC 3396).
//
// NOT defensive, stated rather than discovered: the decoder does not bound the
// total number of options, and it does not reject a message that is
// semantically impossible (an OFFER with no yiaddr, say). The first is bounded
// anyway — the input is a single datagram the caller has already sized — and
// the second is ring 1's job, because "is this message usable" depends on the
// state the machine is in.
//
// D3 (own codec versus insomniacslk/dhcp) is still open. This is written
// because the T1 gate refuses any third-party import in a pure ring, and the
// four messages M1 needs are a few hundred lines. If D3 lands on the external
// library, ring 0 is replaceable behind rings 1-3 without touching the design —
// but the gate has to be argued with first, not edited around.
package wire
