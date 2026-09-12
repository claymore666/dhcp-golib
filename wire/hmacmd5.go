// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package wire

// MD5 (RFC 1321) and HMAC (RFC 2104), written here because ring 0 may not
// import the standard library's.
//
// WHY THIS IS NOT crypto/md5 AND crypto/hmac. The T1 gate's pure-ring
// allowlist admits nothing whose dependency closure reaches an impure root,
// and both of those reach os, syscall, time and internal/poll — crypto/hmac
// through crypto/internal/sysrand, which reads the kernel's random device, and
// crypto/md5 through internal/godebug, which reads the environment. MEASURED
// 2026-09-11 with `go list -deps` on go1.25. The gate refusing the import is
// the design talking, and the same argument already produced this package: a
// pure ring writes what it needs. RFC 9915 §20.4.3 authenticates a Reconfigure
// over the octets that arrived, and the octets are here.
//
// WHAT MAKES THIS SAFE TO HAND-WRITE, which is not "MD5 is easy". Three
// observers, none of which is this code:
//
//   - RFC 1321 Appendix A.5's seven test vectors and RFC 2202 §2's seven
//     HMAC-MD5 vectors, asserted verbatim;
//   - a differential test against crypto/md5 and crypto/hmac over generated
//     inputs — the test files are outside the pure ring and may import them;
//   - RKAPVerify's own proofs, which sign with a THIRD implementation written
//     out in the test file from RFC 2104's own words.
//
// MD5 is used for nothing else in this library, and it is not a choice: §20.4
// names HMAC-MD5 as RKAP's algorithm 1 and defines no other.

// md5BlockSize is RFC 1321's 512-bit block, and RFC 2104's B.
const md5BlockSize = 64

// md5DigestSize is RFC 1321's 128-bit output.
const md5DigestSize = 16

// md5Table is RFC 1321 §3.4's T, "a 64-element table constructed from the sine
// function": T[i] is the integer part of 4294967296 times abs(sin(i)), i in
// radians, for i from 1 to 64. Written out rather than computed, because
// computing it would need math.Sin and a pure ring's arithmetic should not
// depend on a libm's rounding.
var md5Table = [64]uint32{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
}

// md5Shift is RFC 1321 §3.4's per-round rotation amounts, four rounds of four
// repeated four times.
var md5Shift = [64]uint{
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
}

// md5Sum is RFC 1321's MD5 over msg.
func md5Sum(msg []byte) [md5DigestSize]byte {
	// §3.3's initial values, "low-order bytes first".
	a, b, c, d := uint32(0x67452301), uint32(0xefcdab89), uint32(0x98badcfe), uint32(0x10325476)

	// §3.1 padding: "a single '1' bit is appended ... then '0' bits are
	// appended so that the length in bits of the padded message becomes
	// congruent to 448, modulo 512", and §3.2: "a 64-bit representation of b"
	// — the original length in bits, low-order word first.
	bits := uint64(len(msg)) * 8
	padded := make([]byte, 0, len(msg)+md5BlockSize+8)
	padded = append(padded, msg...)
	padded = append(padded, 0x80)
	for len(padded)%md5BlockSize != 56 {
		padded = append(padded, 0)
	}
	for i := range 8 {
		padded = append(padded, byte(bits>>(8*i)))
	}

	var x [16]uint32
	for off := 0; off < len(padded); off += md5BlockSize {
		block := padded[off : off+md5BlockSize]
		for i := range 16 {
			j := 4 * i
			x[i] = uint32(block[j]) | uint32(block[j+1])<<8 |
				uint32(block[j+2])<<16 | uint32(block[j+3])<<24
		}
		aa, bb, cc, dd := a, b, c, d
		for i := range 64 {
			var f uint32
			var g int
			// §3.4's four rounds, with the auxiliary functions of §3.4:
			// F(X,Y,Z) = XY v not(X) Z, G = XZ v Y not(Z),
			// H = X xor Y xor Z, I = Y xor (X v not(Z)).
			switch {
			case i < 16:
				f, g = (b&c)|(^b&d), i
			case i < 32:
				f, g = (d&b)|(^d&c), (5*i+1)%16
			case i < 48:
				f, g = b^c^d, (3*i+5)%16
			default:
				f, g = c^(b|^d), (7*i)%16
			}
			tmp := d
			d = c
			c = b
			sum := a + f + md5Table[i] + x[g]
			b += sum<<md5Shift[i] | sum>>(32-md5Shift[i])
			a = tmp
		}
		a, b, c, d = a+aa, b+bb, c+cc, d+dd
	}

	var out [md5DigestSize]byte
	for i, v := range [4]uint32{a, b, c, d} {
		out[4*i] = byte(v)
		out[4*i+1] = byte(v >> 8)
		out[4*i+2] = byte(v >> 16)
		out[4*i+3] = byte(v >> 24)
	}
	return out
}

// hmacMD5 is RFC 2104 §2 with H = MD5 and B = 64.
//
// RFC 2104: "(1) append zeros to the end of K to create a B byte string ...
// (2) XOR ... with ipad; (3) append the stream of data 'text' ...; (4) apply H
// ...; (5) XOR ... with opad; (6) append the H result from step (4) ...;
// (7) apply H to the stream generated in step (6) and output the result."
// ipad is the byte 0x36 repeated B times and opad the byte 0x5C repeated B
// times.
func hmacMD5(key, text []byte) []byte {
	// RFC 2104 §2: "Applications that use keys longer than B bytes will first
	// hash the key using H and then use the resultant L byte string as the
	// actual key to HMAC."
	k := make([]byte, md5BlockSize)
	if len(key) > md5BlockSize {
		sum := md5Sum(key)
		copy(k, sum[:])
	} else {
		copy(k, key)
	}
	inner := make([]byte, 0, md5BlockSize+len(text))
	outer := make([]byte, 0, md5BlockSize+md5DigestSize)
	for _, v := range k {
		inner = append(inner, v^0x36)
		outer = append(outer, v^0x5c)
	}
	inner = append(inner, text...)
	is := md5Sum(inner)
	outer = append(outer, is[:]...)
	final := md5Sum(outer)
	return final[:]
}

// equalConstantTime reports whether a and b are the same octets, in time that
// depends on their length and not on their contents.
//
// A byte-at-a-time comparison that returned early would tell an attacker how
// many leading octets of a forged digest were right, which turns a 2^128 search
// into sixteen searches of 2^8. crypto/subtle is the standard answer and is
// refused here for hmacMD5's reason.
func equalConstantTime(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
