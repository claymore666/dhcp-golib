// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

// sha256 is FIPS 180-4 §6.2's SHA-256, written here because crypto/sha256
// reaches os, syscall, time and internal/poll (`go list -deps`, go1.25.0,
// 2026-10-02) and T1 keeps ring 1 off them, as wire/hmacmd5.go does for MD5.
// RFC 7217 §5 is its one caller; its observers are FIPS 180-4's own vectors
// and a differential test against crypto/sha256 (dhcp-golib#54).

// sha256K is FIPS 180-4 §4.2.2's sixty-four constants (dhcp-golib#54).
var sha256K = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// sha256Sum is the SHA-256 digest of msg (dhcp-golib#54).
func sha256Sum(msg []byte) [32]byte {
	h := [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
	// FIPS 180-4 §5.1.1: a 1 bit, zeros to 448 mod 512, the 64-bit length
	// (dhcp-golib#54).
	n := len(msg)
	padded := make([]byte, 0, n+72)
	padded = append(padded, msg...)
	padded = append(padded, 0x80)
	for len(padded)%64 != 56 {
		padded = append(padded, 0)
	}
	bits := uint64(n) * 8
	for i := 7; i >= 0; i-- {
		padded = append(padded, byte(bits>>(8*uint(i))))
	}
	var w [64]uint32
	for off := 0; off < len(padded); off += 64 {
		blk := padded[off : off+64]
		for t := 0; t < 16; t++ {
			w[t] = uint32(blk[4*t])<<24 | uint32(blk[4*t+1])<<16 | uint32(blk[4*t+2])<<8 | uint32(blk[4*t+3])
		}
		for t := 16; t < 64; t++ {
			s0 := rotr32(w[t-15], 7) ^ rotr32(w[t-15], 18) ^ w[t-15]>>3
			s1 := rotr32(w[t-2], 17) ^ rotr32(w[t-2], 19) ^ w[t-2]>>10
			w[t] = w[t-16] + s0 + w[t-7] + s1
		}
		a, b, c, d, e, f, g, hh := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
		for t := 0; t < 64; t++ {
			t1 := hh + (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) + (e&f ^ ^e&g) + sha256K[t] + w[t]
			t2 := (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) + (a&b ^ a&c ^ b&c)
			hh, g, f, e, d, c, b, a = g, f, e, d+t1, c, b, a, t1+t2
		}
		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
		h[4] += e
		h[5] += f
		h[6] += g
		h[7] += hh
	}
	var out [32]byte
	for i, v := range h {
		out[4*i], out[4*i+1], out[4*i+2], out[4*i+3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
	}
	return out
}

func rotr32(x uint32, n uint) uint32 { return x>>n | x<<(32-n) }
