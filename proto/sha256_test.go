// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// FIPS 180-2 Appendix B's three SHA-256 examples, and the empty message
// (dhcp-golib#54).
func TestSHA256MatchesTheFIPSExamples(t *testing.T) {
	cases := map[string]string{
		"":    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq": "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
		strings.Repeat("a", 1000000):                               "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
	}
	for in, want := range cases {
		got := sha256Sum([]byte(in))
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("SHA-256 of a %d-octet message is %x, want %s", len(in), got, want)
		}
	}
}

// Every length across the padding's block boundaries, against the standard
// library, which a test file may import (dhcp-golib#54).
func TestSHA256AgreesWithTheStandardLibraryAtEveryPaddingBoundary(t *testing.T) {
	msg := make([]byte, 300)
	for i := range msg {
		msg[i] = byte(i*131 + 7)
	}
	for n := 0; n <= len(msg); n++ {
		if got, want := sha256Sum(msg[:n]), sha256.Sum256(msg[:n]); got != want {
			t.Fatalf("SHA-256 of %d octets: %x, the standard library %x", n, got, want)
		}
	}
}
