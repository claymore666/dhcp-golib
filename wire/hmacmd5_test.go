// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package wire

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// The proofs for the MD5 and HMAC this package writes out because ring 0 may
// not import the standard library's. See wire/hmacmd5.go for why.
//
// THREE OBSERVERS, AND NOT ONE. Published vectors say the algorithm is the one
// the RFCs name; the differential tests say it agrees with an implementation
// nobody here wrote; and the differential tests are what cover the inputs no
// vector list happens to contain — a message that is exactly one block, one
// octet short of a block, or long enough to need a second length word.
//
// The test files may import crypto/md5 and crypto/hmac: the T1 gate's pure-ring
// rule is about the package's own files, and a test that could only compare
// this code with itself would be no observer at all.

// TestMD5MatchesRFC1321sOwnVectors is RFC 1321 Appendix A.5, "MD5 test suite",
// verbatim and in its own order.
func TestMD5MatchesRFC1321sOwnVectors(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "d41d8cd98f00b204e9800998ecf8427e"},
		{"a", "0cc175b9c0f1b6a831c399e269772661"},
		{"abc", "900150983cd24fb0d6963f7d28e17f72"},
		{"message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
		{"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"},
		{"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a"},
	} {
		got := md5Sum([]byte(tc.in))
		if hex.EncodeToString(got[:]) != tc.want {
			t.Errorf("md5Sum(%q) = %x, RFC 1321 A.5 gives %s", tc.in, got, tc.want)
		}
	}
}

// TestHMACMD5MatchesRFC2202sOwnVectors is RFC 2202 §2, "Test Cases for
// HMAC-MD5", including the two that exercise a key longer than the 64-octet
// block — the branch §2's "Applications that use keys longer than B bytes"
// sentence describes and that a 16-octet reconfigure key never reaches.
func TestHMACMD5MatchesRFC2202sOwnVectors(t *testing.T) {
	for i, tc := range []struct {
		key, data []byte
		want      string
	}{
		{bytes.Repeat([]byte{0x0b}, 16), []byte("Hi There"), "9294727a3638bb1c13f48ef8158bfc9d"},
		{[]byte("Jefe"), []byte("what do ya want for nothing?"), "750c783e6ab0b503eaa86e310a5db738"},
		{bytes.Repeat([]byte{0xaa}, 16), bytes.Repeat([]byte{0xdd}, 50), "56be34521d144c88dbb8c733f0e8b3f6"},
		{mustHex("0102030405060708090a0b0c0d0e0f10111213141516171819"), bytes.Repeat([]byte{0xcd}, 50), "697eaf0aca3a3aea3a75164746ffaa79"},
		{bytes.Repeat([]byte{0x0c}, 16), []byte("Test With Truncation"), "56461ef2342edc00f9bab995690efd4c"},
		{bytes.Repeat([]byte{0xaa}, 80), []byte("Test Using Larger Than Block-Size Key - Hash Key First"), "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"},
		{bytes.Repeat([]byte{0xaa}, 80), []byte("Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"), "6f630fad67cda0ee1fb1f562db3aa53e"},
	} {
		if got := hex.EncodeToString(hmacMD5(tc.key, tc.data)); got != tc.want {
			t.Errorf("RFC 2202 case %d: hmacMD5 = %s, the RFC gives %s", i+1, got, tc.want)
		}
	}
}

// TestMD5AgreesWithTheStandardLibraryAtEveryBoundary walks the lengths a
// vector list does not: every length from 0 to three blocks plus a tail, which
// covers the padding branch that lands exactly on 56, the one that has to add
// a whole extra block, and the multi-block loop.
func TestMD5AgreesWithTheStandardLibraryAtEveryBoundary(t *testing.T) {
	for n := range 200 {
		in := generatedBytes(n, 0x5eed)
		got := md5Sum(in)
		want := md5.Sum(in)
		if got != want {
			t.Fatalf("md5Sum over %d octet(s) = %x, crypto/md5 gives %x", n, got, want)
		}
	}
}

// TestHMACMD5AgreesWithTheStandardLibrary does the same for the construction,
// over key lengths that straddle RFC 2104's B.
func TestHMACMD5AgreesWithTheStandardLibrary(t *testing.T) {
	for _, kn := range []int{0, 1, 16, 63, 64, 65, 100} {
		key := generatedBytes(kn, 0xbeef)
		for _, dn := range []int{0, 1, 55, 56, 63, 64, 65, 128, 300} {
			data := generatedBytes(dn, 0xf00d)
			mac := hmac.New(md5.New, key)
			mac.Write(data)
			if got, want := hmacMD5(key, data), mac.Sum(nil); !bytes.Equal(got, want) {
				t.Fatalf("hmacMD5 with a %d-octet key over %d octet(s) = %x, crypto/hmac gives %x", kn, dn, got, want)
			}
		}
	}
}

// generatedBytes is a deterministic pseudo-random buffer. A fixed pattern such
// as all-zeros would agree with a broken implementation that ignored the input
// past the first block; a seeded sequence does not.
func generatedBytes(n int, seed uint64) []byte {
	out := make([]byte, n)
	x := seed
	for i := range out {
		x = x*6364136223846793005 + 1442695040888963407
		out[i] = byte(x >> 33)
	}
	return out
}

// TestEqualConstantTimeAnswersTheSameQuestionBytesEqualDoes is the correctness
// half of the comparison. Its timing property is a BOUND and not an assertion:
// nothing here measures cycles, because a timing test on a shared box measures
// the box. What is asserted here is only the answer. An early-returning
// compare gives the SAME answer for every input, including one differing only
// in the last octet, so no case in this test can distinguish it — MEASURED as
// a mutant. The read-every-octet property is held by
// TestEqualConstantTimeHasNoEarlyExit, which reads the source instead.
func TestEqualConstantTimeAnswersTheSameQuestionBytesEqualDoes(t *testing.T) {
	for _, tc := range []struct{ a, b []byte }{
		{nil, nil},
		{[]byte{}, nil},
		{[]byte{1}, []byte{1}},
		{[]byte{1}, []byte{2}},
		{[]byte{1, 2, 3}, []byte{1, 2, 3}},
		{[]byte{1, 2, 3}, []byte{1, 2, 4}},
		{[]byte{1, 2, 3}, []byte{9, 2, 3}},
		{[]byte{1, 2, 3}, []byte{1, 2}},
		{bytes.Repeat([]byte{0xff}, 16), bytes.Repeat([]byte{0xff}, 16)},
	} {
		if got, want := equalConstantTime(tc.a, tc.b), bytes.Equal(tc.a, tc.b); got != want {
			t.Errorf("equalConstantTime(%x, %x) = %v, bytes.Equal gives %v", tc.a, tc.b, got, want)
		}
	}
}

// TestRKAPVerifyIsTheOnlyMD5InThisPackage pins the reason this code exists to
// one caller. MD5 is not a hash this library offers; it is RKAP's algorithm 1
// and nothing else, and a second caller appearing would be a decision somebody
// should have to make on purpose.
func TestRKAPVerifyIsTheOnlyMD5InThisPackage(t *testing.T) {
	src := readPackageSources(t)
	var callers []string
	for file, text := range src {
		if file == "hmacmd5.go" {
			continue
		}
		for _, name := range []string{"md5Sum(", "hmacMD5("} {
			if strings.Contains(text, name) {
				callers = append(callers, file+" names "+name)
			}
		}
	}
	if len(callers) != 1 || !strings.HasPrefix(callers[0], "dhcpv6_reconfigure.go") {
		t.Errorf("MD5 is reached from %v, want exactly dhcpv6_reconfigure.go", callers)
	}
}

// readPackageSources is every non-test .go file of this package, by base name.
func readPackageSources(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatalf("reading %s: %v", n, err)
		}
		out[n] = string(b)
	}
	if len(out) == 0 {
		t.Fatal("no package sources were read; this check would pass having judged nothing")
	}
	return out
}

// TestEqualConstantTimeHasNoEarlyExit is the observer the test above cannot
// be: an early-exit compare gives the same ANSWER for every input, so no
// black-box case distinguishes it, and a wall-clock measurement on a shared
// box measures the box rather than the loop.
//
// So the subject is the SOURCE, and the claim is narrow: the comparison loop
// contains no return. That is what makes the number of octets read depend on
// the length and not on where the first difference is. MEASURED as a mutant:
// replacing the accumulate-and-compare with an early return survives every
// behavioural case in this package and is killed here.
func TestEqualConstantTimeHasNoEarlyExit(t *testing.T) {
	src := readPackageSources(t)["hmacmd5.go"]
	if src == "" {
		t.Fatal("hmacmd5.go was not read; this check would pass having judged nothing")
	}
	const open = "\tfor i := range a {"
	i := strings.Index(src, open)
	if i < 0 {
		t.Fatalf("the comparison loop is no longer spelled %q, so this check no longer sees it", open)
	}
	rest := src[i+len(open):]
	j := strings.Index(rest, "\n\t}")
	if j < 0 {
		t.Fatal("the comparison loop has no closing brace at its own indentation; the reader is broken")
	}
	if body := rest[:j]; strings.Contains(body, "return") {
		t.Errorf("the comparison loop returns early:%s", body)
	}
}
