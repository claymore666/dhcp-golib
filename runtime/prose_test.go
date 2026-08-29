package runtime

import (
	"os"
	"strings"
	"testing"
)

// flatten strips comment markers and collapses every run of whitespace to one
// space, so a pinned sentence matches however the source happens to be
// wrapped. Without it the pin is really a pin on the line breaks, and it fails
// the first time gofmt or an editor rewraps the paragraph.
func flatten(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "//", " ")), " ")
}

// TestLoadBearingProseIsStillPresent pins the sentences in this package that
// record something no test can execute, so that deleting one goes red instead
// of going unnoticed.
//
// It exists because that failure happened. The 2026-08-29 comment sweep
// deleted the operator guidance below as a restatement; nothing failed, and it
// was found only by a reviewer reading the diff. The comment rule says a
// decision or an unexecutable bound stays — this is the observer that rule did
// not have.
//
// BOUND, and it is a real one: this pins the TEXT, not its truth. It cannot
// tell a correct sentence from a wrong one, and a legitimate rewording makes
// it fail. Failing on a rewording is the intended direction — the edit then
// has to be made here too, where a reviewer sees it — but it is a bound, not a
// feature. It also protects only the entries somebody put in this list; a
// sentence nobody adds is exactly as unprotected as before.
func TestLoadBearingProseIsStillPresent(t *testing.T) {
	cases := []struct {
		file string
		want string
		why  string
	}{
		{
			file: "transport_packet_linux.go",
			want: "on a physical link showing either state is worth a second look",
			why:  "the actionable half of the checksum counters: what an operator should DO with them. Deleted by the 2026-08-29 sweep and restored; the expectation half survives in the TransportStats doc, this half does not survive anywhere else.",
		},
		{
			file: "doc.go",
			want: "a journal designed around the bug that was already found",
			why:  "why the debug primitives land at M1 rather than when they are needed. Deleted by the same sweep; it survived only in a note that is not part of this repository and would not publish with it.",
		},
		{
			file: "ipudp.go",
			want: "NOT TRANSFERABLE TO IPv6",
			why:  "RFC 8200 section 8.1: an IPv6 receiver must DISCARD a zero-checksum UDP packet, so this file's acceptance must not be copied into a v6 path. Nothing in an IPv4-only tree can execute it.",
		},
		{
			file: "ipudp.go",
			want: "a summarised RFC has already been observed",
			why:  "read the section, not a summary of it. Recorded after a summarised RFC 1122 section 4.1.3.4 was observed asserting the inverse of that section's own MUST with the number intact.",
		},
	}

	for _, c := range cases {
		b, err := os.ReadFile(c.file)
		if err != nil {
			t.Errorf("%s: %v", c.file, err)
			continue
		}
		if !strings.Contains(flatten(string(b)), flatten(c.want)) {
			t.Errorf("%s no longer contains %q\nwhy it is pinned: %s", c.file, c.want, c.why)
		}
	}
}
