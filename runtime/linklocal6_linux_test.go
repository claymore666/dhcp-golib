//go:build linux

package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInterfaceLinkLocalRefusesAnAddressTheKernelIsStillChecking drives every
// arm of InterfaceLinkLocal's parse from a fabricated /proc/net/if_inet6.
//
// IT EXISTS BECAUSE THE INTERESTING ROWS CANNOT BE ARRANGED ON A REAL LINK.
// The tentative window is about a second wide on a freshly-upped veth and
// nothing can hold it open; a dadfailed link-local needs a second node
// answering for a MAC-derived address; and an interface with a global address
// and no link-local at all is a configuration this fixture cannot build. The
// netns proofs use the real file and cover the ordinary row — this covers the
// ones the real file will not produce on demand.
//
// The lines are the format Linux writes: 32 hex digits of address, then the
// interface index, prefix length, scope, flags and name, all hexadecimal
// except the name. The flag values are include/uapi/linux/if_addr.h's, and
// 0xc0 (permanent | tentative) is the value MEASURED on a veth that has just
// come up.
func TestInterfaceLinkLocalRefusesAnAddressTheKernelIsStillChecking(t *testing.T) {
	const (
		llA    = "fe800000000000003802f6fffe2c9d01"
		llB    = "fe80000000000000aabbccfffe112233"
		global = "fd000099000000000000000000000042"
	)

	cases := []struct {
		name    string
		lines   []string
		want    string
		wantErr bool
		// inMsg is a substring the failure message must carry, so that the
		// two refusals are distinguishable by a reader and not only by a
		// counter.
		inMsg string
	}{
		{
			name:  "a settled link-local is returned",
			lines: []string{llA + " 03 40 20 80 v6cli0"},
			want:  "fe80::3802:f6ff:fe2c:9d01",
		},
		{
			name:    "a tentative link-local is refused",
			lines:   []string{llA + " 03 40 20 c0 v6cli0"},
			wantErr: true,
			inMsg:   "1 tentative, 0 failed",
		},
		{
			name:    "one that failed the kernel's own check is refused",
			lines:   []string{llA + " 03 40 20 88 v6cli0"},
			wantErr: true,
			inMsg:   "0 tentative, 1 failed",
		},
		{
			// THE ORDER THIS ANSWERS IN IS THE POINT. A tentative address
			// first and a settled one after is exactly the state a link is in
			// while it is coming up with two addresses, and returning the
			// first row that names the interface would send from an address
			// the kernel has not finished checking.
			name: "a settled address after a tentative one is still found",
			lines: []string{
				llA + " 03 40 20 c0 v6cli0",
				llB + " 03 40 20 80 v6cli0",
			},
			want: "fe80::aabb:ccff:fe11:2233",
		},
		{
			name: "another interface's link-local is not this one's",
			lines: []string{
				llA + " 02 40 20 80 v6srv0",
				llB + " 03 40 20 80 v6cli0",
			},
			want: "fe80::aabb:ccff:fe11:2233",
		},
		{
			// The scope column says "global" and this code does not read it:
			// the address itself is what decides, which is why a fabricated
			// scope cannot talk it into returning a routable address as a
			// link-local one.
			name:    "a global address on the interface is not a link-local",
			lines:   []string{global + " 03 40 00 80 v6cli0"},
			wantErr: true,
			inMsg:   "0 tentative, 0 failed",
		},
		{
			name:    "an interface with no addresses at all",
			lines:   []string{llA + " 02 40 20 80 v6srv0"},
			wantErr: true,
			inMsg:   ErrNoLinkLocal.Error(),
		},
		{
			// Short rows, unparsable hex and a flags column that is not a
			// number are SKIPPED and not fatal: this file is written by the
			// kernel, and a client that refused to start because one line of
			// it was unfamiliar would be refusing on the strength of a format
			// it does not own.
			name: "malformed rows are skipped rather than fatal",
			lines: []string{
				"not-a-row",
				"zz" + llA[2:] + " 03 40 20 80 v6cli0",
				llA + " 03 40 20 zz v6cli0",
				llB + " 03 40 20 80 v6cli0",
			},
			want: "fe80::aabb:ccff:fe11:2233",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "if_inet6")
			if err := os.WriteFile(p, []byte(strings.Join(tc.lines, "\n")+"\n"), 0o600); err != nil {
				t.Fatalf("writing the fixture: %v", err)
			}
			old := ifInet6Path
			ifInet6Path = p
			defer func() { ifInet6Path = old }()

			got, err := InterfaceLinkLocal("v6cli0")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("InterfaceLinkLocal returned %s; want a refusal", got)
				}
				if !errors.Is(err, ErrNoLinkLocal) {
					t.Errorf("error %v does not wrap ErrNoLinkLocal, so a caller cannot tell this apart from a read failure", err)
				}
				if !strings.Contains(err.Error(), tc.inMsg) {
					t.Errorf("error %q does not carry %q; the two refusals have different fixes and the message is where they are told apart", err, tc.inMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("InterfaceLinkLocal: %v", err)
			}
			if got.String() != tc.want {
				t.Errorf("InterfaceLinkLocal = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestInterfaceLinkLocalReportsAFileItCannotRead is the other direction: a
// missing file is an ERROR and never "this interface has no address".
//
// The distinction is the one InterfaceLinkLocal's own message draws — a caller
// told ErrNoLinkLocal waits for the link to settle, and waiting for a link
// that is fine because /proc is not mounted is a hang with a wrong
// explanation.
func TestInterfaceLinkLocalReportsAFileItCannotRead(t *testing.T) {
	old := ifInet6Path
	ifInet6Path = filepath.Join(t.TempDir(), "there-is-no-such-file")
	defer func() { ifInet6Path = old }()

	_, err := InterfaceLinkLocal("v6cli0")
	if err == nil {
		t.Fatal("InterfaceLinkLocal succeeded with no file to read")
	}
	if errors.Is(err, ErrNoLinkLocal) {
		t.Errorf("error %v wraps ErrNoLinkLocal; an unreadable file is not an interface without an address", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error %v does not wrap os.ErrNotExist, so what actually went wrong is not recoverable from it", err)
	}
}
