package scan

import (
	"os"
	"testing"
)

func osWriteFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

// TestDefaultLocal pins the identifier an unaliased import binds.
//
// It exists because a mutant that replaced defaultLocal(path) with path
// SURVIVED the gate suites: every package either gate restricts today (time,
// context, fmt) is a single-element path, for which the two are the same
// string. The mutant was a no-op on the inputs in play and a real hole for the
// next restricted package with a slash in it.
func TestDefaultLocal(t *testing.T) {
	cases := map[string]string{
		"time":         "time",
		"context":      "context",
		"net/netip":    "netip", // the case the surviving mutant broke
		"math/rand/v2": "rand",  // a version element is not the package name
		// "v2" has no package to fall back to. It sliced path[:-1] and
		// panicked the gate before the length guard in defaultLocal; a gate
		// that crashes on a malformed import is not reporting on it.
		"v2": "v2",
		"v":  "v",
		"":   "",
	}
	for path, want := range cases {
		if got := defaultLocal(path); got != want {
			t.Errorf("defaultLocal(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestIsStdlib pins the rule that separates a standard-library import from
// everything else: a dot in the first path element.
func TestIsStdlib(t *testing.T) {
	cases := map[string]bool{
		"time":                                  true,
		"net/netip":                             true,
		"encoding/binary":                       true,
		"github.com/claymore666/dhcplease/wire": false,
		"example.com/x":                         false,
		"gopkg.in/yaml.v3":                      false,
	}
	for path, want := range cases {
		if got := IsStdlib(path); got != want {
			t.Errorf("IsStdlib(%q) = %v, want %v", path, got, want)
		}
	}
}

// TestImportsLocal exercises the CALL SITE, not just defaultLocal.
//
// TestDefaultLocal alone did NOT kill the mutant that replaced
// defaultLocal(path) with path at its one call site: a test on a function does
// not cover the line that calls it. Both gates read Import.Local and nothing
// else, so this is the assertion that actually protects them.
func TestImportsLocal(t *testing.T) {
	src := `package x

import (
	"time"
	"net/netip"
	clk "time"
	. "strings"
	_ "os"
)
`
	path := writeTemp(t, src)
	f, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	type got struct {
		local string
		dot   bool
		blank bool
	}
	want := map[string]got{
		"time":      {local: "time"},
		"net/netip": {local: "netip"},
		"strings":   {dot: true},
		"os":        {blank: true},
	}
	seen := map[string]bool{}
	for _, imp := range f.Imports() {
		if imp.Path == "time" && imp.Local == "clk" {
			seen["time-alias"] = true
			continue
		}
		w, ok := want[imp.Path]
		if !ok {
			t.Errorf("unexpected import %q", imp.Path)
			continue
		}
		seen[imp.Path] = true
		if imp.Local != w.local || imp.Dot != w.dot || imp.Blank != w.blank {
			t.Errorf("import %q: local=%q dot=%v blank=%v, want local=%q dot=%v blank=%v",
				imp.Path, imp.Local, imp.Dot, imp.Blank, w.local, w.dot, w.blank)
		}
	}
	for _, k := range []string{"time", "net/netip", "strings", "os", "time-alias"} {
		if !seen[k] {
			t.Errorf("import %q was not reported at all", k)
		}
	}
}

func writeTemp(t *testing.T, src string) string {
	t.Helper()
	path := t.TempDir() + "/x.go"
	if err := osWriteFile(path, src); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}
