package main_test

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/claymore666/dhcplease/internal/gates/gatetest"
	"github.com/claymore666/dhcplease/internal/gates/rings"
)

// The tests in this file drive the POLICY TABLES through the real gate binary.
//
// rings/policy_test.go asserts things about the tables themselves — that a
// refused name is not also allowed, that an admitted package's closure is
// clean. Those are assertions about a map. This file asserts what the GATE
// DOES when a ring-1 file names one of these things, which is the only
// evidence that the policy is connected to anything.
//
// The cases are GENERATED from the tables rather than listed, so an entry
// added to a table is driven automatically. A hand-listed case per identifier
// is an unrun checklist that drifts from the table beside it.
//
// They are batched — one fixture per table, not one per identifier — because
// each case is a process exec plus a `go list`, and 130 of those would put the
// suite over the wall-clock ceiling that T2 depends on.

// TestPureRefusedPkgsAreRefusedByTheGate: every package on PureRefusedPkgs is
// actually refused when a ring-1 file imports it.
func TestPureRefusedPkgsAreRefusedByTheGate(t *testing.T) {
	pkgs := rings.PureRefusedPkgs
	if len(pkgs) == 0 {
		t.Fatal("PureRefusedPkgs is empty; this test would pass having driven nothing")
	}
	var b strings.Builder
	b.WriteString("package proto\n\nimport (\n")
	for _, p := range pkgs {
		fmt.Fprintf(&b, "\t_ %q\n", p)
	}
	b.WriteString(")\n")

	root := gatetest.Fixture(t, map[string]string{"proto/refused.go": b.String()})
	code, out := gatetest.Run(t, bin(t), root)
	if code != gatetest.Violate {
		t.Fatalf("exit code = %d, want %d (VIOLATION)\noutput:\n%s", code, gatetest.Violate, out)
	}
	for _, p := range pkgs {
		if !strings.Contains(out, `"`+p+`"`) {
			t.Errorf("ring 1 imported %q and the gate did not name it. Ring 1 must not import it.\noutput:\n%s", p, out)
		}
	}
}

// TestPureRefusedIdentsAreRefusedByTheGate: for each package that IS admitted
// but restricted, every identifier on its refusal list is actually refused.
func TestPureRefusedIdentsAreRefusedByTheGate(t *testing.T) {
	if len(rings.PureRefusedIdents) == 0 {
		t.Fatal("PureRefusedIdents is empty; this test would pass having driven nothing")
	}
	for _, pkg := range sortedKeys(rings.PureRefusedIdents) {
		idents := rings.PureRefusedIdents[pkg]
		t.Run(pkg, func(t *testing.T) {
			if len(idents) == 0 {
				t.Fatalf("%q has an empty refusal list", pkg)
			}
			local := pkg[strings.LastIndex(pkg, "/")+1:]
			var b strings.Builder
			fmt.Fprintf(&b, "package proto\n\nimport %q\n\n", pkg)
			for _, id := range idents {
				fmt.Fprintf(&b, "var _ = %s.%s\n", local, id)
			}
			root := gatetest.Fixture(t, map[string]string{"proto/refused.go": b.String()})
			code, out := gatetest.Run(t, bin(t), root)
			if code != gatetest.Violate {
				t.Fatalf("exit code = %d, want %d (VIOLATION)\noutput:\n%s", code, gatetest.Violate, out)
			}
			for _, id := range idents {
				if !strings.Contains(out, local+"."+id) {
					t.Errorf("ring 1 named %s.%s and the gate did not report it\noutput:\n%s", local, id, out)
				}
			}
		})
	}
}

// TestPureAllowlistIsAccepted is the PRESERVATION CONTROL for T1: a ring-1
// file that imports every admitted package and names every admitted
// identifier must PASS.
//
// A guard fails in one direction. Without this, every refusal above could be
// satisfied by a gate that refuses everything — and a gate that refuses honest
// code is the one that gets weakened the first week somebody meets it.
func TestPureAllowlistIsAccepted(t *testing.T) {
	pkgs := sortedKeys(rings.PureStdlib)
	if len(pkgs) == 0 {
		t.Fatal("PureStdlib is empty; this control would pass having driven nothing")
	}
	var imports, decls strings.Builder
	for _, p := range pkgs {
		fmt.Fprintf(&imports, "\t_ %q\n", p)
	}
	named := 0
	for _, pkg := range sortedKeys(rings.PureIdents) {
		local := pkg[strings.LastIndex(pkg, "/")+1:] + "2"
		fmt.Fprintf(&imports, "\t%s %q\n", local, pkg)
		for _, id := range sortedKeys(rings.PureIdents[pkg]) {
			fmt.Fprintf(&decls, "var _ = %s.%s\n", local, id)
			named++
		}
	}
	src := "package proto\n\nimport (\n" + imports.String() + ")\n\n" + decls.String()

	if named == 0 {
		t.Fatal("no restricted identifiers were named; the control would prove nothing")
	}

	root := gatetest.Fixture(t, map[string]string{"proto/allowed.go": src})
	code, out := gatetest.Run(t, bin(t), root)
	if code != gatetest.Pass {
		t.Fatalf("legitimate ring-1 code was refused: exit %d, want PASS. The gate must not "+
			"stand in the way of honest code.\noutput:\n%s", code, out)
	}
	t.Logf("preservation control: %d packages imported, %d restricted identifiers named, PASS", len(pkgs), named)
}

// gateBin is built once for the whole package. Every test in t1 uses it.
var gateBin string

func TestMain(m *testing.M) {
	b, cleanup, err := gatetest.BuildForMain()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	gateBin = b
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func bin(t *testing.T) string {
	t.Helper()
	return gateBin
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
