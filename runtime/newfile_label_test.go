package runtime

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// packageStringConsts is every package-level constant in this package whose
// value is a string literal, by name.
//
// It is collected across ALL the package's non-test files rather than per
// file, because the four socket labels are declared in one file and used in
// four.
func packageStringConsts(t *testing.T, files map[string]*ast.File) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, f := range files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				vs, ok := s.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, n := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						out[n.Name] = true
					}
				}
			}
		}
	}
	return out
}

// nonTestSources parses every non-test .go file in this package's directory.
//
// go/parser applies no build constraints, so one run sees every platform's
// files. That matters here for the same reason it matters in
// platform_parity_test.go: a call site that only compiles elsewhere is still a
// call site, and a check that could not see it would report a domain smaller
// than the package.
func nonTestSources(t *testing.T) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	out := map[string]*ast.File{}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		out[name] = f
	}
	if len(out) == 0 {
		t.Fatal("this package has no non-test sources, so the check below walks nothing")
	}
	return fset, out
}

// TestNoCallerStringReachesOsNewFile is the observer for the CodeQL finding
// `go/path-injection` at nd_linux.go and transport_packet6_linux.go.
//
// os.NewFile's second parameter is a NAME in the sense of *os.File.Name: a
// label the Go runtime carries so that an error about the handle can say which
// handle it was. It opens nothing. CodeQL models it as a filesystem-path sink
// all the same, so a label built by concatenating a caller-supplied interface
// name — `"packet:"+ifName` — reads to the scanner as a caller-controlled
// string reaching a path parameter, and the alert is correct about the flow
// while being wrong about the consequence.
//
// The fix is that no caller string reaches the parameter at all: each socket
// gets a fixed label, and the interface name is kept in a field beside the
// handle so the close error still names it. That is a property of the source,
// not of any execution, which is why this observer reads the source.
//
// THE DOMAIN IS EVERY os.NewFile CALL IN THIS PACKAGE'S NON-TEST FILES, and
// not the two files CodeQL named. A rule that listed the alerts would be
// satisfied by the next call site written the old way — and two of the four
// call sites in this package already had the fixed-label shape before the
// scanner ran, which is exactly how a per-alert rule ends up believing a
// package is clean.
//
// BOUNDS. (1) It reads THIS package only; the same shape elsewhere in the
// tree is not its business, and nothing here can see it. CHECKED at the time
// of writing: os.NewFile appears in no other package of this module, so the
// bound hides no live call site today — it is the site a LATER package adds
// that this observer would not see. (2) It cannot judge
// whether a literal is a GOOD label, only that it is a literal — a call
// passing "" would pass this test. (3) Its domain excludes _test.go files,
// and two test helpers in this package do concatenate the interface name:
// dnsmasq6_linux_test.go's raWatch ("ra_watch:"+ifName) and txWatch
// ("tx_watch:"+ifName). They are named here so the exclusion is visible
// rather than implied; they are fixture code that ships with no binary.
// (4) It is not CodeQL: the scanner's own verdict on this tree is what closes
// the alert, and this test cannot produce it.
func TestNoCallerStringReachesOsNewFile(t *testing.T) {
	fset, files := nonTestSources(t)
	consts := packageStringConsts(t, files)

	calls := 0
	for name, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "NewFile" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "os" {
				return true
			}
			calls++
			where := fset.Position(call.Lparen).String()
			if len(call.Args) != 2 {
				t.Errorf("%s: os.NewFile takes two arguments, this call has %d", where, len(call.Args))
				return true
			}
			switch a := call.Args[1].(type) {
			case *ast.BasicLit:
				if a.Kind != token.STRING {
					t.Errorf("%s: the label is a %s literal, want a string", where, a.Kind)
				}
			case *ast.Ident:
				if !consts[a.Name] {
					t.Errorf("%s: the label is %s, which this package does not declare as a string constant; "+
						"os.NewFile's second parameter must carry no caller-supplied string (go/path-injection)", where, a.Name)
				}
			default:
				t.Errorf("%s: the label is a %T and not a literal or a declared constant; "+
					"a label built from a caller's string is what go/path-injection reports, and %s already keeps "+
					"the interface name in a field beside the handle", where, a, name)
			}
			return true
		})
	}

	// A universal over an empty domain passes having measured nothing, and
	// this domain is one a refactor can empty by accident: the sockets could
	// move behind a helper in another package and every assertion above would
	// still "hold".
	if calls == 0 {
		t.Fatal("no os.NewFile call was found in this package's non-test files; " +
			"the check measured nothing, which is not the same as finding nothing wrong")
	}
	t.Logf("checked %d os.NewFile call(s) across %d non-test file(s)", calls, len(files))
}
