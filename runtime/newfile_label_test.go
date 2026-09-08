// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package runtime

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
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
//
// OBJECT RESOLUTION IS ON, which costs a parse pass and buys the difference
// between an identifier's NAME and what it refers to. Under
// parser.SkipObjectResolution — where this walk started — a function-local
// variable that happened to be spelled like one of the four socket labels was
// indistinguishable from the constant, and an import bound to a name other
// than "os" was not in the walk's domain at all. Both are closed by
// ast.Ident.Obj: an identifier declared in this file carries the declaration
// that made it, and a package qualifier carries none.
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
		f, err := parser.ParseFile(fset, name, src, 0)
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

// osQualifiers is the identifier this file's own import declarations bind to
// the "os" package, and whether it dot-imports it.
//
// IT IS READ FROM THE FILE AND NOT ASSUMED TO BE "os", because an alias is a
// way out of a rule that matches the spelling: `import osx "os"` then
// `osx.NewFile` is the same call site wearing a name no text search and no
// name-keyed walk would look at.
func osQualifiers(f *ast.File) (map[string]bool, bool) {
	out := map[string]bool{}
	dot := false
	for _, im := range f.Imports {
		if im.Path == nil || im.Path.Value != `"os"` {
			continue
		}
		switch {
		case im.Name == nil:
			out["os"] = true
		case im.Name.Name == ".":
			dot = true
		case im.Name.Name == "_":
		default:
			out[im.Name.Name] = true
		}
	}
	return out, dot
}

// newFileLabelFindings applies the rule to one parsed file and reports what it
// found: the complaints, and how many references to os.NewFile it judged.
//
// It is a function over parsed input rather than a walk hard-wired to this
// directory so that every refusal arm can be DRIVEN from fabricated source —
// see TestTheNewFileLabelRuleRefusesEveryWayPastIt. A rule whose refusals are
// only ever asserted against a tree that satisfies them is a rule with one
// possible verdict.
func newFileLabelFindings(fset *token.FileSet, file string, f *ast.File, consts map[string]bool) ([]string, int) {
	var out []string
	say := func(pos token.Pos, format string, args ...any) {
		out = append(out, fset.Position(pos).String()+": "+fmt.Sprintf(format, args...))
	}

	quals, dot := osQualifiers(f)
	if dot {
		say(f.Pos(), "%s dot-imports os, so os.NewFile can be called here with no qualifier at all; "+
			"this rule reads qualified calls and cannot see that shape", file)
	}
	if len(quals) == 0 {
		return out, 0
	}

	// A reference is os.NewFile named anywhere; a call is one that is the
	// function of a CallExpr. The difference is the third way past a rule
	// that inspects arguments: `f := os.NewFile` hands the function to
	// something this walk cannot follow, and its label is chosen there.
	called := map[*ast.SelectorExpr]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			called[sel] = true
		}
		return true
	})

	refs := 0
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "NewFile" {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || !quals[pkg.Name] {
			return true
		}
		// An identifier that resolves to a declaration in this file is a
		// local of that spelling, not the imported package.
		if pkg.Obj != nil {
			return true
		}
		refs++
		if !called[sel] {
			say(sel.Pos(), "os.NewFile is referenced without being called; "+
				"the label is then chosen wherever the function value ends up, which this rule cannot follow")
			return true
		}
		call := parentCall(f, sel)
		if call == nil || len(call.Args) != 2 {
			n := -1
			if call != nil {
				n = len(call.Args)
			}
			say(sel.Pos(), "os.NewFile takes two arguments, this call has %d", n)
			return true
		}
		switch a := call.Args[1].(type) {
		case *ast.BasicLit:
			if a.Kind != token.STRING {
				say(call.Lparen, "the label is a %s literal, want a string", a.Kind)
			}
		case *ast.Ident:
			switch {
			case a.Obj != nil && a.Obj.Kind != ast.Con:
				say(call.Lparen, "the label is %s, which this file declares as a %s and not as a constant; "+
					"a local of the same spelling as a socket label is not that label", a.Name, a.Obj.Kind)
			case !consts[a.Name]:
				say(call.Lparen, "the label is %s, which this package does not declare as a package-level string constant; "+
					"os.NewFile's second parameter must carry no caller-supplied string (go/path-injection)", a.Name)
			}
		default:
			say(call.Lparen, "the label is a %T and not a literal or a declared constant; "+
				"a label built from a caller's string is what go/path-injection reports, and %s already keeps "+
				"the interface name in a field beside the handle", a, file)
		}
		return true
	})
	return out, refs
}

// parentCall is the CallExpr whose Fun is sel, or nil.
func parentCall(f *ast.File, sel *ast.SelectorExpr) *ast.CallExpr {
	var found *ast.CallExpr
	ast.Inspect(f, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok && call.Fun == ast.Expr(sel) {
			found = call
			return false
		}
		return true
	})
	return found
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
// THE DOMAIN IS EVERY os.NewFile REFERENCE IN THIS PACKAGE'S NON-TEST FILES,
// and not the two files CodeQL named. A rule that listed the alerts would be
// satisfied by the next call site written the old way — and two of the four
// call sites in this package already had the fixed-label shape before the
// scanner ran, which is exactly how a per-alert rule ends up believing a
// package is clean.
//
// IT IS KEYED ON WHAT THE IDENTIFIERS REFER TO AND NOT ON HOW THEY ARE SPELLED
// (2026-09-08, from the M7e review). Three shapes used to leave the rule
// satisfied or leave its domain: a function-local variable spelled like one of
// the four socket labels, an aliased import of os, and os.NewFile taken as a
// function value rather than called. The first two are closed by object
// resolution and by reading the file's own import declarations; the third is
// REFUSED, because a rule that inspects a call's arguments cannot follow a
// function value to wherever it is applied.
//
// BOUNDS. (1) It reads THIS package only; the same shape elsewhere in the
// tree is not its business, and nothing here can see it. CHECKED at the time
// of writing: os.NewFile appears in no other package of this module, so the
// bound hides no live call site today — it is the site a LATER package adds
// that this observer would not see. (2) It cannot judge whether a literal is
// a GOOD label, only that it is a literal — a call passing "" would pass.
// (3) Its domain excludes _test.go files, and two test helpers in this
// package do concatenate the interface name: dnsmasq6_linux_test.go's raWatch
// ("ra_watch:"+ifName) and txWatch ("tx_watch:"+ifName). They are named here
// so the exclusion is visible rather than implied; they are fixture code that
// ships with no binary. (4) A dot-import of os is refused rather than read,
// because an unqualified NewFile is outside a walk that keys on the
// qualifier. (5) A function-local `const` spelled like a package-level label
// passes: Go requires a constant expression there, so no caller string can
// reach it. (6) It is not CodeQL: the scanner's own verdict on this tree is
// what closes the alert, and this test cannot produce it.
func TestNoCallerStringReachesOsNewFile(t *testing.T) {
	fset, files := nonTestSources(t)
	consts := packageStringConsts(t, files)

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	refs := 0
	for _, name := range names {
		found, n := newFileLabelFindings(fset, name, files[name], consts)
		refs += n
		for _, f := range found {
			t.Error(f)
		}
	}

	// A universal over an empty domain passes having measured nothing, and
	// this domain is one a refactor can empty by accident: the sockets could
	// move behind a helper in another package and every assertion above would
	// still "hold".
	if refs == 0 {
		t.Fatal("no os.NewFile reference was found in this package's non-test files; " +
			"the check measured nothing, which is not the same as finding nothing wrong")
	}
	if len(consts) == 0 {
		t.Fatal("this package declares no package-level string constant, so the arm that admits a named label " +
			"could not have admitted anything")
	}
	t.Logf("judged %d os.NewFile reference(s) across %d non-test file(s), against %d package-level string constant(s)",
		refs, len(files), len(consts))
}

// TestTheNewFileLabelRuleRefusesEveryWayPastIt drives the rule itself, in both
// directions, over source this test writes.
//
// The tree it runs against satisfies the rule, so nothing there can say what
// the rule DOES when it is broken — and the three ways past it that the M7e
// review found were all shapes the tree does not contain. Each is planted
// here, with the preservation controls beside them so a rule that simply
// complained about everything would fail this test rather than pass it.
func TestTheNewFileLabelRuleRefusesEveryWayPastIt(t *testing.T) {
	const consts = "const socketLabelIPv6 = \"packet6\"\n"
	for _, tc := range []struct {
		name string
		body string
		// want is a substring of the expected complaint, or "" for a shape
		// the rule must accept.
		want string
		refs int
	}{
		{
			name: "a package-level constant label",
			body: "import \"os\"\n" + consts + "func f(fd uintptr) { _ = os.NewFile(fd, socketLabelIPv6) }\n",
			refs: 1,
		},
		{
			name: "a string literal label",
			body: "import \"os\"\nfunc f(fd uintptr) { _ = os.NewFile(fd, \"packet6\") }\n",
			refs: 1,
		},
		{
			name: "a caller string concatenated into the label",
			body: "import \"os\"\nfunc f(fd uintptr, ifName string) { _ = os.NewFile(fd, \"packet6:\"+ifName) }\n",
			want: "not a literal or a declared constant",
			refs: 1,
		},
		{
			name: "a local shadowing a socket label",
			body: "import \"os\"\n" + consts + "func f(fd uintptr, ifName string) {\n\tsocketLabelIPv6 := \"packet6:\" + ifName\n\t_ = os.NewFile(fd, socketLabelIPv6)\n}\n",
			want: "which this file declares as a var",
			refs: 1,
		},
		{
			name: "an aliased import of os",
			body: "import osx \"os\"\nfunc f(fd uintptr, ifName string) { _ = osx.NewFile(fd, \"packet6:\"+ifName) }\n",
			want: "not a literal or a declared constant",
			refs: 1,
		},
		{
			name: "os.NewFile taken as a function value",
			body: "import \"os\"\nfunc f(fd uintptr, ifName string) {\n\tmk := os.NewFile\n\t_ = mk(fd, \"packet6:\"+ifName)\n}\n",
			want: "referenced without being called",
			refs: 1,
		},
		{
			name: "a dot-import of os",
			body: "import . \"os\"\nfunc f(fd uintptr) { _ = NewFile(fd, \"packet6\") }\n",
			want: "dot-imports os",
			refs: 0,
		},
		{
			name: "a method named NewFile on something that is not os",
			body: "type shim struct{}\n\nfunc (shim) NewFile(fd uintptr, s string) any { return nil }\n\nfunc f(fd uintptr, ifName string) {\n\tos := shim{}\n\t_ = os.NewFile(fd, \"packet6:\"+ifName)\n}\n",
			refs: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "planted.go", "package runtime\n\n"+tc.body, 0)
			if err != nil {
				t.Fatalf("the planted source does not parse: %v", err)
			}
			got, refs := newFileLabelFindings(fset, "planted.go", f, map[string]bool{"socketLabelIPv6": true})
			if refs != tc.refs {
				t.Errorf("the rule judged %d reference(s), want %d", refs, tc.refs)
			}
			joined := strings.Join(got, "\n")
			switch {
			case tc.want == "" && len(got) != 0:
				t.Errorf("the rule complained about a shape it must accept:\n%s", joined)
			case tc.want != "" && !strings.Contains(joined, tc.want):
				t.Errorf("the rule said %q, want something containing %q", joined, tc.want)
			}
		})
	}
}
