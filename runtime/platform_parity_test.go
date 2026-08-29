package runtime

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// transportStatsFields renders the TransportStats field list of one source
// file as "name type" strings, in declaration order.
//
// It reads the file with go/parser, which does not apply build constraints, so
// one test run sees both platforms' declarations. That is the whole point: the
// fields' only readers are Linux-only test files, so a build on either
// platform cannot observe a field going missing from the other.
func transportStatsFields(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []string
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, s := range gd.Specs {
			ts, ok := s.(*ast.TypeSpec)
			if !ok || ts.Name.Name != "TransportStats" {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				t.Fatalf("%s: TransportStats is not a struct", path)
			}
			for _, fl := range st.Fields.List {
				typ := fmt.Sprintf("%s", exprString(fl.Type))
				for _, n := range fl.Names {
					out = append(out, n.Name+" "+typ)
				}
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s declares no TransportStats fields; the check would compare two empty lists", path)
	}
	return out
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.StarExpr:
		return "*" + exprString(v.X)
	case *ast.ArrayType:
		return "[]" + exprString(v.Elt)
	default:
		return fmt.Sprintf("%T", e)
	}
}

// TestTransportStatsDeclarationsAgree is the check the non-Linux file's comment
// names. It goes red when either declaration gains, loses or retypes a field.
//
// BOUND, stated because the sentence it replaces overstated its own check:
// this compares the TransportStats field lists of exactly the two files named
// below, by name and by rendered type. It says nothing about the two
// PacketTransport method sets, and it cannot see a third platform file that
// does not exist — if one is added it must be added here too, and nothing but
// this sentence says so.
func TestTransportStatsDeclarationsAgree(t *testing.T) {
	linux := transportStatsFields(t, "transport_packet_linux.go")
	other := transportStatsFields(t, "transport_packet_other.go")
	if len(linux) != len(other) {
		t.Fatalf("field count differs: linux %d %v, other %d %v", len(linux), linux, len(other), other)
	}
	for i := range linux {
		if linux[i] != other[i] {
			t.Errorf("field %d differs: linux %q, other %q", i, linux[i], other[i])
		}
	}
}
