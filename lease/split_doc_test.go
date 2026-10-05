// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// splitDocs is the doc comment of each declaration in file, by the first
// name it declares.
func splitDocs(t *testing.T, file string) map[string]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	docs := map[string]string{}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			docs[d.Name.Name] = d.Doc.Text()
		case *ast.GenDecl:
			for _, s := range d.Specs {
				switch s := s.(type) {
				case *ast.TypeSpec:
					docs[s.Name.Name] = d.Doc.Text()
					if st, ok := s.Type.(*ast.StructType); ok {
						for _, fl := range st.Fields.List {
							for _, n := range fl.Names {
								docs[s.Name.Name+"."+n.Name] = fl.Doc.Text()
							}
						}
					}
				case *ast.ValueSpec:
					docs[s.Names[0].Name] = d.Doc.Text()
				}
			}
		}
	}
	return docs
}

func TestTheSplitReleaseDocsSitOnTheirOwnDeclarations(t *testing.T) {
	rel, mgr := splitDocs(t, "release.go"), splitDocs(t, "manager.go")
	for _, c := range []struct{ name, doc, want string }{
		{"ReleaseDatagram", rel["ReleaseDatagram"], "ReleaseDatagram is"},
		{"the refusals var block", rel["ErrReleaseFamily"], "The refusals BuildRelease returns"},
		{"BuildReleases", rel["BuildReleases"], "RFC 8415 section 18.2.7"},
		{"Config.Resume6", mgr["Config.Resume6"], "ServerDUID, Prefixes and PrefixServerDUID are read"},
	} {
		c.doc = strings.Join(strings.Fields(c.doc), " ")
		if !strings.Contains(c.doc, c.want) || c.name == "ReleaseDatagram" && !strings.HasPrefix(c.doc, c.want) {
			t.Errorf("the doc of %s does not say %q: %q", c.name, c.want, c.doc)
		}
	}
}
