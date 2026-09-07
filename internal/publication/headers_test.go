// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package publication

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The one line every source file in this tree begins with, so that the notice
// travels with a file that is copied out of it — which is not hypothetical: the
// consumer of this library copies this tree into its own, under a different
// licence.
const (
	licenceHeaderGo = "// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE."
	licenceHeaderSh = "# Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE."
)

// treeRoot is the repository, relative to this package.
const treeRoot = "../.."

// The floors. They are LOW-WATER MARKS and not the tree's real counts: this
// check is a universal, and a universal is satisfied by emptying its domain —
// a walk that stopped at the first directory, a suffix test that stopped
// matching, a root that resolved somewhere else. Deleting files until the
// domain is empty is the one defeat a per-file assertion cannot see, so the
// size of the domain is asserted separately from its contents.
const (
	minGoFiles    = 100
	minShellFiles = 4
)

// sourceFiles is every .go and .sh file in the tree, `.git` aside.
//
// IT WALKS THE FILESYSTEM AND NOT THE INDEX. `git ls-files` would be the
// obvious domain and is the wrong one twice over: this test also runs inside
// the arbiter's oracle, on copies of this tree that are not repositories at
// all — where the answer would be "no files", i.e. a pass over nothing — and a
// file that is in the tree but not yet added is still a file somebody will
// copy.
//
// BOUND: the domain is chosen by SUFFIX. A shell script with no .sh extension
// carries no header and is not asked for one; the tree has none today, and the
// arbiter's shellcheck row is the instrument that would notice one arriving.
func sourceFiles(t *testing.T) (goFiles, shFiles []string) {
	t.Helper()
	err := filepath.WalkDir(treeRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		switch {
		case strings.HasSuffix(d.Name(), ".go"):
			goFiles = append(goFiles, path)
		case strings.HasSuffix(d.Name(), ".sh"):
			shFiles = append(shFiles, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", treeRoot, err)
	}
	return goFiles, shFiles
}

// headerOf returns the line the header must be on and the line that must
// follow it: after a shebang if there is one, at the top otherwise.
func headerOf(text string) (got, next string) {
	lines := strings.Split(text, "\n")
	i := 0
	if len(lines) > 0 && strings.HasPrefix(lines[0], "#!") {
		i = 1
	}
	if i < len(lines) {
		got = lines[i]
	}
	if i+1 < len(lines) {
		next = lines[i+1]
	}
	return got, next
}

// TestEveryGoAndShellFileCarriesTheLicenceHeader is the observer for the
// per-file notice. A licence file at the root says nothing about a file that
// has left the root, and this library's one consumer copies files out of this
// tree into a GPL-3.0 one — where the header is the only thing that says under
// what terms the copy is there.
//
// The blank line after the header is required and is not cosmetic: without it
// the header would become the doc comment of whatever follows, so a `package`
// clause would document itself as a copyright notice and `//go:build` would
// stop being a build constraint.
func TestEveryGoAndShellFileCarriesTheLicenceHeader(t *testing.T) {
	goFiles, shFiles := sourceFiles(t)
	if len(goFiles) < minGoFiles || len(shFiles) < minShellFiles {
		t.Fatalf("the walk found %d .go and %d .sh file(s) under %s, below the floors of %d and %d; a universal over a domain this small is not measuring the tree",
			len(goFiles), len(shFiles), treeRoot, minGoFiles, minShellFiles)
	}
	check := func(path, want string) {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("reading %s: %v", path, err)
			return
		}
		got, next := headerOf(string(b))
		if got != want {
			t.Errorf("%s: the first line (after any shebang) is %q, want the licence header %q; a copy of this file would carry no licence at all",
				path, got, want)
			return
		}
		if next != "" {
			t.Errorf("%s: the licence header is not followed by a blank line but by %q; without the blank line the notice becomes the doc comment of whatever follows it",
				path, next)
		}
	}
	for _, f := range goFiles {
		check(f, licenceHeaderGo)
	}
	for _, f := range shFiles {
		check(f, licenceHeaderSh)
	}
}

// TestTheLicenceHeaderPointsAtALicenceThatGrantsIt closes the other half: every
// file can name a LICENSE that is not there, or that grants nothing. The
// header says "see LICENSE", so LICENSE has to exist, carry the same copyright
// line, and carry the grant — the sentence that makes the file usable.
func TestTheLicenceHeaderPointsAtALicenceThatGrantsIt(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(treeRoot, "LICENSE"))
	if err != nil {
		t.Fatalf("every source file in this tree says \"see LICENSE\": %v", err)
	}
	text := string(b)
	for _, want := range []string{
		"MIT License",
		"Copyright (c) 2026 Christian Kamien",
		"Permission is hereby granted, free of charge",
		"THE SOFTWARE IS PROVIDED \"AS IS\"",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("LICENSE does not carry %q; the notice on every file points at it", want)
		}
	}
	if !strings.Contains(licenceHeaderGo, "MIT") || !strings.Contains(text, "MIT") {
		t.Errorf("the header and LICENSE do not name the same licence")
	}
}
