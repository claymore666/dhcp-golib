// Package gatetest builds throwaway module fixtures and runs a gate binary
// against them, so each gate's red-then-green behaviour is a test that reruns
// rather than a transcript somebody once pasted into a report.
//
// The gate is exercised as a BUILT BINARY, not by calling its run function.
// That is deliberate: the gates report three outcomes through three exit codes
// (0 pass, 1 violation, 2 refused), verify.sh distinguishes them, and the
// mapping from an internal result to an exit code is part of what has to work.
// Calling run() in-process would test everything except that.
package gatetest

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Exit codes the gates share.
const (
	Pass    = 0
	Violate = 1
	Refuse  = 2
)

// Build compiles the gate in the current package directory and returns the
// path to the binary.
func Build(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "gate")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building the gate failed: %v\n%s", err, out)
	}
	return bin
}

// Fixture writes a throwaway module rooted at a fresh temp dir. files maps a
// path relative to that root to its contents; the go.mod and the four ring
// packages are written first and any entry in files overwrites them.
//
// The module path matches the real one on purpose: the gates classify an
// import as internal by that prefix, and a fixture declaring a different path
// would exercise a different code path from the one that runs in anger.
func Fixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	base := map[string]string{
		"go.mod":         "module github.com/claymore666/dhcplease\n\ngo 1.25\n",
		"wire/doc.go":    "package wire\n",
		"proto/doc.go":   "package proto\n",
		"lease/doc.go":   "package lease\n",
		"runtime/doc.go": "package runtime\n",
	}
	for path, content := range files {
		base[path] = content
	}
	for path, content := range base {
		if content == Delete {
			continue
		}
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("fixture mkdir %s: %v", path, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("fixture write %s: %v", path, err)
		}
	}
	return root
}

// Delete, used as a file's content in a Fixture map, omits that file. It is
// how a test empties a gate's domain — the case a universal gate passes
// vacuously if nobody checks it.
const Delete = "\x00delete\x00"

// Run executes the gate against root and returns its exit code and combined
// output.
func Run(t *testing.T, bin, root string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"-root", root}, args...)...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var ee *exec.ExitError
	if e, ok := err.(*exec.ExitError); ok {
		ee = e
		return ee.ExitCode(), string(out)
	}
	t.Fatalf("running the gate failed: %v\n%s", err, out)
	return -1, ""
}
