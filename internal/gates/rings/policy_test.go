package rings

import (
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The policy tables in rings.go are DATA that the gates read, and until these
// tests existed nothing checked them. MEASURED 2026-08-29: 21 one-line
// allowlist widenings driven through the whole suite, 12 SURVIVED — admitting
// syscall, context, os/exec and net/http into ring 1; admitting fmt.Printf,
// Fprintf, Fprintln and Fscan into ring 1; admitting time.Tick and
// time.NewTimer into tests; admitting context.WithDeadline and
// context.AfterFunc into tests.
//
// The tests below come in two kinds and the distinction is the point:
//
//   - DERIVED. The property is computed from the toolchain — the dependency
//     closure, or the package's real declared signatures — so it holds over
//     the WHOLE package surface, including identifiers nobody has heard of and
//     ones Go has not shipped yet.
//   - ENUMERATED. A hand-written refusal list. Bounded by construction, and
//     used only where no derivation exists.
//
// A count of things this cannot see is at the bottom of the file.

// impureRoots are the packages that actually perform I/O or read ambient
// state. Everything impure in the standard library reaches one of them, which
// is what makes reachability a usable derivation rather than a name check.
var impureRoots = []string{
	"syscall", "os", "net", "time", "context",
	"internal/poll", "runtime/cgo", "os/signal", "os/exec",
}

// TestPureStdlibClosureIsClean is the DERIVED check, and the one that covers
// packages nobody listed.
//
// Rule: a package on PureStdlib whose transitive dependency closure reaches an
// impure root must carry a PureIdents restriction. A clean closure needs none.
//
// This is what found encoding/hex. It was on the allowlist unrestricted, its
// closure reaches os and syscall, and hex.Dumper takes an io.Writer — so ring 1
// could have held a stream through a package that looks like a codec. No
// enumeration of "the five names the requirement lists" would ever have
// returned it.
func TestPureStdlibClosureIsClean(t *testing.T) {
	pkgs := sortedKeys(PureStdlib)
	if len(pkgs) == 0 {
		t.Fatal("PureStdlib is empty; this check would pass having judged nothing")
	}
	for _, pkg := range pkgs {
		deps, err := goListDeps(pkg)
		if err != nil {
			t.Fatalf("cannot resolve the closure of %q, so the policy is unmeasurable: %v", pkg, err)
		}
		if len(deps) == 0 {
			t.Fatalf("go list returned no dependencies for %q; refusing rather than passing", pkg)
		}
		var reached []string
		for _, root := range impureRoots {
			if deps[root] && root != pkg {
				reached = append(reached, root)
			}
		}
		_, restricted := PureIdents[pkg]
		switch {
		case len(reached) == 0 && restricted:
			t.Errorf("%q has a clean closure but carries a PureIdents restriction. "+
				"Either the restriction is unnecessary or the closure moved; decide which.", pkg)
		case len(reached) > 0 && !restricted:
			t.Errorf("%q is admitted to ring 1 unrestricted, but its closure reaches %v. "+
				"Give it a PureIdents entry naming the identifiers that do not touch a "+
				"stream, or take it off PureStdlib.", pkg, reached)
		}
	}
}

// TestPureRefusedPkgsAreAbsent is the ENUMERATED companion. It exists because
// a package can have a clean closure and still be wrong for ring 1 — math/rand
// carries a global source, reflect defeats the purity argument entirely — and
// reachability cannot see that.
func TestPureRefusedPkgsAreAbsent(t *testing.T) {
	if len(PureRefusedPkgs) == 0 {
		t.Fatal("PureRefusedPkgs is empty; this check would pass having judged nothing")
	}
	for _, pkg := range PureRefusedPkgs {
		if PureStdlib[pkg] {
			t.Errorf("%q is on PureStdlib and on PureRefusedPkgs. Ring 1 must not import it.", pkg)
		}
	}
}

// TestRefusedIdentsAreNotAllowed keeps the two kinds of table disjoint. It is
// cheap and it is not the real guard — TestRefusedIdentsAreDrivenThroughTheGates
// in the t1 and t2 packages is, because membership in a map proves nothing
// about what the gate does.
func TestRefusedIdentsAreNotAllowed(t *testing.T) {
	check := func(kind string, refused map[string][]string, allowed map[string]map[string]bool) {
		if len(refused) == 0 {
			t.Fatalf("%s refusal table is empty; this check would pass having judged nothing", kind)
		}
		for pkg, idents := range refused {
			for _, id := range idents {
				if allowed[pkg][id] {
					t.Errorf("%s: %s.%s is on both the allowlist and the refusal list", kind, pkg, id)
				}
			}
		}
	}
	check("pure", PureRefusedIdents, PureIdents)
	check("test", TestRefusedIdents, TestIdents)
}

// TestAllowlistedIdentifiersExist catches the drift an allowlist rots by: a
// typo, or a name the standard library removed. An allowlist entry naming
// nothing is dead weight that reads as a considered decision.
func TestAllowlistedIdentifiersExist(t *testing.T) {
	n := 0
	for _, tbl := range []map[string]map[string]bool{PureIdents, TestIdents} {
		for _, pkg := range sortedKeys(tbl) {
			for _, id := range sortedKeys(tbl[pkg]) {
				n++
				if !declared(pkg, id) {
					t.Errorf("%s.%s is allowlisted but %q declares no such exported identifier", pkg, id, pkg)
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no allowlisted identifiers were probed; this check would pass having judged nothing")
	}
	t.Logf("probed %d allowlisted identifiers", n)
}

// TestAllowlistsExcludeStreamAPIs is DERIVED from the real declared
// signatures: an identifier taking or returning an io.Writer or io.Reader
// hands a pure ring a stream, whatever it is called. It covers the whole
// package surface, so a function added to fmt in a future Go release is
// covered without anybody editing this file.
func TestAllowlistsExcludeStreamAPIs(t *testing.T) {
	stream := regexp.MustCompile(`\bio\.(Writer|Reader|WriteCloser|ReadCloser|ReadWriter)\b`)
	for pkg, allowed := range PureIdents {
		sigs, err := goDocSignatures(pkg)
		if err != nil {
			t.Fatalf("cannot read the signatures of %q: %v", pkg, err)
		}
		if len(sigs) == 0 {
			t.Fatalf("no signatures parsed for %q; refusing rather than passing", pkg)
		}
		for name, sig := range sigs {
			if stream.MatchString(sig) && allowed[name] {
				t.Errorf("%s.%s is allowlisted for ring 1 but its signature carries a stream: %s", pkg, name, sig)
			}
		}
	}
}

// TestTimeAllowlistExcludesWaiters is DERIVED. Every waiting primitive in
// package time hands back a channel of Times, a *Timer or a *Ticker; the
// value-returning half hands back Durations, Times and strings. So the result
// type is the discriminator, and it holds for a primitive Go has not added yet.
//
// time.Sleep is the one waiter this derivation cannot see — it returns
// nothing — which is why TestRefusedIdents names it explicitly.
func TestTimeAllowlistExcludesWaiters(t *testing.T) {
	waiter := regexp.MustCompile(`\)\s*(<-chan Time|\*Timer|\*Ticker)\b`)
	sigs, err := goDocSignatures("time")
	if err != nil {
		t.Fatalf("cannot read the signatures of time: %v", err)
	}
	if len(sigs) == 0 {
		t.Fatal("no signatures parsed for time; refusing rather than passing")
	}
	hits := 0
	for name, sig := range sigs {
		if !waiter.MatchString(sig) {
			continue
		}
		hits++
		if TestIdents["time"][name] {
			t.Errorf("time.%s is allowlisted in tests but it is a waiting primitive: %s", name, sig)
		}
	}
	if hits == 0 {
		t.Fatal("the waiter pattern matched nothing in package time; the derivation has stopped working " +
			"and would now pass over any waiter")
	}
}

// TestContextAllowlistExcludesDeadlines is DERIVED. A context constructor that
// takes a time.Duration or a time.Time installs a deadline, and whatever later
// blocks on ctx.Done() is waiting for a timer to fire.
func TestContextAllowlistExcludesDeadlines(t *testing.T) {
	deadline := regexp.MustCompile(`\btime\.(Duration|Time)\b`)
	sigs, err := goDocSignatures("context")
	if err != nil {
		t.Fatalf("cannot read the signatures of context: %v", err)
	}
	hits := 0
	for name, sig := range sigs {
		if !deadline.MatchString(sig) {
			continue
		}
		hits++
		if TestIdents["context"][name] {
			t.Errorf("context.%s is allowlisted in tests but it installs a deadline: %s", name, sig)
		}
	}
	if hits == 0 {
		t.Fatal("the deadline pattern matched nothing in package context; the derivation has stopped " +
			"working and would now pass over any deadline constructor")
	}
}

// --- helpers ---------------------------------------------------------------

func goListDeps(pkg string) (map[string]bool, error) {
	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			set[line] = true
		}
	}
	return set, nil
}

// funcRe matches a PACKAGE-LEVEL func in `go doc -all` output. A method reads
// `func (d Duration) Abs() ...`, where the character after "func " is "(", so
// requiring a capital letter there excludes methods without a second pattern.
// That matters: the gates resolve pkg.Ident, and a method is not one.
var funcRe = regexp.MustCompile(`^func ([A-Z]\w*)\(`)
var typeRe = regexp.MustCompile(`^type ([A-Z]\w*)\b`)

// goDocSignatures returns every package-level func and type signature in a
// package, keyed by identifier.
//
// It uses `go doc -all`, and the -all is load-bearing rather than tidy. Plain
// `go doc` groups a constructor UNDER the type it returns and indents it, so
// NewTimer and NewTicker are invisible to a top-level scan. The first version
// of this file used plain `go doc`, and the waiter derivation below therefore
// saw 3 of the 6 waiting primitives while its own non-empty guard stayed
// satisfied by the 3 it did see. Under-coverage hiding behind a passing check
// is the defect this whole file exists to remove.
func goDocSignatures(pkg string) (map[string]string, error) {
	out, err := exec.Command("go", "doc", "-all", pkg).Output()
	if err != nil {
		return nil, err
	}
	sigs := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		if m := funcRe.FindStringSubmatch(line); m != nil {
			sigs[m[1]] = strings.TrimSpace(line)
			continue
		}
		if m := typeRe.FindStringSubmatch(line); m != nil {
			sigs[m[1]] = strings.TrimSpace(line)
		}
	}
	return sigs, nil
}

// declared asks the toolchain whether pkg.ident exists, rather than parsing a
// listing for it. `go doc pkg.Ident` exits non-zero when it does not resolve,
// which is an exact oracle with no format to drift: constants inside a grouped
// const block, methods, types and functions all answer the same way. Measured
// at ~25ms per probe, so the whole allowlist costs a couple of seconds.
func declared(pkg, ident string) bool {
	return exec.Command("go", "doc", pkg+"."+ident).Run() == nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
