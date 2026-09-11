#!/usr/bin/env bash
# Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

#
# govulncheck-pin.sh — the pinned scanner and this toolchain must agree.
#
# Usage:  .github/lane/govulncheck-pin.sh              check the tree
#         .github/lane/govulncheck-pin.sh --self-test  drive both verdicts
# Exit:   0 the pin builds with the Go this job has; 1 it does not, with one
#         ::error:: line naming both operands; 2 the operands could not be read.
#
# THE FAILURE THIS EXISTS FOR, measured: `@latest` resolved to x/vuln v1.8.0 on
# 2026-09-08, v1.8.0 declares `go 1.26.0`, setup-go resolves `go 1.25` in go.mod
# to 1.25.14, and every run since died in `go install` with "requires go >=
# 1.26.0 (running go 1.25.14; GOTOOLCHAIN=local)". The scan never ran. A pin
# removes the float; this refuses when the pin and the toolchain are moved apart
# again, before the install, naming what disagrees rather than leaving a reader
# to parse a toolchain error.
#
# IT FAILS IN ONE DIRECTION, so name the other: a pin that is BEHIND a newer
# x/vuln this toolchain could build is not caught here and is not a blind
# scanner. MEASURED 2026-09-11: the v1.7.0 binary, released 2026-08-13, reports
# GO-2026-6238, published 2026-08-18. The advisory data is fetched from
# https://vuln.go.dev at scan time and is not carried in the binary, so an older
# scanner still sees a newer advisory. What an old pin costs is analysis
# improvements, not coverage, and reddening this lane on x/vuln's release
# schedule would block every merge for a cost that is not a vulnerability.
set -euo pipefail

cd "$(dirname "$0")/../.."

WORKFLOW="${PIN_WORKFLOW:-.github/workflows/govulncheck.yml}"

refuse()  { printf '::error title=govulncheck pin::%s\n' "$*" >&2; exit 1; }
unread()  { printf '::error title=govulncheck pin::%s\n' "$*" >&2; exit 2; }

# A > B over dotted fields, numerically, missing fields read as 0. String
# comparison gets 1.25.14 versus 1.25.9 wrong and that is the live pair.
newer_than() {
	local -a a b
	local i x y
	IFS=. read -r -a a <<<"$1"
	IFS=. read -r -a b <<<"$2"
	for i in 0 1 2; do
		x="${a[i]:-0}"; y="${b[i]:-0}"
		if [ "$x" -gt "$y" ]; then return 0; fi
		if [ "$x" -lt "$y" ]; then return 1; fi
	done
	return 1
}

if [ "${1:-}" = "--self-test" ]; then
	failed=0
	drive() { # drive <expected> <a> <b>
		local want="$1" got=no
		if newer_than "$2" "$3"; then got=yes; fi
		if [ "$got" = "$want" ]; then
			printf 'ok    %s > %s is %s\n' "$2" "$3" "$got"
		else
			printf 'FAIL  %s > %s answered %s, wanted %s\n' "$2" "$3" "$got" "$want"
			failed=1
		fi
	}
	drive yes 1.26.0  1.25.14   # the pair that broke the lane
	drive no  1.25.0  1.25.14   # the pair that fixes it
	drive no  1.25.14 1.25.14   # equal is not newer
	drive no  1.25.9  1.25.14   # the pair string comparison gets wrong
	drive yes 1.25.14 1.25.9
	drive yes 2.0     1.99.99   # a short field is not a small one
	verdict=0
	PIN_REQUIRES=1.26.0 PIN_GOVERSION=go1.25.14 "$0" >/dev/null 2>&1 || verdict=$?
	if [ "$verdict" = 1 ]; then printf 'ok    a pin needing a newer Go is refused\n'
	else printf 'FAIL  a pin needing a newer Go exited %s, wanted 1\n' "$verdict"; failed=1; fi
	verdict=0
	PIN_REQUIRES=1.25.0 PIN_GOVERSION=go1.25.14 "$0" >/dev/null 2>&1 || verdict=$?
	if [ "$verdict" = 0 ]; then printf 'ok    a pin this toolchain can build is accepted\n'
	else printf 'FAIL  a buildable pin exited %s, wanted 0\n' "$verdict"; failed=1; fi
	# The shape that shipped: no version at all. Driven against a file rather
	# than a string, because reading the pin out of the workflow is the half
	# that has to keep working when the workflow is reformatted.
	#
	# `fixdir` is checked before anything is written into it or removed from
	# it. `mktemp -d` prints NOTHING when it fails, and bash's `cd ""`
	# returns 0, so the unchecked spelling of these four lines builds its
	# fixture in the checkout and then removes `/`.
	fixdir="$(mktemp -d 2>/dev/null)" || fixdir=
	if [ -z "$fixdir" ] || [ ! -d "$fixdir" ]; then
		printf 'FAIL  no fixture directory, so the unpinned case was not driven\n'
		exit 1
	fi
	printf '        run: go install golang.org/x/vuln/cmd/govulncheck@latest\n' >"$fixdir/govulncheck.yml"
	verdict=0
	PIN_WORKFLOW="$fixdir/govulncheck.yml" PIN_GOVERSION=go1.25.14 "$0" >/dev/null 2>&1 || verdict=$?
	if [ "$verdict" = 1 ]; then printf 'ok    an unpinned scanner is refused\n'
	else printf 'FAIL  an unpinned scanner exited %s, wanted 1\n' "$verdict"; failed=1; fi
	rm -rf -- "$fixdir"
	exit "$failed"
fi

[ -r "$WORKFLOW" ] || unread "cannot read $WORKFLOW, so there is no pin to check"

pin="$(sed -n 's|.*golang.org/x/vuln/cmd/govulncheck@\([^ ]*\).*|\1|p' "$WORKFLOW" | head -n 1)"
case "$pin" in
	v[0-9]*) ;;
	'')      refuse "$WORKFLOW installs no govulncheck, so nothing scans this module" ;;
	*)       refuse "the scanner is installed at '@$pin' in $WORKFLOW; an unpinned scanner is what broke this lane, so pin a version" ;;
esac

have="${PIN_GOVERSION:-$(go env GOVERSION)}"
have="${have#go}"
[ -n "$have" ] || unread "this job has no Go toolchain to compare the pin against"

# The requirement comes out of the module's own go.mod and NOT out of
# `go list -m -f '{{.GoVersion}}'`. MEASURED: under a go1.25 toolchain that
# field is EMPTY for x/vuln v1.8.0, the one version this guard exists to
# catch, because the toolchain declines to interpret a go line above its own.
# An empty string compared as a version reads as 0, so the field-reading
# version of this guard passed on its own defect. `{{.GoMod}}` is the path of
# the downloaded .mod file and is filled in either way.
if [ -n "${PIN_REQUIRES:-}" ]; then
	need="$PIN_REQUIRES"
else
	gomod="$(go list -m -f '{{.GoMod}}' "golang.org/x/vuln@$pin" 2>&1)" ||
		unread "cannot reach golang.org/x/vuln@$pin: $gomod"
	[ -r "$gomod" ] || unread "go did not leave a readable go.mod for golang.org/x/vuln@$pin at '$gomod'"
	need="$(sed -n 's/^go[[:space:]]\{1,\}\([0-9][0-9.]*\).*/\1/p' "$gomod" | head -n 1)"
fi

case "$need" in
	[0-9]*.[0-9]*) ;;
	*) unread "golang.org/x/vuln@$pin declares no readable go line, so nothing says which toolchain it needs" ;;
esac

if newer_than "$need" "$have"; then
	refuse "golang.org/x/vuln@$pin needs Go $need and this job has $have, so 'go install' will refuse and the module will not be scanned; pin the newest x/vuln whose go line is $have or lower, or raise the go line in go.mod"
fi

printf 'govulncheck pin %s needs Go %s, this job has %s\n' "$pin" "$need" "$have"
