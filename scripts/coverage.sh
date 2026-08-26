#!/usr/bin/env bash
# Per-package statement coverage, checked against the floors in
# test/coverage-floors.txt.
#
#   ./scripts/coverage.sh coverage.out
#
# Called by `make cover` and by the CI integration job, which is the run that
# has PostgreSQL and Redis available — a floor measured without them would be
# about half the truth for internal/audit, whose SQL store is most of the file.
#
# Why per package and not one global number: a single total lets a large,
# well-covered package hide a small, untested one. The floors are also not
# uniform on purpose. The forensic core is held high because a gap there is a
# gap in the project's central claim; a package of glue is held low because
# chasing its last statements buys nothing.
set -uo pipefail

PROFILE="${1:-coverage.out}"
FLOORS="${FLOORS:-test/coverage-floors.txt}"

if [ ! -f "$PROFILE" ]; then
    echo "coverage: no profile at $PROFILE" >&2
    exit 1
fi
if [ ! -f "$FLOORS" ]; then
    echo "coverage: no floors file at $FLOORS" >&2
    exit 1
fi

MODULE="github.com/open-shield/open-shield/"

# Sum covered and total statements per package, straight out of the profile.
# Lines look like:  <import path>/file.go:12.34,15.16 <numStmts> <count>
#
# With -coverpkg the same block appears once per test binary that linked the
# package, so blocks are folded by identity first: a block counts as covered if
# any binary reached it, and its statements are counted once. Summing the raw
# lines would inflate every total and report a fraction of the real figure.
coverage_by_package() {
    awk -v prefix="$MODULE" '
        /^mode:/ { next }
        {
            block = $1
            stmts[block] = $(NF - 1)
            if ($NF + 0 > 0) hit[block] = 1
        }
        END {
            for (block in stmts) {
                colon = index(block, ":")
                path  = substr(block, 1, colon - 1)
                slash = 0
                for (i = length(path); i > 0; i--) {
                    if (substr(path, i, 1) == "/") { slash = i; break }
                }
                pkg = substr(path, 1, slash - 1)
                sub("^" prefix, "", pkg)

                total[pkg] += stmts[block]
                if (block in hit) covered[pkg] += stmts[block]
            }
            for (pkg in total) {
                printf "%s %.1f %d\n", pkg, covered[pkg] * 100 / total[pkg], total[pkg]
            }
        }
    ' "$PROFILE" | sort
}

MEASURED="$(coverage_by_package)"

failed=0
checked=0

printf '\n  %-44s %9s %8s %8s\n' "package" "covered" "floor" "stmts"
printf '  %s\n' "---------------------------------------------------------------------------"

while read -r package floor; do
    case "$package" in
        ''|'#'*) continue ;;
    esac

    line="$(printf '%s\n' "$MEASURED" | awk -v p="$package" '$1 == p')"
    if [ -z "$line" ]; then
        printf '  %-44s %9s %8s   \033[31mno coverage data\033[0m\n' "$package" "-" "$floor%"
        failed=$((failed + 1))
        continue
    fi

    actual="$(printf '%s' "$line" | awk '{print $2}')"
    stmts="$(printf '%s' "$line" | awk '{print $3}')"
    checked=$((checked + 1))

    # Shell arithmetic is integer-only; compare in awk.
    if awk -v a="$actual" -v f="$floor" 'BEGIN { exit !(a + 0 < f + 0) }'; then
        printf '  %-44s %8s%% %7s%% %8s   \033[31mbelow floor\033[0m\n' "$package" "$actual" "$floor" "$stmts"
        failed=$((failed + 1))
    else
        printf '  %-44s %8s%% %7s%% %8s\n' "$package" "$actual" "$floor" "$stmts"
    fi
done < "$FLOORS"

# A package with no floor is not an error — the cmd/ entrypoints and the demo
# backend have none on purpose — but it is worth seeing, because a new package
# with real logic in it should be given one.
unlisted="$(printf '%s\n' "$MEASURED" | while read -r pkg pct stmts; do
    grep -qE "^${pkg}[[:space:]]" "$FLOORS" || printf '  %-44s %8s%% %17s\n' "$pkg" "$pct" "$stmts"
done)"

if [ -n "$unlisted" ]; then
    printf '\n  not held to a floor:\n%s\n' "$unlisted"
fi

echo
if [ "$failed" -gt 0 ]; then
    printf '  \033[31m%d of %d packages are below their floor\033[0m\n\n' "$failed" "$((checked + failed))"
    echo "  Either add tests, or — if the floor is wrong — change it in $FLOORS"
    echo "  and say why in the commit message."
    echo
    exit 1
fi

printf '  \033[32mall %d packages meet their floor\033[0m\n\n' "$checked"
