#!/bin/sh
# ABI regression check: ensure no symbol from tests/abi-baseline.txt has
# disappeared from the current build of libhunspell. Additions are allowed;
# removals or signature changes (which alter the mangled name) fail.
#
# Linux/ELF only; skipped elsewhere.
#
# Usage:
#   tests/abi-check.sh           check current build against baseline
#   tests/abi-check.sh update    rewrite baseline from current build
#                                (use only after a deliberate SONAME bump)

set -e

MODE="${1:-check}"
case "$MODE" in
    check|update) ;;
    *) echo "usage: $0 [check|update]" >&2; exit 2 ;;
esac

if [ "$(uname -s)" != "Linux" ]; then
    echo "abi-check: skipping on $(uname -s)"
    exit 77
fi

DIR="$(dirname "$0")"
LIB="../src/hunspell/.libs/libhunspell-1.7.so"
BASELINE="$DIR/abi-baseline.txt"

if [ ! -e "$LIB" ]; then
    echo "abi-check: $LIB not built (--disable-shared?), skipping"
    exit 77
fi

if ! command -v nm >/dev/null 2>&1; then
    echo "abi-check: nm not found, skipping"
    exit 77
fi

CURRENT="$(mktemp)"
trap 'rm -f "$CURRENT"' EXIT

nm -D --defined-only --extern-only "$LIB" \
    | awk '$2 ~ /[TWRD]/ {print $3}' \
    | grep -v '^_ZNSt\|^_ZSt\|^_ZNKSt' \
    | LC_ALL=C sort -u > "$CURRENT"

if [ "$MODE" = "update" ]; then
    if [ -e "$BASELINE" ]; then
        ADDED="$(LC_ALL=C comm -13 "$BASELINE" "$CURRENT")"
        REMOVED="$(LC_ALL=C comm -23 "$BASELINE" "$CURRENT")"
        if [ -z "$ADDED" ] && [ -z "$REMOVED" ]; then
            echo "abi-check: baseline already up to date"
            exit 0
        fi
        if [ -n "$REMOVED" ]; then
            echo "abi-check: removing $(echo "$REMOVED" | wc -l) symbol(s) from baseline:"
            echo "$REMOVED" | sed 's/^/  - /'
        fi
        if [ -n "$ADDED" ]; then
            echo "abi-check: adding $(echo "$ADDED" | wc -l) symbol(s) to baseline:"
            echo "$ADDED" | sed 's/^/  + /'
        fi
    else
        echo "abi-check: writing fresh baseline ($(wc -l < "$CURRENT") symbols)"
    fi
    cp "$CURRENT" "$BASELINE"
    echo "abi-check: wrote $BASELINE"
    exit 0
fi

MISSING="$(LC_ALL=C comm -23 "$BASELINE" "$CURRENT")"
if [ -n "$MISSING" ]; then
    echo "abi-check: FAIL - symbols missing from current build:"
    echo "$MISSING" | sed 's/^/  /'
    echo
    echo "If a symbol was intentionally removed or its signature changed,"
    echo "this is an ABI break and SONAME must be bumped. Otherwise, fix the"
    echo "code so the baseline symbols remain. Run \`$0 update\` to refresh"
    echo "the baseline only after a deliberate SONAME bump."
    exit 1
fi

echo "abi-check: OK ($(wc -l < "$BASELINE") baseline symbols present)"
