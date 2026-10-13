#!/usr/bin/env bash
# verify.sh — builds crackme2 from source and verifies its password check.
#
# Why this exists: writeup.md documents `entrypt` as the password, but nothing
# executable asserted it. That let a comparison bug through review — the code
# compared the plaintext input against the ENCRYPTED bytes, so the documented
# password was rejected. The first check below is that missing assertion.
#
# The two rejection checks cover the length guard from both sides: `entryp` is
# one byte short, `entryptx` one byte long.
#
# Usage:  ./verify.sh          Exit status 0 only if every check passes.

set -uo pipefail
cd "$(dirname "$0")" || exit 1

SRC=crackme2.c
BIN=./crackme2
PASSWORD='entrypt'
FLAG='entrypoint{re_basics}'

PASS=0
FAIL=0

if [ -t 1 ]; then
  G=$'\033[32m'; R=$'\033[31m'; Z=$'\033[0m'
else
  G=''; R=''; Z=''
fi

ok()  { PASS=$((PASS+1)); printf '%s[PASS]%s %s\n' "$G" "$Z" "$1"; }
bad() { FAIL=$((FAIL+1)); printf '%s[FAIL]%s %s\n' "$R" "$Z" "$1"; }

# check_accepted <input> / check_rejected <input>
# Feeds one line to the binary and asserts on what it prints. Behaviour-based,
# so these checks survive any rebuild — unlike a hardcoded breakpoint address.
check_accepted() {
  local out
  out="$(printf '%s\n' "$1" | "$BIN" 2>&1)"
  case "$out" in
    *Correct*) ok "'$1' is accepted" ;;
    *) bad "'$1' is accepted"
       printf "       expected 'Correct', got: %s\n" "${out#Password: }" ;;
  esac
  case "$out" in
    *"$FLAG"*) ok "'$1' prints the documented flag" ;;
    *) bad "'$1' prints the documented flag ($FLAG)" ;;
  esac
}

check_rejected() {
  local out
  out="$(printf '%s\n' "$1" | "$BIN" 2>&1)"
  case "$out" in
    *Wrong*) ok "'$1' is rejected" ;;
    *) bad "'$1' is rejected"
       printf "       expected 'Wrong.', got: %s\n" "${out#Password: }" ;;
  esac
}

# ---------------------------------------------------------------- build
# Rebuilt on every run: verifying a stale binary is exactly how a document
# drifts away from the code it describes. Flags are the ones from writeup.md.
command -v gcc >/dev/null 2>&1 || { echo "gcc is required" >&2; exit 2; }
[ -f "$SRC" ] || { echo "$SRC not found" >&2; exit 2; }

echo "building $SRC (-O0 -no-pie, stripped)"
gcc -O0 -no-pie -o "$BIN" "$SRC" || { echo "build failed" >&2; exit 2; }
strip "$BIN"
echo

# ---------------------------------------------------------------- checks
check_accepted "$PASSWORD"      # the documented password must work
check_rejected 'entryp'         # one byte short  -> length guard
check_rejected 'entryptx'       # one byte long   -> length guard

# ---------------------------------------------------------------- result
echo
printf -- '--- %d passed, %d failed ---\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "crackme2 behaves as writeup.md describes."