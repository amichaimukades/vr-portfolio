#!/usr/bin/env bash
# verify.sh - builds the three stack-frame demo programs and asserts that the
# bounded read (fgets with sizeof) holds under boundary input.
#
# Why this exists: notes.md and gdb-session.txt document the frame layout by
# hand from a gdb session; nothing executable guarded it. If a later edit
# swapped fgets for gets(), or shrank a buffer, the overflow would come back and
# no test would notice. Each check feeds a line far longer than the buffer and
# asserts the program still exits cleanly - which only holds while the read
# stays bounded. A reintroduced overflow dies on the stack canary (code 134) or
# segfaults (139), and the matching check turns red.
#
# Usage:  ./verify.sh    Exit status 0 only if every check passes.

set -uo pipefail
cd "$(dirname "$0")" || exit 1

PASS=0; FAIL=0
if [ -t 1 ]; then G=$'\033[32m'; R=$'\033[31m'; Z=$'\033[0m'; else G=''; R=''; Z=''; fi
ok()  { PASS=$((PASS+1)); printf '%s[PASS]%s %s\n' "$G" "$Z" "$1"; }
bad() { FAIL=$((FAIL+1)); printf '%s[FAIL]%s %s\n' "$R" "$Z" "$1"; }

command -v gcc >/dev/null 2>&1 || { echo "gcc is required" >&2; exit 2; }

# Rebuilt on every run, -O0 -no-pie like the gdb session in notes.md. Stack
# protector is left ON (gcc's default) so a reintroduced overflow aborts loudly
# instead of corrupting silently.
build() { gcc -O0 -no-pie -o "$2" "$1" 2>/dev/null || { echo "build failed: $1" >&2; exit 2; }; }
echo "building the three variants (-O0 -no-pie)"
build mem.c         ./mem
build mem_100.c     ./mem_100
build mem_two_buf.c ./mem_two_buf
echo

# run_bounded <label> <binary> <stdin-lines...>
# Feeds the lines and asserts the process exits WITHOUT a signal (code < 128).
# fgets truncates an over-long line and returns normally; an unbounded read
# would overflow and the process would die on the canary (134) or segfault
# (139) - exactly the regression this guards against.
run_bounded() {
  local label="$1" bin="$2"; shift 2
  printf '%s\n' "$@" | "$bin" >/dev/null 2>&1
  local code=$?
  if [ "$code" -lt 128 ]; then ok "$label (clean exit $code)"
  else bad "$label (died on signal $((code-128)) - the read was not bounded)"; fi
}

BIG=$(printf 'A%.0s' $(seq 1 300))   # 300 chars, far past every buffer

# functional sanity: a normal name is echoed back
out=$(printf 'Alice\n' | ./mem 2>&1)
case "$out" in *"Hello, Alice"*) ok "mem.c        - normal name is echoed" ;;
  *) bad "mem.c        - normal name is echoed" ;; esac

# boundary: an over-long line into each buffer must stay bounded (no crash)
run_bounded "mem.c        - 300-char name stays bounded"        ./mem         "$BIG"
run_bounded "mem_100.c    - 300-char name stays bounded"        ./mem_100     "$BIG"
run_bounded "mem_two_buf  - over-long first name stays bounded" ./mem_two_buf "$BIG"

echo
printf -- '--- %d passed, %d failed ---\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "all three variants keep their reads bounded under boundary input."