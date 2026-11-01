#!/usr/bin/env bash
#
# verify.sh - rebuilds the four targets from source and verifies that each of
# the four "escapes" obtains a shell. Also re-asserts the wall (no arg gadget
# in the baseline binary), so the premise of the whole writeup is checked too.
#
# The exploit scripts end in p.interactive(), so this driver feeds `id` into
# the shell over stdin and checks for a uid= line -- that line only appears if
# control flow reached /bin/sh and our command ran. The short sleep gives each
# exploit time to reach interactive mode before the input arrives.
#
# Run from 04-binexp-defeating-mitigations/ret2libc/ inside the pwntools venv:
#     ./verify.sh
#
# Exits non-zero if any check fails, so it can be driven from a Makefile or CI.

set -u

PASS=0
FAIL=0
pass() { printf '[PASS] %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '[FAIL] %s\n' "$1"; [ $# -gt 1 ] && printf '       %s\n' "$2"; FAIL=$((FAIL + 1)); }

command -v gcc        >/dev/null 2>&1 || { echo "missing gcc" >&2; exit 2; }
command -v ROPgadget  >/dev/null 2>&1 || { echo "missing ROPgadget" >&2; exit 2; }
python3 -c 'import pwn' 2>/dev/null   || { echo "pwntools not importable - activate the venv" >&2; exit 2; }

echo "rebuilding targets from source"
make >/dev/null 2>&1
for b in vuln vuln_gadget vuln_static vuln_leak; do
    [ -x "$b" ] || { echo "build failed: $b" >&2; exit 2; }
done
echo

# ---------------------------------------------------------------------------
echo "--- the wall: the baseline binary must have NO arg-control gadget ---"
# ---------------------------------------------------------------------------
# This is the premise of the writeup. If a future toolchain starts emitting a
# pop rdi here, the "deadlock" framing would no longer hold - so we assert it.
if ROPgadget --binary vuln | grep -qE ': pop (rdi|rsi|rdx)'; then
    fail "vuln unexpectedly contains an arg-control gadget" \
         "the deadlock premise no longer holds on this toolchain"
else
    pass "vuln has no pop rdi/rsi/rdx (the wall holds)"
fi
if readelf -sW vuln | grep -qi csu; then
    fail "__libc_csu_init is present (pre-2.34 behaviour)"
else
    pass "__libc_csu_init is absent (glibc >= 2.34)"
fi
echo

# ---------------------------------------------------------------------------
echo "--- each escape must obtain a shell ---"
# ---------------------------------------------------------------------------
# Each exploit ends in p.interactive(). We pipe `id` into that shell; the
# uid=0(root) line is the proof that control flow survived all the way into
# /bin/sh, not just that the exploit script ran without error.

run_escape() {
    local script="$1" label="$2" out
    out=$( (sleep 1; printf 'id\nexit\n') | timeout 60 python3 "$script" 2>&1 )
    if grep -q 'uid=' <<<"$out"; then
        pass "$label"
    else
        fail "$label: no shell" "$(grep -E 'Traceback|Error|EOFError|failed' <<<"$out" | head -1)"
    fi
}

run_escape exploit_A_gadget.py 'A: bootstrap gadget restored  -> two-stage ret2libc, ASLR on'
run_escape exploit_B_static.py 'B: static linking             -> bss pivot + execve, no leak'
run_escape exploit_C_noaslr.py 'C: ASLR off                   -> libc gadget at fixed addr'
run_escape exploit_D_leak.py   'D: format-string leak         -> ret2libc, ASLR on, no bin gadget'
echo

# ---------------------------------------------------------------------------
printf -- '--- %d passed, %d failed ---\n' "$PASS" "$FAIL"
if [ "$FAIL" -eq 0 ]; then
    echo "the wall holds, and all four escapes work."
    exit 0
else
    echo "writeup.md and the binaries disagree."
    exit 1
fi