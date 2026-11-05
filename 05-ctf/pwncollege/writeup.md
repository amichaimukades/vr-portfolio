# Bounds Breaker Easy

**Category:** pwn.college / Program Security - Stack Buffer Overflow + Signedness Bug
**Link:** https://pwn.college/program-security/program-security/
**Flag:** `pwn.college{wznywnreRZGzRM_brNxF-VQCCZ9.dVTOywiN0YTMyIzW}`

## The Goal
There's a separate `win()` function here (`0x4016a9`) that we need to make the program actually jump to. The input buffer is 82 bytes, but the saved return address of `challenge()` sits 104 bytes after the start of the buffer. The canary is disabled and the binary is not PIE, so the addresses are fixed in advance and can be calculated from the output/from `disas` with no guessing.

## The Vulnerability

**The vulnerable code (from `disas challenge`, no source code - only a binary):** - I looked for the comparison against the size of the payload I'm entering.
```asm
mov    -0x64(%rbp),%eax   ; eax = the size that was entered (int, signed 32-bit)
cmp    $0x52,%eax          ; 0x52 = 82 (the buffer's size)
jle    <continue>          ; signed jump: if eax <= 82 (signed!), continue
...
mov    -0x64(%rbp),%eax    ; the same value, loaded again
mov    %eax,%edx           ; *** the critical point ***
call   read@plt            ; read(0, buf, (size_t)edx)
```

On my first attempt to send a payload of 112 bytes (104 bytes from the start of the buffer to the return address, plus 8 more bytes to overwrite it) I got blocked - and by searching the assembly for the check being performed, I found that there is a check on the input size, but the check (`cmp`/`jle`) compares the entered size as a **signed** `int`: if it's negative, it "passes" the `<= 82` condition every time, no matter how large its absolute value is. But `read()` expects a size parameter of type **unsigned** `size_t`, 64 bits wide - and the instruction `mov %eax,%edx` (moving from a 32-bit register to a 32-bit register) automatically does **zero-extension** to the full 64 bits of `rdx`. And this is what lets us overwrite it using an integer overflow.

## The Technique
Input `2147483648` (= `INT_MAX+1`) causes a signed integer overflow at the `scanf("%d")` stage and wraps around (two's complement) to `INT_MIN` (`0x80000000`). The full payload:
```bash
{ printf '2147483648\n'; printf 'A%.0s' $(seq 1 104); printf '\xa9\x16\x40\x00\x00\x00\x00\x00'; } > /tmp/payload
./bounds-breaker-easy < /tmp/payload
```
104 bytes of padding (up to the return address, 104 bytes after the start of the buffer) + the address of `win()` (`0x4016a9`, little-endian) overwrite the saved return address.

## Why This Matters
Two layers of vulnerability at once: a regular buffer overflow, and on top of it a signed/unsigned mismatch that cancels out exactly the bounds check meant to prevent it.

This is the practical reason C recommends using unsigned types (`size_t`) for anything that represents a "size"/"amount" - and checking the range **before** converting between types, not after.