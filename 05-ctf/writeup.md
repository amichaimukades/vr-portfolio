# CTF - Writeup

## About the module

This module applies what was learned in stages 01-04 (memory layout, reverse engineering, buffer overflow, defeating mitigations) against real CTF challenges from two platforms: picoGym and pwn.college, plus a new Web Exploitation category. Unlike the earlier stages, which are built on source code written in advance and developed gradually, here every challenge is independent, usually with no visible source code (black-box), and sometimes against a remote server rather than just a local binary.

Ten challenges were solved, across four categories, each documented in a separate writeup under `05-ctf/`. One challenge - Format String 2 - was picked for an extended writeup (the second part of this document), because it was among the more challenging exercises in this module.

**Tools:** `gdb`/`pwndbg`, `objdump`, `curl`, `pwntools` (`fmtstr_payload`, `remote`, `process`), Ghidra.

---

### Binary Exploitation (picoGym)

- **[Format Strings 1](./picogym/binary-exploitation/format-string-1/writeup.md)** - leak from the stack using `%p`, with the offset calculated in advance from the calling convention instead of trial and error.
- **[Format String 2](./picogym/binary-exploitation/format-string-2/writeup.md)** - arbitrary write to memory (`%n`/`%hn`). Covered in depth in the second part of this document.
- **[Local Target](./picogym/binary-exploitation/local-target/writeup.md)** - stack buffer overflow with `gets()`, including finding that the real distance between variables in memory is different from what the source code "promises."

### Reverse Engineering (picoGym)

- **[GDB Baby Step 2](./picogym/reverse-engineering/gdb-baby-step-2/writeup.md)** - finding the value of `eax` at the end of a loop, with a trap in choosing where to place the breakpoint.
- **[GDB Baby Step 3](./picogym/reverse-engineering/gdb-baby-step-3/writeup.md)** - reading bytes from memory and the practical understanding of little-endian.
- **[GDB Baby Step 4](./picogym/reverse-engineering/gdb-baby-step-4/writeup.md)** - identifying a constant as an immediate operand, with three different methods that reach the same answer.

### Web Exploitation (picoGym)

- **[Crack the Gate 1](./picogym/web-exploitation/crack-the-gate-1/writeup.md)** - a developer's backdoor, hidden with a Caesar cipher inside an HTML comment.
- **[Old Sessions](./picogym/web-exploitation/old-sessions/writeup.md)** - a session cookie that never expires, combined with a debug path that exposes the entire session store, including admin.
- **[SSTI1](./picogym/web-exploitation/ssti1/writeup.md)** - Server-Side Template Injection in Jinja2, from fingerprinting the engine (`{{7*7}}` versus `{{7*'7'}}`) to running code fully on the server through `__mro__`/`__subclasses__`, with no `import` at all.

### pwn.college - Program Security

- **[Bounds Breaker Easy](./pwncollege/writeup.md)** - ret2win with a signed/unsigned mismatch that cancels out a bounds check that looks correct.

---

## Extended Writeup: Format String 2

This challenge was picked for the extended writeup because, unlike Format Strings 1 (a leak only), this one required an actual **write** to memory - and almost every step didn't work on the first few tries. The path to the solution went through several new things I learned along the way, not just technical steps.

### The Task
We need to make the value of `sus` (`0x21737573`) actually turn into `0x67616c66` - not just read memory, but **change it**.

### The Source Code
```c
int sus = 0x21737573;

int main() {
  char buf[1024];
  char flag[64];

  scanf("%1024s", buf);
  printf(buf);                    // <- the same bug as in Format Strings 1

  if (sus == 0x67616c66) {
    // opens flag.txt and prints it
  }
}
```

### Step 1: Finding the target address

```
$ objdump -d ./vuln | grep sus
```
Gave the address `0x404048`. This was the easy part - the earlier leak from Format Strings 1 already taught how to identify addresses in a binary.

### Step 2: Finding the offset - and a first mistake

To write through `%n`, you need to know which `printf` argument number, `$N`, points exactly to the bytes I typed. The method: a unique, easy-to-spot input followed by a sequence of `%1$p-%2$p-...-%40$p`, then looking through the output for where the value matching what was typed shows up.

I entered `aaaaaaaaa` (9 characters) plus the sequence, and got output containing `0x6161616161616161` (eight times `0x61`, which is `'a'`) at a certain slot. **This is where I made a counting mistake** - I counted by hand and decided it was `$15`, but it was actually `$14`. The mistake was found by counting again carefully, value by value, following the order the output actually gave: the first eight characters (`"aaaaaaaa"`) fill exactly 8 bytes = one full 64-bit argument, and that's exactly `$14`. The ninth character "spilled over" into the start of the next slot (`$15`), together with the start of the next `%1$p` in the input - and that's what confused me in the first count.

Lesson: it's not enough to look "roughly" at the output - you need to count every value separately, without skipping any, and compare exactly what was typed against what came back.

### Step 3: `%n` versus `%hn` - first thing I learned

I knew `%n` writes "the number of characters printed so far" to the address its argument points to. But `%n` writes a whole `int` - 4 bytes. My target (`0x67616c66`) is about 1.7 billion - meaning to write it with a regular `%n` I would need to make `printf` **print 1.7 billion characters** before the `%n` runs. Not practical.

The solution: `%hn` - a version of `%n` with the `h` length modifier, which writes only 2 bytes (a short) instead of 4. Since the target is 4 bytes, you need **two** separate `%hn` writes - one for the address `sus`, one for the address `sus+2`, each with its own padding, which is far more reasonable (a maximum of 65535 instead of a billion).

Here I had a misunderstanding: I thought you need to "split the address itself" into two parts and enter them separately into the input. That's not right - the address (`sus`, `sus+2`) stays whole each time; what gets split is **the write**, not the address. Each `%hn` writes 2 bytes to its own address, and the addresses themselves (8 bytes each, as a whole number) are passed as ordinary arguments through the buffer.

### Step 4: The null-byte problem

Any address like `0x404048`, when written as 8 bytes in little-endian, ends in several `0x00` bytes (`48 40 40 00 00 00 00 00`). The problem: `printf` treats `buf` as a regular null-terminated C string - the moment it "reads" a `0x00` byte inside the format string, it **stops right there**, and everything after it (including the `%hn` that needs to run) doesn't happen.

The standard solution: place both addresses **at the end** of the string, after all the padding and the `%N$hn` parts themselves. That way the null bytes only "cut off" something that wasn't needed anyway. But this means the offset `$14` I found earlier is no longer enough - because the addresses are no longer at the start of the buffer, but at its end, after a variable amount of padding. Calculating this by hand (exactly where `$N` will point to the address when it's at the end instead of the start) is prone to mistakes.

### Step 5: The practical solution - `fmtstr_payload`

At this stage I moved from building it by hand to `pwntools.fmtstr_payload`, which does exactly everything described in steps 3-4, automatically and correctly:

```python
from pwn import *
context.binary = elf = ELF('./vuln')

io = remote('chatelaine.cylabacademy.net', <current port>)
io.recvuntil(b'?\n')

sus_addr = 0x404048
target_value = 0x67616c66
offset = 14

payload = fmtstr_payload(offset, {sus_addr: target_value})
io.sendline(payload)
io.interactive()
```
`fmtstr_payload` automatically splits the write into two `%hn`s, calculates the exact padding for each half, keeps the write order correct (smaller value first, larger second, because padding within one `printf` call can only go up, never down), and places both addresses at the end of the string.

### Step 6: A "failure" that was actually a success

Running locally (`process('./vuln')`) I got:
```
I have NO clue how you did that, you must be a wizard. Here you go...
[*] Got EOF while reading in interactive
$ echo hi
[*] Process './vuln' stopped with exit code -11 (SIGSEGV)
```
My first read on this: the exploit failed because the program crashed. In fact it's **the opposite** - the message "I have NO clue how you did that" is printed **only** when `sus == 0x67616c66`, meaning the exploit had already fully succeeded before the crash. The crash happened for a separate, unrelated reason: running locally there's no `flag.txt`, so `fopen("flag.txt", "r")` returns `NULL`, and `fgets(flag, 64, NULL)` tries to access address 0 - SIGSEGV. Against remote, where `flag.txt` actually exists, this doesn't happen.

The lesson: a crash **after** a success message doesn't necessarily mean the attempt failed - you need to check *exactly when* the crash happened relative to the steps that had already succeeded.

### The Result
```
Here you go...
academy{f0rm47_57r?_f0rm47_m3m_1c092a1e}
```

### Why This Matters - what this path taught

This challenge wasn't hard because of one complicated step - it was hard because every step required understanding **the difference between what looks like a failure and what's actually a failure**:
- A wrong offset count (`$15` instead of `$14`) that was fixed only after a careful recount.
- A misunderstanding that "splitting" refers to the write (two `%hn`s), not the address itself.
- The null-byte problem, which required changing the **position** of the addresses inside the payload, not just their content.
- A crash (SIGSEGV) that was actually **proof of success**, not of failure.

The practical takeaway: when exploiting a vulnerability, it's worth checking **exactly when** something "failed" relative to the steps that had already succeeded, before assuming the whole approach is wrong.