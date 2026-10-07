# Reverse Engineering - Writeup
 
## About the module
 
This module covers reverse engineering of Linux binaries (ELF 64-bit, x86-64): how to take an executable with no source code, understand what it does, and extract the information you're after - a password, a flag, or an internal value. The module is built around two complementary approaches that recur throughout all the exercises:
 
- **Static analysis** - reading the binary without running it: `file` to identify the file type, `strings` to extract strings, `readelf` for the ELF structure, `objdump` to disassemble into assembly, and Ghidra to decompile into C-like code.
- **Dynamic analysis** - running the binary under a debugger (`GDB/pwndbg`), `strace` and `ltrace`, to see real values at runtime: register contents, function arguments, and strings that are computed on the fly.
The guiding thread across all exercises: **a conclusion reached in static analysis is verified dynamically** - proven by running it.
 
The module is divided into four exercises. The first three work on the same hand-built crackme that evolves gradually - from a visible string comparison (`strcmp`), through XOR obfuscation, to analyzing the `scanf` calling convention. The fourth exercise applies the tools to three real reverse challenges from picoGym, each representing a different pattern.
 
**Tools:** `file`, `strings`, `readelf`, `objdump`, `Ghidra`, `ltrace`, `GDB/pwndbg`.
 
---
 
## Build (crackme, crackme2)

The binaries for exercises 1-2 were built from source like this - without PIE (fixed addresses) and stripped (no symbols), to reproduce the analysis conditions:

```bash
# Exercise 1
gcc -O0 -no-pie -o crackme crackme.c
strip crackme

# Exercise 2
gcc -O0 -no-pie -o crackme2 crackme2.c
strip crackme2
```

- `-O0` - no optimization, so the assembly stays close to the source (and in crackme2 the XOR stays visible and isn't constant-folded).
- `-no-pie` - fixed addresses around `0x400000`, which `file` shows as `executable`.
- `strip` - removes the symbol table, so `main` must be located manually.

## Exercise 1 - Recovering the crackme password
 
**Goal:** Recover the password from the binary using static analysis, and verify the conclusion by running it dynamically.
 
### 1.1 Identifying the target
 
```
$ file crackme
crackme: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=f8ad..., for GNU/Linux 3.2.0, stripped
```
 
What this tells me before I even start:
 
| Field | Meaning | Implication for analysis |
|------|---------|------------------|
| `executable` (not `shared object`) | `ET_EXEC` - **not PIE** | Addresses are fixed around `0x400000`, convenient for debugging |
| `x86-64` | CPU architecture | x86-64 assembly, System V calling conventions |
| `dynamically linked` | libc loaded at runtime | Names like `strcmp`/`printf` survive via the PLT |
| `stripped` | Internal symbol table removed | No `main`/`check` - must be located manually |
 
### 1.2 Static analysis
 
**Strings** - the first step:
 
```
$ strings crackme
...
entrypt
Password: 
%63s
Correct. Flag: entrypoint{re_basics}
Wrong.
```
 
Already here we see the prompt (`Password: `), the input format (`%63s`), a password candidate (`entrypt`), and the flag itself. These strings live in `.rodata` and therefore survive even when stripped.
 
**Entry point** - to locate `_start`:
 
```
$ readelf -h crackme | grep Entry
Entry point address: 0x4010d0
```
 
**Disassembling and locating `main`** - `objdump -d -M intel crackme`. In `_start` (at `0x4010d0`) I saw the pattern that leads to `main`:
 
```asm
4010e8:  mov    rdi,0x4011b6            ; main passed as first argument (rdi)
4010ef:  call   __libc_start_main
4010f5:  hlt
```
 
According to the System V ABI, the first argument is passed in `rdi`. Therefore **`main` is at `0x4011b6`**. There, inside `main`, is the core logic:
 
```asm
4011d1:  movabs rax,0x74707972746e65    ; "entrypt" in little-endian
4011db:  mov    [rbp-0x58],rax          ; the password is built on the stack
...
4011ee:  call   printf@plt              ; "Password: "
401209:  call   __isoc99_scanf@plt      ; "%63s" -> user input
...
401228:  call   strcmp@plt              ; strcmp(input, "entrypt")
40122f:  jne    0x401242                ; not equal -> "Wrong."
40123b:  call   puts@plt                ; equal    -> "Correct. Flag: ..."
```
 
Decoding the `movabs`: the bytes `65 6e 74 72 79 70 74` in little-endian are `e n t r y p t` = **`entrypt`**. That's the string the input is compared against.
 
**Ghidra** - a quick confirmation of all of the above. After auto-analysis, jumping to address `0x4011b6` (`g` -> `4011b6`), the Decompiler displayed matching C-like code: a call to `printf`, to `scanf("%63s", ...)`, and a `strcmp` comparison against the value decoded as `entrypt`. The advantage of Ghidra here: what required manual little-endian decoding in `objdump` appears directly as readable code.
 
### 1.3 Dynamic verification
 
**`ltrace`** - shows the library calls at runtime, including the comparison itself:
 
```
$ ltrace ./crackme
printf("Password: ")                 = 10
__isoc99_scanf(...)                  = 1        [input: abcdef]
strcmp("abcdef", "entrypt")          = -4
puts("Wrong.")                       = 7
```
 
`ltrace` revealed both sides of the comparison in a single line - `"entrypt"` is the fixed side.
 
**GDB/pwndbg** - a breakpoint just before `strcmp`, to check the registers when the arguments are ready:
 
```
pwndbg> b *0x401225
pwndbg> r
Password: abcdef
 
pwndbg> x/s $rsi
0x7fffffffd678: "entrypt"      # second argument - the correct password
pwndbg> x/s $rax
0x7fffffffd680: "abcdef"       # my input
```
 
### 1.4 Conclusion
 
- **Password:** `entrypt`
- **Flag:** `entrypoint{re_basics}`
```
$ ./crackme
Password: entrypt
Correct. Flag: entrypoint{re_basics}
```
 
**How I got there:** `strings` gave direction -> `readelf` gave the entry point -> `objdump` located `main` via the `rdi` before `__libc_start_main`, and exposed the `movabs` of the password -> Ghidra confirmed it in readable C -> `ltrace` and GDB verified that `entrypt` is indeed what's compared at runtime. The static conclusion was verified dynamically.
 
**The binary's weakness:** the password is compared as plaintext against `strcmp`, so it's exposed in `strings`, in `ltrace`, and in GDB. Exercise 2 tightens exactly this point.
 
---
 
## Exercise 2 - More complex check logic
 
**Goal:** Change the crackme so the comparison isn't `strcmp` against a visible string, recompile + strip, and analyze again - documenting what changed in each tool.
 
### 2.1 The code change
 
The password is no longer stored as text. It's built at runtime: each byte of `entrypt` goes through XOR with a key, and the comparison is a byte-by-byte loop (not `strcmp`). A length check was also added, closing a hole where any prefix of the password would pass.
 
```c
int xor = 0x55;
char secret[] = {0x65^xor, 0x6e^xor, 0x74^xor, 0x72^xor, 0x79^xor, 0x70^xor, 0x74^xor, 0x00};
int len = sizeof(secret) - 1;              // 7
...
if (strlen(input) != len) { puts("Wrong."); return 0; }   // length check
for (int i = 0; i < len; i++)
    if (input[i] != secret[i]) { ok = 0; break; }          // byte-by-byte comparison
```
 
### 2.2 What changed in the analysis - compared to Exercise 1
 
| Tool | Exercise 1 | Exercise 2 |
|------|---------|---------|
| `strings` | shows `entrypt` in the clear | **`entrypt` is gone** - no password string in the file |
| `ltrace` | `strcmp("abcdef","entrypt")` | only `strlen` - the real comparison isn't visible from outside |
| GDB | one `x/s $rsi` gives everything | no single moment - must read encrypted bytes and decode |
 
```
$ ltrace ./crackme2
printf("Password: ")     = 10
strlen("abcdef")         = 6
puts("Wrong.")           = 7      # no strcmp at all
```
 
### 2.3 Static analysis - Ghidra and objdump
 
In the Decompiler the new logic is clear: a `strlen(input) == 7` check, then a `for` loop comparing `input[i] != secret[i]` byte-by-byte. No more `strcmp`.
 
The compiler (at `-O0`, with `xor` as a variable) did **not** do constant folding, so the XOR operation stayed visible in assembly - and that exposes everything:
 
```asm
4011d1:  mov    DWORD PTR [rbp-0x60],0x55   ; key = 0x55, stored on the stack
4011d8:  mov    eax,DWORD PTR [rbp-0x60]    ; load key from stack into eax
4011db:  xor    eax,0x65                    ; eax = key XOR 0x65   (0x65='e')
4011de:  mov    BYTE PTR [rbp-0x58],al      ; store the encrypted byte -> secret[0]
4011e1:  mov    eax,DWORD PTR [rbp-0x60]    ; load key again
4011e4:  xor    eax,0x6e                    ; eax = key XOR 0x6e   (0x6e='n')
4011e7:  mov    BYTE PTR [rbp-0x57],al      ; -> secret[1]
4011ea:  mov    eax,DWORD PTR [rbp-0x60]    ; key again
4011ed:  xor    eax,0x74                    ; XOR 0x74  ('t')
4011f0:  mov    BYTE PTR [rbp-0x56],al      ; -> secret[2]
...                                         ; and so on for r, y, p, t
 
```
 
That is, the original bytes `65 6e 74 72 79 70 74` = `entrypt` appear directly as operands of the `xor`. The password can be read from the assembly without running it at all.
 
### 2.4 Dynamic verification - recovery from the stack
 
A breakpoint inside `main` after the secret is built. In pwndbg's STACK window the two components appear:
 
```
-060  0x...d670 <- 0x55                     # the key
-058  0x...d678 <- 0x21252c27213b30 /* "0;!',%!" */   # the encrypted secret (little-endian)
```
 
The encrypted bytes (in reverse order): `30 3b 21 27 2c 25 21`. pwndbg displays them as gibberish `"0;!',%!"` - the readable password is never in memory at any moment. Manual recovery with XOR against `0x55`:
 
| encrypted | `^ 0x55` | char |
|-------|----------|-----|
| 0x30 | 0x65 | e |
| 0x3b | 0x6e | n |
| 0x21 | 0x74 | t |
| 0x27 | 0x72 | r |
| 0x2c | 0x79 | y |
| 0x25 | 0x70 | p |
| 0x21 | 0x74 | t |
 
-> `entrypt`.
 
### 2.5 Conclusion
 
- **Password:** `entrypt` (unchanged), **Flag:** `entrypoint{re_basics}`.
- **What was achieved:** `strings` and `ltrace` no longer expose the password - easy static analysis is no longer enough.
- **Why it still breaks:** XOR is reversible, and the key (`0x55`) is visible both in assembly and in GDB. Once you identify the key and the encrypted bytes, recovery is `enc[i] ^ key` - without running. The protection slows you down by a few steps, it doesn't block you.
- **Key takeaway:** as long as the CPU needs to see the values in order to compare, so can the analyst. Better obfuscation would require a one-way hash instead of reversible XOR.
---
 
## Exercise 3 - breakpoint on scanf and the calling convention
 
**Goal:** Stop at the call to scanf (instead of at the comparison), document what each argument register holds at the moment of the call, and explain how this relates to the calling convention.
 
### 3.1 The idea
 
At the machine level there are no "arguments" - only registers. When the code calls `scanf("%63s", input)`, the compiler must hand scanf two things: the format string `"%63s"` (the instruction on what to read) and the buffer address `input` (where to write the input). The handover follows a fixed rule - the System V ABI - which dictates which register each argument goes in.
 
### 3.2 The stop
 
The call to scanf in crackme2 is at `0x40124c`. We set a breakpoint there and run:
 
```gdb
pwndbg> b *0x40124c
pwndbg> r
```
 
The two instructions before the call show how the registers are loaded:
 
```asm
40123a:  mov rsi,rax     ; rsi = buffer address   (argument 2)
401244:  mov rdi,rax     ; rdi = "%63s" address    (argument 1)
401247:  mov eax,0x0     ; al = 0  (variadic: no vector arguments)
40124c:  call __isoc99_scanf@plt
```
 
### 3.3 The registers at the moment of the call
 
```
RDI  0x402013 <- '%63s'           # argument 1: the format string
RSI  0x7fffffffd680 <- 0          # argument 2: buffer address (empty - nothing typed yet)
RAX  0                            # al=0: no SSE/float arguments
```
 
Important point: the register holds the **address** that points to the string itself. `rdi = 0x402013`, and at that address sits `"%63s"`. `rsi` points to an area on the stack where `<- 0` (empty) - because scanf hasn't written there yet. After running, that same address will hold the input.
 
### 3.4 Relation to the calling convention
 
According to the System V AMD64 ABI, the first six arguments pass in registers in a fixed order:
 
| Argument | Register | In the call `scanf("%63s", input)` |
|----------|---------|-------------------------------|
| 1 | `rdi` | `"%63s"` ✓ |
| 2 | `rsi` | address of `input` ✓ |
| 3 | `rdx` | - (scanf takes only 2) |
| 4 | `rcx` | - |
| 5 | `r8` | - |
| 6 | `r9` | - |
 
scanf takes 2 arguments, so only `rdi` and `rsi` carry meaning; the other registers (`rcx`, `rdx`, `r8`...) hold general state/leftovers and are not part of the call.
The `al=0` is an additional ABI rule for variadic functions (like scanf/printf): `al` indicates how many `double/float` arguments pass in SSE registers - here, zero.
 
### 3.5 Conclusion
 
The call `scanf("%63s", input)` in C is translated at the machine level into "put the format in rdi, the buffer address in rsi, then call". Stopping at the call lets you see the ABI with your own eyes: `rdi` -> format, `rsi` -> destination. And this is how GDB (and the analyst) knows how to read the arguments of any call - the order is fixed in advance.
 
---
 
## Exercise 4 - picoGym challenges
 
### Challenge 1 of 3: Reverse (file: `ret`)
 
**Link**: https://learn.cylabacademy.org/library/372
**Flag:** `academy{3lf_r3v3r5ing_succe55ful_8fb4d69c}`
 
#### Initial survey (static)
 
The first step was `file` to understand the baseline:
 
```
ret: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
     interpreter /lib64/ld-linux-x86-64.so.2, not stripped
```
 
Two conclusions that shaped everything that followed: the binary is **PIE** (so every address from objdump/Ghidra is an offset, not a runtime address), and it's **not stripped** (so there are symbols, and you can work with names like `main` instead of computing addresses).
 
#### String extraction (static)
 
`strings ret` showed parts of the password, but truncated:
 
```
academy{H
3lf_r3v3H
r5ing_suH
cce55fulH
_8fb4d69
```
 
Why it's truncated: as we'll see below, the password isn't stored as a continuous string but is built on the stack from `mov` instructions with 8-byte immediate values. So `strings` finds it in 8-character chunks. The `H` at the end of each chunk is not part of the password: it's the byte `0x48` (REX.W prefix) of the next instruction, which happens to be a printable character. The last characters (`c}`) remained a sequence shorter than 4 characters, so `strings` filtered them out.
 
With the default minimum changed to 2, `strings -n 2`, all the characters are visible.
```
academy{H
3lf_r3v3H
r5ing_suH
cce55fulH
_8fb4d69
c}
```
 
`strings` did reveal the full flag in the success message (`Password correct, please see flag: ...`). That's a weakness of the challenge itself.
 
#### Ghidra analysis (decompiler)
 
Import `ret`, auto-analysis, and navigate to `main` (exists as a symbol, so no need to trace from entry). The core pseudo-C (abbreviated):
 
```c
char local_118 [128];   // user input
char local_98 [136];    // the password
...
builtin_strncpy(local_98, "academy{3lf_r3v3r5ing_succe55ful_8fb4d69c}", 0x2b);
// ... then zero out the rest of the array
__isoc99_scanf(&DAT_00102031, local_118);
printf("You entered: %s\n", local_118);
iVar1 = strcmp(local_118, local_98);
if (iVar1 == 0) {
    puts("Password correct, please see flag: ...");
} else {
    puts("Access denied");
}
```
 
What was discovered here and how:
- **Building the password:** `builtin_strncpy(local_98, "academy{...}", 0x2b)`. In the machine code there is no call to `strncpy`; the compiler wrote the password in `mov` instructions, and Ghidra recognized the pattern and displayed it as a single copy. This directly explains the truncation we saw in `strings`. `0x2b` = 43 bytes: 42 password characters plus a `\0`.
- **The logic:** the program compares the input (`local_118`) to the password (`local_98`) with `strcmp`. A match -> prints the flag; otherwise -> "Access denied". Hence the password is the flag.
#### Dynamic verification (gdb / pwndbg)
 
To verify that static correctly described what's compared at runtime, I stopped at `strcmp`. The difficulty: `strcmp` is called dozens of times by the dynamic loader before my code starts, so `b strcmp` right at the beginning stops over and over in `dl_main`.
 
The solution: reach the `main` code first and only then set the breakpoint, since the loader has already finished:
 
```gdb
b *_start        # a symbol name, gdb fixes it to the right base on its own
entry            # runs up to the binary's entry point
b strcmp         # now there are no more loader calls
c                # type any password when the program asks
```
 
Stopping at `strcmp`, checking the arguments per the System V calling convention (argument 1 in `rdi`, argument 2 in `rsi`):
 
```gdb
x/s $rdi   ->  "aaaaaaa"                                      (my input)
x/s $rsi   ->  "academy{3lf_r3v3r5ing_succe55ful_8fb4d69c}"   (the password)
```
 
This dynamically confirms the static conclusion: the input in `rdi`, the password in `rsi`, exactly like `strcmp(local_118, local_98)` in the decompiler. The offsets match too: `local_118` is `rbp-0x110` and `local_98` is `rbp-0x90`, which I saw in the disassembly of the call at `main+295`.
 
> Note on PIE: an attempt to create a breakpoint `b *0x10e0` (the entry from readelf) failed with `Cannot insert breakpoint`, because `0x10e0` is an offset, not a runtime address. On a PIE binary, a numeric address needs a base; a symbol name (`*_start`) or `breakrva <offset>` after `starti` work because they compute the base.
 
#### Additional findings (vulnerability-research thinking)
 
Beyond the solution, the analysis exposed two things worth noting:
- **Buffer overflow:** double-clicking `DAT_00102031` in the Listing window showed the bytes `25 73 00`, i.e. `"%s"` with no length limit. The input goes into `local_118`, which is 128 bytes, with no bound. (Unlike the crackme in the first exercise, which uses `"%63s"`.)
- **Stack canary:** the code contains `local_10 = *(long *)(in_FS_OFFSET + 0x28)` and a check at the end of `main` that calls `__stack_chk_fail`. That's a canary protection.
Verifying the overflow and crash: the distance from the start of the input (`rbp-0x110`) to the canary (`rbp-0x8`) is `0x108` = 264 bytes, so input longer than ~265 should crash it. In practice `cyclic 300 | ./ret` crashed with:
 
```
*** stack smashing detected ***: terminated
```
 
So there is a real overflow, and the canary catches it and prevents hijacking control via the return address. This is a static calculation verified dynamically, and the basis for the exploitation stage later on.
 
#### The path in brief
 
`file` (identify PIE, not stripped) -> `strings` (truncated hint + understanding why it's truncated) -> Ghidra (the comparison logic and password building) -> `gdb` (verifying the registers at `strcmp`) -> analyzing `scanf` and the canary. The static conclusion (the input is compared to a fixed password) was verified dynamically at every step.
 
---
 
### Challenge 2 of 3: `reverse_cipher` (files: `rev`, `rev_this`)
 
**Link:** https://learn.cylabacademy.org/library/79
**Flag:** `academy{r3v3rs397436647}` · Rating: Hard · picoCTF 2019
 
#### What was given
 
Two files: a binary `rev` and a text file `rev_this`. The logic: the binary reads a clean flag from `flag.txt`, encrypts it, and writes the result to `rev_this`. We hold the encrypted output (`rev_this`) and need to recover the original input.
 
`rev_this`: `academy{w1{1wq87<284;2<}`
 
#### Initial survey (static)
 
```
file rev   ->  ELF 64-bit PIE, not stripped
strings rev
```
 
`file` confirmed PIE and not stripped. Unlike `ret`, `strings` gave no useful hint here, because the flag isn't fixed in the code but computed at runtime, so it doesn't appear as a string. That's already an indication that you need to read the logic, not search for a string.
 
#### Ghidra analysis (decompiler)
 
Straight to `main` (symbols present). The pseudo-C:
 
```c
fread(local_58, 0x18, 1, local_20);            // reads 24 bytes from flag.txt
 
for (local_10 = 0; local_10 < 8; local_10++)   // positions 0-7: copied as-is
    fputc(local_58[local_10], local_28);
 
for (local_14 = 8; local_14 < 0x17; local_14++) {   // positions 8-22
    if ((local_14 & 1) == 0)                   // even position
        local_9 = local_58[local_14] + 5;      //   +5
    else                                       // odd position
        local_9 = local_58[local_14] - 2;      //   -2
    fputc(local_9, local_28);
}
 
fputc(local_41, local_28);                     // position 23 (the 24th char): copied as-is
```
 
What was discovered and how:
- **Fixed length:** `fread(..., 0x18, ...)` reads exactly 24 bytes (`0x18`). The flag is 24 characters long.
- **Three regions:** positions 0-7 (the prefix `academy{`) and position 23 (`}`) are copied as-is. Only positions 8-22 undergo a transformation. This explains why the start and end of `rev_this` are readable and the middle is scrambled.
- **The condition is on the position, not the value:** `(local_14 & 1)` is tested on the loop variable (the position `i`), not on the character's value. Even position -> +5, odd position -> -2.
#### Recovery (reversing the algorithm)
 
The reversal is the inverse operation at each position:
 
| Position | Encryption (the binary) | Recovery (us) |
|-------|------------------|----------------|
| 0-7 | copy | copy |
| even (8,10,...) | +5 | -5 |
| odd (9,11,...) | -2 | +2 |
| 23 | copy | copy |
 
Decoding example, position 8: in `rev_this` there's `w` (ASCII 119). Position 8 is even, so the encryption added 5. Recovery: 119 - 5 = 114 = `r`. That is indeed the first character after the prefix in the recovered flag.
 
#### Dynamic verification
 
Instead of relying on the calculation alone, I let the original binary verify: I put the recovered flag into `flag.txt`, ran `rev`, and compared the output to the original `rev_this`.
 
```bash
mv rev_this rev_this.backup                  # save the original (the binary writes in append)
echo -n 'academy{r3v3rs397436647}' > flag.txt
./rev
diff rev_this rev_this.backup                # no output = identical
```
 
The `diff` came back empty, meaning the binary produced from my flag exactly the original `rev_this`. This confirms the algorithm was decoded correctly and the input recovery is accurate.
 
#### The path in brief
 
`file` -> `strings` (didn't help, because the flag is computed) -> Ghidra (the three transformation regions and the condition on the position) -> reversing the algorithm -> running the original binary to verify. Unlike `ret`, here an algorithm was recovered rather than a fixed string, and that's exactly the transition from "string extraction" to "pattern understanding" that the exercise asks for.
 
---
 
### Challenge 3 of 3: GDB baby step 1 (file: `debugger0_a`)
 
**Link**: https://learn.cylabacademy.org/library/395
**Flag:** `academy{549698}` · Category: Reverse Engineering · picoCTF
 
#### What the challenge asked
 
The task: find the value that's in `eax` at the end of `main`. This is a debugger-focused exercise. The flag is that same value in decimal, in the format `academy{<decimal>}`.
 
#### Initial survey (static)
 
```
file debugger0_a   ->  ELF 64-bit, not stripped
```
 
not stripped, meaning there are symbols and you can work with the name `main` directly, without tracing from entry.
 
#### Dynamic verification (gdb / pwndbg) - the heart of the challenge
 
Here there's no need to decode an algorithm; you need to catch a register value at the right moment. The efficient way is `finish` instead of stepping manually with `ni`:
 
```gdb
gdb ./debugger0_a
b main
run
finish        # runs main to the end and exits it
```
 
The moment `finish` completes, RIP is at `__libc_start_call_main+122`, and the instruction there is:
 
```
mov edi, eax        EDI => 0x86342
```
 
This is conclusive proof that the value is correct, from two angles:
 
**1. The instruction after it is `call exit`.** The DISASM shows the full sequence:
 
```asm
main+15: mov eax, 0x86342        ; the value is loaded into eax
main+20: pop rbp
main+21: ret                     ; main returns
-> __libc_start_call_main+122: mov edi, eax    ; EDI => 0x86342
  __libc_start_call_main+124: call exit        ; exit(0x86342)
```
 
That is, the point we stopped at is exactly one instruction before `call exit`. libc moves main's return value from `eax` to `edi` (the first argument of `exit` per the calling convention), and immediately calls `exit`. The fact that `call exit` is the next target confirms this is indeed the moment of exit, and that the value in `eax` is the final return value.
 
**2. pwndbg confirms the transfer:** `RAX = 0x86342` and the DISASM shows `EDI => 0x86342`, meaning the value was copied intact. No instruction overwrote `eax` between main's `ret` and this point.
 
Hence, the value in `eax` at the end of `main` is `0x86342`.
 
> An additional note from static: at `main+15` we see `mov eax, 0x86342`, meaning the value isn't computed at all but loaded directly as a constant. It could also have been found in objdump/Ghidra without running, but the challenge explicitly asked to read it at runtime, and that's exactly what `finish` provides.
 
Converting to the flag format: `0x86342` = 549698 in decimal. Hence:
 
```
academy{549698}
```
 
#### The path in brief
 
`file` (not stripped) -> `gdb` with `b main` and `finish` -> reading `eax` at the moment of exit (`0x86342`), verified via `mov edi, eax` in libc -> conversion to decimal (549698).
 
---
 
## Exercise 4 summary
 
Three Reverse Engineering challenges from picoGym, three different patterns:
 
| Challenge | File | Pattern | What was required |
|------|------|------|---------|
| Reverse | `ret` | fixed password built with `mov` | reading the decompiler + verifying the registers at `strcmp` |
| reverse_cipher | `rev` | byte-by-byte encryption algorithm | reversing the algorithm + running the binary to verify |
| GDB baby step 1 | `debugger0_a` | return value at runtime | `finish` in gdb and reading `eax` |