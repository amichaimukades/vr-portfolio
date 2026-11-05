# GDB Baby Step 4

**Category:** Reverse Engineering - Static Analysis (Immediate Operand)
**Link:** https://learn.cylabacademy.org/library/398
**Binary:** `debugger0_d`
**Flag:** `academy{12905}`

## The Task

`main` calls a function that multiplies `eax` by a constant. The flag is that constant in decimal (`0x1000` -> `academy{4096}`).


```asm
; main:
mov    DWORD PTR [rbp-0x4], 0x28e
call   0x401106 <func1>

; func1:
mov    DWORD PTR [rbp-0x4], edi
mov    eax, DWORD PTR [rbp-0x4]
imul   eax, eax, 0x3269        ; *** the constant we're after ***
```

## The Approach

```
pwndbg> disas main
   ...
   mov DWORD PTR [rbp-0x4], 0x28e     ; arg = 654
   mov edi, eax
   call 0x401106 <func1>

pwndbg> disas func1
   mov DWORD PTR [rbp-0x4], edi
   mov eax, DWORD PTR [rbp-0x4]       ; <- 0x401111
   imul eax, eax, 0x3269              ; <- 0x401114
   pop rbp                            ; <- 0x40111a
```

### Method 1: breakpoint after the imul, then extract the constant from the ratio
```
pwndbg> b *0x40111a
pwndbg> r
pwndbg> p $edi            # 654
pwndbg> p $eax            # 8439870
pwndbg> p $eax / $edi     # 12905
```

### Method 2: feed in eax=1 and let gdb hand back the constant
```
pwndbg> b *0x401114       # before the imul
pwndbg> r
pwndbg> set $eax = 1
pwndbg> stepi
pwndbg> p $eax            # 12905  <- the constant itself
```
When `eax = 1`, the product is the constant.


### Method 3 - reading it from the assembly / the pseudocode

pwndbg> disas func1
   mov DWORD PTR [rbp-0x4], edi
   mov eax, DWORD PTR [rbp-0x4]       ; <- 0x401111
   imul eax, eax, 0x3269              ; <- 0x401114
   pop rbp                            ; <- 0x40111a
```
Ghidra pseudocode:
```
return param_1 * 0x3269;
```
Both expose the constant directly. Converted to decimal, the answer is: `0x3269 = 12905`.

## Why This Matters
Not every constant requires runtime debugging - the difference between "a constant written to memory" (you need `run`+breakpoint to catch it) and "a constant that's a literal operand inside a machine instruction" (visible from static disassembly alone) is exactly the kind of intuition this exercise is meant to build - and picking the right tool (static vs. dynamic analysis) saves significant time.

## Lessons
- If you change the input to a neutral value (1), the instruction "prints out" the constant by itself.