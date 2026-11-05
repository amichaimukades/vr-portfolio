# GDB Baby Step 3

**Category:** Reverse Engineering - Memory Layout / Endianness
**Link:** https://learn.cylabacademy.org/library/397
**Binary:** `debugger0_c`
**Flag:** `academy{0x6bc96222}`

## The Task and the Code That Was Decoded

`main` writes a hexadecimal constant directly to the stack:
```asm
0x401115 <+15>:  mov    DWORD PTR [rbp-0x4], 0x2262c96b
0x40111c <+22>:  mov    eax, DWORD PTR [rbp-0x4]
```
The task: find the address where the constant is, and understand how it's stored in memory. x86-64 is a **little-endian** architecture: the least significant byte (LSB) is stored at the lowest memory address.

## The Technique
To capture the bytes **after** the writing instruction (`mov [rbp-4], 0x2262c96b`) has already run, the breakpoint was placed not on the writing instruction itself (since `b`/`s` stop *before* it executes) but on the instruction **right after it**:
```
b *0x40111c
r
x/4xb $rbp-4
```
The output: `0x6b 0xc9 0x62 0x22` - **reversed** from the order it's written in the code (`0x22 0x62 0xc9 0x6b`). The required format assembles the bytes in the order they're stored in memory, not the order they were written: `academy{0x6bc96222}`.

## Why This Matters
This shows, physically and not just theoretically, what "little-endian" actually means - and also a critical rule of thumb in debugging: a breakpoint/step always stops *before* the instruction it's placed on gets executed, not after - which is critical when checking side effects (like a memory write), not just the flow of code.