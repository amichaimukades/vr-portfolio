# GDB Baby Step 2

**Category:** Reverse Engineering - Static/Dynamic Disassembly
**Link:** https://learn.cylabacademy.org/library/396
**Binary:** `debugger0_b` (not stripped)
**Answer:** `academy{307019}`

## The Task
Find what the value of the `eax` register is at the end of `main`, in decimal.

The goal is to learn dynamic analysis: breakpoints, running, and reading registers. I added a manual calculation to verify it.

## Solving with gdb
```
$ chmod +x debugger0_b
$ gdb ./debugger0_b
pwndbg> disas main
```

In the disassembly you can see a loop (`jmp` to `main+48`, and `jl` back to `main+38`). After it:
Disassembling `main` revealed that it's made up of a loop:
```asm
401111 <+11>:    mov    QWORD PTR [rbp-0x20],rsi
401115 <+15>:    mov    DWORD PTR [rbp-0x4],0x1e0da ; A = 0x1e0da (123,098)
40111c <+22>:    mov    DWORD PTR [rbp-0xc],0x25f   ; B = 0x25f (607) - loop limit
401123 <+29>:    mov    DWORD PTR [rbp-0x8],0x0     ; C = 0 - counter
loop body:
40112a <+36>:    jmp    0x401136 <main+48>
40112c <+38>:    mov    eax,DWORD PTR [rbp-0x8]
40112f <+41>:    add    DWORD PTR [rbp-0x4],eax     ; A += C
401132 <+44>:    add    DWORD PTR [rbp-0x8],0x1     ; C += 1
401136 <+48>:    mov    eax,DWORD PTR [rbp-0x8]
401139 <+51>:    cmp    eax,DWORD PTR [rbp-0xc]     ; C < B?
40113c <+54>:    jl     0x40112c <main+38>          ; loop
40113e <+56>:    mov    eax,DWORD PTR [rbp-0x4]
```

**The important point: where to place the breakpoint.** The value gets loaded into `eax` by the instruction at `main+56`, so you need to stop *after* it, at `main+59` (`0x401141`):

```
pwndbg> b *0x401141
pwndbg> r
pwndbg> p/x $eax
$1 = 0x4af4b
pwndbg> p/d $eax
$2 = 307019
```

### A trap I ran into
1. On the first try I put a breakpoint at `0x40113e` (`main+56`), *before* the `mov`. `p/x $eax` returned `0x25f` (607), which is the loop limit left in `eax` from the last `cmp`, **not** the answer. Only after `s` (stepping one instruction to `0x401141`) did `eax` become `0x4af4b`. Stopping at an instruction doesn't mean it has been executed yet.

2. In Intel syntax (the default in pwndbg) the destination is the **first** operand. In AT&T the order is reversed. This makes it easy to confuse `acc += i` with `i += acc`.


## Ghidra pseudocode:
```c
int local_c = 0x1e0da; // 123098
for (int local_10 = 0; local_10 < 0x25f; local_10++) // 0x25f == 607
    local_c = local_c + local_10;
return local_c;
```

**A pitfall:** my first mistake was reading `add eax, [rbp-4]` as if the destination is `eax`. But the order is the opposite of what I remembered. Reading it wrong turns `A += C` into `C += A`, two completely different operations in terms of the result.

Calculation: the sum of 0..606 is `606*607/2 = 183921`, plus `123098` gives `307019`. In hex that's `0x4af4b`, exactly what gdb showed.

## Lessons
- **Put the breakpoint after the instruction you care about, not on it.** Stopping at an instruction doesn't execute it.
- Dynamic analysis verifies things without relying on manually reading the assembly (and in particular, on the order of the operands).
- The closed-form calculation (sum of an arithmetic series) is a sanity check, not a substitute for actually running it.