# Research Journal

This document describes **how** I approach an unknown target: the loop I work in, and the habits that keep every finding reproducible and defensible. It is not a tutorial but a record of method, distilled from the stages in this repo.

## 1. The research loop

The spine of every analysis I do is a single loop:

**Hypothesis → static evidence → dynamic evidence → refutation test → conclusion.**

- **Hypothesis** - a statement of what I think is happening, phrased so it can be falsified.
- **Static evidence** - reading the code (disassembly / decompiler) to locate *where* to test.
- **Dynamic evidence** - running under a debugger to see what *actually* happens: register values, which branch is taken, what is computed at runtime.
- **Refutation test** - change one thing that should break the claim, and confirm it does.
- **Conclusion** - only what survived the loop.

The loop is not linear: the static finding tells me where to breakpoint, the dynamic result reveals what can't be seen from reading code alone, and then I return to the code with a better understanding. Each round shrinks the unknown.

*Example (crackme, stage 02):* in static analysis with Ghidra I saw the program compare my input against a secret string with `strcmp`, where the secret is built on the stack across several `mov` instructions. Hence the **hypothesis**: my input is compared exactly against that secret. To **verify dynamically** I broke on the call to `strcmp` and read its two arguments per the ABI - `x/s $rdi` showed my input, `x/s $rsi` showed the secret - exactly as the static analysis predicted. The **refutation test** was `verify.sh`: it rebuilds the binary and checks not only that the correct password is accepted but also that a wrong password is rejected - if the understanding is wrong, the check fails.

## 2. First contact with an unknown target

**Questions first, not tools.** What is it (`file`: stripped? PIE? architecture?)? What is the input surface? Which protections are active (`checksec`: NX / PIE / canary / RELRO)? And where does the untrusted input meet a **decision** (comparison/branch) or a **memory operation** (copy/write)? That is where the bug lives, and where I go deep.

**The tool order I settled on:**

1. `file` - stripped and PIE.
2. `strings` - quick hints (without stopping there; relying on `strings` alone is not understanding the code).
3. `nm | grep ' T '` - which functions exist.
4. `objdump --disassemble=<func>` or Ghidra - the logic.
5. `ltrace` - a quick dynamic check of library calls.
6. `gdb` with `b <func>` or `b *<func>+offset` - precise verification.

In a **stripped** binary the symbol-based steps fall away; then I follow, from the entry point, the argument passed in `rdi` to `__libc_start_main` to find `main`.

**When the target is not a binary.** The same loop and the same questions apply to web too, only the tools differ: first map the application (which endpoints, parameters and forms, what is sent over the Network), intercept and modify requests in Burp, and look for where untrusted input reaches a sink - a SQL query, a template (SSTI), a file path, or an outbound request (SSRF). The verification is a controlled payload that breaks one thing: `' OR 1=1--`, `{{7*7}}`, or an internal range through the vulnerable parameter. And in CVE analysis, the "target" is the difference between a vulnerable and a patched version, and the root cause emerges from cross-referencing the advisory, `grep` over the source, and the diff between versions.

**Principle: prefer a method over a hardcoded address.** I ran into this when I wanted to break on `strcmp`: the loader calls it dozens of times before my code even starts, so an immediate breakpoint stops again and again in the wrong place. The fix was to first run to the start of my own code (`b *_start` then `entry`), and only then set the breakpoint on `strcmp` - once the loader is done. In general I prefer a route that describes *how* to reach a point over a numeric address that changes on every build.

## 3. Evidence discipline

- **Per-breakpoint documentation.** Every claim about a register rests on the continuous instruction sequence that computes the value **and** on a register snapshot from the same stop - so another reader can reconstruct where each argument came from, not just trust the conclusion.
- **Measure, don't assume.** An offset is measured with `cyclic` and checked against the theoretical calculation. A trap worth knowing: a double endianness flip returned three values (69/72/73) **with no error at all** - which is what makes it dangerous. The rule: don't flip bytes by hand. Likewise - the real distance between variables is measured in the assembly, not from the declared buffer size; and gadget availability is a property of the binary, not the source, and depends on the compiler.
- **Claim ↔ evidence.** No unverified claim. Every number in a title, an analysis and a conclusion comes from the same evidence, and the PoC I show must demonstrate the mechanism I explain (for example, the payload must contain the `.%2e` pattern that the root-cause analysis is built on).
- **`None` is not evidence of absence.** A tool that returns "None" (like pwntools' `find_gadget`) does not prove the thing is absent from the binary - that is a wrong conclusion about the binary itself. (When I searched for `pop rdi; ret`, `find_gadget` returned `None` because it looks for an exact match; but the binary had a **similar but not identical** gadget - `pop rdi; pop rbp; ret`.)
- **Reproducibility via `verify.sh`.** The script builds from source and checks **two** claims: that the exploit works, and that wrong input does **not**. A flag-only check would have passed a broken exploit - in 1.6 the flag printed while `system()` crashed on alignment. Each negative case changes exactly one thing to isolate one claim. Better still is a self-verifying target: `win(int code)`, which prints the flag only for the right value, turns the run itself into the evidence.

## 4. Pre-exploit assumptions table

Before writing an exploit I write a short table, then check each row with the right tool:

| Assumption | Evidence source |
|---|---|
| Active protections | `checksec` |
| Address source (leak / fixed / base) | runtime / `readelf` |
| Gadget source | `ROPgadget` / the binary |
| Stack alignment (16-byte before `call`; need a `ret`?) | `gdb` at the `ret` |
| Success signal | shell / `uid=` / branch taken |

This is the discipline that would have caught the alignment surprise up front, instead of after the crash.

## 5. Working safely

- **Lab boundaries before any PoC:** which containers run, which ports are published, and which targets outside the machine the process must not reach.
- **An external service is a conscious exception.** A DNS canary or an external webhook is marked explicitly as an optional exception with a local alternative.
- **Ethics.** Only against targets I own or am authorized for. For a real finding - responsible disclosure: a private report, reasonable time to fix, a coordinated release, no exploitation and no sale.

## 6. Before I call it done

- The repo is clean of flags and sensitive files.
- I can explain, in my own words, every artifact I built.