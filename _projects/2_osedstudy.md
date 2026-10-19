---
layout: page
title: OSED Study
description: A study journey for the OSED.
img: 
importance: 2
category: Personal
subcategory: red
status: paused
related_publications: false
---

<h2>Introduction</h2>

So, once upon a time, I took the Offensive Security Exploit Developer (OSED). I unfortunately failed the exam at that time. Discouraged, I shelved it and transferred to the Blue Team before I could return to it.

Why I’m returning to this: OSED represents advanced exploit development skills that complement my OSCP foundation. This structured study plan keeps me accountable and demonstrates a methodical approach to complex technical challenges. Time to crush it like a cockroach.

What I am going to add: I am adding x64 custom shellcoding and VM escape modules in addition to the course material. Microsoft is slowly trying to kill support for x86 (or maybe they already have?) so incorporating x86_64, while I am already studying anyways, just seems like a good idea so I am actually useful once I pass. VM escapes seem like a good addition because virtualization is ubiquitous at this point as that is the backbone of the cloud (t3.micro is a VM). I expect the exam itself remains focused on 32-bit (x86) Windows user-mode exploitation. That is what it was when I took it last time.

Well, I was playing with KaliGPT and decided to ask it for help. I decided to ask for a curriculum and checklist and see what it would develop for me. I then decided to play dueling LLMs and have Claude lay into it. Might go back to KaliGPT, not sure how many rounds. Anyways, this is the result of that little experiment. Since I didn’t know where to save it to keep me honest, my portfolio projects section will have to do.

<br />
<h2>Links</h2>
<a href="https://www.offsec.com/courses/exp-301/">Offsec OSED Link</a><br />
<a href="https://github.com/biscottidiskette/osed">https://github.com/biscottidiskette/osed</a>

<br />
<h2>Process</h2>

<h3>Resources</h3>

<br />
<h4>Books</h4>
<ul>
    <li><i>Practical Reverse Engineering</i> — Bruce Dang</li>
    <li><i>Windows Internals, Part 1</i> — Mark Russinovich</li>
    <li><i>The IDA Pro Book</i> — Chris Eagle</li>
    <li><i>The Shellcoder's Handbook</i> — Jack Koziol</li>
    <li><i>Hacking: The Art of Exploitation, 2nd Ed</i> — Jon Erickson</li>
    <li><i>The C Programming Language</i> — Kernighan and Ritchie (or <i>C Programming: A Modern Approach</i> — K.N. King)</li>
</ul>

<h4>Online Courses & Tutorials</h4>
<ul>
    <li><a href="https://opensecuritytraining.info/IntroX86.html">OpenSecurityTraining — Intro to x86</a></li>
    <li><a href="https://www.corelan.be/index.php/articles/">Corelan Exploit Writing</a></li>
    <li><a href="https://www.fuzzysecurity.com/tutorials.html">FuzzySecurity — Exploit Dev Tutorials</a></li>
    <li><a href="https://ropemporium.com/">ROP Emporium</a></li>
    <li><a href="https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN">LiveOverflow – Stack Overflow & Exploitation</a></li>
</ul>

<h4>Tools & References</h4>
<ul>
    <li><a href="https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools">Microsoft Learn – WinDbg Preview Guide</a></li>
    <li><a href="https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/debugger-commands">WinDbg Commands Reference</a></li>
    <li><a href="https://learn.microsoft.com/en-us/windows/win32/debug/pe-format">Microsoft — PE Format Specification</a></li>
    <li><a href="https://www.learn-c.org/">Learn-C</a></li>
</ul>

<br />
<h3>Overall Path</h3>

The phases below are aligned to the EXP-301 module order and the core exploit development skill areas. Each phase builds on the last. **Do not skip ahead** — this material rewards depth, not breadth.

<h3>Phase 0: Foundation & Setup (1–2 weeks)</h3>
<b>Goal: Lock in C fundamentals, x86 assembly, Windows internals, PE format, and tool fluency before touching exploits.</b>

<h6>Topics:</h6>
<ul>
    <li>C programming: pointers, arrays, strings, structs, memory allocation (malloc/free)</li>
    <li>Understanding what vulnerable C code looks like before the compiler turns it into assembly</li>
    <li>x86 Assembly (32-bit focus): registers, stack operations, calling conventions (stdcall/cdecl)</li>
    <li>Stack layout: function prologs/epilogs, EBP/ESP relationship</li>
    <li>PE file format: headers, sections, IAT, image loading</li>
    <li>Virtual memory, Windows API basics (VirtualAlloc, LoadLibrary, GetProcAddress)</li>
    <li>WinDbg workflow: breakpoints, stepping, memory inspection, !address, !exchain</li>
    <li>IDA Free/Pro workflow: navigation, cross-references, string analysis, function identification</li>
</ul>

<h6>Resources:</h6>
<ul>
    <li><i>The C Programming Language</i> — Kernighan and Ritchie (or <i>C Programming: A Modern Approach</i> — K.N. King)</li>
    <li><a href="https://www.learn-c.org/">Learn-C</a></li>
    <li><a href="https://opensecuritytraining.info/IntroX86.html">OpenSecurityTraining — Intro to x86</a></li>
    <li>Practical Reverse Engineering — Bruce Dang (Ch. 1–3)</li>
    <li>Windows Internals, Part 1 — Mark Russinovich (Ch. 1–4)</li>
    <li>The IDA Pro Book — Chris Eagle (Ch. 1–3)</li>
    <li><a href="https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools">Microsoft — WinDbg Preview Guide</a></li>
    <li><a href="https://markpelf.com/1628/pe-format-illustrated-part-1/">Mark Pelf — PE Format Illustrated</a></li>
</ul>

<br />
<h3>Phase 1: Stack Overflows & SEH (2–3 weeks)</h3>
<b>Goal: Master vanilla buffer overflows and SEH-based exploitation — the foundation for everything that follows.</b>

<h6>Topics:</h6>
<ul>
    <li>Stack-based buffer overflows: manual EIP control</li>
    <li>Cyclic pattern generation and offset calculation</li>
    <li>Bad character identification and handling</li>
    <li>SEH overwrite technique and nSEH/SEH chain mechanics</li>
    <li>Short jumps and trampolining</li>
</ul>

<h6>Resources:</h6>
<ul>
    <li><a href="https://www.corelan.be/index.php/articles/">Corelan Exploit Writing Parts 1–3 (Stack, SEH)</a></li>
    <li>The Shellcoder's Handbook — Jack Koziol (buffer overflow chapters)</li>
    <li><a href="https://www.fuzzysecurity.com/tutorials.html">FuzzySecurity — Exploit Dev Tutorials</a></li>
    <li><a href="https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN">LiveOverflow — Binary Exploitation</a></li>
</ul>

<br />
<h3>Phase 2: Egghunters (1–2 weeks)</h3>
<b>Goal: Overcome space restrictions by using egghunters to locate shellcode in memory.</b>

<h6>Topics:</h6>
<ul>
    <li>Why egghunters: limited buffer space after gaining EIP control</li>
    <li>NtAccessCheckAndAuditAlarm and NtDisplayString syscall egghunters</li>
    <li>Egg tag placement strategies</li>
    <li>Combining egghunters with SEH-based delivery</li>
</ul>

<h6>Resources:</h6>
<ul>
    <li><a href="https://www.corelan.be/index.php/2009/09/28/writing-egg-hunters-with-buffer-overflows/">Corelan — Writing Egghunters</a></li>
    <li><a href="https://www.fuzzysecurity.com/tutorials/expDev/8.html">FuzzySecurity — Stack Smashing 0x08</a></li>
    <li><a href="https://www.skullsecurity.org/blog/2010/writing-egg-hunters">SkullSecurity — Egghunter Explanation</a></li>
</ul>

<br />
<h3>Phase 3: IDA Reverse Engineering (2–3 weeks)</h3>
<b>Goal: Become fluent in static analysis — RE is how you find the bug before you can exploit it.</b>

<h6>Topics:</h6>
<ul>
    <li>Navigating IDA: Functions window, Strings window, Imports, cross-references (Xrefs)</li>
    <li>Identifying vulnerability patterns: unsafe string operations, unchecked buffer copies</li>
    <li>Tracing data flow from input to vulnerable function</li>
    <li>Recognizing calling conventions and reconstructing function prototypes</li>
    <li>Patching binaries in IDA for testing</li>
    <li>Mapping IDA static analysis to WinDbg dynamic analysis</li>
    <li>Crackmes: tracing program logic in IDA with no source code to fall back on</li>
</ul>

<h6>Resources:</h6>
<ul>
    <li>The IDA Pro Book — Chris Eagle (full analysis sections)</li>
    <li>Practical Reverse Engineering — Bruce Dang (reversing chapters)</li>
    <li><a href="https://crackmes.one/">Crackmes.one</a> — practice RE challenges (start easy, work up)</li>
    <li>Practice: download vulnerable apps and find the bug in IDA before looking at writeups</li>
</ul>

<br />
<h3>Phase 4: Custom Shellcode from Scratch (4–5 weeks)</h3>
<b>Goal: Write Windows shellcode entirely by hand in x86 assembly. This includes building multiple payloads beyond those included in class for variety and to anchor the skill.</b>

<h6>Topics:</h6>
<ul>
    <li>PEB walking: resolving kernel32.dll base address at runtime</li>
    <li>Export table parsing: finding function addresses by hash (GetProcAddress equivalent)</li>
    <li>Position-independent code (PIC) — no hardcoded addresses</li>
    <li>Null-byte avoidance and bad character constraints</li>
    <li>Writing a reverse shell from scratch</li>
    <li>Writing a dropper/stager from scratch</li>
    <li>Writing an add-user-to-admin payload from scratch</li>
    <li>Custom encoder/decoder stubs: XOR encoding to evade bad character filters</li>
    <li>Alphanumeric and Unicode shellcode constraints</li>
</ul>

<h6>Key Win32 APIs to Know Cold:</h6>
<ul>
    <li><b>LoadLibraryA</b> — load a DLL (e.g., urlmon.dll) at runtime</li>
    <li><b>GetProcAddress</b> — resolve function addresses from loaded DLLs</li>
    <li><b>URLDownloadToFileA</b> — download a file from a URL to a local path</li>
    <li><b>WinExec / CreateProcessA</b> — execute a local file</li>
    <li><b>ExitProcess</b> — clean exit</li>
    <li>Understand the <b>stdcall</b> convention: arguments pushed right-to-left, callee cleans the stack</li>
</ul>

<h6>Resources:</h6>
<ul>
    <li>The Shellcoder's Handbook — (shellcode development chapters)</li>
    <li><a href="https://www.corelan.be/index.php/2010/11/07/exploit-writing-tutorial-part-9-writing-unicode-exploits/">Corelan Part 9 — Unicode Exploitation</a></li>
    <li><a href="https://github.com/epi052/osed-scripts">epi052/osed-scripts</a> — study the automation approach, then replicate by hand</li>
    <li><a href="https://www.hick.org/code/skape/papers/">Skape's Shellcode Papers</a></li>
    <li><a href="https://www.pentesteracademy.com/course?id=3">SLAE 32 (SecurityTube Linux Assembly Expert)</a> — Linux-focused but teaches the shellcoding mindset</li>
</ul>

<br />
<h3>Phase 5: DEP Bypass with ROP Chains (3–4 weeks)</h3>
<b>Goal: Bypass DEP by constructing ROP chains. The course teaches VirtualAlloc — learn it for understanding, then focus heavily on VirtualProtect and WriteProcessMemory as they are more versatile and cover more real-world scenarios.</b>

<h6>Topics:</h6>
<ul>
    <li>DEP and NX: what they prevent and what they don't</li>
    <li>Return-Oriented Programming: concept, gadget types, chaining</li>
    <li>Stack pivoting: controlling ESP to point to your ROP chain</li>
    <li><b>VirtualAlloc ROP chain</b> — learn for understanding (course method)
        <ul>
            <li>Allocates new RWX memory, copies shellcode there, jumps to it</li>
            <li>Arguments: lpAddress, dwSize, flAllocationType (0x1000 = MEM_COMMIT), flProtect (0x40 = PAGE_EXECUTE_READWRITE)</li>
        </ul>
    </li>
    <li><b>VirtualProtect ROP chain</b> — drill this
        <ul>
            <li>Changes protection of existing memory region to RWX</li>
            <li>Arguments: lpAddress, dwSize, flNewProtect (0x40), lpflOldProtect (writable address)</li>
            <li>Shellcode stays in place, you just make it executable</li>
        </ul>
    </li>
    <li><b>WriteProcessMemory ROP chain</b> — drill this
        <ul>
            <li>Copies shellcode to a code cave in an executable region</li>
            <li>Arguments: hProcess (-1 = current process pseudo-handle), lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten</li>
            <li>Useful when you cannot change memory protections</li>
        </ul>
    </li>
    <li>Gadget discovery: IDA manual search, ROPgadget, rp++</li>
    <li>Handling bad characters in ROP chains (encoding gadget addresses)</li>
    <li>Pushad technique for setting up API arguments</li>
</ul>

<h6>Resources:</h6>
<ul>
    <li>Practical Reverse Engineering — Bruce Dang (ROP chapters)</li>
    <li><a href="https://ropemporium.com/">ROP Emporium</a> (work through all challenges)</li>
    <li><a href="https://www.corelan.be/index.php/2010/06/27/exploit-writing-tutorial-part-8-win32-rop/">Corelan — ROP Exploitation Series (Part 8+)</a></li>
    <li><a href="https://github.com/ForsakenSystems/.github/blob/main/content/lost-and-found/expl/skel.md">ForsakenSystems — DEP Bypass Skeleton Templates</a></li>
    <li><a href="https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/debugger-commands">WinDbg Commands Reference</a></li>
</ul>

<br />
<h3>Phase 6: ASLR Bypass (2–3 weeks)</h3>
<b>Goal: Understand ASLR and bypass it using non-ASLR modules and info leaks.</b>

<h6>Topics:</h6>
<ul>
    <li>What ASLR randomizes: stack, heap, module base addresses</li>
    <li>Identifying ASLR-enabled vs. non-ASLR modules (lm in WinDbg)</li>
    <li>Partial ASLR bypass: using non-ASLR modules</li>
    <li>Constructing ROP chains from non-ASLR module gadgets</li>
    <li>Information leaks via format strings (bridge to Phase 7)</li>
</ul>

<h6>Resources:</h6>
<ul>
    <li>Practical Reverse Engineering — Ch. 7 (ASLR internals)</li>
    <li><a href="https://www.corelan.be/index.php/2009/10/18/exploit-writing-tutorial-part-5-bypassing-aslr/">Corelan — ASLR Explained & Bypass</a></li>
    <li>Windows Internals Part 1 — Image loading and memory layout sections</li>
</ul>

<br />
<h3>Phase 7: Format String Specifier Attacks (2–3 weeks)</h3>
<b>Goal: Exploit format string vulnerabilities to build read and write primitives. This is a standalone EXP-301 topic — not a subtopic.</b>

<h6>Topics:</h6>
<ul>
    <li>Format string basics: %x for reading stack, %n for writing to memory</li>
    <li>Building a read primitive: leaking stack values, module base addresses (ASLR bypass via info leak)</li>
    <li>Building a write primitive: overwriting function pointers, return addresses</li>
    <li>Direct parameter access (%N$x, %N$n) for precise targeting</li>
    <li>Combining format string leaks with ROP chains for full exploitation</li>
</ul>

<h6>Resources:</h6>
<ul>
    <li>Hacking: The Art of Exploitation, 2nd Ed — Jon Erickson (format strings chapter)</li>
    <li><a href="https://insecure.org/stf/format-string.txt">Format String Vulnerabilities — Aleph One</a></li>
    <li><a href="https://www.fuzzysecurity.com/tutorials/expDev/7.html">FuzzySecurity — Stack Smashing 0x07</a></li>
    <li><a href="https://github.com/RPISEC/MBE">Modern Binary Exploitation (RPISEC)</a></li>
    <li><a href="https://ropemporium.com/">ROP Emporium — 'write4' and 'badchars' challenges</a></li>
</ul>

<br />
<h3>Phase 8: Full Exploit Chains & Practice (4–6 weeks)</h3>
<b>Goal: Combine everything into end-to-end exploits. RE in IDA → crash triage in WinDbg → exploit development → shell. Practice under time pressure and document as you go.</b>

<h6>Topics:</h6>
<ul>
    <li>Full chain: Crash → root cause analysis → offset calculation → SEH/stack overflow → DEP bypass (ROP) → shellcode injection → execution</li>
    <li>Combining ASLR bypass (non-ASLR module or format string leak) with DEP bypass (ROP) with custom shellcode</li>
    <li>Writing exploit automation scripts in Python (socket connections, struct packing, payload assembly)</li>
    <li>Report writing: documenting every step with screenshots</li>
</ul>

<h6>Practice Targets:</h6>
<ul>
    <li>Vulnserver (multiple commands test different techniques)</li>
    <li>FreeFloat FTP</li>
    <li>Any vulnerable binary with DEP enabled + a non-ASLR module</li>
    <li><b>EXP-301 Challenge Labs (3 labs)</b> — treat as dress rehearsals</li>
</ul>

<h6>Resources:</h6>
<ul>
    <li>The IDA Pro Book — Chris Eagle (full analysis section)</li>
    <li><a href="https://www.fuzzysecurity.com/tutorials.html">FuzzySecurity — Exploit Dev Tutorials</a></li>
    <li><a href="https://github.com/epi052/osed-scripts">epi052/osed-scripts</a></li>
</ul>

<br />
<h3>Phase 9 (Bonus): x64 Shellcode & VM Escape (Post-Pass Study)</h3>
<b>Goal: Extend into x64 exploitation and hypervisor escape techniques. These are my additions beyond the core EXP-301 curriculum — practical skills for a world that has largely moved past 32-bit.</b>

<h6>Topics:</h6>
<ul>
    <li>x64 calling convention differences (RCX, RDX, R8, R9 for first 4 args; shadow space)</li>
    <li>x64 shellcode development</li>
    <li>VM escape concepts and hypervisor attack surfaces</li>
</ul>

<h6>Resources:</h6>
<ul>
    <li>TBD</li>
</ul>


<br />
<h2>Checklist</h2>

<ol>
    <li><h5>Pre-Phase: C & Assembly Fundamentals</h5></li>
    <b>Goal: Get comfortable reading C and x86 assembly. Reading C is an explicit EXP-301 prerequisite — when you're staring at disassembly of a strcpy overflow, you need to understand what the C code was doing before the compiler got to it.</b>
    <ul>
        <li>C Fundamentals</li>
        &#x274F;&nbsp;&nbsp;Complete core C exercises: pointers, arrays, strings, structs, malloc/free<br />
        &#x274F;&nbsp;&nbsp;Write a deliberately vulnerable C program (e.g., unchecked strcpy into a fixed buffer)<br />
        &#x274F;&nbsp;&nbsp;Compile it, crash it, examine the crash in WinDbg<br />
        &#x274F;&nbsp;&nbsp;Read K&R or K.N. King (at least through pointers and memory chapters)<br />
        &#x274F;&nbsp;&nbsp;Complete exercises on <a href="https://www.learn-c.org/">Learn-C</a><br />
        <li>Assembly</li>
        &#x274F;&nbsp;&nbsp;Complete <a href="https://opensecuritytraining.info/IntroX86.html">OpenSecurityTraining — Intro to x86</a><br />
        &#x274F;&nbsp;&nbsp;TCM Security Assembly course (if available)<br />
        &#x274F;&nbsp;&nbsp;Read Practical Reverse Engineering Ch. 1 (Registers, Stack, Calling Conventions)<br />
        &#x274F;&nbsp;&nbsp;Solve 3 exercises from Protostar Stack (stack0–stack2)<br />
        &#x274F;&nbsp;&nbsp;Write 5 small assembly programs (loops, function calls, string operations) and step through them in WinDbg<br />
    </ul>
    <li><h5>Phase 0: Foundation & Lab Setup</h5></li>
    <b>Goal: Establish core knowledge of Windows internals, PE format, and tool fluency.</b>
    <ul>
        <li>System & Tools Setup</li>
        &#x274F;&nbsp;&nbsp;Install Kali or Windows lab VMs (Windows 7/10 x86)<br />
        &#x274F;&nbsp;&nbsp;Install WinDbg Preview<br />
        &#x274F;&nbsp;&nbsp;Install IDA Free<br />
        &#x274F;&nbsp;&nbsp;Install PE-bear for PE header inspection<br />
        &#x274F;&nbsp;&nbsp;Set up Python 3 exploit dev environment with pwntools and struct<br />
        <li>PE Format & Memory</li>
        &#x274F;&nbsp;&nbsp;Read <a href="https://learn.microsoft.com/en-us/windows/win32/debug/pe-format">Microsoft PE Format Specification</a><br />
        &#x274F;&nbsp;&nbsp;Read <a href="https://markpelf.com/1628/pe-format-illustrated-part-1/">Mark Pelf — PE Format Illustrated</a><br />
        &#x274F;&nbsp;&nbsp;Inspect PE headers with PE-bear on calc.exe and notepad.exe<br />
        &#x274F;&nbsp;&nbsp;Trace IAT in IDA — locate VirtualAlloc, VirtualProtect, WriteProcessMemory, ExitProcess<br />
        &#x274F;&nbsp;&nbsp;Use WinDbg: lm (list modules), !address (memory layout), !peb (PEB structure)<br />
        <li>Windows Internals</li>
        &#x274F;&nbsp;&nbsp;Read Windows Internals Part 1, Ch. 1–4<br />
        &#x274F;&nbsp;&nbsp;Understand PEB structure and how modules are linked (PEB → PEB_LDR_DATA → InMemoryOrderModuleList)<br />
        &#x274F;&nbsp;&nbsp;Trace a VirtualAlloc call from user mode to kernel in WinDbg<br />
    </ul>
    <li><h5>Phase 1: Stack Overflows & SEH</h5></li>
    <b>Goal: Master vanilla and SEH-based buffer overflows.</b>
    <ul>
        <li>Vanilla Stack Overflow</li>
        &#x274F;&nbsp;&nbsp;Reproduce vanilla buffer overflow (gain EIP control)<br />
        &#x274F;&nbsp;&nbsp;Calculate exact offset using cyclic patterns (msf-pattern_create / msf-pattern_offset)<br />
        &#x274F;&nbsp;&nbsp;Identify bad characters using memory dump comparison in WinDbg<br />
        &#x274F;&nbsp;&nbsp;Analyze crash state: registers, stack, !exploitable<br />
        &#x274F;&nbsp;&nbsp;Redirect execution to shellcode via JMP ESP or similar<br />
        <li>SEH Overflows</li>
        &#x274F;&nbsp;&nbsp;Understand SEH chain structure (nSEH → SEH handler)<br />
        &#x274F;&nbsp;&nbsp;Trigger and overwrite SEH structures (!exchain in WinDbg)<br />
        &#x274F;&nbsp;&nbsp;Use POP-POP-RET to redirect to nSEH<br />
        &#x274F;&nbsp;&nbsp;Short jump from nSEH to shellcode<br />
        &#x274F;&nbsp;&nbsp;Combine SEH overwrite with egghunter when buffer is small<br />
    </ul>
    <li><h5>Phase 2: Egghunters</h5></li>
    <b>Goal: Overcome limited buffer space by searching memory for your payload.</b>
    <ul>
        <li>Study</li>
        &#x274F;&nbsp;&nbsp;<a href="https://www.corelan.be/index.php/2009/09/28/writing-egg-hunters-with-buffer-overflows/">Corelan — Writing Egghunters</a><br />
        &#x274F;&nbsp;&nbsp;<a href="https://www.fuzzysecurity.com/tutorials/expDev/8.html">FuzzySecurity — Stack Smashing 0x08</a><br />
        &#x274F;&nbsp;&nbsp;<a href="https://www.skullsecurity.org/blog/2010/writing-egg-hunters">SkullSecurity — Egghunter Explanation</a><br />
        <li>Practice</li>
        &#x274F;&nbsp;&nbsp;Write an egghunter from scratch using NtAccessCheckAndAuditAlarm syscall<br />
        &#x274F;&nbsp;&nbsp;Deploy egghunter + staged shellcode against a SEH overflow with limited buffer<br />
        &#x274F;&nbsp;&nbsp;Test with different egg tags and verify memory scanning in WinDbg<br />
    </ul>
    <li><h5>Phase 3: IDA Reverse Engineering</h5></li>
    <b>Goal: Build RE fluency — finding the vulnerability is half the battle.</b>
    <ul>
        <li>Core IDA Skills</li>
        &#x274F;&nbsp;&nbsp;Read The IDA Pro Book Ch. 1–3<br />
        &#x274F;&nbsp;&nbsp;Navigate: Functions, Strings, Imports, Exports windows<br />
        &#x274F;&nbsp;&nbsp;Master cross-references (Xrefs): find all callers/callees of a function<br />
        &#x274F;&nbsp;&nbsp;Trace data flow: input buffer → vulnerable copy function<br />
        &#x274F;&nbsp;&nbsp;Identify unsafe functions: strcpy, sprintf, memcpy with unchecked sizes<br />
        <li>Crackmes</li>
        &#x274F;&nbsp;&nbsp;Complete 5+ crackmes from <a href="https://crackmes.one/">crackmes.one</a> (start easy, work up)<br />
        &#x274F;&nbsp;&nbsp;Trace program logic in IDA with no source code — this is the muscle you need<br />
        <li>Practical RE</li>
        &#x274F;&nbsp;&nbsp;RE a simple vulnerable binary: find the overflow in IDA, confirm in WinDbg<br />
        &#x274F;&nbsp;&nbsp;RE a network-facing binary: identify the protocol parsing, find the input vector<br />
        &#x274F;&nbsp;&nbsp;Practice on 3+ binaries from VulnBins or ExploitDB without looking at existing writeups first<br />
    </ul>
    <li><h5>Phase 4: Custom Shellcode from Scratch</h5></li>
    <b>Goal: Write custom shellcode and build a variety of payloads to develop well-rounded shellcoding ability.</b>
    <ul>
        <li>Foundations</li>
        &#x274F;&nbsp;&nbsp;Understand PEB walking to find kernel32.dll base address<br />
        &#x274F;&nbsp;&nbsp;Write a function hash resolver: parse export table to find APIs by hash<br />
        &#x274F;&nbsp;&nbsp;Write a simple "call WinExec('calc.exe')" shellcode from scratch<br />
        &#x274F;&nbsp;&nbsp;Eliminate null bytes from your shellcode<br />
        &#x274F;&nbsp;&nbsp;Verify position independence: shellcode must work at any memory address<br />
        <li>Reverse TCP Shellcode</li>
        &#x274F;&nbsp;&nbsp;Resolve LoadLibraryA and GetProcAddress from kernel32.dll<br />
        &#x274F;&nbsp;&nbsp;Call LoadLibraryA("ws2_32.dll") to load Winsock<br />
        &#x274F;&nbsp;&nbsp;Resolve and call WSAStartup to initialize Winsock<br />
        &#x274F;&nbsp;&nbsp;Resolve and call WSASocketA to create a TCP socket<br />
        &#x274F;&nbsp;&nbsp;Build a sockaddr_in structure on the stack (IP, port, AF_INET)<br />
        &#x274F;&nbsp;&nbsp;Resolve and call connect to reach the attack machine<br />
        &#x274F;&nbsp;&nbsp;Redirect stdin/stdout/stderr to the socket via STARTUPINFO<br />
        &#x274F;&nbsp;&nbsp;Call CreateProcessA to spawn cmd.exe over the connection<br />
        &#x274F;&nbsp;&nbsp;Call ExitProcess(0) for clean exit<br />
        <li>Dropper/Stager Shellcode</li>
        &#x274F;&nbsp;&nbsp;Resolve LoadLibraryA and GetProcAddress from kernel32.dll<br />
        &#x274F;&nbsp;&nbsp;Call LoadLibraryA("urlmon.dll") to load the URL download library<br />
        &#x274F;&nbsp;&nbsp;Resolve URLDownloadToFileA from urlmon.dll<br />
        &#x274F;&nbsp;&nbsp;Construct the destination file path on the stack (Desktop path + filename)<br />
        &#x274F;&nbsp;&nbsp;Call URLDownloadToFileA(NULL, url, dest_path, 0, NULL) to download the .exe<br />
        &#x274F;&nbsp;&nbsp;Call WinExec(dest_path, SW_SHOW) or CreateProcessA to execute the downloaded file<br />
        &#x274F;&nbsp;&nbsp;Call ExitProcess(0) for clean exit<br />
        <li>Add Local Admin User Shellcode</li>
        &#x274F;&nbsp;&nbsp;Resolve LoadLibraryA and GetProcAddress from kernel32.dll<br />
        &#x274F;&nbsp;&nbsp;Call LoadLibraryA("netapi32.dll") to load the Net API library<br />
        &#x274F;&nbsp;&nbsp;Resolve NetUserAdd from netapi32.dll<br />
        &#x274F;&nbsp;&nbsp;Build a USER_INFO_1 structure on the stack (username, password, privilege level, flags)<br />
        &#x274F;&nbsp;&nbsp;Call NetUserAdd(NULL, 1, &userInfo, NULL) to create the local user<br />
        &#x274F;&nbsp;&nbsp;Resolve NetLocalGroupAddMembers from netapi32.dll<br />
        &#x274F;&nbsp;&nbsp;Build a LOCALGROUP_MEMBERS_INFO_3 structure on the stack (username pointer)<br />
        &#x274F;&nbsp;&nbsp;Construct the group name string "Administrators" on the stack<br />
        &#x274F;&nbsp;&nbsp;Call NetLocalGroupAddMembers(NULL, "Administrators", 3, &memberInfo, 1) to add the user to local admins<br />
        &#x274F;&nbsp;&nbsp;Call ExitProcess(0) for clean exit<br />
        <li>Shellcode Encoding</li>
        &#x274F;&nbsp;&nbsp;Write a XOR encoder in Python and a decoder stub in assembly<br />
        &#x274F;&nbsp;&nbsp;Handle bad character constraints by encoding shellcode<br />
        &#x274F;&nbsp;&nbsp;Create alphanumeric payloads using known-safe instruction encodings<br />
        &#x274F;&nbsp;&nbsp;Reproduce Corelan ASCII/Unicode SEH exploit<br />
        <li>Extra Shellcode Practice</li>
        &#x274F;&nbsp;&nbsp;Write a bind shell from scratch<br />
        &#x274F;&nbsp;&nbsp;Write shellcode that works under Unicode constraints<br />
    </ul>
    <li><h5>Phase 5: DEP Bypass with ROP Chains</h5></li>
    <b>Goal: Build ROP chains using all three DEP bypass APIs. Start with reviewing and understanding VirtualAlloc from the course material. Then focus on VirtualProtect and WriteProcessMemory for versatility.</b>
    <ul>
        <li>DEP Foundations</li>
        &#x274F;&nbsp;&nbsp;Enable DEP on test app, verify shellcode crash in WinDbg (!address, !exploitable)<br />
        &#x274F;&nbsp;&nbsp;Read Practical Reverse Engineering Ch. 2 (Windows memory management)<br />
        &#x274F;&nbsp;&nbsp;Understand ROP concept: chaining small instruction sequences ending in RET<br />
        <li>VirtualAlloc ROP Chain (Course Method — Learn, Don't Drill)</li>
        &#x274F;&nbsp;&nbsp;Build a VirtualAlloc ROP chain following Corelan Part 8<br />
        &#x274F;&nbsp;&nbsp;Understand the arguments: lpAddress, dwSize, flAllocationType, flProtect<br />
        <li>VirtualProtect ROP Chain (Drill This)</li>
        &#x274F;&nbsp;&nbsp;Build a VirtualProtect ROP chain from scratch using gadgets from a non-ASLR DLL<br />
        &#x274F;&nbsp;&nbsp;Arguments: lpAddress (shellcode addr), dwSize (0x400+), flNewProtect (0x40 = RWX), lpflOldProtect (writable addr)<br />
        &#x274F;&nbsp;&nbsp;Practice the pushad technique for setting up arguments on the stack<br />
        &#x274F;&nbsp;&nbsp;Build VirtualProtect chains against 3+ different binaries with different gadget sets<br />
        <li>WriteProcessMemory ROP Chain (Drill This)</li>
        &#x274F;&nbsp;&nbsp;Build a WriteProcessMemory ROP chain from scratch<br />
        &#x274F;&nbsp;&nbsp;Arguments: hProcess (0xFFFFFFFF = GetCurrentProcess pseudo-handle), lpBaseAddress (code cave), lpBuffer (shellcode location), nSize, lpNumberOfBytesWritten (writable addr)<br />
        &#x274F;&nbsp;&nbsp;Find code caves in target binaries for shellcode destination<br />
        &#x274F;&nbsp;&nbsp;Build WriteProcessMemory chains against 3+ different binaries<br />
        <li>ROP Mastery</li>
        &#x274F;&nbsp;&nbsp;Complete all <a href="https://ropemporium.com/">ROP Emporium</a> challenges (x86)<br />
        &#x274F;&nbsp;&nbsp;Use ROPgadget and rp++ for automated gadget discovery, but also find gadgets manually in IDA<br />
        &#x274F;&nbsp;&nbsp;Practice stack pivot techniques: XCHG EAX,ESP; MOV ESP,EAX; etc.<br />
        &#x274F;&nbsp;&nbsp;Handle bad characters in gadget addresses (find alternative gadgets or use encoding)<br />
        &#x274F;&nbsp;&nbsp;<a href="https://www.hick.org/code/skape/papers/">Skape's Shellcode Paper (Advanced)</a><br />
    </ul>
    <li><h5>Phase 6: Understanding ASLR</h5></li>
    <b>Goal: Identify and exploit non-ASLR modules; understand info leak techniques.</b>
    <ul>
        <li>ASLR Detection</li>
        &#x274F;&nbsp;&nbsp;Use lm in WinDbg to list all loaded modules and their base addresses<br />
        &#x274F;&nbsp;&nbsp;Use narly WinDbg extension to check for security headers<br />
        &#x274F;&nbsp;&nbsp;Use !address to view full memory layout and ASLR status<br />
        <li>Partial ASLR Bypass</li>
        &#x274F;&nbsp;&nbsp;Identify static modules loaded at fixed addresses<br />
        &#x274F;&nbsp;&nbsp;Read <a href="https://www.corelan.be/index.php/2009/10/18/exploit-writing-tutorial-part-5-bypassing-aslr/">Corelan — ASLR Tutorial</a><br />
    </ul>
    <li><h5>Phase 7: Format String Specifier Attacks</h5></li>
    <b>Goal: Use format string vulnerabilities for information leaks (ASLR bypass) and arbitrary writes.</b>
    <ul>
        <li>Reading</li>
        &#x274F;&nbsp;&nbsp;Hacking: The Art of Exploitation, 2nd Ed — Format Strings chapter<br />
        &#x274F;&nbsp;&nbsp;<a href="https://insecure.org/stf/format-string.txt">Format String Vulnerabilities — Aleph One</a><br />
        &#x274F;&nbsp;&nbsp;<a href="https://github.com/RPISEC/MBE">Modern Binary Exploitation (RPISEC)</a> — format string labs<br />
        <li>Practice</li>
        &#x274F;&nbsp;&nbsp;Leak stack values using %x and %p format specifiers<br />
        &#x274F;&nbsp;&nbsp;Leak a module base address to bypass ASLR<br />
        &#x274F;&nbsp;&nbsp;Write to an arbitrary address using %n with direct parameter access<br />
        &#x274F;&nbsp;&nbsp;Overwrite a function pointer to redirect execution<br />
        &#x274F;&nbsp;&nbsp;Combine a format string info leak with a ROP chain for full DEP+ASLR bypass<br />
        &#x274F;&nbsp;&nbsp;<a href="https://www.fuzzysecurity.com/tutorials/expDev/7.html">FuzzySecurity — Stack Smashing 0x07</a><br />
    </ul>
    <li><h5>Phase 8: Full Exploit Chains & Practice</h5></li>
    <b>Goal: Put it all together. Pick binaries you haven't seen before, RE them in IDA, build full exploits under time pressure. Document everything as you go.</b>
    <ul>
        <li>Skill Drills</li>
        &#x274F;&nbsp;&nbsp;Pick a vulnerable binary — RE it in IDA, find the bug, build a working exploit<br />
        &#x274F;&nbsp;&nbsp;Build a VirtualProtect ROP chain against a new binary with DEP enabled<br />
        &#x274F;&nbsp;&nbsp;Build a WriteProcessMemory ROP chain against a different binary<br />
        &#x274F;&nbsp;&nbsp;Write a complete dropper shellcode from scratch without referencing notes<br />
        <li>End-to-End Exploits (2+ targets)</li>
        &#x274F;&nbsp;&nbsp;Target 1: Vulnserver — Full chain with multiple commands<br />
        &#x274F;&nbsp;&nbsp;Target 2: FreeFloat FTP or similar — Full chain from fuzzing to shell<br />
        &#x274F;&nbsp;&nbsp;Build each exploit with: crash analysis → offset → ROP/SEH → shellcode → reverse shell<br />
        <li>Tooling & Reporting</li>
        &#x274F;&nbsp;&nbsp;Write custom boofuzz fuzzer for a target app<br />
        &#x274F;&nbsp;&nbsp;Build a Python exploit template with modular sections (connection, overflow, ROP, shellcode)<br />
        &#x274F;&nbsp;&nbsp;Write a bad character detection script using WinDbg memory dumps<br />
        &#x274F;&nbsp;&nbsp;Practice report writing: screenshot every key step, document your methodology<br />
        <li>EXP-301 Challenge Labs</li>
        &#x274F;&nbsp;&nbsp;Complete Challenge Lab 1<br />
        &#x274F;&nbsp;&nbsp;Complete Challenge Lab 2<br />
        &#x274F;&nbsp;&nbsp;Complete Challenge Lab 3<br />
        &#x274F;&nbsp;&nbsp;Re-do any lab where you needed hints — you should be able to solo them<br />
    </ul>
</ol>

<br />
<h2>PE Format Study Plan</h2>
<ol>
    <li><h5>Microsoft's Official PE Specification</h5></li>
    <ul>
        <li>Definitions of headers, sections, flags, and load-time behavior</li>
        <li><a href="https://learn.microsoft.com/en-us/windows/win32/debug/pe-format">Learn Microsoft — PE Format</a></li>
    </ul>
    <li><h5>PE Format Illustrated — Mark Pelf (2-part article)</h5></li>
    <ul>
        <li><a href="https://markpelf.com/1628/pe-format-illustrated-part-1">Illustrated PE Format</a></li>
    </ul>
    <li><h5>Deep Dive YouTube Videos</h5></li>
    <ul>
        <li><a href="https://www.youtube.com/watch?v=CM2Tfvxrs74">Getting Started</a></li>
        <li><a href="https://www.youtube.com/watch?v=pNXmrYecJeA">Deep Inside</a></li>
    </ul>
    <li><h5>Blogs & Tutorials</h5></li>
    <ul>
        <li><a href="https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2">Tech Zealots</a></li>
        <li><a href="https://blog.filovirid.com/page/Windows-Portable-Executable-Files-Structure">Inside PE Structure</a></li>
    </ul>
    <li><h5>GitHub "PE101-v1" PDF</h5></li>
    <ul>
        <li><a href="https://github.com/ellroch/reverse-engineering-and-malware-analysis/blob/main/PE101-v1.pdf">PE101-v1</a></li>
    </ul>
</ol>

<br />
<h2>Exam Day Strategy</h2>

<h4>Before the Exam</h4>
<ul>
    <li>Have your scripts, skeletons, and templates ready to go</li>
    <li>Have a cheat sheet of WinDbg commands, IDA shortcuts, and Win32 API signatures</li>
    <li>Test your VPN setup and tooling in advance</li>
    <li>Sleep because exhaustion won't help you</li>
</ul>

<h4>During the Exam</h4>
<ul>
    <li><b>Time boxing:</b> If stuck for 2+ hours on one problem, switch to another. Fresh eyes solve problems.</li>
    <li><b>Breaks:</b> Every 2 hours, take a 10–15 minute break. Walk around, eat, hydrate. Fatigue kills more attempts than lack of knowledge.</li>
    <li><b>Document as you go:</b> Screenshot every significant step. Take notes on what you tried and why. You will NOT remember details after a long exam session.</li>
    <li><b>Shellcode tip:</b> Follow the course on how to test your shellcode as you go instead of waiting to the end to find out it doesn't work.</li>
    <li><b>ROP tip:</b> Don't tunnel vision into a single WinAPI.  Have a workbench of WinAPIs just in case you need to pivot.</li>
</ul>

<h4>The Report</h4>
<ul>
    <li>Follow the <a href="https://help.offsec.com/hc/en-us/articles/360052977212">OSED Exam Guide</a> report format exactly</li>
    <li>Every step must be reproducible from your report</li>
    <li>Include: proof screenshots, full exploit code (commented), step-by-step methodology</li>
    <li>Include: raw `.py` code files (one per assignment)</li>
    <li>Submit as .7z with the required naming convention — check the guide</li>
</ul>

<br />
<h3>Study</h3>
Just getting started.  Not much to report yet.

<br />
<h3>Extra</h3>
<a href="https://github.com/nop-tech/OSED">https://github.com/nop-tech/OSED</a><br />
<a href="https://github.com/Gabb4r/osed">https://github.com/Gabb4r/osed</a><br />
<a href="https://github.com/r0r0x-xx/OSED-Pre">https://github.com/r0r0x-xx/OSED-Pre</a><br />
<a href="https://github.com/epi052/osed-scripts">https://github.com/epi052/osed-scripts</a><br />
<a href="https://github.com/CyberSecurityUP/OSCE3-Complete-Guide">https://github.com/CyberSecurityUP/OSCE3-Complete-Guide</a><br />
<a href="https://github.com/ForsakenSystems/.github/blob/main/content/lost-and-found/expl/skel.md">https://github.com/ForsakenSystems/.github/blob/main/content/lost-and-found/expl/skel.md</a><br />

<br />
<h3>References:</h3>
<a href="https://claude.ai">https://claude.ai</a><br />
<a href="https://chatgpt.com/">https://chatgpt.com/</a><br />