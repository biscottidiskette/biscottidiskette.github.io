---
layout: page
title: OSED Study
description: A study journey for the OSED.
img: 
importance: 2
category: Personal
subcategory: red
related_publications: false
---

<h2>Introduction</h2>
So, about two years ago, I took the Offensive Security Exploit Developer (OSED).  I unfortunately failed the exam at that time.  Discouraged, I shelved it at the time.  Well, I was playing with KaliGPT and decided to ask it for help.  I decided to ask for a curriculum and checklist and see what it would develop for me.  I didn't know where to save it to keep me honest so my portolio projects section will have to do.

<br />
<h2>Links</h2>
<a href="https://www.offsec.com/courses/exp-301/">Offsec OSED Link</a><br />
<a href="https://github.com/biscottidiskette/osed">https://github.com/biscottidiskette/osed</a>

<br />
<h2>Process</h2>

<h3>Resources</h3>
<ul>
    <li><i>Practical Reverse Engineering</i> by Bruce Dang</li>
    <li><i>Windows Internals, Part 1</i> by Mark Russinovich</li>
    <li><i>The IDA Pro Book</i> by Chris Eagle</li>
    <li><i>The Shellcoder's Handbook</i> by Jack Koziol</li>
    <li><a href="https://opensecuritytraining.info/IntroX86.html">OpenSecurityTraining – Intro to x86</a></li>
    <li><a href="https://www.corelan.be/index.php/articles/">Corelan Exploit Writing</a></li>
    <li><a href="https://www.fuzzysecurity.com/tutorials.html">FuzzySecurity – Exploit Dev Tutorials</a></li>
    <li><a href="https://ropemporium.com/">ROP Emporium</a></li>
    <li><a href="https://www.learn-c.org/">Learn-C</a></li>
    <li><a href="https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools">Microsoft Learn – WinDbg Preview Guide</a></li>
    <li><a href="https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/debugger-commands">WinDbg Commands Reference</a></li>
    <li><a href="https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN">LiveOverflow – Stack Overflow & Exploitation</a></li>
</ul>

<br />
<h3>Overall Path</h3>
<ol>
    <li><h5>Phase 0: Foundation Cleanup (1–2 weeks)</h5></li>
        <h6>Topics:</h6>
            <ul>
                <li>x86 Assembly (focus on 32-bit)</li>
                <li>Calling conventions and stack layout</li>
                <li>PE file format basics</li>
                <li>Virtual memory and Windows API</li>
            </ul>
        <h6>Tools:</h6>
            <ul>
                <li>WinDbg Preview</li>
                <li>IDA Free or IDA Pro</li>
            </ul>
        <h6>Tasks:</h6>
            <ul>
                <li>Trace function prologs/epilogs in WinDbg</li>
                <li>Use IDA to identify entry points, strings, function calls</li>
                <li>Explore VirtualAlloc, LoadLibrary, etc., in memory</li>
            </ul>
        <h6>Resources:</h6>
            <ul>
                <li>Practical Reverse Engineering – Bruce Dang (Ch. 1–3)</li>
                <li>Windows Internals, Part 1 – Mark Russinovich (Ch. 1–4)</li>
                <li><a href="https://opensecuritytraining.info/IntroX86.html">OpenSecurityTraining – Intro to x86</a></li>
                <li>The IDA Pro Book – Chris Eagle (Ch. 1–3)</li>
                <li><a href="https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools">Microsoft Learn – WinDbg Preview Guide</a></li>
            </ul>
    <li><h5>Phase 1: Basic Exploitation + SEH (2–3 weeks)</h5></li>
        <h6>Topics:</h6>
            <ul>
                <li>Stack-based overflows (manual EIP control)</li>
                <li>SEH overwrite technique</li>
                <li>Bad character handling</li>
                <li>Egghunters</li>
            </ul>
        <h6>Tools:</h6>
            <ul>
                <li>WinDbg: Breakpoints, memory inspection, !exploitable</li>
                <li>IDA: String analysis, function mapping</li>
                <li>Python: Pattern generation & automation scripts</li>
            </ul>
        <h6>Tasks:</h6>
            <ul>
                <li>Fuzz Vulnserver, SLMail, etc.</li>
                <li>Manually find offsets using cyclic patterns</li>
                <li>Trigger and redirect execution via SEH overwrite</li>
            </ul>
        <h6>Resources:</h6>
            <ul>
                <li><a href="https://www.corelan.be/index.php/articles/">Corelan Exploit Writing Part 1–3 (Manual SEH)</a></li>
                <li>The Shellcoder's Handbook – Jack Koziol (Buffer overflow chapters)</li>
                <li><a href="https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN">LiveOverflow – Stack Overflow & Exploitation</a></li>
                <li><a href="https://www.fuzzysecurity.com/tutorials.html">FuzzySecurity – Exploit Dev Tutorials</a></li>
            </ul>
    <li><h5>Phase 2: DEP Bypass + ROP (3–4 weeks)</h5></li>
        <h6>Topics:</h6>
            <ul>
                <li>DEP and NX concepts</li>
                <li>ROP chain construction and validation</li>
                <li>VirtualAlloc and pivoting</li>
                <li>Gadget discovery and chaining</li>
            </ul>
        <h6>Tools:</h6>
            <ul>
                <li>WinDbg: Set breakpoints, analyze stack pivots</li>
                <li>IDA: Manual gadget identification and verification</li>
                <li>Python: ROP chain builder and encoder</li>
            </ul>
        <h6>Tasks:</h6>
            <ul>
                <li>Build ROP chains from IDA-only gadgets</li>
                <li>Validate stack behavior and shellcode allocation in WinDbg</li>
                <li>Deploy shellcode via controlled memory regions</li>
            </ul>
        <h6>Resources:</h6>
            <ul>
                <li>Practical Reverse Engineering – Bruce Dang (ROP chapters)</li>
                <li><a href="https://ropemporium.com/">ROP Emporium</a></li>
                <li><a href="https://www.corelan.be/index.php/2010/06/27/exploit-writing-tutorial-part-8-win32-rop/">Corelan – ROP Exploitation Series</a></li>
                <li><a href="https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/debugger-commands">WinDbg Commands Reference</a></li>
            </ul>
    <li><h5>Phase 3: ASLR Awareness & Partial Bypass (2–3 weeks)</h5></li>
        <h6>Topics:</h6>
            <ul>
                <li>What ASLR does (module randomization)</li>
                <li>How ASLR behaves with system vs. non-system modules</li>
                <li>Static vs. dynamic linking (ASLR implications)</li>
                <li>Partial ASLR bypass via non-ASLR modules (e.g., loaded DLLs)</li>
                <li>Return-to-non-ASLR (ret2lib) techniques</li>
            </ul>
        <h6>Tools:</h6>
            <ul>
                <li>WinDbg: Use !address, lm to inspect ASLR-enabled modules</li>
                <li>IDA: Analyze binary headers and imports for ASLR compliance</li>
                <li>procmon or PE-bear to inspect DLL loading behavior</li>
            </ul>
        <h6>Tasks:</h6>
            <ul>
                <li>Identify ASLR-enabled vs non-ASLR modules</li>
                <li>Build ROP chains using non-ASLR modules</li>
                <li>Patch binaries to toggle ASLR for practice</li>
                <li>Automate ASLR state analysis in WinDbg</li>
            </ul>
        <h6>Resources:</h6>
            <ul>
                <li>Practical Reverse Engineering – Ch. 7 (ASLR internals)</li>
                <li><a href="https://www.corelan.be/index.php/2009/10/18/exploit-writing-tutorial-part-5-bypassing-aslr/"></a>Corelan – ASLR Explained</li>
                <li>Windows Internals Part 1 – Section on image loading and memory layout</li>
            </ul>
    <li><h5>Phase 4: Complex Payloads & Constraints (3–4 weeks)</h5></li>
        <h6>Topics:</h6>
            <ul>
                <li>XOR and alphanumeric encoding</li>
                <li>Unicode shellcode techniques</li>
                <li>Staged payloads</li>
                <li>Heap spraying introduction</li>
            </ul>
        <h6>Tools:</h6>
            <ul>
                <li>IDA: Manual shellcode inspection & decoding</li>
                <li>WinDbg: Memory dump comparison and shellcode tracing</li>
                <li>Python: Custom shellcode encoders</li>
            </ul>
        <h6>Tasks:</h6>
            <ul>
                <li>Write XOR encoder with decoder stub</li>
                <li>Create alphanumeric payloads using known instructions</li>
                <li>Deliver staged shellcode through SEH with character constraints</li>
            </ul>
        <h6>Resources:</h6>
            <ul>
                <li>The Shellcoder's Handbook – (Shellcode development chapters)</li>
                <li><a href="https://www.corelan.be/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial/"></a>Corelan – Shellcode & Encoding</li>
            </ul>
    <li><h5>Phase 5: Full Exploit Chains & Simulation (4–6 weeks)</h5></li>
        <h6>Topics:</h6>
            <ul>
                <li>Crash → SEH → DEP bypass → Shellcode injection → Shell</li>
                <li>Unicode/ASCII-only ROP shellcode chains</li>
                <li>Manual analysis and patching in IDA</li>
            </ul>
        <h6>Tools:</h6>
            <ul>
                <li>IDA: Static reversing, API identification, gadget discovery</li>
                <li>WinDbg: Dynamic debugging, crash triage, shellcode tracing</li>
                <li>Python: Full exploit automation</li>
            </ul>
        <h6>Tasks:</h6>
            <ul>
                <li>Full exploit chain (including egghunter or encoder)</li>
                <li>Manual shellcode injection into allocated memory</li>
                <li>Develop automation script to validate exploit success</li>
            </ul>
        <h6>Resources:</h6>
            <ul>
                <li>The IDA Pro Book – Chris Eagle (full analysis section)</li>
                <li><a href="https://www.fuzzysecurity.com/tutorials.html">FuzzySecurity – OSED Exploit Tutorials</a></li>
            </ul>
</ol>

<br />
<h3>Check List</h3>
<ol>
    <li><h5>Pre-Phase: Assembly</h5></li>
    <b>Goal: Get an understanding of Assebmly</b>
        <ul>
            <li>Online Class</li>
            &#x274F;&nbsp;&nbsp;TCM Security Released a course on Assembly<br />
        </ul>
    <li><h5>Phase 0: Foundation & Setup</h5></li>
    <b>Goal: Establish core knowledge of x86, Windows internals, and core tools.</b>
        <ul>
            <li>System & Tools Setup</li>
            &#9989;&nbsp;&nbsp;Install Kali or Windows lab VMs (Windows XP, Win7 x86)<br />
            &#9989;&nbsp;&nbsp;Install WinDbg Preview from Microsoft Store<br />
            &#9989;&nbsp;&nbsp;Install IDA Free or Pro<br />
            <li>Assembly and OS Basics</li>
            &#x274F;&nbsp;&nbsp;Complete OpenSecurityTraining’s x86 Assembly Part 1 (<a href="https://opensecuritytraining.info/IntroX86.html">OST link</a>)<br />
            &#x274F;&nbsp;&nbsp;Read PRE Chapter 1 (Computer Architecture, Stack, Registers)<br />
            &#x274F;&nbsp;&nbsp;Solve 3 exercises from Protostar Stack (stack0–stack2)<br />
            <li>PE Format & Memory</li>
            &#x274F;&nbsp;&nbsp;Read <a href="https://markpelf.com/1628/pe-format-illustrated-part-1/">Mark Pelf's PE Format Illustrated</a><br />
            &#x274F;&nbsp;&nbsp;Inspect PE headers with PE-bear on calc.exe<br />
            &#x274F;&nbsp;&nbsp;Trace IAT in IDA, locate VirtualAlloc, ExitProcess<br />
        </ul>
    <li><h5>Phase 1: Basic Exploitation Plus SEH</h5></li>
    <b>Exploit stack-based and SEH-based buffer overflows.</b>
        <ul>
            <li>Vanilla BOF</li>
            &#x274F;&nbsp;&nbsp;Reproduce vanilla buffer overflow (EIP control)<br />
            &#x274F;&nbsp;&nbsp;Calculate exact offset with pattern generation<br />
            &#x274F;&nbsp;&nbsp;Identify bad characters<br />
            &#x274F;&nbsp;&nbsp;Analyze crashes and stack state in WinDbg<br />
            <li>SEH</li>
            &#x274F;&nbsp;&nbsp;Trigger and overwrite SEH structures<br />
            &#x274F;&nbsp;&nbsp;Use egghunters and SEH-based delivery with shellcode<br />
        </ul>
    <li><h5>Phase 2: Egghunter</h5></li>
    <b>Goal: Gain a better understanding of egghunting.</b>
        <ul>
            <li>Online Materials</li>
            &#9989;&nbsp;&nbsp;<a href="https://www.corelan.be/index.php/2009/09/28/writing-egg-hunters-with-buffer-overflows/">Corelan Tutorial: Writing Egghunters</a><br />
            &#9989;&nbsp;&nbsp;<a href="https://www.fuzzysecurity.com/tutorials/expDev/8.html">FuzzySecurity Stack Smashing 0x08</a><br />
            &#9989;&nbsp;&nbsp;<a href="https://www.skullsecurity.org/blog/2010/writing-egg-hunters">SkullSecurity Egghunter Explanation</a><br />
        </ul>
    <li><h5>Phase 3: DEP Bypass + ROP Chains</h5></li>
    <b>Goal: Bypass DEP using ROP and execute shellcode in allocated memory.</b>
        <ul>
            <li>DEP Mechanics</li>
            &#x274F;&nbsp;&nbsp;Enable DEP in test app, verify crash with WinDbg: !address, !exploitable<br />
            &#x274F;&nbsp;&nbsp;Read: PRE Chapter 2 – Windows Memory Management<br />
            &#x274F;&nbsp;&nbsp;Watch: <a href="https://www.corelan.be/index.php/2010/06/27/exploit-writing-tutorial-part-8-win32-rop-stackpivoting/">Corelan ROP Series Part 1</a><br />
            <li>ROP Chains</li>
            &#x274F;&nbsp;&nbsp;Build a ROP chain to call VirtualAlloc with correct arguments<br />
            &#x274F;&nbsp;&nbsp;Use ROPgadget or IDA to locate gadgets in non-ASLR DLL<br />
            &#x274F;&nbsp;&nbsp;Validate control of stack after pivot<br />
            &#x274F;&nbsp;&nbsp;Trigger execution of shellcode in newly allocated memory<br />
            &#x274F;&nbsp;&nbsp;<a href="https://www.pentesteracademy.com/course?id=3">SLAE 32 (SecurityTube Linux Assembly Expert)</a><br />
            &#x274F;&nbsp;&nbsp;<a href="https://www.hick.org/code/skape/papers/">Skape’s Shellcode Paper (Advanced)</a><br />
        </ul>
    <li><h5>Phase 4: ASLR Identification & Bypass</h5></li>
    <b>Goal: Learn how ASLR affects exploitation and bypass it using loaded modules.</b>
        <ul>
            <li>ASLR Detection</li>
            &#x274F;&nbsp;&nbsp;Use lm in WinDbg to list loaded modules and addresses<br />
            &#x274F;&nbsp;&nbsp;Use PE-bear to confirm ASLR flag (/DYNAMICBASE)<br />
            <li>Partial ASLR Bypass</li>
            &#x274F;&nbsp;&nbsp;Identify static modules (e.g., libeay32.dll) loaded with fixed addresses<br />
            &#x274F;&nbsp;&nbsp;Construct ROP chain using non-ASLR binary<br />
            &#x274F;&nbsp;&nbsp;Read: <a href="https://www.corelan.be/index.php/2009/10/18/exploit-writing-tutorial-part-5-bypassing-aslr/">Corelan ASLR Tutorial</a><br />
        </ul>
    <li><h5>Phase 5: Format String Vulnerability</h5></li>
    <b>Goal: Understand Format String vulnerabilies for ASLR</b>
        <ul>
            <li>General Information</li>
            &#x274F;&nbsp;&nbsp;Hacking: The Art of Exploitation, 2nd Edition by Jon Erckson (Chapter on Format Strings)<br />
            &#x274F;&nbsp;&nbsp;<a href="https://insecure.org/stf/format-string.txt">Format String Vulnerabilities – by Aleph One</a><br />
            &#x274F;&nbsp;&nbsp;<a href="https://github.com/RPISEC/MBE">Modern Binary Exploitation (RPISEC)</a><br />
            <li>Targeted Tutorials for ASLR Bypass</li>
            &#x274F;&nbsp;&nbsp;<a href="https://ioactive.com/pdfs/Format-String-Vulnerabilities.pdf">IOActive – Format String to ASLR Bypass</a><br />
            &#x274F;&nbsp;&nbsp;<a href="https://www.fuzzysecurity.com/tutorials/expDev/7.html">FuzzySecurity – Stack Smashing 0x07</a><br />
            &#x274F;&nbsp;&nbsp;<a href="https://sploitfun.wordpress.com/2015/01/28/heap-exploitation-in-detail-part-1/">Heap Exploitation – Info Leak via Format Bug</a><br />
            <li>Specific Techniques</li>
            &#x274F;&nbsp;&nbsp;<a href="https://www.qualys.com/2021/01/26/cve-2021-3156/heap-overflow-sudo.txt">Partial Pointer Leaks via Uninitialized Strings</a><br />
            &#x274F;&nbsp;&nbsp;<a href="https://ropemporium.com/">ROP Emporium – ‘write4’ or ‘badchars’ challenges</a><br />
        </ul>
    <li><h5>Phase 6: Payload Encoding & Constraints</h5></li>
    <b>Goal: Build payloads that bypass filtering: badchars, nulls, unicode, etc.</b>
        <ul>
            <li>Badchar Handling</li>
            &#x274F;&nbsp;&nbsp;Write badchar detection script using memory dump from WinDbg<br />
            &#x274F;&nbsp;&nbsp;Confirm which characters break shellcode execution<br />
            <li>Encoding & Unicode</li>
            &#x274F;&nbsp;&nbsp;Use msfvenom -e x86/shikata_ga_nai and test<br />
            &#x274F;&nbsp;&nbsp;Write XOR encoder/decoder in Python<br />
            &#x274F;&nbsp;&nbsp;Reproduce Corelan ASCII/Unicode SEH exploit:<br />
                <ul>
                    <li>Reference: <a href="https://www.corelan.be/index.php/2010/11/07/exploit-writing-tutorial-part-9-writing-unicode-exploits/">Corelan Part 9: Unicode Exploitation</a></li>
                </ul>
        </ul>
    <li><h5>Phase 7: Full Exploit Chains & Practice</h5></li>
    <b>Goal: Build from fuzzer to shell manually using everything learned.</b>
    <ul>
        <li>Fuzzing and Crash Triaging</li>
        &#x274F;&nbsp;&nbsp;Write custom boofuzz fuzzer for target app<br />
        &#x274F;&nbsp;&nbsp;Catch crash in WinDbg, analyze faulting instruction and memory state<br />
        <li>End-to-End Exploit</li>
        &#x274F;&nbsp;&nbsp;Pick 2 vulnerable binaries (e.g., Vulnserver + FreeFloat FTP)<br />
        &#x274F;&nbsp;&nbsp;Build exploit with:<br />
            <ul>
            <li>Fuzzer</li>
            <li>Crash detection</li>
            <li>Offset calculation</li>
            <li>ROP/SEH logic</li>
            <li>Shellcode</li>
            <li>Successful reverse shell</li>
            </ul>
    </ul>
</ol>

<br />
<h3>PE Format Study Plan</h3>
<ol>
    <li><h5>Microsoft’s Official PE Specification</h5></li>
    <ul>
        <li>Definitions of headers, sections, flags, and load-time behavior</li>
        <li><a href="https://learn.microsoft.com/en-us/windows/win32/debug/pe-format">Learn Microsoft - PE Format</a></li>
    </ul>
    <li><h5>PE Format Illustrated – Mark Pelf (2-part article)</h5></li>
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
    <li><h5>GitHub “PE101-v1” PDF</h5></li>
    <ul>
        <li><a href="https://github.com/ellroch/reverse-engineering-and-malware-analysis/blob/main/PE101-v1.pdf">PE101-v1</a></li>
    </ul>
</ol>

<br />
<h3>Study</h3>
Just getting started.  Not much to report yet.

<br />
<h3>Extra</h3>
<a href="https://github.com/nop-tech/OSED">https://github.com/nop-tech/OSED</a>
<a href="https://github.com/Gabb4r/osed">https://github.com/Gabb4r/osed</a>
<a href="https://github.com/r0r0x-xx/OSED-Pre">https://github.com/r0r0x-xx/OSED-Pre</a>

<br />
<h3><u>References:</u></h3>
Pass