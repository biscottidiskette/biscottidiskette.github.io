---
layout: page
title: Intro to Binary Exploitation
description: Intro to Binary Exploitation by Hack The Box Academy.
img:
importance: 3
category: badge
subcategory: red
related_publications: false
---

<div class="row justify-content-sm-center">
  <div class="col-sm-4 mt-3 mt-md-0">
    {% include figure.liquid loading="eager" path="/assets/img/htbbin/logo.png" title="HTB - Intro to Binary Exploitation" class="img-fluid rounded z-depth-1" %}
  </div>
</div>

<br />
## Certification Link/Proof
- Path page: <https://academy.hackthebox.com/path/preview/intro-to-binary-exploitation>  
- Proof: Verification available upon request.

<br />
## Introduction
<p>Binary exploitation covers the techniques for understanding and manipulating compiled programs to achieve code execution or other unintended behaviour. This course establishes foundations in computer architecture, assembly language, buffer overflows, and practical exploit scripting.  These are key skills for advanced offensive work and vulnerability research.</p>

<br />
## Why I Took It
<p>I completed this path to build a strong foundation in low-level exploitation techniques (stack overflows, basic ROP concepts, and assembly reasoning) so I could better understand vulnerability mechanics and develop more reliable exploit proof-of-concepts in real-world labs.</p>

<br />
## Modules
<ol>
  <li>Introduction to Python 3.</li>
  <li>Intro to Assembly Language.</li>
  <li>Stack-based Buffer Overflows on Linux x86.</li>
  <li>Stack-based Buffer Overflows on Windows x86.</li>
</ol>

<br />
## Learning Objectives

### Introduction to Python 3
- Learn Python basics useful for exploit scripting and automation.  
- Automate repetitive tasks and build simple tools to aid exploitation workflows.  
- Practice data parsing, socket programming, and scripting helper utilities.

### Intro to Assembly Language
- Understand CPU registers, calling conventions, and the stack.  
- Read basic x86 assembly to trace program flow and identify vulnerable code paths.  
- Map compiled binary behaviour back to source-level logic during analysis.

### Stack-based Buffer Overflows (Linux x86)
- Recognise classic stack-based overflow patterns and vulnerable code.  
- Craft payloads to overwrite return addresses and achieve code execution.  
- Practice safe testing techniques and use debugging tools to validate exploits.

### Stack-based Buffer Overflows (Windows x86)
- Understand Windows calling conventions, DEP, and basic mitigation concepts.  
- Exploit local and remote buffer overflow vulnerabilities on Windows targets.  
- Learn initial mitigation bypasses applicable to older/legacy protections.

<br />
## Hands‑On/Labs
- Practical exercises include basic exploit development, controlled overflow labs, and scripting simple proof-of-concepts.  
- Work completed in HackTheBox Academy lab environments; screenshots and short writeups available upon request.

<br />
## Tools & Techniques Covered
- `gdb`/`pwndbg`, `objdump`/`readelf`, `radare2` (analysis & debugging).  
- Python 3 scripting for socket-based exploits and automating workflows.  
- Basic use of `nc`, `strace`, and common binary hardening checks.  
- Introduction to mitigation concepts (ASLR, DEP/NX, stack canaries) and early bypass patterns.

<br />
## Career/Practical Benefits
- Builds fundamental low-level skills required for exploit development, vulnerability research, and advanced pentesting.  
- Improves ability to reason about root causes of software bugs and craft reliable PoCs.  
- Provides a stepping stone to more advanced topics (ROP, kernel exploitation, modern mitigations).

<br />
## Tips & Lessons Learned
- Master the basics (registers, stack, calling conventions) before chasing complex ROP chains.  
- Use incremental testing.  Small, reproducible steps make exploit development manageable.  
- Keep detailed notes and repeatable scripts; reproducibility is critical for reliable PoCs.  
- Practice on intentionally vulnerable targets to retain safe and ethical habits.

<br />
## Outcome/Status  
- Verification available upon request.

<br />
## Related Projects/Walkthroughs
- [Offensive Security Exploit Development (OSED) – In Progress]({{ '/projects/2_osedstudy/' | relative_url }})