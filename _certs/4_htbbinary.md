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

<p>Corporatese translation: Stuffing my exploits and shellcode into running memory to take boxes.  Good times to be had for all, except the victim I guess.</p>

<br />
## Why I Took It
<p>I completed this path to build a strong foundation in low-level exploitation techniques (stack overflows, basic ROP concepts, and assembly reasoning) so I could better understand vulnerability mechanics and develop more reliable exploit proof-of-concepts in real-world labs.</p>

<br />
## Now, Why I Actually Took It
As a primer to restart my OSED studies.  I am really looking forward to ticking that one of my personal list.  Unfortunately, shelved again since I transitioned to blue team.

<br />
## Modules
<ol>
  <li>Introduction to Python 3.</li>
  <li>Intro to Assembly Language.</li>
  <li>Stack-based Buffer Overflows on Linux x86.</li>
  <li>Stack-based Buffer Overflows on Windows x86.</li>
</ol>

<br />
## How This Connects
This course is why I could actually write those exploits instead of just copying PoCs from GitHub, changing the IP address, and praying they work.

**Next step:** OSED, which builds on these fundamentals with DEP/ASLR bypass, ROP chains, and modern mitigations.  Feel free to check out my OSED study plan once a start that adventure.  [OSED Study](/projects/2_osedstudy/)

<br />
## Related Work
- [Vanilla Buffer Overflows](/projects/5_vanillabof/)
- [OSED Study - In Progress](/projects/2_osedstudy/)
- [Buffer Overflow Prep](/boxes/60_bofprep/)

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
## Tips & Lessons Learned
- Master the basics (registers, stack, calling conventions) before chasing complex ROP chains.  
- Use incremental testing.  Small, reproducible steps make exploit development manageable.  
- Keep detailed notes and repeatable scripts; reproducibility is critical for reliable PoCs.  
- Practice on intentionally vulnerable targets to retain safe and ethical habits.

<br />
## Outcome/Status  
- Verification available upon request.