---
layout: page
title: python
description: Used for Buffer Overflows and Red Team Scripting.
img: 
importance: 1
category: automation/scripting
internal_proof: /boxes/59_bofprep/
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/python/logo.png" title="Python" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://www.python.org/">Software Link</a>

<br />
## How I used it

Python is my go-to for exploit development and automation. It's cleaner than Bash, more intuitive than C, and has libraries for everything I need right out of the box.  Plus, the `struct` and `socket` modules make writing buffer overflow exploits way easier than trying to reinvent the wheel.

<br />
**What I use it for**

<table>
  <thead>
    <tr>
      <th>Category</th>
      <th>What I Built</th>
      <th>Why Python</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Exploit Development</td>
      <td>Buffer overflow scripts (payload crafting, offset calculation, badchar detection).</td>
      <td>The pack method from the struct library for converting addresses, and the socket library for sending exploits. Way easier to use than C.</td>
    </tr>
    <tr>
      <td>Red Team Tooling</td>
      <td>Password crackers and mutators.</td>
      <td>Quick iteration on wordlist generation. Faster to prototype than C, good enough performance for CTFs.</td>
    </tr>
    <tr>
      <td>Automation</td>
      <td>Reconnaissance and enumeration scripts.</td>
      <td>When I'm tired of typing the same nmap/curl commands 50 times.</td>
    </tr>
  </tbody>
</table>

<br />
**Proof:**
- [Buffer Overflow Prep](/boxes/59_bofprep/) - Full Python exploit chain
- [Brainpan](/boxes/1_brainpan/) - Custom fuzzer and shellcode delivery
- [Vanilla BOF Project](/projects/5_vanillabof/) - Complete exploit development series
- [Curling](/boxes/57_curling/) - Password cracker + mutator combo

<br />
## Code Snippets I Use Constantly

<br />
**Socket client (for exploit delivery):**

{% capture socketpy %}
import socket
s = socket.create_connection(('127.0.0.1', 9001))
s.sendall(b'HELLO\n')
resp = s.recv(4096)
s.close()
{% endcapture %}
{% include terminal.html language='python' title='Socket client' content=socketpy %}

<br />
**Pack addresses (for ROP/shellcode):**

{% capture packpy %}
from struct import pack, unpack
jmp_esp = pack('<I', 0xdeadbeef)  # little-endian 32-bit
{% endcapture %}
{% include terminal.html language='python' title='Pack addresses' content=packpy %}

<br />
## What I Learned the Hard Way

**Bytes vs strings**<br />
Python 3's bytes/string distinction will bite you if you're not careful. Always send `b'bytes'` through sockets, not `'strings'`.

<br />
**Indentation Matters**<br />
Multiple spaces and tab aren't the same even if they look like they "line up".  Seeing how they look like they look like they line up, good luck finding it.  Guarantee you are going to drain both time and sanity trying.  Always pay attention to your spacing because it matters in Python.  Or else, you might end-up a security researcher named after a cookie writing a portfolio blog at 3am.

<br />
## Why Python?
It provides for fast prototyping, quick development, and load of libraries that I can use right out of the box.  So, I use Python *most* of the time.  I will always stick to the most appropriate tool for the job.  Language agnostic, I say.  Honorable mention to C.  Good to also learn for exploit development for better understanding the assembly.