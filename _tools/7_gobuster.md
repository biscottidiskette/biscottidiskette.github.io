---
layout: page
title: gobuster
description: Discovered web directories files and folders.
img:
importance: 3
category: red
internal_proof: /boxes/1_brainpan/
related_publications: false
---

<div class="row justify-content-sm-center">
  <div class="col-sm-4 mt-3 mt-md-0">
    {% include figure.liquid loading="eager" path="assets/img/gobuster/logo.png" title="Gobuster" class="img-fluid rounded z-depth-1" %}
  </div>
</div>

<br />
<h2>Link</h2>
<a href="https://github.com/OJ/gobuster" target="_blank" rel="noopener noreferrer">Software Link</a>

<br />
## How I used it

This is the first program that I learned to be able to brute-force files and directories from websites.

<br />
<table>
  <thead>
    <tr>
      <th>Category</th>
      <th>What I did</th>
      <th>Why I did it</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Brute-Force Directories</td>
      <td>Discover hidden directories/files with medium wordlist.</td>
      <td>Find admin panels, backup files, forgotten endpoints.</td>
    </tr>
    <tr>
      <td>Brute-Force Directories</td>
      <td>Use `-x` switch to find specific file types.</td>
      <td>Sometimes the gold is in `.bak` files or hidden `.txt` notes, like dev notes.</td>
    </tr>
  </tbody>
</table>

<br />
**Proof**
- [THM Vulnversity](/boxes/3_vulnversity/) - Brute-forced directories.
- [THM Brainpan](/boxes/1_brainpan/) - Tries to find interesting goodies.

<br />
## Commands I Use Most

<br />
**Find Juicy Files and Directories**

{% capture checkdirs %}
┌──(sec㉿kali)-[~]
└─$ gobuster dir -u http://10.10.207.42:3333 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster
{% endcapture %}
{% include terminal.html language='bash' title='Finding the good stuff' content=checkdirs %}

<br />
## What I Learned the Hard Way

<br />
**Choosing the right extension**<br />
Spent like an hour getting nothing. Finally checked gobuster usage and realized I needed the `-x` flag for extensions. Face, meet palm.

<br />
**Playing with the wordlists**<br />
Choose those wordlists carefully. Seclists offers a bunch to play with running.  But if you get stuck, double back and try bigger, better wordlists and maybe you will find what you are looking for.

<br />
## When gobuster Let Me Down

When I started a box late at night, watching the gobuster results just absolutely crawl.  This is the time that I switched to ffuf.