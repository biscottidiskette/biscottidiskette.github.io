---
layout: page
title: ffuf
description: Performed web directory brute-forcing and discovery.
img:
importance: 1
category: red
internal_proof: /boxes/29_cronos/
related_publications: false
---

<div class="row justify-content-sm-center">
  <div class="col-sm-4 mt-3 mt-md-0">
    {% include figure.liquid loading="eager" path="assets/img/ffuf/logo.png" title="ffuf" class="img-fluid rounded z-depth-1" %}
  </div>
</div>

<br />
<h2>Link</h2>
<a href="https://github.com/ffuf/ffuf/" target="_blank" rel="noopener noreferrer">Software Link</a>

<br />
## How you used it

Fuzz Faster You Fool (ffuf) is my default standard for fuzzing directories, subdirectories, and HTTP parameters.  I used to use gobuster since that is what I learned first but the speed of ffuf had me hooked.

<br />
<table>
  <thead>
    <tr>
      <th>Category</th>
      <th>What I do</th>
      <th>Why I am doing it</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Fuzzing Directories and Files</td>
      <td>FUZZ at the end of the URL to find juicy files and directories.</td>
      <td>Hoping to find something fun to play with.</td>
    </tr>
    <tr>
      <td>Find Subdomains</td>
      <td>FUZZ before the domain to find subdomains we can explore.</td>
      <td>The best ones are the "dev" subdomains.</td>
    </tr>
    <tr>
      <td>Enumerate HTTP Parameters</td>
      <td>FFUZ for HTTP parameter our request might need.</td>
      <td>Rarer but sometimes I look for them if I think I can increase my functionality.</td>
    </tr>
  </tbody>
</table>

<br />
**Proof**
- [HTB Popcorn](/boxes/10_popcorn/) - Discovered abusable directory with the fuff.
- [HTB Cronos](/boxes/29_cronos/) - Found a subdomain to enumerate.
- [HTB Planning](/boxes/48_planning/) - Multiple ffufs including the HTTP parameter one.

<br />
## Command I Use Every Box

<br />
**Fuzzing Directories and Files**

{% capture dirscan %}
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://cronos.htb/FUZZ -e .txt,.bak,.html,.php -fw 990
{% endcapture %}
{% include terminal.html language='bash' title='Banner Grab' content=dirscan %}

<br />
**Find Subdomains**

{% capture testsubs %}
──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://cronos.htb -H "Host: FUZZ.cronos.htb" -fw 3534
{% endcapture %}
{% include terminal.html language='bash' title='Enumerate for Subdomains' content=testsubs %}

<br />
## What I Learned the Hard Way

<br />
**Wordlist Selection Matters**<br />
Choose those wordlists carefully. Seclists offers a bunch to play with running.  But if you get stuck, double back and try bigger, better wordlists and maybe you will find what you are looking for.

<br />
**Filters are necessary**<br />
When you first run ffuf you are going to get ton of results because it will just show you everything.  But take a value, words for example, and give an `fw` option to filter out results by number of words.

<br />
## When ffuf Let Me Down
I can't remember the specific box unfortunately but I was pretty sure I was suppose to find something by brute-force.  So, I switched it up with the gobuster and finally found it.  So, always be flexible and ready to pivot to move deeper in the attack.