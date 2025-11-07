---
layout: page
title: john
description: Cracked password hashes and ssh passphrases.
img:
importance: 3
category: red
internal_proof: /boxes/3_vulnversity/
related_publications: false
---

<div class="row justify-content-sm-center">
  <div class="col-sm-4 mt-3 mt-md-0">
    {% include figure.liquid loading="eager" path="assets/img/john/logo.png" title="John the Ripper" class="img-fluid rounded z-depth-1" %}
  </div>
</div>

<br />
<h2>Link</h2>
<a href="https://www.openwall.com/john/" target="_blank" rel="noopener noreferrer">Software Link</a>

<br />
## How I used it

Whenever I dump password hashes from a database, John is my go-to for cracking them. Tag-teaming with rockyou.txt, hopefully like a hurricane.

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
      <td>Recovering an id_rsa Passphrase</td>
      <td>Offline cracking of an OpenSSH private key (id_rsa) passphrase using wordlists and GPU tools.</td>
      <td>I needed the passphrase to be able to authentice via SSH.</td>
    </tr>
    <tr>
      <td>Dictionary Attack</td>
      <td>Wordlist-based recovery of password hashes (fast, offline dictionary cracking).</td>
      <td>Trying to get those sweet cleartext passwords.</td>
    </tr>
  </tbody>
</table>

<br />
**Proof**
- [HTB OpenAdmin](/boxes/58_openadmin/) - Recovering an id_rsa Passphrase.
- [HTB Cronos](/boxes/29_cronos/) - Wordlist-based recovery of raw MD5 password hashes.
- [HTB Greenhorn](/boxes/25_greenhorn/) - Wordlist-driven cracking of SHA‑512 password hashes.
- [HTB Passage](/boxes/55_passage/) - SHA‑256 Password Cracking.

<br />
## Commands I Use Most

<br />
**Crack SSH Passphrase**

{% capture crackssh %}
┌──(kali㉿kali)-[~/Documents/htb/openadmin]
└─$ ssh2john id_rsa > id_rsa.hash
┌──(kali㉿kali)-[~/Documents/htb/openadmin]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
{% endcapture %}
{% include terminal.html language='bash' title='Crack SSH Passphrase' content=crackssh %}

<br />
**Dictionary Attack on Hashes**

{% capture crackhash %}
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
{% endcapture %}
{% include terminal.html language='bash' title='Crack Password Hashes' content=crackhash %}

<br />
## What I Learned the Hard Way

<br />
**Learning the hash type helps**<br />

If you forget, you get a bunch of warnings about the hash type.  So, now I run it through hash-identifier so I can pass it the format switch.

<br />
**Overly relying on john**

Sometimes, I get so excited to try crack the password, I don't realize that I already have the password or can get it from somewhere else.  It blinds me.

<br />
## When john Let Me Down

I had to crack a password with a salt and hashcat was just simply easier to use to set-up to consider the salt value.