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
<h2>Process</h2>

<h3>How you used it</h3>

<br />
<table>
  <thead>
    <tr>
      <th>Category</th>
      <th>Usage</th>
      <th>Proof</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Recovering an id_rsa Passphrase</td>
      <td>Offline cracking of an OpenSSH private key (id_rsa) passphrase using wordlists and GPU tools.</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/58_openadmin/' | relative_url }}">HTB OpenAdmin</a></li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>MD5 — Dictionary Attack</td>
      <td>Wordlist-based recovery of raw MD5 password hashes (fast, offline dictionary cracking).</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/54_code/' | relative_url }}">HTB Code</a></li>
          <li><a href="{{ '/boxes/29_cronos/' | relative_url }}">HTB Cronos</a></li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>Bcrypt / Blowfish Password Recovery</td>
      <td>Dictionary and rule-based cracking against Blowfish (bcrypt) password hashes — slow, cost-aware attacks.</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/53_devvortex/' | relative_url }}">HTB Devvortex</a></li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>SHA‑512 Hash Recovery</td>
      <td>Wordlist-driven cracking of SHA‑512 password hashes, with rule mangling for higher success rates.</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/25_greenhorn/' | relative_url }}">HTB Greenhorn</a></li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>SHA‑256 Password Cracking</td>
      <td>Dictionary-based attempts to recover SHA‑256 hashed passwords (tuning and hybrid attacks).</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/55_passage/' | relative_url }}">HTB Passage</a></li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>

<br />
<h3>Commands / Cheatsheet</h3>

<ul>
  <li>Recovering an id_rsa Passphrase</li>
  {% capture idrsa %}
# Use ssh2john to create a crackable file.
ssh2john id_rsa > john_id_rsa

# Crack the new file.
john --wordlist=/usr/share/wordlists/rockyou.txt john_id_rsa
  {% endcapture %}
  {% include terminal.html language='bash' title='Cracking id_rsa Passphrase' content=idrsa %}

<li>MD5 — Dictionary Attack</li>
  {% capture md5 %}
john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5 passes.txt
  {% endcapture %}
  {% include terminal.html language='bash' title='MD5 — Dictionary Attack' content=md5 %}

</ul>