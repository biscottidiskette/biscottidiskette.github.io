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
      <td>Exploit Development</td>
      <td>Developed and tested multiple buffer overflow exercises (payload crafting, encoding, offsets).</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/59_bofprep/' | relative_url }}">Buffer Overflow Prep</a></li>
          <li><a href="{{ '/boxes/1_brainpan/' | relative_url }}">Brainpan</a></li>
          <li><a href="{{ '/projects/5_vanillabof/' | relative_url }}">Vanilla Projects</a></li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>Red Team Tooling</td>
      <td>Developed password crackers to try passwords for login pages.</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/57_curling/' | relative_url }}">Curling (password cracker)</a></li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>Red Team Tooling</td>
      <td>Developed password mutator to develop better password dictionaries for crackers.</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/57_curling/' | relative_url }}">Curling (mutator)</a></li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>

<br />
<h3>Commands / Cheatsheet</h3>

<ul>
  <li>Simple socket client</li>
  {% capture socket %}
  import socket
  s = socket.create_connection(('127.0.0.1', 9001))
  s.sendall(b'HELLO\n')
  resp = s.recv(4096)
  s.close()
  {% endcapture %}
  {% include terminal.html language='python' title='python' content=socket %}

  <li>Pack/unpack integers</li>
  {% capture getaddress %}
  from struct import pack, unpack
  jmpesp = pack('<I', (0xdeadbeef))   # little-endian 32-bit
  {% endcapture %}
  {% include terminal.html language='python' title='python' content=getaddress %}
</ul>

<br />
<h3>Common mistakes</h3>
<ul>
  <li>Sending wrong newline format when service expects <code>\r\n</code> vs <code>\n</code>.</li>
  <li>Not sending bytes through a send function to a socket.</li>
</ul>

<br />
<h3>Tips / Best use cases</h3>
<ul>
  <li>Keep small helper scripts in a <code>scripts/</code> folder inside each box repo to show provenance.</li>
  <li>Use virtualenvs for consistent Python versions when sharing scripts.</li>
</ul>