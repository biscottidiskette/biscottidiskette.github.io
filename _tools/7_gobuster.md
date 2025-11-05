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
      <td>Brute-Force Directories</td>
      <td>Brute-Force directories with medium wordlist.</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/3_vulnversity/' | relative_url }}">THM Vulnversity</a></li>
        </ul>
        <ul>
          <li><a href="{{ '/boxes/1_brainpan/' | relative_url }}">THM Brainpan</a></li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>

<br />
<h3>Commands / Cheatsheet</h3>

<ul>
  <li>Directory and File Brute-Force</li>
  {% capture general %}
gobuster dir -u https://TARGET -w /path/to/wordlist.txt -o gobuster_dir.txt
  {% endcapture %}
  {% include terminal.html language='bash' title='Directory and File Brute-Force' content=general %}

  <li>Brute-Force Usernames with Extension</li>
  {% capture gobusterext %}
gobuster dir -u https://TARGET -w /path/to/wordlist.txt -x php,html,txt,js -o gobuster_ext.txt
  {% endcapture %}
  {% include terminal.html language='bash' title='Brute-Force Usernames with Extension' content=gobusterext %}

  <li>Vhosts</li>
  {% capture vhosts %}
gobuster vhost -u https://example.com -w /path/to/vhosts.txt -o gobuster_vhost.txt
  {% endcapture %}
  {% include terminal.html language='bash' title='Vhosts' content=vhosts %}

  <li>DNS Subdomains</li>
  {% capture subs %}
gobuster dns -d example.com -w /path/to/subdomains.txt -o gobuster_dns.txt
  {% endcapture %}
  {% include terminal.html language='bash' title='Subdomains' content=subs %}

</ul>

<br />
<h3>Common mistakes</h3>
<ul>
  <li>Using the wrong wordlist.  Sometimes, it takes multiple lists to find the goods.</li>
  <li>Forgetting to add extension to find the key files that would need the proper extension.</li>
  <li>Assuming that absence in results means it is not there.</li>
</ul>

<br />
<h3>Tips / Best use cases</h3>
<ul>
  <li>Always get permission to run the tool on the target. </li>
  <li>Choose your wordlists carefully.  Seclists is a good source. </li>
  <li>Save the output for future reporting.</li>
</ul>