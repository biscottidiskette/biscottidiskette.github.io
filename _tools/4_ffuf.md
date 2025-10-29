---
layout: page
title: ffuf
description: Performed web directory brute-forcing and discovery.
img:
importance: 2
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
      <td>Enumerate Directories and Files</td>
      <td>FUZZ at the ende of the URL to find juicy files and directories.</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/10_popcorn/' | relative_url }}">HTB Popcorn</a></li>
          <li><a href="{{ '/boxes/28_boardlight/' | relative_url }}">HTB Boardlight</a></li>
          <li><a href="{{ '/boxes/29_cronos/' | relative_url }}">HTB Cronos</a></li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>Enumerate Subdomains</td>
      <td>FUZZ before the domain to find subdomains we can explore.</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/29_cronos/' | relative_url }}">HTB Cronos</a></li>
          <li><a href="{{ '/boxes/28_boardlight/' | relative_url }}">HTB Boardlight</a></li>
          <li><a href="{{ '/boxes/52_analytics/' | relative_url }}">HTB Analytics</a></li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>Enumerate HTTP Paramters</td>
      <td>FFUZ for HTTP paramter our request might need.</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/48_planning/' | relative_url }}">HTB Planning</a></li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>

<br />
<h3>Commands / Cheatsheet</h3>

<ul>
  <li>Enumerate Directories and Files</li>
  {% capture dirfiles %}
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://cronos.htb/FUZZ -e .txt,.bak,.html,.php -fw 990
  {% endcapture %}
  {% include terminal.html language='bash' title='Enumerate Directories and Files' content=dirfiles %}

  <li>FUZZ before the domain to find subdomains we can explore</li>
  {% capture subdomain %}
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://cronos.htb -H "Host: FUZZ.cronos.htb" -fw 3534
  {% endcapture %}
  {% include terminal.html language='bash' title='Enumerate Subdomain' content=subdomain %}

  <li>Enumerate HTTP Paramters</li>
  {% capture params %}
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u 'http://planning.htb/contact.php?FUZZ=1' -fw 6
  {% endcapture %}
  {% include terminal.html language='bash' title='Enumerate HTTP Parameters' content=params %}

</ul>

<br />
<h3>Common mistakes</h3>
<ul>
  <li>Using the wrong wordlist.  Sometimes, it takes multiple lists to find something good.</li>
  <li>Forgetting the extensions or using the wrong extensions.</li>
  <li>Failing to output or document the results for later reporting.</li>
</ul>

<br />
<h3>Tips / Best use cases</h3>
<ul>
  <li>Pick a large, comprehensive word list, like SecLists.  Consider using a tool like cewl for a custom list. </li>
  <li>Use extension with the -e option and try to use the proper extension for the tech stack.</li>
  <li>Always snag the output.</li>
</ul>