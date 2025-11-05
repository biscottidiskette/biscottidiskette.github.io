---
layout: page
title: sqlmap
description: Performed automated SQL Injection attacks.
img:
importance: 3
category: red
internal_proof: /boxes/56_love/
related_publications: false
---

<div class="row justify-content-sm-center">
  <div class="col-sm-4 mt-3 mt-md-0">
    {% include figure.liquid loading="eager" path="assets/img/sqlmap/logo.png" title="SQLMap" class="img-fluid rounded z-depth-1" %}
  </div>
</div>

<br />
<h2>Link</h2>
<a href="https://sqlmap.org/" target="_blank" rel="noopener noreferrer">Software Link</a>

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
      <td>SQL Injection Database Dump</td>
      <td>Dump database via SQL Injection.</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/34_gamezone/' | relative_url }}">THM GameZone</a></li>
          <li><a href="{{ '/boxes/56_love/' | relative_url }}">HTB Love</a></li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>

<br />
<h3>Commands / Cheatsheet</h3>

<ul>
  <li>SQLMap Overview</li>
  {% capture overview %}
sqlmap -u "http://www.example.com/vuln.php?id=1" --batch
  {% endcapture %}
  {% include terminal.html language='bash' title='SQLMap Overview' content=overview %}

  <li>SQLMap Post Request</li>
  {% capture postrequest %}
hydra -L fsocity.dic -p admin 10.10.11.55 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.11.55%2Fwp-admin%2F&testcookie=1:Invalid Username"
  {% endcapture %}
  {% include terminal.html language='bash' title='Post Requests' content=postrequest %}

  <li>Full Request</li>
  {% capture fullrequest %}
sqlmap -r req.txt
  {% endcapture %}
  {% include terminal.html language='bash' title='SQLMap with Full Request' content=fullrequest %}

</ul>

<br />
<h3>Common mistakes</h3>
<ul>
  <li>Testing the wrong parameter and missing something juicy.</li>
  <li>Overly aggressive default runs which could corrupt data.</li>
  <li>Blindly using batch which could run destructive commands.</li>
</ul>

<br />
<h3>Tips / Best use cases</h3>
<ul>
  <li>Manually scope down (database -> table -> columns) and avoid all to retain control of tests run. </li>
  <li>Always document your findings for reporting purposes. </li>
  <li>Use proxy to push traffic through Burp and monitor testing requests.</li>
</ul>