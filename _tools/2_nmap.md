---
layout: page
title: nmap
description: Used for enumeration and red team recon.
img:
importance: 2
category: red
internal_proof: /boxes/1_brainpan/
related_publications: false
---

<div class="row justify-content-sm-center">
  <div class="col-sm-4 mt-3 mt-md-0">
    {% include figure.liquid loading="eager" path="assets/img/nmap/logo.png" title="Nmap" class="img-fluid rounded z-depth-1" %}
  </div>
</div>

<br />
<h2>Link</h2>
<a href="https://nmap.org/" target="_blank" rel="noopener noreferrer">Software Link</a>

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
      <td>Service Enumeration</td>
      <td>Version detection (`-sV`) and script-based checks to identify exploitable services.</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/55_passage/' | relative_url }}">HTB Passage</a></li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>Vulnerability Scanning</td>
      <td>Run focused NSE scripts (`vuln`) to pinpoint likely attack vectors.</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/11_bluehtb/' | relative_url }}">HTB Blue (found MS17-010)</a></li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>UDP Scanning</td>
      <td>Run udp (`-sU`) to identify UDP ports.</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/43_billing/' | relative_url }}">THM Billing</a></li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>

<br />
<h3>Commands / Cheatsheet</h3>

<ul>
  <li>Initial version grab and OS</li>
  {% capture versiongrab %}
nmap -sC -sV -A -O -oN nmap 10.0.0.5
  {% endcapture %}
  {% include terminal.html language='bash' title='Version grab' content=versiongrab %}

  <li>Scan all port for hidden services</li>
  {% capture fullenum %}
nmap -p- -sS -oN nmapfull 10.0.0.5
  {% endcapture %}
  {% include terminal.html language='bash' title='Full enum' content=fullenum %}

  <li>Run NSE vuln scripts</li>
  {% capture nse %}
nmap --script vuln -oN vulnchk 10.0.0.5
  {% endcapture %}
  {% include terminal.html language='bash' title='NSE vuln scripts' content=nse %}

  <li>Run UDP scan</li>
  {% capture udpscan %}
nmap -sU -sV -oN nmapudp 10.0.0.5
  {% endcapture %}
  {% include terminal.html language='bash' title='UDP' content=udpscan %}
</ul>

<br />
<h3>Common mistakes</h3>
<ul>
  <li>Not checking for rate limits or IDS/IPS.</li>
  <li>Assuming `-sV` output is always reliable.</li>
  <li>Scanning too aggressively on fragile networks (avoid `-p- -T5` on production).</li>
</ul>

<br />
<h3>Tips / Best use cases</h3>
<ul>
  <li>Save outputs (`-oA`) and store them with each box for reproducibility and triage. </li>
  <li>Combine NSE scripts with `--script-args` for targeted checks (e.g., creds or paths).</li>
  <li>Use timing options (`-T`) and throttling when testing live targets.</li>
  <li>Always follow up with manual checks and banner grabs.</li>
</ul>