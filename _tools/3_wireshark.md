---
layout: page
title: wireshark
description: Analyzed .pcap files for investigation.
img:
importance: 3
category: blue
internal_proof: /projects/malware-lab/
related_publications: false
---

<div class="row justify-content-sm-center">
  <div class="col-sm-4 mt-3 mt-md-0">
    {% include figure.liquid loading="eager" path="assets/img/wireshark/logo.png" title="Wireshark" class="img-fluid rounded z-depth-1" %}
  </div>
</div>

<br />
<h2>Link</h2>
<a href="https://www.wireshark.org/" target="_blank" rel="noopener noreferrer">Software Link</a>

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
      <td>PCAP Triage</td>
      <td>Quickly filter and identify suspicious flows, extract files and IoCs from captures.</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/1_brainpan/' | relative_url }}">THM Overpass2 (Research Attacker TTP)</a></li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>Protocol Debugging</td>
      <td>Inspect TCP streams, reassemble HTTP traffic, and analyze TLS handshakes for anomalies.</td>
      <td>
        <ul>
          <li><a href="{{ '/boxes/36_overpass2/' | relative_url }}">THM Overpass2 (Follow HTTP Stream)</a></li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>IOC Extraction</td>
      <td>Use alongside INETSim to analyze malware traffic.</td>
      <td>
        <ul>
          <li>In Progress...</li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>

<br />
<h3>Commands / Cheatsheet</h3>

<ul>
  <li>Open capture and filter for suspicious traffic</li>
  {% capture basicfilter %}
# open file in tshark (CLI)
tshark -r capture.pcap -Y "http.request or dns or tcp.flags.syn==1"
  {% endcapture %}
  {% include terminal.html language='bash' title='Tshark quick filter' content=basicfilter %}

  <li>Export HTTP objects (reassemble)</li>
  {% capture exporthttp %}
# extract HTTP objects with tshark
tshark -r capture.pcap --export-objects "http,./http_extracted"
  {% endcapture %}
  {% include terminal.html language='bash' title='Export HTTP objects' content=exporthttp %}

  <li>Follow TCP stream (tshark)</li>
  {% capture followtcp %}
tshark -r capture.pcap -qz follow,tcp,streams
  {% endcapture %}
  {% include terminal.html language='bash' title='Follow TCP streams' content=followtcp %}
</ul>

<br />
<h3>Common mistakes</h3>
<ul>
  <li>Not setting display vs capture filters correctly.</li>
  <li>Opening very large PCAPs in GUI without indexing or using `tshark` first.</li>
  <li>Not exporting extracted artifacts in a preserved file format for downstream analysis.</li>
</ul>

<br />
<h3>Tips / Best use cases</h3>
<ul>
  <li>Use `tshark` for scripted extraction and automation; use Wireshark GUI for deep exploration and reassembly.</li>
  <li>Store extracted IoCs in a central repo (YARA, Suricata rules, DNS blocklists) for hunting and detection.</li>
</ul>