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
## How I Use It
Wireshark is my key weapon for traffic analysis, whether it is analyzing traffic live looking for juicy information to steal or pcaps after a breach to figure out what happend.  Wireshark is the first packet sniffer I learned in Grad school and still my default to this day.

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
      <td>PCAP Triage</td>
      <td>Filter and identify suspicious flows and IoCs from captures.</td>
      <td>We can use the captures to identify file names and connections to identify IoCs to further our investigations.</td>
    </tr>
    <tr>
      <td>Extract Files</td>
      <td>Extract files and other artifacts from the traffic.</td>
      <td>Malicious files can be extracted out of the traffic so we can review them.</td>
    </tr>
    <tr>
      <td>Protocol Debugging</td>
      <td>Inspect TCP streams, reassemble HTTP traffic, and analyze TLS handshakes for anomalies.</td>
      <td>Follow entire TCP and HTTP streams so you can get an idea of the full picture of a conversation.</td>
    </tr>
    <tr>
      <td>IOC Extraction</td>
      <td>Use alongside INETSim to analyze malware traffic.</td>
      <td>I run Wireshark on REMNux to get a better idea of what malware is doing when I execute it.</td>
    </tr>
    <tr>
      <td>Steal Goodies</td>
      <td>Check unencrypted traffic for juicy tidbits like credentials.</td>
      <td>Protocols like http, ftp, and telnet have historically been cleartext so we can sometimes see credentials and other juicy goodies.</td>
    </tr>
  </tbody>
</table>

<br />
**Proof**
- [Webstrike Lab](/boxes/69_webstrike/) - Identify attacker actions from TCP Stream.
- [Meerkat](/boxes/62_meerkat/) - Identify credentials in the traffic.
- [Web Investigation Lab](/boxes/85_webinvestigation/) - Investigate a SQL Injection attack from the traffic.
- [PoisonedCredentials Lab](/boxes/79_poisonedcreds/) - Analyze protocols to piece together attacks.

<br />
## Features I Use Most

**Follow TCP Stream** - Right-click packet → Follow → TCP Stream  
*Why: Reconstruct full conversations, especially for plaintext protocols (HTTP, FTP, Telnet)*

**Export Objects** - File → Export Objects → HTTP  
*Why: Extract files transferred over HTTP without manual carving*

<br />
## What I Learned the Hard Way

<br />
**Filters are necessary**<br />
Wireshark just keeps sniffing. The conversation you were watching 30 seconds ago? Buried under 500 ARP requests. Use display filters or drown in noise.

<br />
**Sometimes, you really have to drill-down in a request**<br />
Finding a hostname once took me embarrassingly long because I didn't realize how many nested sections Wireshark hides data in. Sometimes you have to expand like 5 layers deep to find what you need.

<br />
## When Wireshark Let Me Down

[HTB Meerkat](/boxes/62_meerkat/) - I was trying to get a count of password spraying but was struggling to address duplicate attempts to get a unique count.  So, I used tshark to export out and wrote a python parser script to get the count.