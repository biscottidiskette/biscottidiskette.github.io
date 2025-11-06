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
## How I used it

<br />
<table>
  <thead>
    <tr>
      <th>Category</th>
      <th>What I Run</th>
      <th>Why I Run It</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Service Enumeration</td>
      <td>I grabbed the banner for top ports, the top scripts, and finger-print OS.</td>
      <td>Checking banner grabbing with script can give us a starting point to continue the attack.</td>
    </tr>
    <tr>
      <td>All Ports</td>
      <td>Scan all the 65,535 ports with Stealth Scan.</td>
      <td>Identify services that run on unusual ports.</td>
    </tr>
    <tr>
      <td>Vulnerability Scanning</td>
      <td>Run the vuln category of NSE scripts to identify vulnerabilities.</td>
      <td>Identify low hanging fruit vulnerabilities for an easy win.</td>
    </tr>
    <tr>
      <td>UDP Scanning</td>
      <td>Run udp scans since it is the other half of TCP.</td>
      <td>Identify any ports running the UDP protocol.</td>
    </tr>
  </tbody>
</table>

<br />
**Proof**
- [HTB Passage](/boxes/55_passage/) - Banner grab to identify the services.  Trust but verify.
- [HTB Blue (found MS17-010)](/boxes/11_bluehtb/) - Run the vuln category of NSE scripts.
- [THM Billing](/boxes/43_billing/) - Run the UDP scans.

<br />
## Commands I Use Every Box

<br />
**Banner Grabbing, Top Scripts, and Operating System Fingerprinting**

{% capture firstscan %}
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -A -O -oN nmap <IP>
{% endcapture %}
{% include terminal.html language='bash' title='Banner Grab' content=firstscan %}

<br />
**Stealth scan, all ports**

{% capture secscan %}
┌──(kali㉿kali)-[~]
└─$ nmap -sS -p- -oN nmapfull <IP>
{% endcapture %}
{% include terminal.html language='bash' title='All Ports' content=secscan %}

<br />
**All Vulnerability Scripts**

{% capture thirdscan %}
┌──(kali㉿kali)-[~]
└─$ nmap --script vuln -oN vulnchk <IP>
{% endcapture %}
{% include terminal.html language='bash' title='Vulnerability Scan' content=thirdscan %}

<br />
**UDP Scanning**

{% capture fourthscan %}
┌──(kali㉿kali)-[~]
└─$ nmap -sU -oN nmapudp <IP>
{% endcapture %}
{% include terminal.html language='bash' title='UDP Scan' content=fourthscan %}

<br />
## What I Learned

<br />
**`-A` is loud**<br />
Runs OS detection, version detection, script scanning, and traceroute.  Great for CTFs.  Terrible for real pentests (triggers every IDS).  Use targeted scans instead.

<br />
**UDP scanning takes forever**<br />
Seriously.  Don't scan all 65535 UDP ports unless you enjoy watching paint dry.  Top 20 ports catches 90% of interesting services.

<br />
**NSE scripts are hit-or-miss**<br />
`--script vuln` finds easy wins (MS17-010, EternalBlue) but also throws tons of false positives.  Always manually verify.

<br />
## When Nmap Let Me Down

[HTB Love](/boxes/56_love/) - Service was on a weird high port that didn't show up in top 1000.  Had to run full `-p-` scan.  Lesson: if you're stuck, scan everything.

[THM Billing](/boxes/43_billing/) - SNMP was running on UDP.  Missed it completely until I ran UDP scan.  Lesson: don't forget UDP exists. Also, SNMP is always interesting when you find it.