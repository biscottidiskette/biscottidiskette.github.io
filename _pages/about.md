---
layout: about
title: about
permalink: /
subtitle: <a href='https://app.hackthebox.eu/profile/biscottidiskette'>HackTheBox</a> | <a href='https://tryhackme.com/r/p/BiscottiDiskette'>TryHackMe</a>

profile:
  align: right
  image: frontpage/Logo1.png
  image_circular: false # crops the image to make it circular
  more_info: >

news: false # includes a list of news items
selected_papers: false # includes a list of papers marked as "selected={true}"
social: false # includes social icons at the bottom of the page
---

### Information Security Professional | PMRP-Certified | OSCP-Certified
#### Former Pentester → Current Blue Team Operations

Former pentester turned malware analyst. I understand attackers because I was one.

{% assign offensive_count = site.boxes | where: "team", "Red Team Labs" | size %}
{% assign defensive_count = site.boxes | where: "team", "Blue Team Labs" | size %}

**Professional Experience:**<br />
- 4+ years penetration testing & security operations
- OSCP & PMRP certified (offensive + defensive expertise)
- Malware analysis research → [Malware Analysis Report](/projects/6_malwareanalysis/)
- Active practitioner: {{ offensive_count }} offensive labs, {{ defensive_count }} defensive challenges

**Current Focus:**
- Malware analysis & incident response operations
- CISSP preparation (exam target: Q1 2026)

**Skills:** Malware Analysis • Reverse Engineering • Incident Response • SOC Operations • Python • Linux • Web Security • CTF<br />
**Exploring:** Advanced Malware Analysis (GREM track) • Exploit Development • Detection Engineering

[Projects](/projects/)&nbsp;|&nbsp;[View All Labs ({{ site.boxes | size }} Total)](/boxes/)&nbsp;|&nbsp;[Tools](/tools/)&nbsp;|&nbsp;[Certifications](/certifications/)&nbsp;|&nbsp;[Blog](/blog/)&nbsp;|&nbsp;[Contact](/contact/)

---

I specialize in malware analysis and incident response, applying offensive security expertise to defensive operations. My OSCP background provides attacker-level insight into exploit methodology, while my PMRP certification demonstrates reverse engineering capability for threat detection, hunting, and incident response.

#### Beyond Security

When I'm not breaking (or defending) systems, I'm training Muay Thai and learning 
Thai language. The discipline required for both martial arts and language learning 
translates directly to security work: pattern recognition, iterative improvement, 
and the patience to work through complex problems.

[Read: Learning Thai and Why It Matters →](/blog/2025/learn-Thai/)