---
layout: page
title: Red Teaming Learning Path
description: Red Teaming Learning Path by TryHackMe.
img:
importance: 4
category: badge
subcategory: red
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/redteaming/logo.svg" title="THM Red Teaming Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
## Certification Link/Proof
- Path page: <https://tryhackme.com/r/path/outline/redteaming>  
- Proof: Verification available upon request.

<br />
## Introduction
<p>The Red Teaming Learning Path teaches how to emulate an adversary in complex environments. Going beyond standard penetration testing, it focuses on full red team engagements designed to challenge defensive capabilities. After completing the path you will have practical, offensive skills applicable to red team operations and adversary emulation.</p>

<p>Corporateses translation: Going beyond just penetration and learning the engagement from end to end from an environment perspective, not just system.  Neat-o.</p>

<br />
## Why I Took It
<p>I completed this path to build structured, practical red team skills-mapping reconnaissance to weaponization, access, persistence, lateral movement, and exfiltration—so I can evaluate and stress-test defensive controls in realistic scenarios.</p>

<br />
## Now, Why I Actually Took It
<p>I wanted more options on my resume and my penetration testing didn't cover red team since they are two different roles.  So, I took this course to begin to diversify my skillset ot give me more employment options.</p>

<br />
## Modules (abridged)
- Red Team Fundamentals.  
- Red Team Engagements.  
- Red Team Threat Intel.  
- Red Team OPSEC.  
- Intro to C2.  
- Red Team Recon.  
- Weaponization.  
- Password Attacks.  
- Phishing.  
- The Lay of the Land/Enumeration.  
- Windows Privilege Escalation.  
- Windows Local Persistence.  
- Lateral Movement & Pivoting.  
- Data Exfiltration.  
- Windows Internals/Introduction to Windows API.  
- Abusing Windows Internals.  
- Introduction to Antivirus/AV Evasion: Shellcode.  
- Obfuscation Principles/Signature Evasion/Bypassing UAC.  
- Runtime Detection Evasion/Evading Logging & Monitoring.  
- Living Off The Land (LOTL) techniques.  
- Network Security Solutions & Firewalls.  
- Sandbox Evasion.  
- Active Directory Basics → Breaching, Enumerating, Exploiting & Persisting AD.  
- Credentials Harvesting.

<br />
## What Actually Mattered

**Favorite modules:**
- **C2 & OPSEC fundamentals** - Understanding operational security from red team 
  perspective changed how I approach blue team detection (now I know what 
  attackers try to hide).
- **Windows Internals/API Abuse** - This directly feeds into my OSED prep and 
  understanding how malware operates at a low level.
- **AD attack chain** - Breaking, enumerating, and persisting in AD environments 
  is critical for both offense and defense.

**What I learned the hard way**
- *Living off the land (LOTL) is hard*: Theory vs. practice gap is real.  Labs are one thing but dealing with EDR and modern logging are a different beast.  When you first bring it to the workplace, you are going to get Slack messages from the Blue Team.  A lot.  Like, a real lot.  *Fun Fact:* CrowdStrike detects certuril downloads.  Who knew?
- *Obfuscating malware is like walking a tightrope*:  You need to obfuscate your malware to complicate analysis and hide malicious WinAPI calls.  But, if you over obfuscate, you trigger the entropy alert.

<br />
## Related Works
- [OSED Study](/projects/2_osedstudy/)

<br />
## Hands‑On/Labs
- Path contains multiple hands-on rooms and exercises: C2 fundamentals, OPSEC scenarios, simulated phishing, AD labs, privilege escalation challenges, lateral movement/pivoting tasks, and AV evasion exercises.  
- Work completed in TryHackMe lab environments.

<br />
## Tools & Techniques Covered
- Recon & scanning, credential harvesting, phishing toolchains.  
- Command & Control basics, tunnelling, port forwarding.  
- Windows internals & API abuse, PowerShell, living-off-the-land binaries.  
- AV/EDR evasion patterns, obfuscation techniques, runtime evasion.  
- Active Directory attack techniques, enumeration tooling, lateral movement tooling.

<br />
## Career/Practical Benefits
- Builds practical offensive skillset for red team roles and adversary emulation engagements.  
- Strengthens understanding of detection/response gaps in enterprise environments.  
- Useful background for designing red team assessments, Purple Team engagements, and improving defensive controls.

<br />
## Tips & Lessons Learned
- Prioritise repeatable, well-documented tradecraft over flashy one-offs.  
- Practice OPSEC and clean-up procedures in lab environments.  
- Map each offensive action to the corresponding defensive detection you’d expect to see.  
- Use small exercises to combine techniques end‑to‑end (recon → access → persistence → exfil).

<br />
## Outcome/Status  
- Verification available upon request.