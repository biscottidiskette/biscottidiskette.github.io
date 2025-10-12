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

<br />
## Why I Took It
<p>I completed this path to build structured, practical red team skills—mapping reconnaissance to weaponization, access, persistence, lateral movement, and exfiltration—so I can evaluate and stress-test defensive controls in realistic scenarios.</p>

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
## Learning Objectives
- Use diverse techniques for initial access (phishing, password attacks, service exploits).  
- Perform thorough enumeration to build an accurate target picture and attack plan.  
- Implement persistence and lateral movement strategies to maintain and expand access.  
- Evade common security controls (AV, EDR, logging, sandboxing) with practical techniques.  
- Understand and exploit Active Directory in enterprise contexts.  
- Apply OPSEC and C2 fundamentals for realistic adversary emulation.

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

<br />
## Related Projects/Walkthroughs
- [THM Brainstorm]({{ '/boxes/37_brainstorm/' | relative_url }})
- [THM Retro]({{ '/boxes/46_retro/' | relative_url }})