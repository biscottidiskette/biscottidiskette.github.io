---
layout: page
title: Certified Web Exploitation Specialist
description: Certified Web Exploitation Specialist (CWES) by HackTheBox (HTB).
img:
importance: 3
category: certification
subcategory: red
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cwes/logo.png" title="CWES Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
## Certification Link/Proof
<ul>
    <li>Course page: <a href="https://academy.hackthebox.com/app/exams/5">https://academy.hackthebox.com/app/exams/5</a></li>
    <li>Proof: Verification available upon request.</li>
</ul>

<br />
## Introduction
<p>The CWES covers the full spectrum of web application penetration testing and bug bounty hunting.  The full spectrum means reconnaissance, exploitation, privilege escalation, chaining, and reporting.  It encourages thinking outside of the box for maximum impact.  It also teaches adding value by strong report writing.</p>

<p>Corporatese translation: We developed this web application as fast as possible to be first to market completely ignoring your shift left advice.  Please fix our security.</p>

<br />
## Why I Took It
<p>Web applications are currently the dominant form of application in the market today creating a rich attack surface that will need to be secured.  They will likely be a mainstay even as mobile and AI continue to advance.  Since it is an entrenched stalwart, knowing how to properly test these apps and securing them will remain important for some time to come, probably.</p>

<br />
## Now, Why I Actually Took It

I accidentally bought two vouchers when I was buying the COAE because I was impatient and clicked the button twice.  Turns out having an extra voucher is excellent motivation to take an exam that you have been diligently putting off for a couple years.  This is especially true given the fact that I already had the learning path complete.  I just never took the exam.  Furthermore, at the time of this writing, I am in the middle of a job hunt adding extra incentive to kick bug bounties in the bountiful behind.  These factors combine to make taking the CWES a great idea, in my less than humble opinion. 

<br />
## Skills Gained

You start off by learning the different ways to enumerate a website that you are tasked with testing.  Nmap for ports, fuzzing for directories, and Burp for multi-request testing (Intruder and Repeater).  Then, you can take that knowledge and learn all about the various types of attacks that are available for web applications.  You have the vulnerabilities when you are at the door (Broken authentication).  Once you are in, there are the application attacks like XSS, SQLi, File Uploads, and Server-Side attacks.  There are also web facing attacks like CSRF, IDOR, and XXE.  Once you've covered the application extensively, you have your API attacks and JavaScript Deobfuscation.  Plus, modules for common applications like your CMSs. Finally, some professional polish like Bug Bounty Hunting Process and Reporting.

<br />
## Tools & Technologies Used.
- Burp Suite
- SQLMap
- Ffuf
- Wpscan (and other common CMS scanners)
- CherryTree (I didn't learn anything about it, but I did have it open more than any other program)

<br />
## Related Works
- Coming soon!

<br />
## Tips & Lessons Learned
- **Remember remote code execution:**  The purpose isn't to "read the flag".  Take the machine, then the flag is automatically yours.
- **Professional reporting matters...still:**  They will review your report to make sure it meets certain standards, it is not incidental.
- **Plan the chain:**  We all have tricks for elevating primitives to full RCEs.  Think about them.  Use them.
- **Check the notes:**  If you get lost, recheck your notes from class.   Maybe you missed something.
- **Configuration files are useful:**  Files that are very useful for configuring applications.  Neat.

<br />
## Outcome/Status
<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cwes/passed.png" title="Passed Status" class="img-fluid rounded z-depth-1" %}
    </div>
</div>