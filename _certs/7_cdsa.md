---
layout: page
title: Certified Defensive Security Analyst
description: Certified Defensive Security Analyst (CDSA) by HackTheBox (HTB).
img:
importance: 3
category: certification
subcategory: blue
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cdsa/logo.png" title="CDSA Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
## Certification Link/Proof
<ul>
    <li>Course page: <a href="https://academy.hackthebox.com/app/exams/4">https://academy.hackthebox.com/app/exams/4</a></li>
    <li>Proof: Verification available upon request.</li>
</ul>

<br />
## Introduction
<p>The CDSA focuses on the practical side of defensive security: investigating alerts, correlating data across multiple sources, and figuring out what actually matters. It tests your ability to work through logs, identify attacker behavior, and build a coherent picture of an incident under time pressure.</p>

<p>Corporate translation: The SIEM is screaming. Figure out if it’s real, how bad it is, and what to do next.</p>

<br />
## Why I Took It
<p>I took this certification to sharpen my effectiveness on the blue team. Detection is only as good as the analyst behind it, and I wanted to be faster and more accurate when working through alerts and potential incidents. This filled a gap between “we have visibility” and “we know what we’re looking at.”</p>

<br />
## Now, Why I Actually Took It

I like being the person who can look at a messy pile of logs and make sense of it. There’s something satisfying about turning noise into a clear timeline of what actually happened.  Also, CDSA has a reputation for being hands-on and unforgiving. No multiple-choice safety net, just you, the data, and your ability to think. That’s the kind of challenge I tend to gravitate toward.  And honestly, alert fatigue is real. I wanted to get better at cutting through the junk and finding the signal without second-guessing every decision.

<br />
## Skills Gained

The first thing you learn is how to approach an alert without getting lost immediately. That means forming a hypothesis, validating it quickly, and knowing when to pivot.  From there, it’s log analysis across different sources: Windows event logs, network telemetry, authentication data, and correlating them to build a timeline. Instead of treating alerts in isolation, you start chaining them together into actual attacker behavior.  You also develop a much better understanding of common attack techniques. Not just memorizing them, but recognizing what they look like in real data: lateral movement, privilege escalation, persistence mechanisms.  Another major skill is triage. Not everything matters, and part of the job is deciding what to ignore. That sounds simple, but it’s one of the harder things to do well.  Finally, reporting. Taking everything you’ve found and explaining it clearly, what happened, how it happened, and why it matters.  All this without drowning the reader in raw logs.

<br />
## Tools & Technologies Used.
- Kibana
- Elastic
- Splunk
- Velocity3
- EventLog Analysis
- Sysmon Analysis

<br />
## Related Works
- Coming soon!

<br />
## Tips & Lessons Learned
- **Document as you go:**  I know I said it in the PMRP but seriously.  This is important.
- **Work on the report as you progress:**  Everytime I hit a breakpoint in the exam I worked on the report. That way it wasn't excruciating at the end.
- **Remember where you are:**  You can only go forward or backwards in the timeline so keep a sense of where you are in it.
- **Be thorough:**  You search one event code you could get 100 results and you need one specific record.  Be sharp.
- **Breathe**  You are going to get lost.  The fun of event logs.  Stay calm.

<br />
## Outcome/Status
<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cdsa/passed.png" title="Passed Status" class="img-fluid rounded z-depth-1" %}
    </div>
</div>