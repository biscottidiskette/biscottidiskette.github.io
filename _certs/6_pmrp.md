---
layout: page
title: Practical Malware Research Professional
description: Practical Malware Research Professional (PMRP) by TCM.
img:
importance: 3
category: certification
subcategory: blue
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/pmrp/logo.png" title="PMRP Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
## Certification Link/Proof
<ul>
    <li>Course page: <a href="https://certifications.tcm-sec.com/pmrp/">https://certifications.tcm-sec.com/pmrp/</a></li>
    <li>Proof: Verification available upon request.</li>
</ul>

<br />
## Introduction
<p>The PMRP uses all their skills to analyze malware samples, extract indicators of compromise (IoCs), produce YARA rules to detect, and create a professional report to bring it all together.  PMRP holders demonstrate that they can analyze multiple samples in a restricted time-frame.</p>

<p>Corporatese translation: We need to understand what this malware does and how we can detect it on our systems.</p>

<br />
## Why I Took It
<p>I pursued this certification after transferring to the blue team and wanted to make maximum impact. These skills were lacking on the team and I knew that I could provide them to help support the team.</p>

<br />
## Now, Why I Actually Took It

I hope to transition into cyber security research and thought this would be an excellent starting point into the reverse engineering heavy career path.  Plus, I have a tendency to gravitate towards difficult topics.  After hearing other people talk about its difficulty, I was hooked and knew that I had to take it.  Finally, I like classes with a hands-on, practical component.  The challenge itself is part of the appeal.

<br />
## Skills Gained

The first thing that we had to learn is to set-up a lab so we could work with the malware in a safe, isolated environment.  This environment would also have the tools available to track what the malware was doing, from a host and network perspective.  After getting set-up, we can perform basic static analysis.  This includes strings and library analysis looking for any interesting artifacts.  Then, we perform basic dynamic analysis which includes detonation.  We can use the detonation output to confirm the basic static analysis.  We move up to advanced static and dynamic analysis.  This includes using a disassembler and debugger to get a deeper, assembly view of what the malware is doing.  Based on the output of the analysis, we can develop YARA rules to discover the files on disk.  Finally, we learned report writing to make professional reports.

<br />
## Tools & Technologies Used.
- FlareVM.  
- REMNux.  
- Cutter.  
- x32dbg.  
- Procmon.
- TCPView.
- Regshot.
- Floss.
- PEStudio.
- INETSim.
- Wireshark.

<br />
## Related Works
- [Malware Analysis Report](/projects/6_malwareanalysis/)
- [My Malware Analysis Certification Journey](/blog/2025/pmrp/)

<br />
## Tips & Lessons Learned
- **Maintain Lab Hygiene:**  Snapshots and version control as you detonate samples.
- **Build a Solid Workflow:**  Solid workflow to standardize process.
- **Document as you go:**  Saves massive time in reporting.
- **Be thorough:**  Read large output for important pieces.

<br />
## Outcome/Status
<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/pmrp/passed.png" title="Passed Status" class="img-fluid rounded z-depth-1" %}
    </div>
</div>