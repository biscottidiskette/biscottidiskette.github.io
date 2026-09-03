---
layout: page
title: Certified Offensive AI Expert
description: Certified Offensive AI Expert (COAE) by HackTheBox (HTB).
img:
importance: 3
category: certification
subcategory: red
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/coae/logo.png" title="COAE Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
## Certification Link/Proof
<ul>
    <li>Course page: <a href="https://academy.hackthebox.com/app/exams/9">https://academy.hackthebox.com/app/exams/9</a></li>
    <li>Proof: Verification available upon request.</li>
</ul>

<br />
## Introduction
<p>The COAE covers a comprehensive range of Artificial Intelligence and Machine Learning: training models, prompt injection, data output attacks, data poisoning attacks, mcp attacks, image classifier attacks, defenses, and figuring out how different components feed each other. It challenges your ability to test the safety of the AI models in production.</p>

<p>Corporatese translation: We deployed a bunch of AI because it is trendy.  Now you have to figure out how to secure it.</p>

<br />
## Why I Took It
<p>I took this to take a proactive stance as AI is quickly becoming a dominant technology in the world today while the security for it largely lags behind its mass scale deployments.  This is going to become increasingly important as jurisdictions, like the European Union, pass legislation to regulate it and ensure its citizens' safety.  This just goes to further illustrate the importance of properly securing our AI application.</p>

<br />
## Now, Why I Actually Took It

I want to be the person responsible for the unreasonably complicated tasks, as I enjoy the mental challenge of cracking a hard puzzle.  And AI/ML (as well as its resulting security) definitely fits this bill.  Getting my prompt injection to land, nudging image pixels to confuse image classifiers, counting my perturbations to avoid detections, struggling with hallucinations, and figuring out why that injection payload didn't work are just some of the issues I got to struggle with during this certification.  Plus, as I worked through the issues, I could start to work out how I could apply this on the job to add value to the client.  

<br />
## Skills Gained

You start off by learning the different types of AI algorithms out there, supervised, unsupervised, etc., so you know what to choose.  Then, you get to learn how to actually train different models, specifically PolynomialNB, Random Forest, and Convolutional Neural Network.  From here, you roll this new (at least new to me) knowledge into the attack everyone recognized, injection.  This also includes chaining data like using one AI model to inject a log that then gets consumed by a second model (the victim).  We also get to practice stuffing models with "Good Words" to confuse its sentiment analysis and data label flipping to interfere with training.  There were also multiple pixel manipulation attacks to trick badge scanners to give you access, for example.  You also get to explore shadow and membership inference attacks. You will also learn techniques like teacher ensemble to increase data privacy, as well as, defensive tactics like LLM-as-a-judge.    

<br />
## Tools & Technologies Used.
- SciKit-Learn
- PolynomialNB
- Convolutional Neural Networks (CNN)
- FastMCP
- Model Ensembles

<br />
## Related Works
- Coming soon!

<br />
## Tips & Lessons Learned
- **Remember the classics:**  Cross-site scripting, SQL injection, command injection, etc. all still count, even though this is an AI class.
- **Professional reporting matters:**  They will review your report to make sure it meets certain standards, it is not incidental.
- **Take Screenshots:**  Resetting the environment changes the flags, so if you don't get your trophy capture your report could look weird.
- **Beware the rabbit holes:**  I wasted days going down an attack path that was never going to work.  Learn to pivot.
- **Remember the lessons:**  The exam is testing the material from the learning path.  If you get stuck, go back.
- **Keep it Simple:**  Follow the attacks from the class.  There is no need to create novel attacks.

<br />
## Outcome/Status
<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/coae/passed.png" title="Passed Status" class="img-fluid rounded z-depth-1" %}
    </div>
</div>