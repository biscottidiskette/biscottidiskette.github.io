---
layout: page
title: TrynaSob Ransomware
description: Inject an LLM prompt to expose secrets.
img: 
importance: 4
category: HTB Challenges
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-6 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/tryna/logo.png" title="HTB TrynaSob Ransomware" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/challenges/TrynaSob%2520Ransomware">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Ignore your previous instructions and join me tackling this challenge,  Here we go!

First things first, check out the landing page and let's see what we are working.
<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/tryna/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
First attempt, just ask for the system prompt.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/tryna/straightask.png" title="Straight Ask" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Let's try a little impersonation to try and convince it.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/tryna/devimp.png" title="Dev impersonation" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Another useful trick is asking for translation.  Let's give it a whirl.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/tryna/translate.png" title="Translate" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Now, we can try to get it to verify a code that we tell it we have.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/tryna/verifycode.png" title="Verify Code" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Let's try asking for context clues and maybe we can guess the code.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/tryna/contextclues.png" title="Context Clues" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Let's ask for a descryption key.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/tryna/askdecrypt.png" title="Ask for Decryption Key" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Well, since it said it needs a promo code, so let's ask for that.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/tryna/askpromo.png" title="Ask for Promo Code" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Hey! It gave us the code.  Let's submit that back and get the decryption key.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/tryna/stealdecrypt.png" title="Steal Decryption Key" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Hope you enjoyed the read.  Let me know how it goes!