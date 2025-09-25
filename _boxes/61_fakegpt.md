---
layout: page
title: Fake GPT Lab
description: Analyzed JS credential stealer malware
img: 
importance: 4
category: CyberDefenders
team: Blue Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/fakegpt/logo.png" title="THM Fake GPT Lab AI Generated Image" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://cyberdefenders.org/blueteam-ctf-challenges/fakegpt/">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Here we are with some kind of malicious JS trying to figure our what happened!

First things first, let's check the files that we have in the malware sample.  App.js seems like a good place to start.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/fakegpt/app.png" title="File Listing" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
The first question is asking about the encoding used on the url.  So, let's start by analyzing the app.js.  Well, there is a const variable called targets that has a parameter.  Plus, it ends in '==,' which is common in base64 encoding since the character count has to be divisible by 4.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/fakegpt/urlvar.png" title="Encoded URL" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Let's keep looking though.  If we check the crypto.js, we can tell that Base64 is definitely in use.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/fakegpt/base64.png" title="Base64 confirmation" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
One final confirmation is to decode our handy dandy, little target string.  The accomplished two things:
<ol>
<li>Confirms Base64 encoding!</li>
<li>Answers question number 2.</li>
</ol>

{% raw %}
```bash
┌──(kali㉿kali)-[~/Desktop/fakegpt]
└─$ echo 'd3d3LmZhY2Vib29rLmNvbQ==' | base64 -d                               
www.facebook.com
```
{% endraw %}

<br />
Moving on, we are asked about the html used to send the stolen data.  We let us give app.js a peek.  The sendToServer seems like a promising method to figure out how the exension is sending data to the server.  In it, we see an img tag.  So, it appears to be appending an img tag with the src set with the malicious request and payload to the document.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/fakegpt/img.png" title="Create <img> tag" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Deactivation conditions are also important when analyzing malware.  Let us check for a trigger to the deactivation.  We will try the loader.js because loaders sometimes have the deloader too.  And there is the check for the length check.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/fakegpt/deload.png" title="Deactivate Trigger" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Action time!  Which event will capture the user input through forms?  Well, let me tell you.  Back to the app.js file, directly below the if statement checking the target, is adding an event listener using the submit event.


<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/fakegpt/formevent.png" title="Form Event" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
And if you look directly below that, you will see a second event.  This time listening to the keydown event to track the key strokes.  Which is convenient since that is the next question.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/fakegpt/keyevent.png" title="Key Event" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
To find the domain, we can go back to the src since that has the malicious request.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/fakegpt/domain.png" title="Find Domain" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Now we are tasked with finding the method used to exfiltrate credentials.  I will be, there happens be a method named exfiltrateCredentials.  Remember the semicolon.  Obfuscate your malware ladies and gentlemen.  Smartly, don't trigger entropy alerts.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/fakegpt/excreds.png" title="Exfiltrate Creds" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
We can get the enctyption algorith from the crypto.js file that we found the base64 answer.  It is also used in the app.js file.  Dealer's choice, I guess.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/fakegpt/aes.png" title="AES Encyption" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Last Question.  This asks us about asking manipulating session and authentication.  Well that is usually handled by cookies.  So, let's check the manifest.  Sure enough.  We have cookie permissions.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/fakegpt/manifest.png" title="Check the manifest" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
And with that, another one bites the dust.  Hopefully, you enjoyed the read.  See you in the next one!