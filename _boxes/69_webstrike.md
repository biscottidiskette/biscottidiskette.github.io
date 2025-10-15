---
layout: page
title: WebStrike Lab
description: Reviewed PCAP for Webshell Upload Attack.
img: 
importance: 4
category: CyberDefenders
team: Blue Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webstrike/logo.png" title="CyberDefenders WebStrike Lab" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://cyberdefenders.org/blueteam-ctf-challenges/webstrike/">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Oh no!  Looks like our server got hit with a web shell in WebStrike Lab.  Let's dive in and see what happened.

First up, let's identify the IP of the attacker from the PCAP in WireShark.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webstrike/idip.png" title="Identify the Attack's IP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Next, we can geolocate where the attack originated from based on that IP.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webstrike/findcity.png" title="Find the City" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
From the same request, we can identify the attacker's User-Agent.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webstrike/getuseragent.png" title="Get the User-Agent" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
It is also really important to find the name of the malicious shell.  We can get this from the GET request they used to trigger it.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webstrike/getfilename.png" title="Get the File Name" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
From this same request, we can also identify the folder that the file was uploaded to.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webstrike/findfolder.png" title="Find Folder" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Shortly after that GET request, the connection is made and we can get the local port, or LPORT, the attacker was using.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webstrike/getlport.png" title="Get LPORT" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Finally, we need to know what data was exfiltrated.  We can do this by following the TCP Stream and giving it a peek.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webstrike/etcpasswd.png" title="TCP Stream" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Well, well, WebStrike Lab.  Looks like you've been...Thunderstuck!  See you all in the next one!