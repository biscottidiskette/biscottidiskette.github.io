---
layout: page
title: PoisonedCredentials Lab
description: Reviewed PCAP for LLMNR/NBT-NS Poisoning Attack.
img: 
importance: 4
category: CyberDefenders
team: Blue Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/poisonedcreds/logo.png" title="CyberDefenders PoisonedCredentials Lab" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://cyberdefenders.org/blueteam-ctf-challenges/poisonedcredentials/">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
I had to look-up what an LLMNR/NBT-NS Poisoning was.  So, I consulted the ChatGPT and the MITRE Framework.  I include the MITRE here for your perusal. Anyways, on to the Wireshark.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/poisonedcreds/mitre.png" title="MITRE ATT&CK" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<a href="https://attack.mitre.org/techniques/T1557/001/">https://attack.mitre.org/techniques/T1557/001/</a>

<br />
Okay so the first thing that we had to do was spot a query that was mistype originating from 192.168.232.162.  So, let's set a filter for `ip.src == 192.168.232.162 && (llmnr || nbns || mdns), where it uses our source IP and the potential poisoned protocols.  The typo <strong>should</strong> standout.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/poisonedcreds/fileshaare.png" title="Fileshaare" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Next thing we have to identify is the rogue machine in the system.  So, shortly after the Name query request, we should see the Name query response giving up the rouge IP.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/poisonedcreds/rougeip.png" title="Rouge IP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
After this, we should probably identify other potentially compromised machines.  Look for another IP that the 192.168.232.215 responds to.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/poisonedcreds/secvic.png" title="Second Victim" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Scrolling through the traffic, if we filter for the rouge IP and smb protocol, we should be able to identify an auth request and get the user name.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/poisonedcreds/janesmith.png" title="Get User Name" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Okay, now for this last one, I had to burn all the hints.  I struggled.  But if we use the ntlm.challenge.target_info filter, there is one request.  And if we drill down deep enough into the request, we should come across the NetBIOS computer name.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/poisonedcreds/computername.png" title="Computer Name" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
And with that, another attack bites the dust.  See you in the next one!