---
layout: page
title: Oski Lab
description: Analyzed Virustotal and Any.Run virus reports.
img: 
importance: 4
category: CyberDefenders
team: Blue Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/oski/logo.png" title="CyberDefenders Oski Lab" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://cyberdefenders.org/blueteam-ctf-challenges/oski/">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
First thing up, let's get the hash so we can search it online.

{% capture gethash %}
┌──(kali㉿kali)-[~/Desktop/oski/temp_extract_dir]
└─$ cat hash.txt       
MD5 Hash: 12c1842c3ccafe7408c23ebf292ee3d9 


Use this hash on online threat intel platforms (e.g., VirusTotal, Hybrid Analysis) to complete the lab analysis.
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=gethash %}

<br />
We can then take this hash value and plug it into VirusTotal.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/oski/virustotal.png" title="VirusTotal" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Review the VirusTotal output to find the Creation Time in the History section.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/oski/createdate.png" title="Create Date" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
If we review the Contacted URLs, we can the URL of the C2 server.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/oski/c2.png" title="C2 Server" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
In that same section, we can get the first library that the malware first requested.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/oski/library.png" title="Library" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Moving on to the any.run report, we can get the RC4 key.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/oski/rc4.png" title="RC4 Key" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
If we review the any.run run, we can get the MITRE framework Technique ID. If we click on the VPN.exe process, it will expose the Technique ID.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/oski/mitre.png" title="MITRE Technique ID" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
From this same run, you can get the delete command from the cmd command prompt.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/oski/delcommand.png" title="DLL Folder" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
If we get the cmd details, we can get the timeout time value.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/oski/timeout.png" title="Timeout" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
With that, we wrapped this one nicely.  Hopefully, you enjoyed the read.