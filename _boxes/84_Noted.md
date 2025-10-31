---
layout: page
title: Noted
description: Investigated Notepad++ artifacts after exfiltration attack.
img: 
importance: 4
category: Sherlocks
team: Blue Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/noted/logo.png" title="HTB Noted Logo" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/sherlocks/Noted">Room Link</a>

<br/>
<h2>Process</h2>

<br />
The CERT team notified us that they Noted an attack on Simon's computer.  Let's dive right on in.

The first task at hand is identifying the evironment.  We can start this by idenifying the script that Simon used for AWS operations.  If you review the config.xml, you will notice in Simon.stark's Documents folder called Dev_Ops with a perl script called AWS objects migration.

{% capture devopsfile %}

<snip>

<History nbMaxFile="10" inSubMenu="no" customLength="-1">
        <File filename="C:\Program Files\Notepad++\change.log" />
        <File filename="C:\Users\Simon.stark\Documents\Internal-DesktopApp\Prototype-Internal_Login.cs" />
        <File filename="C:\Users\Simon.stark\Documents\Dev-WebServer-BetaProd\dev2prod_fileupload.php" />
        <File filename="C:\Users\Simon.stark\Documents\Internal-DesktopApp\App_init_validation.yml" />
        <File filename="C:\Users\Simon.stark\Documents\Dev_Ops\AWS_objects migration.pl" />
    </History>

<snip>
{% endcapture %}
{% include terminal.html language='xml' title='config.xml' content=devopsfile %}

<br />
Simon had the tools to compile and run Java code so the attacker didn't have to transfer any tools to the victim machine.  But we should find the source file that was used.  If we review the session.xml, we can see that there is a file called LootAndPurge.java.  Looks like a good candidate.

{% capture malfile %}

<snip>

<File firstVisibleLine="21" xOffset="0" scrollWidth="848" startPos="1697" endPos="1697" selMode="0" offset="0" wrapCount="1" lang="Java" encoding="-1" userReadOnly="no" filename="C:\Users\Simon.stark\Desktop\LootAndPurge.java" backupFilePath="C:\Users\Simon.stark\AppData\Roaming\Notepad++\backup\LootAndPurge.java@2023-07-24_145332" originalFileLastModifTimestamp="-1354503710" originalFileLastModifTimestampHigh="31047188" tabColourId="-1" mapFirstVisibleDisplayLine="-1" mapFirstVisibleDocLine="-1" mapLastVisibleDocLine="-1" mapNbLine="-1" mapHigherPos="-1" mapWidth="-1" mapHeight="-1" mapKByteInDoc="512" mapWrapIndentMode="-1" mapIsWrap="no" />

<snip>

{% endcapture %}
{% include terminal.html language='xml' title='session.xml' content=malfile %}

<br />
If we investigate the source file, we can get the name of the final archive.

{% capture landp %}

<snip>HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
  <body><h1>Index</h1></body>
</html>

collectFiles(new File(desktopDirectory), extensions, collectedFiles);
        
        String zipFilePath = desktopDirectory + "Forela-Dev-Data.zip";
        String password = "sdklY57BLghvyh5FJ#fion_7";
        
        createZipArchive(collectedFiles, zipFilePath, password);

<snip>

{% endcapture %}
{% include terminal.html language='java' title='java' content=landp %}

<br />
As a part of this investigation, we should probably also get the last modified time of that source file.  The first thing that we need to do is get the originalFileLastModifTimestamp and the originalFileLastModifTimestampHigh file from the session.xml from earlier.

{% capture malfile %}

<snip>

<File firstVisibleLine="21" xOffset="0" scrollWidth="848" startPos="1697" endPos="1697" selMode="0" offset="0" wrapCount="1" lang="Java" encoding="-1" userReadOnly="no" filename="C:\Users\Simon.stark\Desktop\LootAndPurge.java" backupFilePath="C:\Users\Simon.stark\AppData\Roaming\Notepad++\backup\LootAndPurge.java@2023-07-24_145332" originalFileLastModifTimestamp="-1354503710" originalFileLastModifTimestampHigh="31047188" tabColourId="-1" mapFirstVisibleDisplayLine="-1" mapFirstVisibleDocLine="-1" mapLastVisibleDocLine="-1" mapNbLine="-1" mapHigherPos="-1" mapWidth="-1" mapHeight="-1" mapKByteInDoc="512" mapWrapIndentMode="-1" mapIsWrap="no" />

<snip>

{% endcapture %}
{% include terminal.html language='xml' title='session.xml' content=malfile %}

<br />
After a significant amount of Googling, and trying to explain it to ChatGPT who kept telling me that it wasn't possible, finally ChatGPT came up with a script to do the coversion for us.

{% capture convpy %}
low_signed = -1354503710
low = (low_signed + (1<<32)) & 0xFFFFFFFF
high = 31047188
filetime = (high << 32) | low
import datetime
unix_secs = (filetime / 10_000_000) - 11644473600
print("UTC:", datetime.datetime.utcfromtimestamp(unix_secs).isoformat(" "))
{% endcapture %}
{% include terminal.html language='python' title='convert.py' content=convpy %}

<br />
Running this code in a REPL will produce the following output.

{% capture timecode %}
<stdin>:1: DeprecationWarning: datetime.datetime.utcfromtimestamp() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.fromtimestamp(timestamp, datetime.UTC).
UTC: 2023-07-24 09:53:23.322723
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=timecode %}

<br />
If you are still frustrated, no worries at all.  I have included some sources for further reading.  Hopefully, these let the lightbulb click so to speak.

<ul>
    <li><a href="https://0xdf.gitlab.io/2024/06/13/htb-sherlock-noted.html">https://0xdf.gitlab.io/2024/06/13/htb-sherlock-noted.html</a></li>
    <li><a href="https://community.notepad-plus-plus.org/topic/22662/need-explanation-of-a-few-session-xml-parameters-values/7">https://community.notepad-plus-plus.org/topic/22662/need-explanation-of-a-few-session-xml-parameters-values/7</a></li>
</ul>

<br />
If it makes you feel any better, the next two are chip shots after that one.  We need to find the crypto wallet address for the attacker.  Well, Simon mentioned a note that triggered this investigation.  Let's give it a look and see what it says.  Looks like we have a link to a pastebin.

{% capture hacknote %}
Hello

This note is placed in your desktop and copied to other locations too. You have been hacked and your data has been deleted from your
system. We made copies of your sensitive data and uploaded to our servers. The rule is simple

                                                       YOU PAY US
                                                           AND 
                         WE DO NOT RELEASE YOUR COMPANY SECRETS TO PUBLIC AND RETURN YOUR DATA SAFELY TO YOU
						 
						 
Failiure to oblige will result in immediate data leak to the public. 



For detailed information and process , Visit any of the below links

i)  https://pastebin.ai/bigbsy36to
ii) https://pastebin.com/xmTkajd5
iii) https://pastecode.io/s/0rqtutec
{% endcapture %}
{% include codebox.html title="YOU_HAVE_BEEN_HACKED.txt" content=hacknote %}

<br />
Navigating to the pastebin in the note, reveals a promp for a password.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/noted/passwordprompt.png" title="Password Prompt" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
If you remember back from when we reviewed that Java file, there was a password file indicated in that file.  How convenient?

{% capture landp %}

<snip>

collectFiles(new File(desktopDirectory), extensions, collectedFiles);
        
        String zipFilePath = desktopDirectory + "Forela-Dev-Data.zip";
        String password = "sdklY57BLghvyh5FJ#fion_7";
        
        createZipArchive(collectedFiles, zipFilePath, password);

<snip>

{% endcapture %}
{% include terminal.html language='java' title='java' content=landp %}

<br />
The first thing to note is the Ethereum wallet ID.  The second thing to note is the contact person if we run into any issues.

{% capture walletandemail %}
If you are here then you have no other choice then to pay us. Your Sensitive DATA is in our hands and we WILL release it to PUBLIC by midnight if you don't pay us a ransom. 
 
We want 50000 $ in ETH currency by midnight. This amount is very reasonable as we know FORELA is a multi million dollar company, but since we were able to extort small amount of data, this is our final offer. 
 
Ethereum wallet : 0xca8fa8f0b631ecdb18cda619c4fc9d197c8affca
 
Person of contact :  CyberJunkie@mail2torjgmxgexntbrmhvgluavhj7ouul5yar6ylbvjkxwqf6ixkwyd.onion
{% endcapture %}
{% include terminal.html language='browser' title='https://pastebin.com/xmTkajd5' content=walletandemail %}

<br />
With that, we Noted all the answers to this Sherlock!  I look forward to seeing you in the next one!