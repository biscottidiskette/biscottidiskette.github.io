---
layout: page
title: SpookyPass
description: Extracted STRINGS to steal password.
img: 
importance: 5
category: HTB Challenges
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/spookypass/logo.png" title="HTB SpookyPass" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/challenges/SpookyPass">Room Link</a>

<br/>
<h2>Process</h2>

<br />
They're coming to get you, Barbara.  That's right a challenge called SpookyPass.

First up, let's run file to know what type of file that we are have.

{% capture file %}
┌──(kali㉿kali)-[~/Desktop/rev_spookypass]
└─$ file pass  
pass: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3008217772cc2426c643d69b80a96c715490dd91, for GNU/Linux 4.4.0, not stripped
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=file %}

<br />
Run the binary to see what it does.

{% capture firstrun %}
┌──(kali㉿kali)-[~/Desktop/rev_spookypass]
└─$ ./pass  
Welcome to the SPOOKIEST party of the year.
Before we let you in, you'll need to give us the password: biteme
You're not a real ghost; clear off!
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=firstrun %}

<br />
Run strings against the binary.  Search the list for the password.

{% capture stringspassword %}
<snip>

Welcome to the 
[1;3mSPOOKIEST
[0m party of the year.
Before we let you in, you'll need to give us the password: 
s3cr3t_p455_f0r_gh05t5_4nd_gh0ul5
Welcome inside!
You're not a real ghost; clear off!

<snip>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=stringspassword %}

<br />
Re-run the program and use the password from strings.

{% capture getflag %}
┌──(kali㉿kali)-[~/Desktop/rev_spookypass]
└─$ ./pass      
Welcome to the SPOOKIEST party of the year.
Before we let you in, you'll need to give us the password: s3cr3t_p455_f0r_gh05t5_4nd_gh0ul5
Welcome inside!
<redacted>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=getflag %}