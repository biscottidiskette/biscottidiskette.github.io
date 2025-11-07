---
layout: page
title: hydra
description: Performed credential brute-force dictionary attacks.
img:
importance: 2
category: red
internal_proof: /boxes/29_cronos/
related_publications: false
---

<div class="row justify-content-sm-center">
  <div class="col-sm-4 mt-3 mt-md-0">
    {% include figure.liquid loading="eager" path="assets/img/hydra/logo.png" title="hydra" class="img-fluid rounded z-depth-1" %}
  </div>
</div>

<br />
<h2>Link</h2>
<a href="https://github.com/vanhauser-thc/thc-hydra" target="_blank" rel="noopener noreferrer">Software Link</a>

<br />
## How I used it

Hydra is the tools I use for my password dictionary attacks against all those pesky web app login forms, assuming I don't write my script.  But wait, there is more! It also does other protocols that I don't feel like scripting like ssh.

<br />
<table>
  <thead>
    <tr>
      <th>Category</th>
      <th>What I did</th>
      <th>Why I did it</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Brute-Force Password</td>
      <td>Dictionary attack against login forms.</td>
      <td>Quick wins from weak passwords.  I like low-hanging fruit.</td>
    </tr>
    <tr>
      <td>Brute-Force Usernames</td>
      <td>Enumerate valid users on WordPress/forums.</td>
      <td>Some logins differentiate between "wrong password" vs "unknown user".</td>
    </tr>
    <tr>
      <td>Brute-Force SSH</td>
      <td>Target SSH with common credentials.</td>
      <td>If SSH is open with weak passwords, easiest path to shell.</td>
    </tr>
  </tbody>
</table>

<br />
**Proof**
- [THM Hackpark](/boxes/47_hackpark/) - Cracking website admin passwords.
- [THM Mr. Robot](/boxes/24_mrrobot/) - Brute-forcing Wordpress username.
- [HTB Dog](/boxes/59_dog/) - Break into the SSH protocol.

<br />
## Commands I Use Most

<br />
**Cracking Passwords**

{% capture crackpass %}
┌──(kali㉿kali)-[~/Documents/thm/mrrobot]
└─$ hydra -l Elliot -P fsocity.dic 10.10.145.112 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.11.55%2Fwp-admin%2F&testcookie=1:The password you entered"
{% endcapture %}
{% include terminal.html language='bash' title='Crack Passwords' content=crackpass %}

<br />
**Brute-force Username**

{% capture crackuser %}
┌──(kali㉿kali)-[~/Documents/thm/mrrobot]
└─$ hydra -L fsocity.dic -p admin 10.10.11.55 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.11.55%2Fwp-admin%2F&testcookie=1:Invalid Username"
{% endcapture %}
{% include terminal.html language='bash' title='Brute-force Username' content=crackuser %}

<br />
**Break into SSH**

{% capture breakssh %}
┌──(kali㉿kali)-[~/Documents/htb/dog]
└─$ hydra -l tiffany -P /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt -t 4 10.10.11.58 ssh
{% endcapture %}
{% include terminal.html language='bash' title='Break SSH' content=breakssh %}

<br />
## What I learned the Hard Way

<br />
**Wordlist Selection Matters**<br />
Choose those wordlists carefully. Seclists offers a bunch to play with running.  You can also use CEWL to generate a custom wordlist.

<br />
**Choose the Right Fail Check**<br />
Consider what you choose as the fail check.  There have been boxes where I wasted a couple hours because hydra was the right vector but didn't work because it didn't know the right password was right.

<br />
## When hydra Let Me Down

Brute-force protections are a thing.  Sometimes, five incorrect passwords will get your account locked, or worse IP banned.  Not fun calling your customer to let them know you locked yourself out.  Be mindful when you choose to brute-force.