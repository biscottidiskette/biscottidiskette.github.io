---
layout: page
title: sqlmap
description: Performed automated SQL Injection attacks.
img:
importance: 3
category: red
internal_proof: /boxes/56_love/
related_publications: false
---

<div class="row justify-content-sm-center">
  <div class="col-sm-4 mt-3 mt-md-0">
    {% include figure.liquid loading="eager" path="assets/img/sqlmap/logo.png" title="SQLMap" class="img-fluid rounded z-depth-1" %}
  </div>
</div>

<br />
<h2>Link</h2>
<a href="https://sqlmap.org/" target="_blank" rel="noopener noreferrer">Software Link</a>

<br />
## How I used it

SQLMap answers the SQL injection question fast: Is this parameter vulnerable? If yes, dump everything. It's the lazy (and smart) way to exploit SQL injection without manually crafting payloads.

<br />
<table>
  <thead>
    <tr>
      <th>Category</th>
      <th>What I use</th>
      <th>Why I chose it</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Dump All</td>
      <td>Dump everything using the all switch.</td>
      <td>When I don't know what I'm looking for or just want everything fast.  It might be lazy, but it is effective.</td>
    </tr>
    <tr>
      <td>Database Dump</td>
      <td>Dump database via SQL Injection.</td>
      <td>Trying to dump the user table to get a user password hash, for cracking purposes.</td>
    </tr>
  </tbody>
</table>

<br />
**Proof** 
- [THM GameZone](/boxes/34_gamezone/) - Dumping the database.
- [HTB Love](/boxes/56_love/) - Grab everything using the all option.

<br />
## Commands I commonly use

<br />
**Exploit with All Switch**

{% capture allswitch %}
┌──(kali㉿kali)-[~/Documents/htb/love]
└─$ sqlmap -r request.txt --batch --level=1 --risk=3 -r request.txt --dbms=mysql -p voter --all
{% endcapture %}
{% include terminal.html language='bash' title='Exploit with the All Switch' content=allswitch %}

<br />
**Dump the Database**

{% capture dumpdb %}
┌──(kali㉿kali)-[~/Documents/thm/gamezone]
└─$ sqlmap -r request.txt --dbms=mysql --dump
{% endcapture %}
{% include terminal.html language='bash' title='Dump Database' content=dumpdb %}

<br />
## What I Learned the Hard Way

<br />
**Choose the right parameter**<br />

Getting no results because I choose the wrong parameter to check.  Ran it three time with the same results before I finally check the `request.txt` file to see my blunder.  Fixed it up and was able to get my plunder (hehe...it rhymed)! w00t w00t!

<br />
**Used the Wrong Level and Risk**

After struggling to get the results that I want, I had to play with the risk and level switch and the results magically appeared.  Wild, wild stuff.

<br />
## When sqlmap Let Me Down

Sometimes, the SQL injection is so tricky that it just requires that edge of human ingenuity to craft the right payload.