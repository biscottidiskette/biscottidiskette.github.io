---
layout: page
title: Web Investigation Lab
description: Reviewed PCAP for SQL Injection Attack.
img: 
importance: 4
category: CyberDefenders
team: Blue Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webinvestigation/logo.png" title="CyberDefenders WebInvestigation Lab" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://cyberdefenders.org/blueteam-ctf-challenges/web-investigation/">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
The bookworldstore had incident and we have to investigate.  You can't judge a book by its cover so let's find out what really happened. 

Time to figure out the IP of the attacker.  Open the .pcap that was presented in the box description.  If we search for odd search behaviour, like test+test, to find a potential attack.  Snag to source IP.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webinvestigation/attackip.png" title="Attack IP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Next, we can geolocate where the attack originated from based on that IP.  We can plug that IP into iplocation to get the city.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webinvestigation/findcity.png" title="Find the City" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Now, we need to find the vulnerable php script.  Since the attacker IP was probing the search.php page, this was a good candidate.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webinvestigation/searchphp.png" title="Search PHP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Keep scrolling down through the traffic until you find the first attack string.  You will also have to decode the string.  Fun fact, %20 is space.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webinvestigation/firstattackstring.png" title="First Attack String" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Search for frames that contains "search.php" since we know that this is the vulnerable script.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webinvestigation/filtersearch.png" title="Filter Search" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Reading the information_schema to get databases we are working with is a common early technique we discovering SQL Injection.  Scroll down from the string we just found until we see the proper attack string.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webinvestigation/databaseattackstring.png" title="Database Attack String" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Right-click on the request, hover over Follow, and click on HTTP Stream.  Give it a look to get the full attack string.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webinvestigation/databasefollowhttp.png" title="Database Follow HTTP Stream" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Decode the database attack string. 

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webinvestigation/databasedecode.png" title="Database Decode Attack String" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Now, that we know the juicy database (you can see it in the response above), we can get all the tables in bookworld_db.  So, scroll until you find the information_schema query that dumps the tables.  Right-click on the packet, hover over Follow, and click HTTP Stream.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webinvestigation/tableshttpstream.png" title="Tables HTTP Stream" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Review the HTTP Stream and note the customers table.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webinvestigation/tablescustomer.png" title="Tables Customers" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
The, we noticed a sensitive directory was breached.  We need to now how they discovered it.  Let's identify the program that they used to brute-force the directories.  Find the brute-force and review the User-Agent and notice the gobuster.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webinvestigation/gobusteruser.png" title="Gobuster User-Agent" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Review the attack and find the request returned something other than Not Found or Forbidden.  We eventually see a 301.  Reviewing the location with see the redirect to /admin/,

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webinvestigation/adminbrute.png" title="Admin Brute-Force" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

Filter the requests for frames that contain "/admin/" so we can find the right request.  Find the request that contains something like login that is a POST.  Check the next couple of requests to ensure that the login succeeded.  This should be right request.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webinvestigation/findlogin.png" title="Find Login Request" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Follow the HTTP Stream to see the request.  You can get the credentials from there.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webinvestigation/getadmincreds.png" title="Get Admin Creds" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
You can decode the URL encoding in Burp Suite Decode tab.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webinvestigation/decodeadmincreds.png" title="Decode Admin Creds" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Find a POST request to the admin section.  This could be the upload.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webinvestigation/findadminpost.png" title="Find Admin Post Request" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Follow the HTTP Stream and view the request.  You should be able to get the malicious file from there.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/webinvestigation/findadminpost.png" title="Find Admin Post Request" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
One more for the good guys!  See you all in the next one!