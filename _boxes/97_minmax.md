---
layout: page
title: MinMax
description: Identify smallest and largest numbers in dataset.
img: 
importance: 4
category: HTB Challenges
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/minmax/logo.png" title="HTB MinMax" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/challenges/MinMax">Room Link</a>

<br/>
<h2>Process</h2>

<br/>
I ain't affraid of ghosts.  Big or small.  Here we go with MinMax.

Launch the programming interface.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/minmax/interface.png" title="Programming Interface" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Develop the code to find the max and min.

{% capture pythoncode %}
# take in the number
n = list(map(float,input().split()))

# calculate answer

# print answer
print(min(n))
print(max(n))
{% endcapture %}
{% include terminal.html language='python' title='python' content=pythoncode %}

<br />
Run the code and get the flag.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/minmax/getflag.png" title="Get Flag" class="img-fluid rounded z-depth-1" %}
    </div>
</div>