---
layout: page
title: Mathematics
description: Completed a math pop quiz.
img: 
importance: 5
category: HTB Challenges
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/mathematics/logo.png" title="HTB Mathematics" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/challenges/818">Room Link</a>

<br/>
<h2>Process</h2>

<br />
No pun for this one.

The only question that was of any note was the third one.  Asking how to create a negative number by adding two positive numbers. This has to do with how signed integers work.  If you overflow the signed integer, it will wrap around and become negative.  So, if you take 2147483647, which is at the UBOUND, and add 1, which will cause the overflow, the sum will be 2147483648, which is a negative number.

{% capture summe %}
┌──(kali㉿kali)-[~]
└─$ nc 94.237.122.241 36612

        🎉 ~~ w3lC0m3 2 tH3 M4th3M4tR1kCs c0nt35t ~~ 🎉

                        ■ ■ ■ ■ ■ ■ ■
                        ■           ■
                        ■ 1. Play   ■
                        ■ 2. Rules  ■
                        ■           ■
                        ■ ■ ■ ■ ■ ■ ■

                        🥸 2

                        ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■
                        ■                                                                     ■
                        ■  Solve the math questions to get the flag, some of them are tricky! ■
                        ■                                                                     ■
                        ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■

                        ■ ■ ■ ■ ■ ■ ■
                        ■           ■
                        ■ 1. Play   ■
                        ■ 2. Rules  ■
                        ■           ■
                        ■ ■ ■ ■ ■ ■ ■

                        🥸 1

                🎉 ~~ Let the game begin! ~~ 🎉

                Q1: 1 + 1 = ?

                > 2

                [+] THAT WAS AMAZING!

                Q2: 2 - 1 = ?

                > 1

                [+] WE HAVE A MATHEMATICIAN AMONG US!

                Q3: 1337 - 1337 = ?

                > 0

                [+] GOD OF MATHS JUST ENTERED THE CHAT..

                Q4: Enter 2 numbers n1, n2 where n1 > 0 and n2 > 0 and n1 + n2 < 0

                n1: 2147483647                               

                n2: 1
<redacted>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=summe %}

<br />
And, after reflecting on this question, you want to know what is odd?  Both number in the answer!  You will never escape my puns.  Deal with it.