---
layout: page
title: Questionaire
description: Took a pop quiz, hotshot.
img: 
importance: 5
category: HTB Challenges
team: Red Team Labs
related_publications: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/questionaire/logo.png" title="HTB Questionaire" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<h2>Link</h2>
<a href="https://app.hackthebox.com/challenges/460">Room Link</a>

<br/>
<h2>Process</h2>

<br />
Do you have time for a questionaire?  Well, I do so we can crush this challenge.

Try connecting to the IP:Port and see what it says.

{% capture firstconnect %}
┌──(kali㉿kali)-[~]
└─$ nc 94.237.48.12 47617                         

This is a simple questionnaire to get started with the basics.                                                                                                                                                                             
                                                                                                                                                                                                                                           
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  When compiling C/C++ source code in Linux, an ELF (Executable and Linkable Format) file is created.  ◉                                                                                                                                  
◉  The flags added when compiling can affect the binary in various ways, like the protections.          ◉                                                                                                                                  
◉  Another thing affected can be the architecture and the way it's linked.                              ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  If the system in which the challenge is compiled is x86_64 and no flag is specified,                 ◉                                                                                                                                  
◉  the ELF would be x86-64 / 64-bit. If it's compiled with a flag to indicate the system,               ◉                                                                                                                                  
◉  it can be x86 / 32-bit binary.                                                                       ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  To reduce its size and make debugging more difficult, the binary can be stripped or not stripped.    ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  Dynamic linking:                                                                                     ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  A pointer to the linked file is included in the executable, and the file contents are not included   ◉                                                                                                                                  
◉  at link time. These files are used when the program is run.                                          ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  Static linking:                                                                                      ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  The code for all the routines called by your program becomes part of the executable file.            ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  Stripped:                                                                                            ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  The binary does not contain debugging information.                                                   ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  Not Stripped:                                                                                        ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  The binary contains debugging information.                                                           ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  The most common protections in a binary are:                                                         ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  Canary: A random value that is generated, put on the stack, and checked before that function is      ◉                                                                                                                                  
◉  left again. If the canary value is not correct-has been changed or overwritten, the application will ◉                                                                                                                                  
◉  immediately stop.                                                                                    ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  NX: Stands for non-executable segments, meaning we cannot write and execute code on the stack.       ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  PIE: Stands for Position Independent Executable, which randomizes the base address of the binary     ◉                                                                                                                                  
◉  as it tells the loader which virtual address it should use.                                          ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  RelRO: Stands for Relocation Read-Only. The headers of the binary are marked as read-only.           ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  Run the 'file' command in the terminal and 'checksec' inside the debugger.                           ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  The output of 'file' command:                                                                        ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  ✗ file test                                                                                          ◉                                                                                                                                  
◉  test: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,                       ◉                                                                                                                                  
◉  interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5a83587fbda6ad7b1aeee2d59f027a882bf2a429,     ◉                                                                                                                                  
◉  for GNU/Linux 3.2.0, not stripped.                                                                   ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  The output of 'checksec' command:                                                                    ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  gef➤  checksec                                                                                       ◉                                                                                                                                  
◉  Canary                        : ✘                                                                    ◉                                                                                                                                  
◉  NX                            : ✓                                                                    ◉                                                                                                                                  
◉  PIE                           : ✘                                                                    ◉                                                                                                                                  
◉  Fortify                       : ✘                                                                    ◉                                                                                                                                  
◉  RelRO                         : Partial                                                              ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉                                                                                                                                  
                                                                                                                                                                                                                                           
[*] Question number 0x1:                                                                                                                                                                                                                   
                                                                                                                                                                                                                                           
Is this a '32-bit' or '64-bit' ELF? (e.g. 1337-bit)                                                                                                                                                                                        
                                                                                                                                                                                                                                           
>>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=firstconnect %}

<br />
Answer the first question.  You can get the answer from the file output in the text box from the banner.

{% capture ZeroOne %}
[*] Question number 0x1:                                                                                                                                                                                                                   
                                                                                                                                                                                                                                           
Is this a '32-bit' or '64-bit' ELF? (e.g. 1337-bit)                                                                                                                                                                                        
                                                                                                                                                                                                                                           
>> 64-bit                                                                                                                                                                                                                                  
                                                                                                                                                                                                                                           
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠      Correct      ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠         
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ZeroOne %}

<br />
Answer the second question.  This answer is also from the file output.

{% capture ZeroTwo %}
[*] Question number 0x2:                                                                                                                                                                                                                   
                                                                                                                                                                                                                                           
What's the linking of the binary? (e.g. static, dynamic)                                                                                                                                                                                   
                                                                                                                                                                                                                                           
>> dynamic                                                                                                                                                                                                                                 
                                                                                                                                                                                                                                           
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠      Correct      ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ZeroTwo %}

<br />
Answer the third question.  Keep using the file output at this point.

{% capture ZeroThree %}
[*] Question number 0x3:                                                                                                                                                                                                                   
                                                                                                                                                                                                                                           
Is the binary 'stripped' or 'not stripped'?                                                                                                                                                                                                
                                                                                                                                                                                                                                           
>> not stripped                                                                                                                                                                                                                            
                                                                                                                                                                                                                                           
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠      Correct      ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ZeroThree %}

<br />
Answer the fourth quetion.  For this question, you can use the gef checksec output.  Look for the checkmark.

{% capture ZeroFour %}
[*] Question number 0x4:                                                                                                                                                                                                                   
                                                                                                                                                                                                                                           
Which protections are enabled (Canary, NX, PIE, Fortify)?                                                                                                                                                                                  
                                                                                                                                                                                                                                           
>> NX                                                                                                                                                                                                                                      
                                                                                                                                                                                                                                           
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠      Correct      ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ZeroFour %}

<br />
It was at this point, we get another info text prompt for your reading pleasure.

{% capture secbox %}
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  Great job so far! Now it's time to see some C code and a binary file.                                ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  In the pwn_questionnaire.zip there are two files:                                                    ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  1. test.c                                                                                            ◉                                                                                                                                  
◉  2. test                                                                                              ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  The 'test.c' is the source code and 'test' is the output binary.                                     ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  Let's start by analyzing the code.                                                                   ◉                                                                                                                                  
◉  First of all, let's focus on the '#include <stdio.h>' line.                                          ◉                                                                                                                                  
◉  It includes the 'stdio.h' header file to use some of the standard functions like 'printf()'.         ◉                                                                                                                                  
◉  The same principle applies for the '#include <stdlib.h>' line, for other functions like 'system()'.  ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  Now, let's take a closer look at:                                                                    ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  void main(){                                                                                         ◉                                                                                                                                  
◉      vuln();                                                                                          ◉                                                                                                                                  
◉  }                                                                                                    ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  By default, a binary file starts executing from the 'main()' function.                               ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  In this case, 'main()' only calls another function, 'vuln()'.                                        ◉                                                                                                                                  
◉  The function 'vuln()' has 3 lines.                                                                   ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  void vuln(){                                                                                         ◉                                                                                                                                  
◉      char buffer[0x20] = {0};                                                                         ◉                                                                                                                                  
◉      fprintf(stdout, "\nEnter payload here: ");                                                       ◉                                                                                                                                  
◉      fgets(buffer, 0x100, stdin);                                                                     ◉                                                                                                                                  
◉  }                                                                                                    ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  The first line declares a 0x20-byte buffer of characters and fills it with zeros.                    ◉                                                                                                                                  
◉  The second line calls 'fprintf()' to print a message to stdout.                                      ◉                                                                                                                                  
◉  Finally, the third line calls 'fgets()' to read 0x100 bytes from stdin and store them to the         ◉                                                                                                                                  
◉  aformentioned buffer.                                                                                ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  Then, there is a custom 'gg()' function which calls the standard 'system()' function to print the    ◉                                                                                                                                  
◉  flag. This function is never called by default.                                                      ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  void gg(){                                                                                           ◉                                                                                                                                  
◉      system("cat flag.txt");                                                                          ◉                                                                                                                                  
◉  }                                                                                                    ◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉  Run the 'man <function_name>' command to see the manual page of a standard function (e.g. man fgets).◉                                                                                                                                  
◉                                                                                                       ◉                                                                                                                                  
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=secbox %}

<br />
Review the info box to see the source code for main.  Nick the function call name.

{% capture ZeroFive %}
[*] Question number 0x5:                                                                                                                                                                                                                   
                                                                                                                                                                                                                                           
What is the name of the custom function the gets called inside `main()`? (e.g. vulnerable_function())                                                                                                                                      
                                                                                                                                                                                                                                           
>> vuln()                                                                                                                                                                                                                                  
                                                                                                                                                                                                                                           
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠      Correct      ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ZeroFive %}

<br />
Next up, check the char buffer declaration and initialization.  That should give you the buffer size.

{% capture ZeroSix %}
[*] Question number 0x6:                                                                                                                                                                                                                   
                                                                                                                                                                                                                                           
What is the size of the 'buffer' (in hex or decimal)?                                                                                                                                                                                      
                                                                                                                                                                                                                                           
>> 0x20                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                           
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠      Correct      ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ gg()
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ZeroSix %}

<br />
Follow the chain of code.  Main calls vuln.  Vuln calls fprintf and fgets (Remember this, I would say sploiler but you are reading a walkthrough).  But if you notice there is also a function call gg, which never gets called from main or vuln.

{% capture ZeroSeven %}
[*] Question number 0x7:                                                                                                                                                                                                                   
                                                                                                                                                                                                                                           
Which custom function is never called? (e.g. vuln())                                                                                                                                                                                       
                                                                                                                                                                                                                                           
>> gg()                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                           
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠      Correct      ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠p
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ZeroSeven %}

<br />
There was a text box that I didn't save.  Oops.  It was all about buffer overflows.  And if you want, I have multiple parts of this site that walks through buffer overflows. Shameless self-promotion.

<ul>
    <li><a href="{{ '/boxes/59_bofprep/' | relative_url }}">Buffer Overflow Prep</a></li>
    <li><a href="{{ '/boxes/1_brainpan/' | relative_url }}">Brainpan</a></li>
    <li><a href="{{ '/projects/5_vanillabof/' | relative_url }}">Vanilla Projects</a></li>
</ul>

<br />
Anyway, remember when I suggested remembering fgets()?  Yeah, it the answer to 0x8.

{% capture ZeroEight %}
[*] Question number 0x8:                                                                                                                                                                                                                   
                                                                                                                                                                                                                                           
What is the name of the standard function that could trigger a Buffer Overflow? (e.g. fprintf())                                                                                                                                           
                                                                                                                                                                                                                                           
>> fgets()                                                                                                                                                                                                                                 
                                                                                                                                                                                                                                           
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠      Correct      ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ 
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ZeroEight %}

<br />
The next question can be answered from the question itself.  It literally says the breakpoint was 40 As.

{% capture ZeroNine %}
[*] Question number 0x9:                                                                                                                                                                                                                   
                                                                                                                                                                                                                                           
Insert 30, then 39, then 40 'A's in the program and see the output.                                                                                                                                                                        
                                                                                                                                                                                                                                           
After how many bytes a Segmentation Fault occurs (in hex or decimal)?                                                                                                                                                                      
                                                                                                                                                                                                                                           
>> 40                                                                                                                                                                                                                                      
                                                                                                                                                                                                                                           
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠      Correct      ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ZeroNine %}

<br />
The answer for the last question is in the text box I didn't include.  But I swear it was in there.

{% capture ZeroA %}
[*] Question number 0xa:                                                                                                                                                                                                                   
                                                                                                                                                                                                                                           
What is the address of 'gg()' in hex? (e.g. 0x401337)                                                                                                                                                                                      
                                                                                                                                                                                                                                           
>> 0x401176                                                                                                                                                                                                                                
                                                                                                                                                                                                                                           
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠      Correct      ♠                                                                                                                                                                                                                      
♠                   ♠                                                                                                                                                                                                                      
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=ZeroA %}

<br />
With the quiz crushed, we get the flag.

{% capture getflag %}
Great job! It's high time you solved your first challenge! Here is the flag!  

<redacted>
{% endcapture %}
{% include terminal.html language='bash' title='bash' content=getflag %}