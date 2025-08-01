---
layout: page
title: Buffer Overflow Lab Setup
description: Setup a lab for buffer overflow.
img: 
importance: 2
category: lab setup
related_publications: false
---

<h2>Introduction</h2>
To be able to write the buffer overflow, you will need two machines.  One Linux machine that will serve as your attack machine.  There will also be a 32-bit Windows 10 machine that will be the victim machine.  You will also need to ensure that the machines sit on the same network so they can communicate with each other.  We will be using VirtualBox from Oracle to serve as our virtualization software.  This will NOT include the installation of VirtualBox.  Please refer to Oracle documentation.

<br />
<h2>Links</h2>
<a href="https://www.virtualbox.org/wiki/Downloads">https://www.virtualbox.org/wiki/Downloads</a><br />
<a href="https://www.microsoft.com/en-au/software-download/windows10">https://www.microsoft.com/en-au/software-download/windows10</a><br />
<a href="https://www.kali.org/get-kali/#kali-installer-images">https://www.kali.org/get-kali/#kali-installer-images</a><br />

<br />
<h2>Process</h2>

<h3>Kali Linux</h3>

Download a copy of the ISO from the Kali Official Website.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/linuxdownloadpage.png" title="Linux Download Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
This assumes VirtualBox version 7.  Click New at the top of the VirtualBox interface.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/clicknew.png" title="Click New" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Chose a name for the virtual machine.  Select the Kali ISO that we just downloaded.  Choose Next.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/vbselectiso.png" title="Select ISO" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose an appropriate amount of memory and processors for the virtual machine.  Choose Next.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxmemory.png" title="Set memory and cpu" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Set the hard disk space requirements.  Choose Next.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxhddspace.png" title="Set HDD space" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose Finish on the summary screen.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxchoosefinish.png" title="Choose Finish" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
If the virtual machine doesn't automatically start, start the virtual machine.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxstart.png" title="Linux Start" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose the Graphical install option.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxgraphicalinstall.png" title="Choose Graphical Install" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Select the language of your choice.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxselectlang.png" title="Select Language" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose your location.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxchooselocation.png" title="Select Location" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose the keyboard layout.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxchoosekeyboard.png" title="Select Keyboard Layout" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose your hostname.  I usually go with a blank domain.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxhostname.png" title="Choose your hostname" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Come up with your full name and username.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxusername.png" title="Choose your username" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose a password, ignore DRY, and repeat the password.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxpassword.png" title="Choose your password" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose your timezone.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxtimezone.png" title="Choose your timezone" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose to use the entire disk.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxdevsda.png" title="Choose the SDA disk" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose to install everything in a single partition.  Choose to finish the partition and save to disk.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxsinglepart.png" title="Choose Single Partition" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Confirm that you want to save the changes to the disk.  Select 'Yes' radio button.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxsavedisk.png" title="Confirm Save Disk" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Select the desktop environment and tools to install.  Wait.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxtools.png" title="Select DE and Tools" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Finally.  The tools has been install to the hard drive.  Now, install GRUB boot loader.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxinstallgrub.png" title="Install Grub" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose the device to install GRUB to.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxchoosedevice.png" title="Choose the hardware device" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click continue to reboot the machine.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxclickcontinue.png" title="Click Continue" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Download the keyring.

{% raw %}
```bash
sudo wget https://archive.kali.org/archive-keyring.gpg -O /usr/share/keyrings/kali-archive-keyring.gpg
```
{% endraw %}
<a href="https://www.kali.org/blog/new-kali-archive-signing-key/">https://www.kali.org/blog/new-kali-archive-signing-key/</a>

<br />
Update the machine.

{% raw %}
```bash
┌──(kali㉿kali)-[~]
└─$ sudo apt -y update && sudo apt -y full-upgrade                                                        
Get:1 http://kali.download/kali kali-rolling InRelease [41.5 kB]
Get:2 http://kali.download/kali kali-rolling/main amd64 Packages [21.0 MB]
Get:3 http://kali.download/kali kali-rolling/main amd64 Contents (deb) [51.4 MB]                                                                                                                                                           
Get:4 http://kali.download/kali kali-rolling/contrib amd64 Packages [117 kB]                                                                                                                                                               
Get:5 http://kali.download/kali kali-rolling/contrib amd64 Contents (deb) [327 kB]                                                                                                                                                         
Get:6 http://kali.download/kali kali-rolling/non-free amd64 Packages [198 kB]                                                                                                                                                              
Get:7 http://kali.download/kali kali-rolling/non-free amd64 Contents (deb) [911 kB]                                                                                                                                                        
Get:8 http://kali.download/kali kali-rolling/non-free-firmware amd64 Packages [10.8 kB]                                                                                                                                                    
Get:9 http://kali.download/kali kali-rolling/non-free-firmware amd64 Contents (deb) [26.7 kB]

<snip>
```
{% endraw %}

<br />
Power down the machine.

<br />
<h3>Windows 10 (32-bit)</h3>
***Note: Windows 10 is reaching EOL***
***Second Note: Steps may vary based on host machine***

<br />
Download the Windows 10 installation media tool from the Microsoft download page.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/windownloadpage.png" title="Windows Download Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run the MediaCreationTool_22H2 and click 'Yes' on the UAC prompt.  Accept the License terms if you accept the terms.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/wineula.png" title="Windows EULA Terms" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Chose the radio button for to create an iso.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/wincreateiso.png" title="Windows Create ISO" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Unselect 'Use the recommended options for this PC' and select '32-bit (x86)' option for the Architecture.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winchoosearch.png" title="Windows Choose Architecture" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose the radio button for ISO.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winchooseiso.png" title="Windows Choose ISO" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose the file name and save location for the ISO.  Please wait because it will take some time.  Click Finish to wrap it up.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/wingeniso.png" title="Windows Generate ISO" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click New at the top of the VirtualBox interface.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/clicknew.png" title="Click New" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Chose a name for the virtual machine.  Select the Windows ISO that we just created.  Select Skip unintended installation.  Choose Next.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/vbselectwiniso.png" title="Select ISO" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose an appropriate amount of memory and processors for the virtual machine.  Choose Next.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxmemory.png" title="Set memory and cpu" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Set the hard disk space requirements.  Choose Next.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/lxhddspace.png" title="Set HDD space" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click Finish to end the set-up.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winfinishsetup.png" title="Finish Set-up" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
If the virtual machine doesn't automatically start, start the virtual machine.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winstart.png" title="Windows Start" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on the Next button.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winclickstart.png" title="Click Next" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on the Install Now button.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winclickinstall.png" title="Click Install Now" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on 'I don't have a product key.'

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winproductkey.png" title="No Product Key" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Select a version of Windows that matches the 'victim' machine.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winversionselect.png" title="Version Select" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Accept the license terms.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winacceptterms.png" title="Select Terms" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose the custom install option.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/wincustominstall.png" title="Select Terms" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Select the new button to create the partitions.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winclicknew.png" title="Click New" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click Apply to set the partition size.  Click OK on the resulting pop-up.  Highlight the primary partition and click next.  It will take awhile and restart automatically.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winclickapply.png" title="Click Apply" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Select the Region.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winselectregion.png" title="Select Region" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Select the Keyboard.  Skip the second layout.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winselectkeyboard.png" title="Select Keyboard" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Select the license agreement...again.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winseclicense.png" title="Accept license" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Right-click the two computers in the lower right-hand corner and select Connect Network Adapter to disable the network.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/windisablenetwork.png" title="Disable Network" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Select the Set up for personal use option.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winpersonaluse.png" title="Select personal use" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose the username.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winchoosename.png" title="Choose Username" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose a passowrd.  Click Next.  Re-enter the password.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winchoosepassword.png" title="Choose Password" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose answer for the security questions.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winanswerquestions.png" title="Answer Questions" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Turn off all the tracking type of options.  Select Not Now for the Cortana option.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winturnoffoptions.png" title="Turn Off Options" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
What for it to finish installing and repeat the network option from above to turn the networking back on.  For the pop-up box click on all the continues and Coninue Without Data until it goes away.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winclickwodata.png" title="Click Though" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Install Google Chrome.  This is optional.  You can use Edge, if you want to.  You can leave other browswers behind.  Because if your browsers don't browse, and if they don't browse, then they are no browser of mine!

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/wininstallchrome.png" title="Install Chrome" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://www.google.com/intl/en_au/chrome/">https://www.google.com/intl/en_au/chrome/</a>

<br />
Download the Windows SDK installer so we can install WinDBG.  WinDBG is my debugger of choice.  You can use whichever you prefer.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/windbg.png" title="Download Windows SDK" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<a href="https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/">https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/</a>

<br />
Launch the installler.  Choose all of the default options.  When you get to the install options, I usually just install everything.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/wininstallwindbg.png" title="Install WinDBG" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose it insert the VirtualBox Guest Additions ISO.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/wininsertadditions.png" title="Insert ISO" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Navigate to the ISO we just inserted.  Run the option for x86 since we are on a 32-bit system.  A reboot will be required so just shut down the machine so we can set-up networking.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/winnavtools.png" title="Navigate to Folder" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h3>Networking</h3>

<br />
Click on the hamburger button on top and click on the networking option.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/netclicknetwork.png" title="Click Network" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click the Create button to create a Nat Network.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/netclickcreate.png" title="Click Create" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
On the NAT Networks, set the server information with IP range that you can differentiate from the normal network.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/netcreatenat.png" title="Create NAT Network" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
On the Settings screen, set the Linux virtual machine Network to NAT Network and choose the network we just created.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/netsetlinux.png" title="Set Linux Network" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
On the Settings screen, set the Windows virtual machine Network to NAT Network and choose the network we just created.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/netsetwindows.png" title="Set Windows Network" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
From the Windows machine, ping the Linux machine to make sure that you can connect to it.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/netwintestlinux.png" title="Check Windows Connection" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
On the Windows Security screen, disable all of the firewalls.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/netdisablesecurity.png" title="Disable Firewalls" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
From the Linux machine, ping the Windows machine to make sure that your connect to it.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/boflab/netlinuxtestwindows.png" title="Check Linux Connection" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
And with that, we should be good to go to set up the vulnerable software and get started.