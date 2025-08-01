---
layout: page
title: Domain Set-up
description: Setup a domain for testing purposes.
img: 
importance: 2
category: lab setup
related_publications: false
---

<h2>Introduction</h2>
I recently registered for Certified Red Team Professional (CRTP) course.  To aid in my studies, I decided to set-up a personal domain lab to play and test the different methodologies from the course.  I eventaully plan on adding a SIEM and XDR for purple team adventures.  Maybe expand it out with more machines to simulate something like the PWK lab.  Either way, that will be different posts.  This will just be basic set-up.

<br />
<h2>Links</h2>
<a href="https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019">https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019</a><br />
<a href="https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise">https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise</a><br />

<br />
<h2>Process</h2>

<h3>Windows Server 2019</h3>

Download a copy of Windows Server 2019 ISO.  You can snag a copy from their download page.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servdownload.png" title="Server Download" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Boot up VirtualBox and click 'New' to create a new virtual machine.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servvboxnew.png" title="Click New" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose the ISO that we just downloaded.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servchooseiso.png" title="Choose ISO" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Set the hardware requirements for the server.  Please note, depending on your host machine hardware, your available resources might be different.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servsethardware.png" title="Set Hardware" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Set the disk space requirements.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servsetharddisk.png" title="Set Hard Disk" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click Finish to finish the creation process.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servclickfinish.png" title="Click Finish" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
At the top of the interface, click the hamburger button.  Select the Network option.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servclicknetwork.png" title="Click Network" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Create a NAT Network so the whole domain can sit on a single network and communicate.  We won't change to this network until after install so we can connect to the internet.  Changing to Bridged Network should also work for our purposes.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servcreatenatnetwork.png" title="Create NAT Network" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Since you can also use Bridged, switch to Bridged connection.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servbridgeadapter.png" title="Bridged Adapter" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Boot up the virtual machine, choose your language, and click Next.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servchooselang.png" title="Choose Language" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click the Install button to start the installation process.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servclickinstall.png" title="Click Install" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Select the Windows Server 2019 Standard Evaluation (with the Desktop) version.  Click Next.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servselectversion.png" title="Select Version" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Read the license terms, accept them, and click Next.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servacceptlicense.png" title="Read License" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Select the Custom: Install Windows only (advanced) option.  You can't upgrade since there is nothing to upgrade.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servselectcustom.png" title="Select Custom" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
On the hard drive screen, select the Drive 0 Unallocated Space option and clicked Next.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servallocatespace.png" title="Allocate Space" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
This is the point the Microsoft installer should initiate.  So, it is basically a waiting game, at this point.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servautoinstall.png" title="Installers" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Set the password for the built-in administrator account.  Follow proper password best practices.  Please note, Administrator:Administrator is not appropriate.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servsetpassword.png" title="Set Password" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Authenticate into the server with the Administrator account.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servauthserver.png" title="Authenticate Server" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click Add roles and features.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servclickaddroles.png" title="Click Add roles and features" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Totally read the Before you begin screen and when you are ready...click Next >.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servbeginsetup.png" title="Read" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose the Role-based or feature-based installation radio option.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servrolebased.png" title="Select Role-based" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Select the new server that we just created.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servselectnewserver.png" title="Select New Server" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on the check box for Active Directory Domain Services.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servchoosead.png" title="Choose Active Directory" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
On the prompt that pops up after checking, click on the Add Features button.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servaddfeatures.png" title="Add Features" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose the checkbox for DNS Server.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servchoosedns.png" title="Select DNS Server" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Another prompt will when you check DNS Server, click on the Add Features button.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servadddnsfeatures.png" title="Add Features" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
You can click Continue through the Static IP address warning.  In a production environment, you should probably resolve it.  But this is a hacking lab, so we should be ok.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servstaticwarning.png" title="Static Warning" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click Next until you get to the Confirmation screen.  Click the Checkbox for the Restart the destination server automatically if require option and Yes on the pop-up box.  Click the Install button.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servconfirmation.png" title="Confirmation" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Allow the installation to complete and close out the box.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servinstallserver.png" title="Server Installation" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Notice the Yellow exclamation point over the notification icon.  Click on it.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servnotification.png" title="New Notification" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on the option to Promote this server to a domain controller.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servpromoteserver.png" title="New Notification" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Select the radio button to choose Add a new forest.  Choose a Root domain name.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servnewforest.png" title="Create New Forest" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Set the DSRM password.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servsetdomainpassword.png" title="Set the Domain Password" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on Next until you get to the Prerequisites Check.  If everything passes with the green check, you can click Install.  Please note, that the machine will reboot because you told it to when installing the server features.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servprereq.png" title="Prerequisites" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
When the computer comes up, you should then see the domain in front of the Administrator name.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servcompletedomain.png" title="DC Connected to Domain" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
This should wrap-up the domain controller for now.  Now, time to add a Windows 10 machine to our new domain.

<br />
<h3>Windows 10</h3>

Download an evaluation copy of Windows Enterprise edition.  You can get the ISO from their download page.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/windownloadpage.png" title="Windows Download Page" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Boot up VirtualBox and click 'New' to create a new virtual machine.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servvboxnew.png" title="Click New" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose to the ISO that was just downloaded.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winchooseiso.png" title="Choose the ISO" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Set the memory space.  This will vary based on resources available on your host machine.  Set something appropriate for your situation.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winsetmemory.png" title="Set Memory" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Set the hard disk space for your virtual machine.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winsetharddisk.png" title="Set Hard Disk" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click Finish to finish the set-up process.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winclickfinish.png" title="Click Finish" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Set the Network in the Settings menu to either Bridged Adapter or the NAT Network we created earlier.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winsetnetwork.png" title="Set Network" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click the Next button to get this party started.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/wingettingstarted.png" title="Getting Started" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click the Install button since it is the only button on the screen.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winclickinstall.png" title="Click Install" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Accept the Microsoft license terms.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winacceptlicense.png" title="Accept License" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Select the Custom: Install Windows only (advanced) option to do a fresh install since no OS exists.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winselectcustom.png" title="Select Custom" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click the New to create a new partition.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winnewpartition.png" title="Click New" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click Apply to set the partition size.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winclickapply.png" title="Click Apply" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click OK on the pop-up that explains that the installer will create necessary partitions.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winackpart.png" title="Click OK" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Highlight the partition that was just created and click Next.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winselectpartition.png" title="Click Next" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
The Windows Installer will take over.  Wait.  

<br />
While Windows 10 is installing, switch back to the DC.  Open the Active Directory Users and Computers app.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servusersandcomps.png" title="Open Active Directory Users and Computers" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose to add a new user to the domain.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servdomainnewuser.png" title="Select Add New User" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Fill out all of the information for the new Paddy user in the domain.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servpopulateuserdata.png" title="Populate User Data" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Create a memorable password and repeat it.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servcreatepaddypassword.png" title="Create Paddy Password" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click Finish to finish up the user creation process.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servfinishusersetup.png" title="Finish User Set-up" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Open the run box and enter ncpa.cpl and click OK.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servopenrun.png" title="Open Run" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Right-click on the adapter and select the Properties option.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servopenadapterproperties.png" title="Open Adapter Properties" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Open the Internet Protocol Version 4 (TCP/IPv4) Properties screen.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servopenipv4properties.png" title="Open IPv4 Properties" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose the radio button for the Use the following DNS server addresses and enter the Preferred DNS server IP with the IP address of the DC.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/servupdatednsip.png" title="Update DNS IP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Change back to the Windows 10 machine.  Once the automated installation part is over, you will be prompted to choose your region.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winchooseregion.png" title="Choose Region" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose your keyboard layout.  Skip adding the second layout.  Unless you have a second one...I guess.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winchoosekeyboard.png" title="Choose Keyboard Layout" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click domain join instead.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/windomainjoin.png" title="Domain join instead" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose a name.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winchoosename.png" title="Choose Windows Name" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose a password.  And repeat it in the next screen.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winchoosepassword.png" title="Choose password" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose and answer 3 question for security purposes.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winanswerquestions.png" title="Answer Questions" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Disable all of the privacy options.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/windisableoptions.png" title="Disable Privacy Options" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Disable Cortana by clicking on the Not Now button.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/windisablecortana.png" title="Disable Corana" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on Continue or Start without your data until that irritating pop-up goes away.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winannoyingpopup.png" title="Annoying Pop-up" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Install Chrome, if you want.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/wininstallchrome.png" title="Install Chrome" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Insert the VirtualBox Guest Additions cd.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/wininsertguestadditions.png" title="Insert VirtualBox Guest Additions" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Run the x64 guest additions.  It will restart.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winrunguestadditions.png" title="Run VirtualBox Guest Additions" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Open the Control Panel and click on the Network and Intranet.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/wincontrolpanel.png" title="Windows Control Panel" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Open the Network and Sharing Center part of the Control Panel.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winnetworkandsharing.png" title="Open Network and Sharing Center" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on Change adapter settings on the left-hand side.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winchangeadapter.png" title="Change Adapter" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Right-click on the Ethernet0 and select the properties Selection.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winopenproperties.png" title="Open Properties" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Select the Internet Protocol Version 4 (TCP/IPv4) and click the Properties button.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winipv4properties.png" title="IPv4 Properties" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Choose the radio button for Use the following DNS server addresses: and update the Preferred DNS server with the IP address from the Domain Controller.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winupdatedns.png" title="Update the DNS IP" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Deselect the Internet Protocol Version 6 (TCP/IPv6).

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/windeselectipv6.png" title="Deselect IPv6" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Open the system settings screen and then open the advance system settings.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winadvancedsystems.png" title="Open Advanced System Settings" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on the Change... button.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winclickchange.png" title="Click Change..." class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Update the Computer Name and the Domain.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winupdatedomain.png" title="Update Domain" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Login with the credentials that we created on the DC.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/windomainlogin.png" title="Domain Login" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Welcome to the domain!  Wake up, time to work!

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winwelcomedomain.png" title="Welcome To The Domain" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
There should be a message box welcoming you to the domain.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winrestartprompt.png" title="Restart Prompt" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Click on the Restart Now to restart the computer.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/winrestartnow.png" title="Restart Now" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
Check the Ethernet adapter again and you should see the biscotti.diskette domain.

<div class="row justify-content-sm-center">
    <div class="col-sm-8 mt-3 mt-md-0">
        {% include figure.liquid path="assets/img/domain/wincheckadapter.png" title="Check adapter domain" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
And with that, we are connected to the domain.  Hopefully you enjoyed the read.  See you in the next one!

<br />
<h2>References</h2>
<a href="https://windowsreport.com/windows-cannot-find-the-microsoft-license-software-terms/">https://windowsreport.com/windows-cannot-find-the-microsoft-license-software-terms/</a><br />
<a href="https://www.youtube.com/watch?v=pRf_uU0vrMM">https://www.youtube.com/watch?v=pRf_uU0vrMM</a>