---
layout: post
title: "Purple Team Analysis: Web Investigation Lab"
date: 2025-11-04
description: "Discovering the full picture of the attack."
tags: [purple-team,blue-team,web-security,incident-response,sql-injection]
categories: purple-team
related_posts: false
---

<div class="row justify-content-sm-center">
    <div class="col-sm-4 mt-3 mt-md-0">
        {% include figure.liquid loading="eager" path="/assets/img/firstpurpleblogpost/logo.png" title="Purple Team Analysis" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

<br />
<h2>Link</h2>
<ul>
    <li>
        <a href="https://cyberdefenders.org/blueteam-ctf-challenges/web-investigation/">CyberDefenders Page</a>
    </li>
    <li>
        <a href="{{ '/boxes/85_webinvestigation/' | relative_url }}">Solution Write-up</a>
    </li>
</ul>

<br />
## The Scenario.
Here we go, showing up to the **Security Operations Center(SOC)** for BookWorld at the start of our shift as a cybersecurity analyst.  Our company is renowned across the world for its selection, which is vast and varied.  Outstanding.  We also take great pride in smooth and secure shopping experience for bookophiles on this big, blue space rock.  Late at night on this particular night (attackers do not seem to have consideration for time zones, jerks), there was an increase in database usage and server resource usage. This could be a malicious attack so we have to start an **investigation** posthaste.  We were provided a .pcap to be able to analyze network traffic to figure out what happened.  Since we are looking at this with a purple lens, we will start with analysing the **Red Team Methodology**.

<br />
## Executive Summary
The first action that the attackers did was to test our search page for **SQL Injection** with a `test test`.  Then, they started tapping into the information_schema to get an idea of the database structure.  After this, they started exfiltrating our database by dumping the customer table.  The attacker then performed directory enumeration to discover our admin panel.  Moving on, they used **weak credentials** to gain access as an administrator.  Finally, they were able to upload a malicious PHP file because we allowed **unrestricted file uploads**.  This was the point that it was handed over to **Computer Emergency Response Team (CERT)** who took over the investigation from there.

<br />
## The Red Team View

### Step 1: SQL Injection & Data Exfiltration
<br />
**What the attacker did**<br />
The attacker ran **SQLMap** to exploit our database.  The first thing they did was to test the database to confirm that the exploit actually exists.  This is a good place as any to start.  After this, they queried the information_schema to get the list the databases available in the RDBMS.  They discovered our bookworld_db.  They can now query this DB to get the list of tables.  They discovered our customers table, which unfortunately contained our sensitive customer data.  Now, that they have our juicy table, they can get the columns and start the data exfiltration to dump our data and steal our customer's sensitive information.

<br />
**Why it worked**<br />
Well, I am working **black box testing** here, so I can give you general recommendations related to SQL Injection.  SQL Injection is typically caused by taking untrusted user input and injecting it directly into native queries.  This means that the user, or attacker (in this case), can submit any string, even one that could modify the underlying query.  One fix for this is to use **stored procedures** or **parameterized queries** instead of native queries.  These won't be modified by malformed input.  The next remediation would be **input sanitization**.  Never trust the user supplied input.  The final defense you can implement is some sort of IDS/IPS system that can monitor traffic for attack strings.  The optimal strategy is multiple defense mechanisms just incase one fails.  This is what we call **defense-in-depth**.

<br />
**Tools used**
- [sqlmap](/tools/6_sqlmap/)

### Step 2: Directory Enumeration & Credential Abuse

<br />
**What the attacker did**<br />
The attacker then decided to brute-force our directories looking for more things that they could abuse.  Therefore, they ran **gobuster** with the extension flag to maximize what they were able to find.  Our /admin directory returns a 302 redirect that redirects to /admin/.  This way the attacker now knows about the admin section now exists.  They were able to login to our admin account due to **weak credentials**.  Now, they have admin access to our web application.

<br />
**Why it worked**<br />
First things first, enforce a password policy to remove **weak credentials** that the attackers could exploit.  This is even more pertinent for admin accounts which carry elevated privileges.  The recommended policy is to use a passphrase instead of a password because the passphrase length, complexity greatly increase the time to crack or brute.  Plus, they are usually easier to remember so users are more likely to comply.  Another defensive tactic we can employ is request throttling to make brute-forcing more painful for an attacker.  We can also not use generic, guessable names like admin.  The final defense tactic that I will recommend is restrict the admin section to the intranet so attackers can't access it from the public internet.

<br />
**Tools used**
- [gobuster](/tools/7_gobuster/)

### Step 3: Malicious File Upload & Remote Code Execution

<br />
**What the attacker did**<br />
Since the attacker now has access to our admin, then can then start probing for the different functionalities our administrator can perform.  They were able to discover an **unrestricted file upload**, which allowed them to upload any file that they wanted.  Since they finger-printed our technology, this means that they could craft a PHP reverse shell and upload it to our site.  After setting up some kind of c2 server to catch the connection, they were able to craft an appropriate PHP and upload it.  After connecting to the uploaded file, the server executed the PHP code and they were able to catch the shell.  This would give them full **Remote Command Execution (RCE)**

<br />
**Why it worked**<br />
We have a file upload process that allow for any file to be uploaded.  The first remediation that we could implement would be extension blacklists and whitelists.  We have no reason to allow PHP files to be uploaded so we can restrict all of those files.  Plus, if we know the expected file types, we can implement a whitelist so we know what is coming in.  The final security measure that I will recommend is changing that uploads section to not be executable.  Code should never be able to execute out of there.

<br />
**Tools used**
- Some kind of text editor, probably.

## Blue Team View: How to Detect This

<br />
**Web Server Access Logs (Directory Brute-Force)**<br />
```
What to look for: Lots of 404 requests in an unreasonable amount of time.
Example: Same IP hitting /admin, /backup, /test, especially mostly 404s.
```

<br />
**Web Server Access Logs (SQL Injection)**<br />
```
What to look for: Requests contain **SQLi** keywords.
Example: Requests containing union select, information schema, and other common phrases.
```

<br />
**Individual Requests**
```
What to look for: Suspicious User-Agents of known hacker tools.
Example: In this attack, the User-Agents indicated that they were **gobuster** and **sqlmap**.
```

<br />
**Authentication Logs**
```
What to look for: Multiple failed login attempts followed by a successful one.
Example: Multiple attempts in a time not consistent with human logins could indicate **credential stuffing** or **brute-force attacks**.
```

<br />
**File System / Upload Logs:**
```
What to look for: PHP files uploaded to web-accessible directories
Example: Any PHP file found in the uploads directory.  Users shouldn't be uploading PHP files.
```

<br />
### Detection Ideas

**For SQL Injection**
- Monitor for SQLi keywords in all HTTP parameters and POST data parameters (union, select, information_schema, 1=1)
- Create alerts on database errors from our applications logs that can then be investigated.
- Monitor for abnormal database volume, which we do here a BookWorld.  It is what triggered our investigation.

**Implementation note:** These detections could be built in a SIEM like Splunk, Elastic, or even with basic log grep/awk scripts depending on your environment. As I continue learning blue team tools, I'm working on translating these concepts into actual queries.

<br />
**For Directory Brute-Force**
- Alert if single IP generates 50+ 404 requests in 5 minutes, it is unlikely a bunch of typos.
- Set flags for scanning tools found in the user-agent (gobuster, dirb, dirbuster).
- Monitor web logs for 404->200 patterns.

<br />
**For Weak Credential Abuse**
- Set a base line number of request fails and flag anything above the **heuristic** baseline.
- Alert on multiple failed login attempts in an unreasonable amount of time indicating automation.
- Monitor unusual IPs or locations accessing the admin panel.

<br />
**For Malicious Upload**
- Block executable extensions in upload directory.
- Alert on file creation in web directories by processes other than the web server that should be creating them.
- Use file integrity monitoring on webroot.

<br />
### What I Would Do If I Saw This

**Immediate Actions To Take**
1. Block the attacker IP at the firewall/WAF.
2. Kill all of the active sessions for the compromised admin account.
3. Locate and delete the uploaded PHP shell.  Review the PHP file to know exactly what it does first.
4. Check if the shell was executed (review web server logs for requests to uploaded file).

<br />
**Investigation**
1. Check activity for the www-data (For Apache2 webserver) user for suspicious activity.
2. Review all activity from the attacker IP since the identified beginning of the attack.
3. Check the database logs.  Confirm if customer data was actually exfiltrated.
4. Examine file system for additional backdoors.
5. Perform a comprehensive review of all our admin accounts for **Indicators of Compromise (IoC)**

<br />
**Remediation**
1. Inform Legal and Customer Account Managers about the exfiltration so the appropriate comms can sent out and affected parties notified.
2. Patch the SQL Injection vulnerability (implement parameterized queries).
3. Enforce a strong password policy, reset the admin credentials. 
4. Restrict file upload extensions and make the upload directory non-executable.
5. Implement WAF rules for SQL injection and directory scanning.
6. Consider IP whitelisting for the /admin/ directory access.

<br />
## MITRE ATT&CK Techniques

| Attack Phase | MITRE Technique | How to Detect |
|--------------|----------------|---------------|
| SQL Injection | T1190 - Exploit Public-Facing Application | Monitor web logs for SQLi patterns |
| Directory Brute-Force | T1595.002 - Vulnerability Scanning | Alert on high-volume 404 errors |
| Credential Abuse | T1078 - Valid Accounts | Track failed→successful auth patterns |
| Web Shell Upload | T1505.003 - Server Software Component: Web Shell | File integrity monitoring on webroot |

<br />
## Reflections

It was funny.  As I was reviewing the .pcap in Wireshark, I was actually visualizing how I would perform the attacks and what the attacker was doing.  Reading the Wireshark actually made me excited to try the attack myself.

The best advice that I could give anyone going down this weird, purple road:

> **Know both sides.  It gives you a complete picture of what is happening.**

<br />
## Key Takeaways

- **Understanding Attacker Perspective Is Important.** Use this knowledge to guide the investigation and set priorities.  Know what comes next in the attack chain.
- **Ensure Appropriate Prevention Techniques.** Stop attacks early. Catching SQL Injection before data exfiltration prevents the entire attack chain.
- **Knowing The Sequence.** Use red team knowledge to anticipate next moves. After seeing reconnaissance, immediately check for exploitation attempts.

<br />
## Related Work

**My Investigation Write-up:** [Web Investigation Lab - Detailed Solution](/boxes/85_webinvestigation/)

**Similar Purple Team Content:**
- *More purple team analyses coming soon as I continue learning blue team detection strategies.*

Purple roads, take me home!