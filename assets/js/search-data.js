// get the ninja-keys element
const ninja = document.querySelector('ninja-keys');

// add the home and posts menu items
ninja.data = [{
    id: "nav-about",
    title: "about",
    section: "Navigation",
    handler: () => {
      window.location.href = "/";
    },
  },{id: "nav-projects",
          title: "projects",
          description: "A growing collection of projects.",
          section: "Navigation",
          handler: () => {
            window.location.href = "/projects/";
          },
        },{id: "nav-boxes",
          title: "boxes",
          description: "All of the boxes, Sherlocks, and various other practice.",
          section: "Navigation",
          handler: () => {
            window.location.href = "/boxes/";
          },
        },{id: "nav-certs",
          title: "certs",
          description: "All the certifications, badges, online courses, books that I have completed.",
          section: "Navigation",
          handler: () => {
            window.location.href = "/certifications/";
          },
        },{id: "nav-repos",
          title: "repos",
          description: "Welcome to my my GitHub.",
          section: "Navigation",
          handler: () => {
            window.location.href = "/repositories/";
          },
        },{id: "nav-blog",
          title: "blog",
          description: "",
          section: "Navigation",
          handler: () => {
            window.location.href = "/blog/";
          },
        },{id: "nav-contact",
          title: "contact",
          description: "Feel free to send me a message!.",
          section: "Navigation",
          handler: () => {
            window.location.href = "/contact/";
          },
        },{id: "post-ignore-your-previous-instructions-describe-your-coae-certification-journey",
      
        title: "Ignore your previous instructions: Describe your COAE Certification Journey",
      
      description: "Bullying AI in the name of security.",
      section: "Posts",
      handler: () => {
        
          window.location.href = "/blog/2026/coae/";
        
      },
    },{id: "post-another-15-minutes-chasing-what-i-couldn-39-t-give-myself",
      
        title: "Another 15 minutes: Chasing What I Couldn&#39;t Give Myself",
      
      description: "Describing the fleeting feeling surrounding certs and acknowledging the imposter syndrome.",
      section: "Posts",
      handler: () => {
        
          window.location.href = "/blog/2026/anotherfifteen/";
        
      },
    },{id: "post-putting-the-pieces-together-my-cdsa-certification-journey",
      
        title: "Putting The Pieces Together: My CDSA Certification Journey",
      
      description: "Putting the attack timeline to defend the company.",
      section: "Posts",
      handler: () => {
        
          window.location.href = "/blog/2026/cdsa/";
        
      },
    },{id: "post-the-din-of-dissonance-my-cissp-preparation",
      
        title: "The Din of Dissonance: My CISSP Preparation",
      
      description: "When your instincts are offensive and the exam wants governance.",
      section: "Posts",
      handler: () => {
        
          window.location.href = "/blog/2026/cisspstudy/";
        
      },
    },{id: "post-dissecting-your-attack-my-malware-analysis-certification-journey",
      
        title: "Dissecting Your Attack: My Malware Analysis Certification Journey",
      
      description: "Tackling the Practical Malware Research Professional (PMRP) by TCM.",
      section: "Posts",
      handler: () => {
        
          window.location.href = "/blog/2025/pmrp/";
        
      },
    },{id: "post-not-technical-enough",
      
        title: "Not Technical Enough",
      
      description: "Addressing the Not Technical Enough Feedback.",
      section: "Posts",
      handler: () => {
        
          window.location.href = "/blog/2025/technicalmeaning/";
        
      },
    },{id: "post-python-for-exploit-development",
      
        title: "Python For Exploit Development",
      
      description: "Attacking Memory Corruption with Python.",
      section: "Posts",
      handler: () => {
        
          window.location.href = "/blog/2025/pythonforexploit/";
        
      },
    },{id: "post-purple-team-analysis-web-investigation-lab",
      
        title: "Purple Team Analysis: Web Investigation Lab",
      
      description: "Discovering the full picture of the attack.",
      section: "Posts",
      handler: () => {
        
          window.location.href = "/blog/2025/firstpurpleteam/";
        
      },
    },{id: "post-from-zero-to-oscp-my-penetration-testing-certification-journey",
      
        title: "From Zero to OSCP: My Penetration Testing Certification Journey",
      
      description: "Passing the OSCP certification exam.",
      section: "Posts",
      handler: () => {
        
          window.location.href = "/blog/2025/oscp/";
        
      },
    },{id: "post-learning-thai-language-and-discipline-outside-of-cybersecurity",
      
        title: "Learning Thai: Language and Discipline Outside of Cybersecurity",
      
      description: "Exploring my journey learning the Thai language while training in Muay Thai, using tools like LingoDeer, Anki, and Ling.",
      section: "Posts",
      handler: () => {
        
          window.location.href = "/blog/2025/learn-Thai/";
        
      },
    },{id: "post-first-post",
      
        title: "First post.",
      
      description: "A quick post about this new portfolio.",
      section: "Posts",
      handler: () => {
        
          window.location.href = "/blog/2025/first-post/";
        
      },
    },{id: "bounties-test-bounty",
          title: 'Test Bounty',
          description: "Super cool bounty that I will find eventually.",
          section: "Bounties",handler: () => {
              window.location.href = "/bounties/1_test/";
            },},{id: "boxes-enigma",
          title: 'Enigma',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/100_enigma/";
            },},{id: "boxes-reactor",
          title: 'Reactor',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/101_reactor/";
            },},{id: "boxes-cohort",
          title: 'Cohort',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/102_cohort/";
            },},{id: "boxes-smarthire",
          title: 'SmartHire',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/103_smarthire/";
            },},{id: "boxes-devhub",
          title: 'DevHub',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/104_devhub/";
            },},{id: "boxes-makesense",
          title: 'MakeSense',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/105_makesense/";
            },},{id: "boxes-social-media-investigation-hub",
          title: 'Social Media Investigation Hub',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/106_social_media_investigation/";
            },},{id: "boxes-prometheon",
          title: 'Prometheon',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/107_prometheon/";
            },},{id: "boxes-opensecret",
          title: 'OpenSecret',
          description: "Discovered hard-coded secret in source code.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/108_opensecret/";
            },},{id: "boxes-wander",
          title: 'Wander',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/109_wander/";
            },},{id: "boxes-popcorn",
          title: 'Popcorn',
          description: "Exploited file upload on torrent host",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/10_popcorn/";
            },},{id: "boxes-trynasob-ransomware",
          title: 'TrynaSob Ransomware',
          description: "Inject an LLM prompt to expose secrets.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/110_trynasob/";
            },},{id: "boxes-external-affairs",
          title: 'External Affairs',
          description: "Inject an LLM prompt to approve application.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/111_externalaffairs/";
            },},{id: "boxes-htb-blue",
          title: 'HTB Blue',
          description: "Exploited EternalBlue SMB vulnerability (MS17-010)",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/11_bluehtb/";
            },},{id: "boxes-jerry",
          title: 'Jerry',
          description: "Used default credentials to upload file via Tomcat",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/12_jerry/";
            },},{id: "boxes-haircut",
          title: 'Haircut',
          description: "Leveraged command injection vulnerability",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/13_haircut/";
            },},{id: "boxes-nibbles",
          title: 'Nibbles',
          description: "Exploited Nibbleblog public vulnerability",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/14_nibbles/";
            },},{id: "boxes-knife",
          title: 'Knife',
          description: "Exploited vulnerable PHP version",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/15_knife/";
            },},{id: "boxes-remote",
          title: 'Remote',
          description: "Discovered NFS credentials, executed authenticated exploit",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/16_remote/";
            },},{id: "boxes-blocky",
          title: 'Blocky',
          description: "Decompiled JAR to extract credentials",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/17_blocky/";
            },},{id: "boxes-bashed",
          title: 'Bashed',
          description: "Discovered exposed CLI page with RCE",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/18_bashed/";
            },},{id: "boxes-grandpa",
          title: 'Grandpa',
          description: "Abused IIS WebDAV vulnerability to execute code",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/19_grandpa/";
            },},{id: "boxes-brainpan",
          title: 'Brainpan',
          description: "Wrote buffer overflow exploit for shell",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/1_brainpan/";
            },},{id: "boxes-granny",
          title: 'Granny',
          description: "Uploaded web shell via HTTP PUT",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/20_grandma/";
            },},{id: "boxes-bof",
          title: 'Bof',
          description: "Overwrite the password on the stack.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/21_bof/";
            },},{id: "boxes-irked",
          title: 'Irked',
          description: "Leveraged UnrealIRCd exploit for RCE",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/22_irked/";
            },},{id: "boxes-optimum",
          title: 'Optimum',
          description: "Exploited HFS 2.3 public vulnerability",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/23_optimum/";
            },},{id: "boxes-mr-robot",
          title: 'Mr. Robot',
          description: "Brute-forced credentials using exposed wordlist",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/24_mrrobot/";
            },},{id: "boxes-greenhorn",
          title: 'GreenHorn',
          description: "Discovered credentials in exposed repository",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/25_greenhorn/";
            },},{id: "boxes-sense",
          title: 'Sense',
          description: "Exploited default credentials via known exploit",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/26_sense/";
            },},{id: "boxes-sau",
          title: 'Sau',
          description: "Exploited SSRF to access internal resources",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/27_sau/";
            },},{id: "boxes-boardlight",
          title: 'BoardLight',
          description: "Used default credentials with public exploit",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/28_boardlight/";
            },},{id: "boxes-cronos",
          title: 'Cronos',
          description: "SQLi auth bypass, executed command injection",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/29_cronos/";
            },},{id: "boxes-pickle-rick",
          title: 'Pickle Rick',
          description: "Discovered exposed default credentials command panel",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/2_picklerick/";
            },},{id: "boxes-solidstate",
          title: 'SolidState',
          description: "Exploited JAMES SMTP server",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/30_solidstate/";
            },},{id: "boxes-daily-bugle",
          title: 'Daily Bugle',
          description: "Exploited Joomla via public vulnerability",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/31_daily_bugle/";
            },},{id: "boxes-steel-mountain",
          title: 'Steel Mountain',
          description: "Exploited HttpFileServer 2.3 public vulnerability",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/32_steel_mountain/";
            },},{id: "boxes-alfred",
          title: 'Alfred',
          description: "Discovered exposed script panel via default credentials",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/33_alfred/";
            },},{id: "boxes-game-zone",
          title: 'Game Zone',
          description: "Used SQLMap to retrieve hash, gained SSH access",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/34_gamezone/";
            },},{id: "boxes-skynet",
          title: 'Skynet',
          description: "Discovered credentials",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/35_skynet/";
            },},{id: "boxes-overpass-2",
          title: 'Overpass 2',
          description: "Captured credentials using Wireshark",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/36_overpass2/";
            },},{id: "boxes-brainstorm",
          title: 'Brainstorm',
          description: "Wrote buffer overflow exploit",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/37_brainstorm/";
            },},{id: "boxes-corp",
          title: 'Corp',
          description: "Bypassed whitelist in application",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/38_corp/";
            },},{id: "boxes-blaster",
          title: 'Blaster',
          description: "Discovered credentials and gained RDP access",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/39_blaster/";
            },},{id: "boxes-vulnversity",
          title: 'Vulnversity',
          description: "Bypassed file upload restrictions",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/3_vulnversity/";
            },},{id: "boxes-simplectf",
          title: 'SimpleCTF',
          description: "Exploited CMS via public vulnerability",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/40_simplectf/";
            },},{id: "boxes-ignite",
          title: 'Ignite',
          description: "Exploited Fuel CMS via public vulnerability",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/41_ignite/";
            },},{id: "boxes-colddbox-easy",
          title: 'Colddbox - Easy',
          description: "Brute-forced credentials, exploited theme injection",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/42_colddbox/";
            },},{id: "boxes-billing",
          title: 'Billing',
          description: "Exploited HTTP parameter for command injection",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/43_billing/";
            },},{id: "boxes-library",
          title: 'Library',
          description: "Brute-forced SSH with Hydra",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/44_library/";
            },},{id: "boxes-ice",
          title: 'Ice',
          description: "Executed public exploit",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/45_ice/";
            },},{id: "boxes-retro",
          title: 'Retro',
          description: "Discovered credentials and executed theme code injection",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/46_retro/";
            },},{id: "boxes-hackpark",
          title: 'HackPark',
          description: "Brute-forced credentials and uploaded file",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/47_hackpark/";
            },},{id: "boxes-planning",
          title: 'Planning',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/48_planning/";
            },},{id: "boxes-titanic",
          title: 'Titanic',
          description: "Exploited LFI to steal credentials",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/49_titanic/";
            },},{id: "boxes-thm-blue",
          title: 'THM Blue',
          description: "Gained remote access via MS17-010",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/4_bluethm/";
            },},{id: "boxes-celestial",
          title: 'Celestial',
          description: "Exploited NodeJS deserialization vulnerability",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/50_celestial/";
            },},{id: "boxes-arctic",
          title: 'Arctic',
          description: "Exploited CFIDE vulnerability",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/51_arctic/";
            },},{id: "boxes-analytics",
          title: 'Analytics',
          description: "Escalated privilege via environment variables",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/52_analytics/";
            },},{id: "boxes-devvortex",
          title: 'Devvortex',
          description: "Exploited stolen credentials via password reuse",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/53_devvortex/";
            },},{id: "boxes-code",
          title: 'Code',
          description: "Bypassed Python word and import blacklists.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/54_code/";
            },},{id: "boxes-passage",
          title: 'Passage',
          description: "Exploited CuteNews public vulnerability",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/55_passage/";
            },},{id: "boxes-love",
          title: 'Love',
          description: "Exploited public vulnerability in voting system",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/56_love/";
            },},{id: "boxes-curling",
          title: 'Curling',
          description: "Exploited template injection using discovered password",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/57_curling/";
            },},{id: "boxes-openadmin",
          title: 'OpenAdmin',
          description: "Exploited Ona public vulnerability",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/58_openadmin/";
            },},{id: "boxes-dog",
          title: 'Dog',
          description: "Exploited RCE and exposed credentials.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/59_dog/";
            },},{id: "boxes-kenobi",
          title: 'Kenobi',
          description: "Retrieved private key over SMB",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/5_kenobi/";
            },},{id: "boxes-buffer-overflow-prep",
          title: 'Buffer Overflow Prep',
          description: "Practiced buffer overflow exploitation techniques",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/60_bofprep/";
            },},{id: "boxes-electricbreeze-2",
          title: 'ElectricBreeze-2',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/61_electricbreeze2/";
            },},{id: "boxes-meerkat",
          title: 'Meerkat',
          description: "Investigated PCAPs and correlated log data.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/62_meerkat/";
            },},{id: "boxes-reverse-engineering-another-injection",
          title: 'Reverse Engineering - Another Injection',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/63_anotherinjection/";
            },},{id: "boxes-phishing-analysis",
          title: 'Phishing Analysis',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/64_phishinganalysis/";
            },},{id: "boxes-malware-analysis-ransomware-script",
          title: 'Malware Analysis - Ransomware Script',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/65_randomscript/";
            },},{id: "boxes-bumblebee",
          title: 'Bumblebee',
          description: "Examined databases and correlated log data.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/66_bumblebee/";
            },},{id: "boxes-fake-gpt-lab",
          title: 'Fake GPT Lab',
          description: "Analyzed JS credential stealer malware",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/67_fakegpt/";
            },},{id: "boxes-brutus",
          title: 'Brutus',
          description: "Analyzed logs and identified brute-force.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/68_brutus/";
            },},{id: "boxes-webstrike-lab",
          title: 'WebStrike Lab',
          description: "Reviewed PCAP for Webshell Upload Attack.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/69_webstrike/";
            },},{id: "boxes-cap",
          title: 'Cap',
          description: "Leveraged IDOR to access cleartext credentials",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/6_cap/";
            },},{id: "boxes-the-report",
          title: 'The Report',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/70_thereport/";
            },},{id: "boxes-iloveyou",
          title: 'ILOVEYOU',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/71_iloveyou/";
            },},{id: "boxes-melissa",
          title: 'MELISSA',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/72_melissa/";
            },},{id: "boxes-spookypass",
          title: 'SpookyPass',
          description: "Extracted STRINGS to steal password.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/73_spookypass/";
            },},{id: "boxes-questionaire",
          title: 'Questionaire',
          description: "Took a pop quiz, hotshot.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/74_questionaire/";
            },},{id: "boxes-mathematics",
          title: 'Mathematics',
          description: "Completed a math pop quiz.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/75_mathematics/";
            },},{id: "boxes-phishing-analysis-2",
          title: 'Phishing Analysis 2',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/76_phishinganalysis2/";
            },},{id: "boxes-powershell-analysis-keylogger",
          title: 'PowerShell Analysis Keylogger',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/77_powershellkeylogger/";
            },},{id: "boxes-behind-the-scenes",
          title: 'Behind The Scenes',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/78_behindthescenes/";
            },},{id: "boxes-poisonedcredentials-lab",
          title: 'PoisonedCredentials Lab',
          description: "Reviewed PCAP for LLMNR/NBT-NS Poisoning Attack.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/79_poisonedcreds/";
            },},{id: "boxes-lame",
          title: 'Lame',
          description: "Exploited distcc service for remote code execution",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/7_lame/";
            },},{id: "boxes-oski-lab",
          title: 'Oski Lab',
          description: "Analyzed Virustotal and Any.Run virus reports.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/80_oski/";
            },},{id: "boxes-phishnet",
          title: 'PhishNet',
          description: "Analysed a phishing email and attachment.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/81_phishnet/";
            },},{id: "boxes-meta",
          title: 'Meta',
          description: "Reviewed jpeg metedata and reverse image search.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/82_meta/";
            },},{id: "boxes-att-amp-ck",
          title: 'ATT&amp;amp;CK',
          description: "Mapped adversary tactics using MITRE ATT&amp;CK.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/83_attack/";
            },},{id: "boxes-noted",
          title: 'Noted',
          description: "Investigated Notepad++ artifacts after exfiltration attack.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/84_Noted/";
            },},{id: "boxes-web-investigation-lab",
          title: 'Web Investigation Lab',
          description: "Reviewed PCAP for SQL Injection Attack.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/85_webinvestigation/";
            },},{id: "boxes-bank",
          title: 'Bank',
          description: "Abused PHP file upload functionality.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/86_bank/";
            },},{id: "boxes-unit42",
          title: 'Unit42',
          description: "Reviewed event logs for malware distribution.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/87_unit42/";
            },},{id: "boxes-jeeves",
          title: 'Jeeves',
          description: "Abused Jenkins Script Console.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/88_jeeves/";
            },},{id: "boxes-beep",
          title: 'Beep',
          description: "Exploited Elastix LFI vulnerability.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/89_beep/";
            },},{id: "boxes-legacy",
          title: 'Legacy',
          description: "Exploited SMB vulnerability (MS08-067) for RCE",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/8_legacy/";
            },},{id: "boxes-codeparttwo",
          title: 'CodePartTwo',
          description: "Exfilitrated Exposed Users Database.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/90_codeparttwo/";
            },},{id: "boxes-monitorstwo",
          title: 'MonitorsTwo',
          description: "Exfilitrated Exposed Users Database.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/91_monitorstwo/";
            },},{id: "boxes-cred-hunter",
          title: 'Cred Hunter',
          description: "Created Script To Analyze Data Dump.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/92_credhunter/";
            },},{id: "boxes-pinsmith",
          title: 'PINsmith',
          description: "Programmed a Python to Fix Data.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/93_pinsmith/";
            },},{id: "boxes-webvault-time-machine-investigation",
          title: 'WebVault Time Machine Investigation',
          description: "Performed Historical Web Intestigation Using Archives.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/94_webvault/";
            },},{id: "boxes-the-suspicious-reviewer",
          title: 'The Suspicious Reviewer',
          description: "Investigate Fraudulent Reviewer Profile to Uncover Contact.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/95_susreviewer/";
            },},{id: "boxes-the-suspicious-domain",
          title: 'The Suspicious Domain',
          description: "Investigate domain infrastructure to Uncover Campaign Links.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/96_susdomain/";
            },},{id: "boxes-minmax",
          title: 'MinMax',
          description: "Identify smallest and largest numbers in dataset.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/97_minmax/";
            },},{id: "boxes-cmd1",
          title: 'Cmd1',
          description: "Utilize absolute path to bypass PATH restrictions.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/98_cmd1/";
            },},{id: "boxes-silentium",
          title: 'Silentium',
          description: "Active challenge – details withheld per TOS",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/99_silentium/";
            },},{id: "boxes-devel",
          title: 'Devel',
          description: "Uploaded web shell via FTP server",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/9_devel/";
            },},{id: "certs-oscp",
          title: 'OSCP',
          description: "Offensive Security Certified Professional (OSCP) by OffSec.",
          section: "Certs",handler: () => {
              window.location.href = "/certs/1_OSCP/";
            },},{id: "certs-security",
          title: 'Security+',
          description: "CompTIA Security+ (SY0-601/701)",
          section: "Certs",handler: () => {
              window.location.href = "/certs/2_secplus/";
            },},{id: "certs-red-teaming-learning-path",
          title: 'Red Teaming Learning Path',
          description: "Red Teaming Learning Path by TryHackMe.",
          section: "Certs",handler: () => {
              window.location.href = "/certs/3_redteaming/";
            },},{id: "certs-intro-to-binary-exploitation",
          title: 'Intro to Binary Exploitation',
          description: "Intro to Binary Exploitation by Hack The Box Academy.",
          section: "Certs",handler: () => {
              window.location.href = "/certs/4_htbbinary/";
            },},{id: "certs-soft-skills-for-success",
          title: 'Soft Skills for Success',
          description: "People and Soft Skills for Professional and Personal Success by IBM.",
          section: "Certs",handler: () => {
              window.location.href = "/certs/5_ibmsoftskills/";
            },},{id: "certs-practical-malware-research-professional",
          title: 'Practical Malware Research Professional',
          description: "Practical Malware Research Professional (PMRP) by TCM.",
          section: "Certs",handler: () => {
              window.location.href = "/certs/6_pmrp/";
            },},{id: "certs-certified-defensive-security-analyst",
          title: 'Certified Defensive Security Analyst',
          description: "Certified Defensive Security Analyst (CDSA) by HackTheBox (HTB).",
          section: "Certs",handler: () => {
              window.location.href = "/certs/7_cdsa/";
            },},{id: "certs-certified-offensive-ai-expert",
          title: 'Certified Offensive AI Expert',
          description: "Certified Offensive AI Expert (COAE) by HackTheBox (HTB).",
          section: "Certs",handler: () => {
              window.location.href = "/certs/8_coae/";
            },},{id: "cves-this-is-a-test-cve",
          title: 'This is a test CVE',
          description: "This is a test CVE.",
          section: "Cves",handler: () => {
              window.location.href = "/cves/1_test/";
            },},{id: "news-a-simple-inline-announcement",
          title: 'A simple inline announcement.',
          description: "",
          section: "News",},{id: "news-a-long-announcement-with-details",
          title: 'A long announcement with details',
          description: "",
          section: "News",handler: () => {
              window.location.href = "/news/announcement_2/";
            },},{id: "news-a-simple-inline-announcement-with-markdown-emoji-sparkles-smile",
          title: 'A simple inline announcement with Markdown emoji! :sparkles: :smile:',
          description: "",
          section: "News",},{id: "projects-bugwalk",
          title: 'BugWalk',
          description: "Created an App for Bug Bounty Assistance.",
          section: "Projects",handler: () => {
              window.location.href = "/projects/10_bugwalk/";
            },},{id: "projects-ariadne",
          title: 'Ariadne',
          description: "Created an App for Incident Response Investigation.",
          section: "Projects",handler: () => {
              window.location.href = "/projects/11_ariadne/";
            },},{id: "projects-portfolio",
          title: 'Portfolio',
          description: "A description of building this portfolio.",
          section: "Projects",handler: () => {
              window.location.href = "/projects/1_website/";
            },},{id: "projects-osed-study",
          title: 'OSED Study',
          description: "A study journey for the OSED.",
          section: "Projects",handler: () => {
              window.location.href = "/projects/2_osedstudy/";
            },},{id: "projects-buffer-overflow-lab-setup",
          title: 'Buffer Overflow Lab Setup',
          description: "Setup a lab for buffer overflow.",
          section: "Projects",handler: () => {
              window.location.href = "/projects/3_boflab/";
            },},{id: "projects-domain-set-up",
          title: 'Domain Set-up',
          description: "Setup a domain for testing purposes.",
          section: "Projects",handler: () => {
              window.location.href = "/projects/4_domainsetup/";
            },},{id: "projects-vanilla-buffer-overflows",
          title: 'Vanilla Buffer Overflows',
          description: "Vanilla Buffer Overflow write-ups.",
          section: "Projects",handler: () => {
              window.location.href = "/projects/5_vanillabof/";
            },},{id: "projects-malware-analysis-reporting",
          title: 'Malware Analysis Reporting',
          description: "Prepared a Malware Analysis Report.",
          section: "Projects",handler: () => {
              window.location.href = "/projects/6_malwareanalysis/";
            },},{id: "projects-malware-analysis-lab-set-up",
          title: 'Malware Analysis Lab Set-up',
          description: "Build a Malware Analysis Lab.",
          section: "Projects",handler: () => {
              window.location.href = "/projects/7_malwarelab/";
            },},{id: "projects-certmap",
          title: 'CertMap',
          description: "Develop a CertMap WebApp.",
          section: "Projects",handler: () => {
              window.location.href = "/projects/8_certmap/";
            },},{id: "projects-osedtutor",
          title: 'OSEDTutor',
          description: "Created an App that Creates Lessons.",
          section: "Projects",handler: () => {
              window.location.href = "/projects/9_osedtutor/";
            },},{id: "talks-first-talk",
          title: 'First talk',
          description: "This is a test talk.",
          section: "Talks",handler: () => {
              window.location.href = "/talks/1_test/";
            },},{id: "tools-python",
          title: 'python',
          description: "Used for Buffer Overflows and Red Team Scripting.",
          section: "Tools",handler: () => {
              window.location.href = "/tools/1_python/";
            },},{id: "tools-nmap",
          title: 'nmap',
          description: "Used for enumeration and red team recon.",
          section: "Tools",handler: () => {
              window.location.href = "/tools/2_nmap/";
            },},{id: "tools-wireshark",
          title: 'wireshark',
          description: "Analyzed .pcap files for investigation.",
          section: "Tools",handler: () => {
              window.location.href = "/tools/3_wireshark/";
            },},{id: "tools-ffuf",
          title: 'ffuf',
          description: "Performed web directory brute-forcing and discovery.",
          section: "Tools",handler: () => {
              window.location.href = "/tools/4_ffuf/";
            },},{id: "tools-hydra",
          title: 'hydra',
          description: "Performed credential brute-force dictionary attacks.",
          section: "Tools",handler: () => {
              window.location.href = "/tools/5_hydra/";
            },},{id: "tools-sqlmap",
          title: 'sqlmap',
          description: "Performed automated SQL Injection attacks.",
          section: "Tools",handler: () => {
              window.location.href = "/tools/6_sqlmap/";
            },},{id: "tools-gobuster",
          title: 'gobuster',
          description: "Discovered web directories files and folders.",
          section: "Tools",handler: () => {
              window.location.href = "/tools/7_gobuster/";
            },},{id: "tools-john",
          title: 'john',
          description: "Cracked password hashes and ssh passphrases.",
          section: "Tools",handler: () => {
              window.location.href = "/tools/8_johnripper/";
            },},{
      id: 'light-theme',
      title: 'Change theme to light',
      description: 'Change the theme of the site to Light',
      section: 'Theme',
      handler: () => {
        setThemeSetting("light");
      },
    },
    {
      id: 'dark-theme',
      title: 'Change theme to dark',
      description: 'Change the theme of the site to Dark',
      section: 'Theme',
      handler: () => {
        setThemeSetting("dark");
      },
    },
    {
      id: 'system-theme',
      title: 'Use system default theme',
      description: 'Change the theme of the site to System Default',
      section: 'Theme',
      handler: () => {
        setThemeSetting("system");
      },
    },];
