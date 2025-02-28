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
          description: "All of the boxes, CTFs, and various other practice.",
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
        },{id: "nav-bounties",
          title: "bounties",
          description: "All of my bug bounties that I found.",
          section: "Navigation",
          handler: () => {
            window.location.href = "/bounties/";
          },
        },{id: "nav-cves",
          title: "cves",
          description: "A growing collection of CVEs I earned.",
          section: "Navigation",
          handler: () => {
            window.location.href = "/cves/";
          },
        },{id: "nav-talks",
          title: "talks",
          description: "A growing collection of the presentations that I presented.",
          section: "Navigation",
          handler: () => {
            window.location.href = "/presentations/";
          },
        },{id: "nav-blog",
          title: "blog",
          description: "",
          section: "Navigation",
          handler: () => {
            window.location.href = "/blog/";
          },
        },{id: "nav-repos",
          title: "repos",
          description: "Welcome to my my GitHub.",
          section: "Navigation",
          handler: () => {
            window.location.href = "/repositories/";
          },
        },{id: "nav-publications",
          title: "publications",
          description: "Publications by categories in reversed chronological order.",
          section: "Navigation",
          handler: () => {
            window.location.href = "/publications/";
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
            },},{id: "boxes-popcorn",
          title: 'Popcorn',
          description: "Popcorn from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/10_popcorn/";
            },},{id: "boxes-htb-blue",
          title: 'HTB Blue',
          description: "Blue from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/11_bluehtb/";
            },},{id: "boxes-jerry",
          title: 'Jerry',
          description: "Jerry from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/12_jerry/";
            },},{id: "boxes-haircut",
          title: 'Haircut',
          description: "Haircut from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/13_haircut/";
            },},{id: "boxes-nibbles",
          title: 'Nibbles',
          description: "Nibbles from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/14_nibbles/";
            },},{id: "boxes-knife",
          title: 'Knife',
          description: "Knife from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/15_knife/";
            },},{id: "boxes-remote",
          title: 'Remote',
          description: "Remote from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/16_remote/";
            },},{id: "boxes-blocky",
          title: 'Blocky',
          description: "Blocky from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/17_blocky/";
            },},{id: "boxes-bashed",
          title: 'Bashed',
          description: "Blocky from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/18_bashed/";
            },},{id: "boxes-grandpa",
          title: 'Grandpa',
          description: "Grandpa from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/19_grandpa/";
            },},{id: "boxes-brainpan",
          title: 'Brainpan',
          description: "Brainpan buffer overflow from TryHackMe.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/1_brainpan/";
            },},{id: "boxes-granny",
          title: 'Granny',
          description: "Granny from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/20_grandma/";
            },},{id: "boxes-photographer",
          title: 'Photographer',
          description: "Photographer from Vulnhub.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/21_photographer/";
            },},{id: "boxes-irked",
          title: 'Irked',
          description: "Irked from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/22_irked/";
            },},{id: "boxes-optimum",
          title: 'Optimum',
          description: "Optimum from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/23_optimum/";
            },},{id: "boxes-mr-robot",
          title: 'Mr. Robot',
          description: "Mr. Robot from TryHackMe.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/24_mrrobot/";
            },},{id: "boxes-greenhorn",
          title: 'GreenHorn',
          description: "GreenHorn from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/25_greenhorn/";
            },},{id: "boxes-sense",
          title: 'Sense',
          description: "Sense from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/26_sense/";
            },},{id: "boxes-sau",
          title: 'Sau',
          description: "Sau from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/27_sau/";
            },},{id: "boxes-boardlight",
          title: 'BoardLight',
          description: "BoardLight from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/28_boardlight/";
            },},{id: "boxes-cronos",
          title: 'Cronos',
          description: "Cronos from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/29_cronos/";
            },},{id: "boxes-pickle-rick",
          title: 'Pickle Rick',
          description: "Pickle Rick from TryHackMe.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/2_picklerick/";
            },},{id: "boxes-solidstate",
          title: 'SolidState',
          description: "SolidState from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/30_solidstate/";
            },},{id: "boxes-daily-bugle",
          title: 'Daily Bugle',
          description: "Daily Bugle from TryHackMe.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/31_daily_bugle/";
            },},{id: "boxes-steel-mountain",
          title: 'Steel Mountain',
          description: "Steel Mountain from TryHackMe.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/32_steel_mountain/";
            },},{id: "boxes-vulnversity",
          title: 'Vulnversity',
          description: "Vulnerability from TryHackMe.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/3_vulnversity/";
            },},{id: "boxes-thm-blue",
          title: 'THM Blue',
          description: "Blue from TryHackMe.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/4_bluethm/";
            },},{id: "boxes-kenobi",
          title: 'Kenobi',
          description: "Kenobi from TryHackMe.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/5_kenobi/";
            },},{id: "boxes-cap",
          title: 'Cap',
          description: "Cap from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/6_cap/";
            },},{id: "boxes-lame",
          title: 'Lame',
          description: "Lame from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/7_lame/";
            },},{id: "boxes-legacy",
          title: 'Legacy',
          description: "Legacy from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/8_legacy/";
            },},{id: "boxes-devel",
          title: 'Devel',
          description: "Devel from HackTheBox.",
          section: "Boxes",handler: () => {
              window.location.href = "/boxes/9_devel/";
            },},{id: "certs-oscp",
          title: 'OSCP',
          description: "Offensive Security Certified Professional (OSCP) by OffSec.",
          section: "Certs",handler: () => {
              window.location.href = "/certs/1_OSCP/";
            },},{id: "certs-security",
          title: 'Security+',
          description: "Security+ by CompTIA.",
          section: "Certs",handler: () => {
              window.location.href = "/certs/2_secplus/";
            },},{id: "certs-red-teaming-learning-path",
          title: 'Red Teaming Learning Path',
          description: "Red Teaming Learning Path by TryHackMe.",
          section: "Certs",handler: () => {
              window.location.href = "/certs/3_redteaming/";
            },},{id: "certs-intro-to-binary-exploitation",
          title: 'Intro to Binary Exploitation',
          description: "Intro to Binary Exploitation by HackTheBox.",
          section: "Certs",handler: () => {
              window.location.href = "/certs/4_htbbinary/";
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
          section: "News",},{id: "projects-portfolio",
          title: 'Portfolio',
          description: "A description of building this portfolio.",
          section: "Projects",handler: () => {
              window.location.href = "/projects/1_website/";
            },},{id: "talks-first-talk",
          title: 'First talk',
          description: "This is a test talk.",
          section: "Talks",handler: () => {
              window.location.href = "/talks/1_test/";
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
