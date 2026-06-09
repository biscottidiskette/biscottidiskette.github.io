# biscottidiskette.github.io
 
> **Offensive background. Defensive execution.**  
> Personal cybersecurity portfolio and technical blog — built on a heavily modified [al-folio](https://github.com/alshedivat/al-folio) Jekyll theme.

**[Live Site →](https://biscottidiskette.github.io)**

---

## What This Is
This is my personal security portfolio: a custom Jekyll site where I document labs, projects, certifications, and thoughts on the InfoSec space. The underlying theme is al-folio, but it's been extensively modified to serve a security-focused audience rather than an academic one.

If you're here from a job application or just curious about the build, สวัสดี.

---

## Site Sections
 
| Section | Description |
|---|---|
| [About](https://biscottidiskette.github.io/) | Who I am, what I do, where I'm headed |
| [Projects](https://biscottidiskette.github.io/projects/) | Red/blue/purple team builds — tooling, labs, AI-assisted apps |
| [Boxes](https://biscottidiskette.github.io/boxes/) | 97 write-ups across HTB, TryHackMe, VulnHub, Sherlocks, CyberDefenders |
| [Certs](https://biscottidiskette.github.io/certifications/) | Certifications, badges, and ongoing study (CISSP in progress) |
| [Blog](https://biscottidiskette.github.io/blog/) | ScottiSec — career, certs, exploit dev, and the honest parts |
 
---

## Custom Modifications (vs. stock al-folio)
 
This fork has diverged significantly from the upstream template:
 
- **`_boxes/`** — custom collection for CTF/lab write-ups with per-box metadata (platform, difficulty, team focus, methodology summary)
- **`_certs/`** — custom collection for certifications and credentials with category/focus-area filtering
- **`_bounties/`**, **`_cves/`**, **`_tools/`** — additional custom collections not present in base al-folio
- **Filterable grid UI** — projects, boxes, and certs pages all support multi-axis filtering (category, platform, difficulty, team, focus area) via custom JavaScript
- **Terminal-style profile card** — custom component on the about page rendering a `cat profile.json` block
- **Purple team framing** — site-wide UX language and metadata reframed around offensive→defensive methodology rather than academic publishing
- **Custom nav labels** — condensed navigation using informal labels (`boxes`, `certs`) aligned to the site's voice
- **Social links** — footer includes HackTheBox and TryHackMe profile links alongside GitHub

---
 
## Upstream
 
This repo is a fork of [alshedivat/al-folio](https://github.com/alshedivat/al-folio). Changes here are specific to this portfolio and are not intended to be merged upstream. If you're looking for the original theme, head there.