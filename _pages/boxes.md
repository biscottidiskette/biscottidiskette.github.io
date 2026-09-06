---
layout: page
title: boxes
permalink: /boxes/
description: All of the boxes, Sherlocks, and various other practice.
nav: true
nav_order: 2
display_categories: [HackTheBox, TryHackMe, HTB Challenges, Sherlocks, CyberDefenders, Blue Team Labs, Crackmes, pwnable.kr, pwnable.tw]
teams: [Red Team Labs, Blue Team Labs, Reverse Engineering Labs]
---

<p style="font-size: 1rem; color: #d1d5db; line-height: 1.6; margin-bottom: 1.25rem;">
Hands-on security challenges spanning offensive and defensive domains, each with detailed write-ups covering methodology, tooling, and lessons learned. <strong style="color: #f0f0f0;">Purple team focus:</strong> analyzing red team challenges as an attacker (exploitation, privilege escalation) and blue team challenges as a responder (threat hunting, timeline analysis, IOC extraction).
</p>

<style>
.stats-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  margin-bottom: 1.25rem;
}
.stat-group {
  background: rgba(28,28,28,0.9);
  border-radius: 8px;
  border: 0.5px solid rgba(255,255,255,0.08);
  overflow: hidden;
}
.stat-group-header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  padding: 7px 12px 6px;
  border-bottom: 0.5px solid rgba(255,255,255,0.08);
}
.stat-group-label {
  font-size: 9px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: #888;
}
.stat-group-total { font-size: 10px; color: #888; }
.stat-group-total span { font-weight: 600; color: #4ade80; }
.stat-row {
  display: flex;
  align-items: center;
  padding: 5px 12px;
  border-bottom: 0.5px solid rgba(255,255,255,0.08);
  transition: background 0.15s;
}
.stat-row:last-child { border-bottom: none; }
.stat-row:hover { background: rgba(255,255,255,0.03); }
.stat-name { font-size: 11px; color: #888; width: 110px; flex-shrink: 0; }
.stat-bar-wrap {
  flex: 1;
  margin: 0 10px;
  height: 2px;
  background: rgba(255,255,255,0.07);
  border-radius: 2px;
}
.stat-bar { height: 2px; border-radius: 2px; background: #4ade80; opacity: 0.7; }
.stat-count { font-size: 11px; font-weight: 500; color: #f0f0f0; min-width: 16px; text-align: right; }
@media (max-width: 640px) { .stats-grid { grid-template-columns: 1fr; } }
</style>

{% assign total = site.boxes | size %}

<div class="stats-grid">

  <!-- By Platform -->
  <div class="stat-group">
    <div class="stat-group-header">
      <span class="stat-group-label">By platform</span>
      <span class="stat-group-total">Total <span>{{ total }}</span></span>
    </div>
    {% for category in page.display_categories %}
      {% assign count = site.boxes | where: "category", category | size %}
      {% assign pct = count | times: 100.0 | divided_by: total %}
      <div class="stat-row">
        <span class="stat-name">{{ category }}{% case category %}{% when "HackTheBox" %} · Hacker{% when "TryHackMe" %}{% endcase %}</span>
        <div class="stat-bar-wrap">
          <div class="stat-bar" style="width:{{ pct }}%"></div>
        </div>
        <span class="stat-count">{{ count }}</span>
      </div>
    {% endfor %}
  </div>

  <!-- By Team -->
  <div class="stat-group">
    <div class="stat-group-header">
      <span class="stat-group-label">By team</span>
      <span class="stat-group-total">Total <span>{{ total }}</span></span>
    </div>
    {% for team in page.teams %}
      {% assign count = site.boxes | where: "team", team | size %}
      {% assign pct = count | times: 100.0 | divided_by: total %}
      <div class="stat-row">
        <span class="stat-name">{{ team }}</span>
        <div class="stat-bar-wrap">
          <div class="stat-bar" style="width:{{ pct }}%"></div>
        </div>
        <span class="stat-count">{{ count }}</span>
      </div>
    {% endfor %}
  </div>

</div>

<!-- Difficulty Legend -->
<div class="cert-key mb-4" style="display: flex; gap: 1rem; flex-wrap:wrap; align-items: center;">
  <div style="display: flex; align-items: center; gap: 0.3rem;">
    <span style="display:inline-block;width:20px;height:20px;background-color:rgba(255,255,255,0.3);border:1px solid #000;"></span>
    <span>Insane</span>
  </div>
  <div style="display: flex; align-items: center; gap: 0.3rem;">
    <span style="display:inline-block;width:20px;height:20px;background-color:rgba(255,0,0,0.3);border:1px solid #000;"></span>
    <span>Hard</span>
  </div>
  <div style="display: flex; align-items: center; gap: 0.3rem;">
    <span style="display:inline-block;width:20px;height:20px;background-color:rgba(255,255,0,0.3);border:1px solid #000;"></span>
    <span>Medium</span>
  </div>
  <div style="display: flex; align-items: center; gap: 0.3rem;">
    <span style="display:inline-block;width:20px;height:20px;background-color:rgba(0,148,0,0.3);border:1px solid #000;"></span>
    <span>Easy</span>
  </div>
  <div style="display: flex; align-items: center; gap: 0.3rem;">
    <span style="display:inline-block;width:20px;height:20px;background-color:rgba(178,0,237,0.3);border:1px solid #000;"></span>
    <span>Very Easy</span>
  </div>
</div>

<!-- Search -->
<div style="margin-bottom: 1.5rem; display: flex; justify-content: flex-end;">
  <input 
    type="text" 
    id="box-search" 
    placeholder="Search boxes..." 
    style="width:300px;
           padding: 0.6rem 1rem;
           background: #1e1e1e;
           border: 1px solid #333;
           border-radius: 6px;
           color: #eee;
           font-family: 'JetBrains Mono', monospace;
           font-size: 0.9rem;
           outline: none;"
    onfocus="this.style.borderColor='rgba(255,255,255,0.4)'"
    onblur="this.style.borderColor='#333'"
  >
</div>

<div class="projects">
  <!-- Loop through teams -->
  {% for team in page.teams %}
    <a id="{{ team | slugify }}" 
       style="display:block;
              font-size:1.6rem;
              font-weight:700;
              margin-top:2rem;
              margin-bottom:0.75rem;
              padding-bottom:0.25rem;
              border-bottom:2px solid #444;
              color:#fff;
              text-decoration:none;">
      {{ team }}
    </a>

    <!-- Loop through categories -->
    {% for category in page.display_categories %}
      {% assign categorized_boxes = site.boxes 
          | where: "category", category 
          | where: "team", team %}
      {% assign sorted_boxes = categorized_boxes | sort: "importance" %}

      {% if sorted_boxes != empty %}
        <a id="{{ category | slugify }}" 
           style="display:block;
                  font-size:1.2rem;
                  font-weight:600;
                  margin-top:1.25rem;
                  margin-bottom:0.5rem;
                  padding-left:0.5rem;
                  color:#bbb;
                  text-decoration:none;">
          {{ category }}{% case category %}{% when "HackTheBox" %} · Hacker{% when "TryHackMe" %}{% endcase %}
        </a>

        <div class="row row-cols-1 row-cols-md-3">
          {% for box in sorted_boxes %}
            <div class="col" data-search="{{ box.title | downcase }} {{ box.description | downcase }} {{ box.category | downcase }} {{ box.team | downcase }}">
              <a href="{{ box.url | relative_url }}">
                <div class="card h-100 hoverable"
                     style="border-radius:0.5rem;
                            border:1px solid #333;
                            transition:transform 0.15s ease, box-shadow 0.15s ease;
                            {% case box.importance %}
                              {% when 5 %}background-color:rgba(178,0,237,0.05);
                              {% when 4 %}background-color:rgba(0,148,0,0.05);
                              {% when 3 %}background-color:rgba(255,255,0,0.05);
                              {% when 2 %}background-color:rgba(255,0,0,0.05);
                              {% when 1 %}background-color:rgba(255,255,255,0.05);
                              {% else %}background-color:#1c1c1c;
                            {% endcase %}">
                  <div class="card-body">
                    <h2 class="card-title" style="font-size:1.1rem; color:#fff;">{{ box.title }}</h2>
                    <p class="card-text" style="font-size:0.9rem; color:#aaa;">{{ box.description }}</p>
                  </div>
                </div>
              </a>
            </div>
          {% endfor %}
        </div>
      {% endif %}
    {% endfor %}
  {% endfor %}
</div>

<script>
document.getElementById('box-search').addEventListener('input', function() {
  var query = this.value.toLowerCase().trim();
  var cols = document.querySelectorAll('.projects .col[data-search]');

  cols.forEach(function(col) {
    var text = col.getAttribute('data-search');
    col.style.display = (!query || text.includes(query)) ? '' : 'none';
  });

  // Hide category headings with no visible cards
  document.querySelectorAll('.projects .row').forEach(function(row) {
    var visible = Array.from(row.querySelectorAll('.col[data-search]'))
      .filter(function(c) { return c.style.display !== 'none'; }).length;
    var heading = row.previousElementSibling;
    if (heading && heading.tagName === 'A') {
      heading.style.display = visible ? '' : 'none';
    }
    row.style.display = visible ? '' : 'none';
  });

  // Hide team headings with no visible cards
  document.querySelectorAll('.projects > a').forEach(function(teamHeading) {
    var next = teamHeading.nextElementSibling;
    var visible = 0;
    while (next && next !== teamHeading.nextElementSibling.nextElementSibling) {
      visible += Array.from(next.querySelectorAll('.col[data-search]'))
        .filter(function(c) { return c.style.display !== 'none'; }).length;
      next = next.nextElementSibling;
    }
    teamHeading.style.display = visible ? '' : 'none';
  });
});
</script>