---
layout: page
title: boxes
permalink: /boxes/
description: All of the boxes, Sherlocks, and various other practice.
nav: true
nav_order: 2
display_categories: [HackTheBox, TryHackMe, HTB Challenges, VulnHub, Sherlocks, CyberDefenders, Blue Team Labs]
teams: [Red Team Labs, Blue Team Labs]
---

<style>
  /* Responsive counters table */
  .counters-table {
    width: 100%;
    border-spacing: 0.75rem; /* slightly tighter */
    table-layout: fixed;
    margin-bottom: 1.5rem; /* space from legend */
  }

  @media (max-width: 640px) {
    .counters-table tr {
      display: block;
    }
    .counters-table td {
      display: block;
      width: 100%;
      margin-bottom: 0.75rem;
      border-right: none;
    }
  }

  /* Counter box styling - compact and blended */
  .counter-box {
    background-color: rgba(28,28,28,0.9); /* charcoal overlay */
    padding: 0.5rem 0.75rem;
    border-radius: 0.5rem;
    display: flex;
    flex-direction: column;
  }

  .counter-title {
    text-transform: uppercase;
    font-size: 0.6rem;
    letter-spacing: 0.05em;
    color: #9ca3af; /* muted gray */
    margin-bottom: 0.3rem;
  }

  .counter-item {
    display: flex;
    justify-content: space-between;
    color: #d1d5db; /* neutral text */
    margin-bottom: 0.1rem;
    font-size: 0.875rem;
  }

  .counter-value {
    font-weight: 600;
    color: rgba(255,255,255,0.85);
  }

  /* Optional subtle separator on desktop */
  .counters-table td:not(:last-child) {
    border-right: 1px solid rgba(255,255,255,0.05);
    padding-right: 0.5rem;
  }
</style>

Hands-on security challenges completed across offensive and defensive domains. 
Each challenge includes detailed technical write-ups covering methodology, tooling, 
and lessons learned.

**Purple Team Approach:** I analyze offensive challenges from an attacker's perspective 
(exploitation techniques, privilege escalation) and defensive challenges from a 
responder's perspective (threat hunting, timeline analysis, IOC extraction). 
This dual focus helps me understand security from both sides.

<table class="counters-table">
  <tr>
    <!-- Categories -->
    <td style="vertical-align:top;">
      <div class="counter-box">
        <p class="counter-title">Site Statistics</p>
        <ul>
          {% for category in page.display_categories %}
            {% assign count = site.boxes | where: "category", category | size %}
            <li class="counter-item">
              <span>{{ category }}</span>
              <span class="counter-value">{{ count }}</span>
            </li>
          {% endfor %}
        </ul>
      </div>
    </td>

    <!-- Teams -->
    <td style="vertical-align:top;">
      <div class="counter-box">
        <p class="counter-title">Team Statistics</p>
        <ul>
          {% for team in page.teams %}
            {% assign count = site.boxes | where: "team", team | size %}
            <li class="counter-item">
              <span>{{ team }}</span>
              <span class="counter-value">{{ count }}</span>
            </li>
          {% endfor %}
        </ul>
      </div>
    </td>
  </tr>
</table>

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
          {{ category }}
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