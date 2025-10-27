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
            <div class="col">
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