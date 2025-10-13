---
layout: page
title: boxes
permalink: /boxes/
description: All of the boxes, Sherlocks, and various other practice.
nav: true
nav_order: 2
display_categories: [HackTheBox, TryHackMe, VulnHub, Sherlocks, CyberDefenders, Blue Team Labs]
teams: [Red Team Labs, Blue Team Labs]
---

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