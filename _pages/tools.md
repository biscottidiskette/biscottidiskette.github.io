---
layout: page
title: tools
permalink: /tools/
description: All the tools I use across my projects, labs, and certifications.
nav: true
nav_order: 3
display_categories: [red, blue, malware/re, forensic/ir, automation/scripting, supporting tools]
horizontal: false
---

<!-- Proficiency Legend -->
<div class="cert-key mb-4" style="display: flex; gap: 1rem; flex-wrap:wrap; align-items: center;">
  <div style="display: flex; align-items: center; gap: 0.3rem;">
    <span style="display:inline-block;width:20px;height:20px;background-color:rgba(255,0,0,0.3);border:1px solid #000;"></span>
    <span>Advanced</span>
  </div>
  <div style="display: flex; align-items: center; gap: 0.3rem;">
    <span style="display:inline-block;width:20px;height:20px;background-color:rgba(255,255,0,0.3);border:1px solid #000;"></span>
    <span>Intermediate</span>
  </div>
  <div style="display: flex; align-items: center; gap: 0.3rem;">
    <span style="display:inline-block;width:20px;height:20px;background-color:rgba(0,148,0,0.3);border:1px solid #000;"></span>
    <span>Beginner</span>
  </div>
  <div style="display: flex; align-items: center; gap: 0.3rem;">
    <span style="display:inline-block;width:20px;height:20px;background-color:rgba(255,255,255,0.3);border:1px solid #000;"></span>
    <span>Dabble</span>
  </div>
</div>

<!-- pages/tools.md -->
<div class="projects">
  {% for category in page.display_categories %}
    <a id="{{ category | slugify }}" 
       style="display:block;
              font-size:1.6rem;
              font-weight:700;
              margin-top:2rem;
              margin-bottom:0.75rem;
              padding-bottom:0.25rem;
              border-bottom:2px solid #444;
              color:#fff;
              text-decoration:none;">
      {{ category }}
    </a>

    {% assign categorized_tools = site.tools | where: "category", category %}
    {% assign sorted_tools = categorized_tools | sort: "importance" %}

    {% if sorted_tools != empty %}
      {% if page.horizontal %}
        <div class="row row-cols-1 row-cols-md-2 g-3">
          {% for tool in sorted_tools %}
            {% include tools_horizontal.liquid %}
          {% endfor %}
        </div>
      {% else %}
        <div class="row row-cols-1 row-cols-md-3 g-3">
          {% for tool in sorted_tools %}
            {% include tools.liquid %}
          {% endfor %}
        </div>
      {% endif %}
    {% endif %}
  {% endfor %}
</div>
