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

<!-- Header Blurb -->
<div style="margin-bottom: 2rem;">
  <p style="font-size: 1rem; color: #d1d5db; line-height: 1.6;">
    Toolkit spanning offensive security, defensive operations, and analysis platforms. 
    Each tool includes practical usage examples, common commands, and integration into 
    real-world workflows across CTF challenges and professional engagements.
  </p>
  <p style="font-size: 0.95rem; color: #9ca3af; margin-top: 0.75rem;">
    <strong>Purple Team Coverage:</strong> Tools organized by function with proficiency levels 
    reflecting hands-on experience from {{ site.boxes | size }}+ completed security challenges.
  </p>
</div>

<!-- Tool Statistics Counter -->
<style>
  .stats-table {
    width: 100%;
    border-spacing: 0.75rem;
    table-layout: fixed;
    margin-bottom: 1.5rem;
  }
  @media (max-width: 640px) {
    .stats-table tr { display: block; }
    .stats-table td {
      display: block;
      width: 100%;
      margin-bottom: 0.75rem;
      border-right: none;
    }
  }
  .stat-box {
    background-color: rgba(28,28,28,0.9);
    padding: 0.5rem 0.75rem;
    border-radius: 0.5rem;
    display: flex;
    flex-direction: column;
  }
  .stat-title {
    text-transform: uppercase;
    font-size: 0.6rem;
    letter-spacing: 0.05em;
    color: #9ca3af;
    margin-bottom: 0.3rem;
  }
  .stat-item {
    display: flex;
    justify-content: space-between;
    color: #d1d5db;
    margin-bottom: 0.1rem;
    font-size: 0.875rem;
  }
  .stat-value {
    font-weight: 600;
    color: rgba(255,255,255,0.85);
  }
  .stats-table td:not(:last-child) {
    border-right: 1px solid rgba(255,255,255,0.05);
    padding-right: 0.5rem;
  }
</style>

<table class="stats-table">
  <tr>
    <!-- Category Statistics -->
    <td style="vertical-align:top;">
      <div class="stat-box">
        <p class="stat-title">Tool Categories</p>
        <ul style="list-style: none; padding: 0; margin: 0;">
          {% for category in page.display_categories %}
            {% assign count = site.tools | where: "category", category | size %}
            <li class="stat-item">
              <span style="text-transform: capitalize;">{{ category }}</span>
              <span class="stat-value">{{ count }}</span>
            </li>
          {% endfor %}
        </ul>
      </div>
    </td>
    
    <!-- Proficiency Statistics -->
    <td style="vertical-align:top;">
      <div class="stat-box">
        <p class="stat-title">Proficiency Distribution</p>
        <ul style="list-style: none; padding: 0; margin: 0;">
          {% assign advanced = site.tools | where: "importance", 4 | size %}
          {% assign intermediate = site.tools | where: "importance", 3 | size %}
          {% assign beginner = site.tools | where: "importance", 2 | size %}
          {% assign dabble = site.tools | where: "importance", 1 | size %}
          <li class="stat-item">
            <span>Advanced</span>
            <span class="stat-value">{{ advanced }}</span>
          </li>
          <li class="stat-item">
            <span>Intermediate</span>
            <span class="stat-value">{{ intermediate }}</span>
          </li>
          <li class="stat-item">
            <span>Beginner</span>
            <span class="stat-value">{{ beginner }}</span>
          </li>
          <li class="stat-item">
            <span>Dabble</span>
            <span class="stat-value">{{ dabble }}</span>
          </li>
        </ul>
      </div>
    </td>
  </tr>
</table>

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
