---
layout: page
title: certs
permalink: /certifications/
description: All the certifications, badges, online courses, books that I have completed.
nav: true
nav_order: 3
display_categories: [certification, badge, online course, book]
subcategories: [red, blue, foundational, general]
horizontal: false
---

<p style="font-size: 1rem; color: #d1d5db; line-height: 1.6; margin-bottom: 1.25rem;">
  Professional certifications spanning offensive security, defensive operations, and 
  foundational knowledge, each with context on skills gained and practical applications.
  <strong style="color: #f0f0f0;">Current focus:</strong> CISSP (In Progress, Expected: Q4 2026).
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

{% assign total = site.certs | size %}

<div class="stats-grid" style="margin-bottom: 1.25rem;">

  <!-- By Credential Type -->
  <div class="stat-group">
    <div class="stat-group-header">
      <span class="stat-group-label">By credential type</span>
      <span class="stat-group-total">Total <span>{{ total }}</span></span>
    </div>
    {% for category in page.display_categories %}
      {% assign count = site.certs | where: "category", category | size %}
      {% assign pct = count | times: 100.0 | divided_by: total %}
      <div class="stat-row">
        <span class="stat-name" style="text-transform: capitalize;">{{ category }}</span>
        <div class="stat-bar-wrap">
          <div class="stat-bar" style="width:{{ pct }}%"></div>
        </div>
        <span class="stat-count">{{ count }}</span>
      </div>
    {% endfor %}
  </div>

  <!-- By Focus Area -->
  <div class="stat-group">
    <div class="stat-group-header">
      <span class="stat-group-label">By focus area</span>
      <span class="stat-group-total">Total <span>{{ total }}</span></span>
    </div>
    {% for subcategory in page.subcategories %}
      {% assign count = site.certs | where: "subcategory", subcategory | size %}
      {% assign pct = count | times: 100.0 | divided_by: total %}
      <div class="stat-row">
        <span class="stat-name" style="text-transform: capitalize;">{{ subcategory }}</span>
        <div class="stat-bar-wrap">
          <div class="stat-bar" style="width:{{ pct }}%"></div>
        </div>
        <span class="stat-count">{{ count }}</span>
      </div>
    {% endfor %}
  </div>

</div>

<div class="cert-key mb-4" style="display: flex; gap: 1rem; align-items: center;">
  <div style="display: flex; align-items: center; gap: 0.3rem;">
    <span style="display:inline-block;width:20px;height:20px;background-color:rgba(255,0,0,0.3);border:1px solid #000;"></span>
    <span>Offensive / Red-Team</span>
  </div>
  <div style="display: flex; align-items: center; gap: 0.3rem;">
    <span style="display:inline-block;width:20px;height:20px;background-color:rgba(0,0,255,0.3);border:1px solid #000;"></span>
    <span>Blue-Team / Defensive Cybersecurity</span>
  </div>
  <div style="display: flex; align-items: center; gap: 0.3rem;">
    <span style="display:inline-block;width:20px;height:20px;background-color:rgba(255,255,0,0.3);border:1px solid #000;"></span>
    <span>Foundational Cybersecurity (e.g., Security+)</span>
  </div>
  <div style="display: flex; align-items: center; gap: 0.3rem;">
    <span style="display:inline-block;width:20px;height:20px;background-color:rgba(255,255,255,0.3);border:1px solid #000;"></span>
    <span>General / Non-Cyber</span>
  </div>
</div>

<!-- pages/certs.md -->
<div class="projects">
  {% for category in page.display_categories %}
    {% assign categorized_certs = site.certs | where: "category", category %}
    {% assign sorted_certs = categorized_certs | sort: "importance" %}

    {% if sorted_certs != empty %}
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
      {% if page.horizontal %}
        <div class="row row-cols-1 row-cols-md-2 g-3">
          {% for cert in sorted_certs %}
            {% include certs_horizontal.liquid %}
          {% endfor %}
        </div>
      {% else %}
        <div class="row row-cols-1 row-cols-md-3 g-3">
          {% for cert in sorted_certs %}
            {% include certs.liquid %}
          {% endfor %}
        </div>
      {% endif %}
    {% endif %}
  {% endfor %}
</div>