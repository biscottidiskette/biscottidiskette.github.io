---
layout: page
title: certs
permalink: /certifications/
description: All the certifications, badges, online courses, books that I have completed.
nav: true
nav_order: 4
display_categories: [certification, badge, online course, book]
subcategories: [red, blue, foundational, general]
horizontal: false
---

<!-- Header Blurb -->
<div style="margin-bottom: 2rem;">
  <p style="font-size: 1rem; color: #d1d5db; line-height: 1.6;">
    Professional certifications spanning offensive security (OSCP), defensive operations (PMRP), and foundational knowledge (Security+). Each certification includes context on skills gained, practical applications, and career impact.
  </p>
  <p style="font-size: 0.95rem; color: #9ca3af; margin-top: 0.75rem;">
    <strong>Current Focus:</strong> CISSP preparation planned to begin post-December 2025, with target exam date Q1 2026.
  </p>
</div>

<!-- Certification Statistics Counter -->
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
        <p class="stat-title">Credential Types</p>
        <ul style="list-style: none; padding: 0; margin: 0;">
          {% for category in page.display_categories %}
            {% assign count = site.certs | where: "category", category | size %}
            <li class="stat-item">
              <span style="text-transform: capitalize;">{{ category }}</span>
              <span class="stat-value">{{ count }}</span>
            </li>
          {% endfor %}
        </ul>
      </div>
    </td>
    
    <!-- Focus Area Statistics -->
    <td style="vertical-align:top;">
      <div class="stat-box">
        <p class="stat-title">Focus Areas</p>
        <ul style="list-style: none; padding: 0; margin: 0;">
          {% for subcategory in page.subcategories %}
            {% assign count = site.certs | where: "subcategory", subcategory | size %}
            <li class="stat-item">
              <span style="text-transform: capitalize;">{{ subcategory }}</span>
              <span class="stat-value">{{ count }}</span>
            </li>
          {% endfor %}
        </ul>
      </div>
    </td>
  </tr>
</table>

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

    {% assign categorized_certs = site.certs | where: "category", category %}
    {% assign sorted_certs = categorized_certs | sort: "importance" %}

    {% if sorted_certs != empty %}
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