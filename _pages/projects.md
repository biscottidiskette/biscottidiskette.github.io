---
layout: page
title: projects
permalink: /projects/
description: A growing collection of projects.
nav: true
nav_order: 1
display_categories: [Reporting, Operations, Development, AI-Assisted Architecture, Lab Setup, Personal]
subcategories: [red,blue,infrastructure,research,miscellaneous]
horizontal: false
---

<p style="font-size: 1rem; color: #d1d5db; line-height: 1.6; margin-bottom: 1.25rem;">
  Personal projects spanning red team tooling, blue team infrastructure, and detection 
  engineering, each with documentation, lessons learned, and practical applications.
  <strong style="color: #f0f0f0;">Purple team focus:</strong> bridging offensive techniques 
  with defensive detection capabilities.
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

{% assign total = site.projects | size %}

<div class="stats-grid" style="margin-bottom: 1.25rem;">

  <!-- By Category -->
  <div class="stat-group">
    <div class="stat-group-header">
      <span class="stat-group-label">By category</span>
      <span class="stat-group-total">Total <span>{{ total }}</span></span>
    </div>
    {% for category in page.display_categories %}
      {% assign count = site.projects | where: "category", category | size %}
      {% assign pct = count | times: 100.0 | divided_by: total %}
      <div class="stat-row">
        <span class="stat-name">{{ category }}</span>
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
    {% for subcat in page.subcategories %}
      {% assign count = site.projects | where: "subcategory", subcat | size %}
      {% assign pct = count | times: 100.0 | divided_by: total %}
      <div class="stat-row">
        <span class="stat-name" style="text-transform: capitalize;">{{ subcat }}</span>
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
    <span>Red Team</span>
  </div>
  <div style="display: flex; align-items: center; gap: 0.3rem;">
    <span style="display:inline-block;width:20px;height:20px;background-color:rgba(0,0,255,0.3);border:1px solid #000;"></span>
    <span>Blue Team</span>
  </div>
  <div style="display: flex; align-items: center; gap: 0.3rem;">
    <span style="display:inline-block;width:20px;height:20px;background-color:rgba(0,128,0,0.3);border:1px solid #000;"></span>
    <span>Infrastructure</span>
  </div>
  <div style="display: flex; align-items: center; gap: 0.3rem;">
    <span style="display:inline-block;width:20px;height:20px;background-color:rgba(218,165,32,0.3);border:1px solid #000;"></span>
    <span>Research</span>
  </div>
  <div style="display: flex; align-items: center; gap: 0.3rem;">
    <span style="display:inline-block;width:20px;height:20px;background-color:rgba(192,192,192,0.3);border:1px solid #000;"></span>
    <span>Miscellaneous</span>
  </div>
</div>

<!-- pages/projects.md -->
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

    {% assign categorized_projects = site.projects | where: "category", category %}
    {% assign sorted_projects = categorized_projects | sort: "importance" %}

    {% if sorted_projects != empty %}
      <div class="row row-cols-1 row-cols-md-3">
        {% for project in sorted_projects %}

        {% case project.subcategory %}
            {% when "red" %}{% assign bg_color = "rgba(255,0,0,0.1)" %}
            {% when "blue" %}{% assign bg_color = "rgba(0,0,255,0.1)" %}
            {% when "infrastructure" %}{% assign bg_color = "rgba(0,128,0,0.1)" %}
            {% when "research" %}{% assign bg_color = "rgba(218,165,32,0.1)" %}
            {% when "miscellaneous" %}{% assign bg_color = "rgba(192,192,192,0.1)" %}
            {% else %}{% assign bg_color = "transparent" %}
          {% endcase %}

          <div class="col">
            <a href="{{ project.url | relative_url }}">
              <div class="card h-100 hoverable"
                   style="border-radius:0.5rem;
                          border:1px solid #333;
                          transition:transform 0.15s ease, box-shadow 0.15s ease;
                          background-color: {{ bg_color }};">

                {% if project.img %}
                  {%
                    include figure.liquid
                    loading="eager"
                    path=project.img
                    sizes="250px"
                    alt="project thumbnail"
                    class="card-img-top"
                  %}
                {% endif %}

                <div class="card-body">
                  {% if project.status %}
                    <span class="status-badge status-{{ project.status }}">{{ project.status }}</span>
                  {% endif %}
                  <h2 class="card-title" style="font-size:1.1rem; color:#fff;">{{ project.title }}</h2>
                  <p class="card-text" style="font-size:0.9rem; color:#aaa;">{{ project.description }}</p>

                  <div class="row ml-1 mr-1 p-0">
                    {% if project.github %}
                      <div class="github-icon">
                        <div class="icon" data-toggle="tooltip" title="Code Repository">
                          <a href="{{ project.github }}"><i class="fa-brands fa-github gh-icon"></i></a>
                        </div>
                        {% if project.github_stars %}
                          <span class="stars" data-toggle="tooltip" title="GitHub Stars">
                            <i class="fa-solid fa-star"></i>
                            <span id="{{ project.github_stars }}-stars"></span>
                          </span>
                        {% endif %}
                      </div>
                    {% endif %}
                  </div>

                </div>
              </div>
            </a>
          </div>

        {% endfor %}
      </div>
    {% endif %}
  {% endfor %}
</div>
