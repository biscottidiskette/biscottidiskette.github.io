---
layout: page
title: projects
permalink: /projects/
description: A growing collection of projects.
nav: true
nav_order: 1
display_categories: [Development, AI-Assisted Architecture, Lab Setup, Personal]
subcategories: [red,blue,infrastructure,research,miscellaneous]
horizontal: false
---

<div style="margin-bottom: 2rem;">
  <p style="font-size: 1rem; color: #d1d5db; line-height: 1.6;">
    Personal projects covering infrastructure setup, tool development, and security research. 
    Each project includes documentation, lessons learned, and practical applications across 
    offensive and defensive security domains.
  </p>
  <p style="font-size: 0.95rem; color: #9ca3af; margin-top: 0.75rem;">
    <strong>Purple Team Focus:</strong> Projects span red team tooling, blue team infrastructure, 
    and bridging offensive techniques with defensive detection capabilities.
  </p>
</div>

<table class="stats-table">
  <tr>
    <!-- Category Statistics -->
    <td style="vertical-align:top;">
      <div class="stat-box">
        <p class="stat-title">Project Categories</p>
        <ul style="list-style: none; padding: 0; margin: 0;">
          {% for category in page.display_categories %}
            {% assign count = site.projects | where: "category", category | size %}
            <li class="stat-item">
              <span>{{ category }}</span>
              <span class="stat-value">{{ count }}</span>
            </li>
          {% endfor %}
        </ul>
      </div>
    </td>
    
    <!-- Subcategory Statistics -->
    <td style="vertical-align:top;">
      <div class="stat-box">
        <p class="stat-title">Focus Areas</p>
        <ul style="list-style: none; padding: 0; margin: 0;">
          {% for subcat in page.subcategories %}
            {% assign count = site.projects | where: "subcategory", subcat | size %}
            <li class="stat-item">
              <span style="text-transform: capitalize;">{{ subcat }}</span>
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
