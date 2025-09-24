---
layout: page
title: boxes
permalink: /boxes/
description: All of the boxes, Sherlocks, and various other practice.
nav: true
nav_order: 2
display_categories: [HackTheBox, TryHackMe, VulnHub, Sherlocks, CyberDefenders]
horizontal: false
---

<div class="cert-key mb-4" style="display: flex; gap: 1rem; align-items: center;">
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
</div>

<!-- pages/boxes.md -->
<div class="projects">
    {% if site.enable_project_categories and page.display_categories %}
        <!-- Display categorized boxes -->
        {% for category in page.display_categories %}
            <a id="{{ category }}" href=".#{{ category }}">
                <h2 class="category">{{ category }}</h2>
            </a>
            {% assign categorized_boxes = site.boxes | where: "category", category %}
            {% assign sorted_boxes = categorized_boxes | sort: "importance" %}
            <!-- Generate cards for each boxes -->
            {% if page.horizontal %}
                <div class="container">
                    <div class="row row-cols-1 row-cols-md-2">
                        {% for box in sorted_boxes %}
                            {% include boxes_horizontal.liquid %}
                        {% endfor %}
                    </div>
                </div>
            {% else %}
                <div class="row row-cols-1 row-cols-md-3">
                    {% for box in sorted_boxes %}
                        {% include boxes.liquid %}
                    {% endfor %}
                </div>
            {% endif %}
        {% endfor %}
    {% else %}
        <!-- Display boxes without categories -->
        {% assign sorted_boxes = site.boxes | sort: "importance" %}
        <!-- Generate cards for each project -->
        {% if page.horizontal %}
            <div class="container">
                <div class="row row-cols-1 row-cols-md-2">
                    {% for box in sorted_boxes %}
                        {% include boxes_horizontal.liquid %}
                    {% endfor %}
                </div>
            </div>
        {% else %}
            <div class="row row-cols-1 row-cols-md-3">
                {% for box in sorted_boxes %}
                    {% include boxes.liquid %}
                {% endfor %}
            </div>
        {% endif %}
    {% endif %}
</div>