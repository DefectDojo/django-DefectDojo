---
title: "Dashboards"
summary: ""
date: 2023-09-07T16:06:50+02:00
lastmod: 2023-09-07T16:06:50+02:00
draft: false
weight: 1
chapter: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
exclude_search: true
---
The Dashboard is the front page of DefectDojo — a summary of your team's performance and a launchpad for monitoring the areas that matter to you.

## Open source vs. DefectDojo Pro

How the dashboard works depends on which edition you run:

| | Open Source | DefectDojo Pro |
|---|---|---|
| **Home dashboard** | One fixed Main Dashboard for everyone | Per-user **customizable** dashboards |
| **Choose what appears** | Superuser toggles a fixed set of charts on/off | Each user adds, configures, and arranges **widgets** |
| **Multiple named dashboards** | No | Yes — build and switch between any number of **layouts** |
| **Share / clone / set a default** | — | Yes — publish layouts to your team, clone templates, set your default |
| **REST API + LLM automation** | — | Yes — discover the catalog, create layouts, render widget data |

In short: **open source** gives every user the same built-in Main Dashboard with a fixed set of components. **DefectDojo Pro** lets each user build their own dashboards out of widgets, share them, and drive the whole system from the UI, the REST API, or an LLM.

## Where to go next

**Open Source**

- **[DefectDojo Main Dashboard](introduction_dashboard/)** — the built-in front page: summary cards, severity charts, and how a superuser configures them.

**DefectDojo Pro**

- **[Customizable Dashboards](custom-dashboards/)** — concepts (layouts, widgets, the catalog, sharing) and a full UI walkthrough.
- **[Automating Dashboards with the API](custom-dashboards-api/)** — discover the widget catalog, create and update layouts, and render widget data over the REST API, with a complete script.
- **[Building Dashboards with an LLM](custom-dashboards-llm/)** — let an LLM design and build dashboards for you.
