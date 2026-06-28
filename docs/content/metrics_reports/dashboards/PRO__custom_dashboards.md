---
title: "Customizable Dashboards"
description: "Build personalized dashboards in DefectDojo Pro from widgets arranged on a drag-and-drop grid"
draft: false
audience: pro
weight: 10
slug: custom-dashboards
aliases:
  - /en/customize_dojo/dashboards/about_custom_dashboard_tiles
  - /metrics_reports/dashboards/about_custom_dashboard_tiles
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Customizable Dashboards (layouts, widgets, and the widget catalog) are a DefectDojo Pro feature, currently in beta. Beta features are available to DefectDojo Pro Cloud subscriptions — contact DefectDojo support or your customer success advocate to enable it for your instance.</span>

DefectDojo Pro Customizable Dashboards let each user assemble their own home page out of **widgets** — counts, charts, leaderboards, feeds, and notes — arranged on a drag-and-drop grid. Instead of a single fixed dashboard for everyone, you build the **layouts** that matter to you: an executive overview, a triage queue, a remediation-velocity board, a scanner-effectiveness view. You can keep layouts private, publish them to your whole team, set one as your default landing page, and clone any layout (yours or a shared template) as a starting point.

## How it compares to open source

Open source DefectDojo has a single, built-in [Main Dashboard](../introduction_dashboard/) with a fixed set of summary cards and charts that a superuser can show or hide. It is the same for every user.

DefectDojo Pro replaces that fixed page with **per-user customizable dashboards**. You choose which widgets appear, how they are filtered, and where they sit on the grid. You can build any number of named layouts, switch between them, share them with your team, and drive the whole system from the [REST API](../custom-dashboards-api/) or an [LLM](../custom-dashboards-llm/).

> **💡 Tip:** In DefectDojo Pro, **Assets** were formerly called **Products** and **Organizations** were formerly **Product Types**. The UI uses the new wording, but some underlying widget settings still use the legacy names — for example, most widgets take a `model` of `finding`, `product`, `engagement`, or `test`. Where this matters, it is called out below.

## Enabling the beta

Customizable Dashboards are off by default while in beta. Beta features are enabled per instance for DefectDojo Pro Cloud subscriptions — contact DefectDojo support ([support@defectdojo.com](mailto:support@defectdojo.com)) or your customer success advocate to turn on Customizable Dashboards for your instance.

Once it is enabled, the **🏠 Home** page shows your customizable dashboard and the [Dashboards REST API](../custom-dashboards-api/) becomes available.

> **🔑 Important:** While the flag is off, the home page keeps the previous dashboard and every `/api/v2/dashboards/` endpoint returns `403 Dashboard V2 is not enabled.` Enabling the flag does **not** change anyone's data access — every widget still respects DefectDojo's role-based access control, so each user only ever sees the Findings, Assets, and other records they are authorized to view.

## Core concepts

A customizable dashboard is built from a few simple pieces.

### Layouts

A **layout** is one named dashboard: a collection of widgets and their positions on the grid. Each layout belongs to you, and you can have as many as you like — for example a "Daily Triage" board and a separate "Exec Overview." A layout stores three things:

- **widgets** — the ordered list of widgets it contains, each with its own type, title, and configuration.
- **layout** — where each widget sits and how big it is on the grid.
- **settings** — layout-level display options.

The first time you open Customizable Dashboards, DefectDojo gives you a personal copy of the **Default Dashboard** starter so you are never staring at a blank page.

### Widgets

A **widget** is a single panel on the dashboard. Every widget is an instance of a **type** from the catalog (a Count, a Graph, a Top-N leaderboard, and so on), and carries its own **configuration**: which data **model** it reads (`finding`, `product`, `engagement`, or `test`), what **filters** scope it, and type-specific display options like chart type, colors, or grouping. Two widgets of the same type with different filters are completely independent.

Each widget also has an optional **auto-refresh interval** (off, 30 seconds, 1 minute, 5 minutes, or 15 minutes) and an editable **title**.

### The widget catalog

The **catalog** is the fixed menu of widget types the platform supports, grouped into four categories — **Numbers**, **Charts**, **Lists & Feeds**, and **Static & Utility**. When you add a widget, you pick its type from the catalog. The catalog is also available over the [API](../custom-dashboards-api/) so scripts and LLMs can discover the available widget types and a known-good starting configuration for each. See [The widget catalog](#the-widget-catalog-1) below for the full list.

### The grid

Widgets are placed on a **12-column grid**. In edit mode you drag widgets to move them and drag the bottom-right corner to resize them; the grid compacts upward to fill gaps. Each widget type has sensible minimum and maximum sizes so charts and tables stay legible.

### Sharing, cloning, and defaults

- **Default** — one of your layouts is your **default**: the one that loads when you open the home page. You can change which layout is your default at any time.
- **Clone** — copy any layout (one of yours, or a shared template) into your own space as a fresh, independent starting point. Cloning gives the copy its own widgets, so editing the clone never touches the original.
- **Share** — publish one of your layouts to the whole team as a **shared layout**. Other users can see it and clone it, but only a team **Maintainer** can publish, edit, or unshare a shared layout. Sharing a layout shares only its *design* — every viewer still sees only the data their own permissions allow.
- **Starter & shared templates** — DefectDojo ships a set of curated **shared templates** you can clone as a head start (see [Shared templates](#shared-templates) below). The **Default Dashboard** is the special "starter" template that new users are given automatically.

## Building a dashboard in the UI

### The dashboard toolbar

The toolbar across the top of the home page is where you switch layouts and manage them. It includes a **layout picker** (with badges that mark your default layout and any shared layouts/templates), and buttons to create a **New Layout**, open **Manage Layouts**, **Refresh** all widgets, and toggle **Edit** mode.

![The Customizable Dashboard with its toolbar](images/pro_dashboard_v2_home.png)

### Step 1: Enter edit mode

Click **Edit** to unlock the dashboard. The grid becomes draggable and resizable, and an **Add Widget** button appears. Click **Done** when you are finished — edit mode also turns off automatically when you switch layouts.

![A dashboard in edit mode, showing drag and resize handles](images/pro_dashboard_v2_edit_grid.png)

### Step 2: Add a widget

In edit mode, click **Add Widget** to open the picker. It has two tabs:

- **By Type** — browse the catalog by category (Numbers, Charts, Lists & Feeds, Static & Utility). Each card shows the widget's name and a short description. Picking one adds it to the grid and opens its configuration dialog.
- **From Catalog** — start from a pre-configured widget taken from one of the shared templates (for example, the "Findings by Severity" chart from the Default Dashboard). These come ready-configured, so they drop straight onto the grid.

![The Add Widget dialog, By Type tab](images/pro_dashboard_v2_add_widget.png)

### Step 3: Configure the widget

Each widget opens a configuration dialog tailored to its type. Common settings include:

- **Title** — the heading shown on the widget.
- **Model** — which records the widget reads (Finding, Asset, Engagement, or Test), where applicable.
- **Filters** — an embedded list-view filter UI that scopes the widget to exactly the records you want (for example, active Critical findings). The filters you pick here are the same ones you would use on that object's list page.
- **Refresh interval** — how often the widget reloads on its own.
- **Type-specific options** — for example chart type and group-by dimension for a Graph, thresholds for a Gauge, or the metric for a Top-N leaderboard.

![Configuring a Graph widget](images/pro_dashboard_v2_widget_config.png)

> **💡 Tip:** A widget's data always respects your permissions. If a shared layout includes a "My Work" widget, every viewer sees *their own* assignments and mentions — not the layout author's.

### Step 4: Arrange, then save

Drag widgets to rearrange them and drag a corner to resize. Use the gear icon on a widget to reconfigure it, and the trash icon to remove it. Position and size changes are saved automatically as you go. Click **Done** to leave edit mode.

### Managing layouts

The **Manage Layouts** dialog (the gear button on the toolbar) is the hub for everything layout-level:

- **Your Layouts** — rename, set as default, share/unshare, clone, or delete each layout you own.
- **Create New** — start a fresh, empty layout to build from scratch.
- **Shared Templates** — browse curated and team-published layouts grouped by category, and click **Use Layout** to clone one into your own space.

![The Manage Layouts dialog](images/pro_dashboard_v2_manage_layouts.png)

### Shared templates

DefectDojo ships four ready-to-use shared templates you can clone as a starting point:

| Template | Purpose |
|----------|---------|
| **Default Dashboard** | The classic home view — 12 at-a-glance counts, severity charts, and top/bottom-graded assets. This is the starter every new user receives automatically. |
| **Priority Layout** | A triage-focused board built around finding priority and risk. |
| **Mitigation Layout** | A remediation-velocity board (closure trends, MTTR/MTTD, aging). |
| **Tool Layout** | A scanner-effectiveness board built around test types and recent scan activity. |

> **💡 Tip:** Cloning a template makes an independent copy. Customize the clone freely — you will not affect the template or anyone else who clones it.

### The empty state

A brand-new layout with no widgets shows a **"Build Your First Dashboard"** prompt. Click **Add Your First Widget** to jump straight into edit mode and start choosing widgets.

![The empty-layout state](images/pro_dashboard_v2_empty_state.png)

## The widget catalog

Customizable Dashboards ship with the following widget types, organized into four categories. Most widgets read one of four models — `finding`, `product` (Assets), `engagement`, or `test` — and are scoped by filters you choose. The fully detailed configuration options for each widget are documented in the [API guide](../custom-dashboards-api/).

### Numbers

Single-glance metrics — counts, KPIs, and gauges.

| Widget | What it shows |
|--------|---------------|
| **Count** | A single number from a filtered query — e.g. "Open Critical Findings" or "Active Engagements." Works with finding / asset / engagement / test. |
| **KPI / Trend** | A headline number plus its change versus the prior period, with an optional sparkline. |
| **Gauge** | A ratio drawn as an arc gauge — a "universe" filter as the denominator and a "pass" filter as the numerator. Use for SLA compliance, mitigation rate, or scan coverage, with configurable warning/OK thresholds. |
| **License Usage** | Your account's license-usage status with a per-signal breakdown (database size, weekly finding volume, and so on). *Requires the Maintainer role.* |
| **Scan Coverage** | What fraction of assets were scanned within 30 / 90 / 180 / 365 days, as a multi-window rollup. |

### Charts

Time-series and distribution visualizations.

| Widget | What it shows |
|--------|---------------|
| **Graph** | A general-purpose chart over any model and group-by dimension — bar, line, area, pie, or doughnut. E.g. Findings by Severity, Findings by Month. |
| **Sankey** | A flow diagram from a source dimension to a target dimension — e.g. Severity → Status. |
| **Sunburst** | A one- or two-level radial breakdown — e.g. Severity, then Test Type within each severity. |
| **Risk Matrix** | An EPSS-probability × risk heatmap of findings — bottom-left safe, top-right dangerous. |
| **Priority Histogram** | The distribution of finding **priority** scores from the prioritization engine, auto-binned. |
| **Rate by Category** | A per-category ratio (numerator / denominator) — e.g. False-Positive Rate by Tool or Mitigation Rate by Asset. |
| **Finding Velocity** | Findings created versus closed over time, showing whether the backlog is growing or shrinking. |
| **MTTR / MTTD** | Mean Time to Remediate and Mean Time to Detect, as paired time-series. |
| **Vulnerability Aging** | Open findings bucketed by age band (0–30d / 30–90d / 90–180d / 180d+), stacked by severity. |
| **Activity Heatmap** | A GitHub-style calendar of daily activity over a rolling window. |
| **Portfolio Treemap** | Nested rectangles for a portfolio rollup (Organization → Asset), sized by count and tinted by severity. |

### Lists & Feeds

Ranked lists, feeds, and embedded tables.

| Widget | What it shows |
|--------|---------------|
| **Top-N Leaderboard** | A ranked list in one of two modes: *aggregate* (top dimension buckets by count, e.g. Top 10 CWEs) or *records* (top individual records by a metric, e.g. Top 10 Assets by Grade). |
| **Embedded Table** | A full list view (Findings, Assets, Engagements, Tests, Risk Acceptances, Organizations, or Test Types) with preset filters and ordering — pagination, sorting, and CSV export included. |
| **Recent Activity** | A scrolling feed of the most-recently updated records, clickable through to detail pages. |
| **SLA Burndown** | Findings approaching SLA breach, ranked by days remaining, with countdown badges. |
| **My Work** | Your personal queue — assignments, mentions, and pending risk-acceptance reviews. Always scoped to the viewer. |
| **Saved Reports** | One-click access to your saved Report Templates. *Requires the Reporting feature.* |

### Static & Utility

Notes, shortcuts, and structure.

| Widget | What it shows |
|--------|---------------|
| **Favorites** | User-curated quick links to specific pages in the app. |
| **Section Break** | A labeled divider for grouping related widgets under a heading. |
| **Markdown / Notes** | An inline rich-text panel for headers, context notes, or reference links. |
| **Quick Actions** | One-click action buttons that navigate to a chosen page. |

## Next steps

- **[Automating Dashboards with the API](../custom-dashboards-api/)** — discover the widget catalog, create and update layouts, and render widget data over the REST API, with a complete script.
- **[Building Dashboards with an LLM](../custom-dashboards-llm/)** — let an LLM design and build dashboards for you (the dashboards API was built with AI agents in mind).
