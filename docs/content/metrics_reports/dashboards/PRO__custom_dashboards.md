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
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Customizable Dashboards (layouts, widgets, and the widget catalog) are a DefectDojo Pro feature. They are off by default — a superuser can turn them on from **Settings > Feature Flags** on both Cloud and On-Premise instances.</span>

DefectDojo Pro Customizable Dashboards let each user assemble their own dashboards out of **widgets** (counts, charts, leaderboards, feeds, and notes) arranged on a drag-and-drop grid. Instead of a single fixed dashboard for everyone, you build the **layouts** that matter to you: an executive overview, a triage queue, a remediation-velocity board, a scanner-effectiveness view. You can keep layouts private, publish them to your whole team, set one as the default that opens on the Dashboards page, and clone any layout (yours or a shared template) as a starting point. The home page itself is the [Command Center](../command-center/), which every user has and which links to these grids.

![A DefectDojo Pro customizable dashboard — the Default Dashboard layout.](images/pro_dashboard_v2_default.png)

## How it compares to open source

Open source DefectDojo has a single, built-in [Main Dashboard](../introduction_dashboard/) with a fixed set of summary cards and charts that a superuser can show or hide. It is the same for every user.

DefectDojo Pro's home page is the [Command Center](../command-center/), and beside it Customizable Dashboards give each user **per-user customizable dashboards**. You choose which widgets appear, how they are filtered, and where they sit on the grid. You can build any number of named layouts, switch between them, share them with your team, and drive the whole system from the [REST API](../custom-dashboards-api/) or an [LLM](../custom-dashboards-llm/).

> **💡 Tip:** In DefectDojo Pro, **Assets** were formerly called **Products** and **Organizations** were formerly **Product Types**. The UI uses the new wording, but some underlying widget settings still use the legacy names — for example, most widgets take a `model` of `finding`, `product`, `engagement`, or `test`. Where this matters, it is called out below.

## Enabling Customizable Dashboards

Customizable Dashboards are off by default. A superuser can turn them on from **Settings > Feature Flags**, on both Cloud and On-Premise instances. See [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Once it is enabled, **Dashboards** appears in the sidebar under **Home** (the [Command Center](../command-center/)), opens your customizable dashboards, and the [Dashboards REST API](../custom-dashboards-api/) becomes available.

> **🔑 Important:** While the feature is off, that sidebar entry reads **Dashboard** and opens the classic tile dashboard instead, and every `/api/v2/dashboards/` endpoint other than the Command Center's own returns `403 Dashboards 2.0 is not enabled.` Home is the Command Center either way. Turning it on does **not** change anyone's data access: every widget still respects DefectDojo's role-based access control, so each user only ever sees the Findings, Assets, and other records they are authorized to view.

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

- **Default** — one of your layouts is your **default**: the one that loads when you open the Dashboards page. You can change which layout is your default at any time.
- **Clone** — copy any layout (one of yours, or a shared template) into your own space as a fresh, independent starting point. Cloning gives the copy its own widgets, so editing the clone never touches the original.
- **Share** — publish one of your layouts to the whole team as a **shared layout**. Other users can see it and clone it, but only a team **Maintainer** can publish, edit, or unshare a shared layout (unless it is collaborative, below). Sharing a layout shares only its *design* — every viewer still sees only the data their own permissions allow.
- **Collaborative** — a Maintainer can mark a shared layout as **collaborative** from **Manage Layouts** (**Make Collaborative**, reversed with **Stop Collaborating**). A collaborative layout is one live dashboard rather than a template to copy: it appears in every user's layout picker, anyone can set it as their default, and anyone can add, remove, rearrange, or configure its widgets. Every change is saved to the same layout, so everyone using it sees it. Renaming, unsharing, deleting, and the collaborative setting itself stay with a Maintainer. If a layout stops being collaborative (or is unshared), users who had it as their default fall back to their own layouts. Edits are saved as they are made, so two people editing at the same moment can overwrite each other's change; the layout re-syncs from the server when you enter edit mode.
- **Read-only**: a Maintainer can also mark a collaborative layout as **read-only** (**Make Read-Only** in **Manage Layouts**, reversed with **Allow Editing**). It stays one live dashboard in every user's layout picker, and anyone can still set it as their default, but only a Maintainer or the layout's owner can change its widgets or arrangement. Everyone sees it tagged **Read-Only**; the owner and Maintainers keep the **Edit** button and everyone else has none, so a Maintainer can keep one dashboard current for the whole team without anyone else changing it. Anyone who wants a version of their own can still duplicate it. Stopping collaboration (or unsharing) also turns read-only off.
- **Starter & shared templates** — DefectDojo ships a set of curated **shared templates** you can clone as a head start (see [Shared templates](#shared-templates) below). The **Default Dashboard** is the special "starter" template that new users are given automatically.
- **Instance Default**: a user who can share dashboards can mark a shared layout as the **Instance Default** from **Manage Layouts** (**Set as Instance Default**, cleared with **Clear Instance Default**). It carries an "Instance Default" badge, and it is the dashboard everyone is shown when dashboard customization is restricted (see below). It can also be chosen from a dropdown on **Settings > Defaults > Instance Defaults** (the **Dashboards** card).

### Restricting customization

An administrator can enable **Restrict Layout Customization** (**Settings > Defaults > Instance Defaults**, the **Layout Customization** card) to limit dashboard changes to superusers. Everyone else is shown the Instance Default dashboard, or the built-in starter dashboard when none is set, with no toolbar options to create, switch, edit, or manage layouts. Personal dashboards saved earlier are kept and reappear if the setting is turned back off.

### Default Profile and instance defaults

When you have not chosen a default dashboard (with **Set as My Default** in the layout manager, tagged **My Default**), the Dashboards page opens the one from the first [Default Profile](/admin/user_management/create_user_group/#defaults) that sets one and that you can open (the profile assigned to you directly, then your Groups' profiles in rank order), else the Instance Default, else your own copy of the starter dashboard. The dashboard picker marks it, as **From <profile>** or **Set by <profile>** when it is locked. Opening the Dashboards page before you had a profile does not count as a choice, so a profile added later still applies. While your customization is restricted, the profile's dashboard is enforced over the Instance Default, which applies when no profile of yours sets one. Under **Restrict to Selected Layouts** the picker offers only the dashboards your profile allows, and New, Edit and Duplicate are not available.

## Building a dashboard in the UI

### The dashboard toolbar

The toolbar across the top of the Dashboards page is where you switch layouts and manage them. It includes a **layout picker** (with badges that mark your default layout, any shared layouts/templates, collaborative layouts shared with you, and a lock on read-only layouts), and buttons to create a **New Layout**, open **Manage Layouts**, **Refresh** all widgets, and toggle **Edit** mode.

![The dashboard toolbar (highlighted): the layout picker, plus New Layout, Manage Layouts, Refresh, and Edit](images/pro_dashboard_v2_home.png)

### Step 1: Enter edit mode

Click **Edit** to unlock the dashboard. The grid becomes draggable and resizable, and an **Add Widget** button appears. Click **Done** when you are finished — edit mode also turns off automatically when you switch layouts.

![A dashboard in edit mode, showing drag and resize handles](images/pro_dashboard_v2_edit_grid.png)

### Step 2: Add a widget

In edit mode, click **Add Widget** to open the picker. It has three tabs:

- **By Type**: browse the catalog by category (Numbers, Charts, Lists & Feeds, Static & Utility). Each card shows the widget's name and a short description. Picking one adds it to the grid and opens its configuration dialog.
- **From Catalog**: start from a pre-configured widget taken from one of the shared templates (for example, the "Findings by Severity" chart from the Default Dashboard). These come ready-configured, so they drop straight onto the grid.
- **From Reports**: start from a Chart or Widget block someone already built in the [Report Builder](../../reports/report-builder/). The widget lands configured the way that block is. This tab appears when Reporting is enabled and you can view report templates.

![The Add Widget dialog, By Type tab](images/pro_dashboard_v2_add_widget.png)

### Step 3: Configure the widget

Each widget opens a configuration dialog tailored to its type. Common settings include:

- **Title** — the heading shown on the widget.
- **Model** — which records the widget reads (Finding, Asset, Engagement, or Test), where applicable.
- **Filters** — an embedded list-view filter UI that scopes the widget to exactly the records you want (for example, active Critical findings). The filters you pick here are the same ones you would use on that object's list page.
- **Refresh interval** — how often the widget reloads on its own.
- **Type-specific options** — for example chart type and group-by dimension for a Graph, thresholds for a Gauge, or the metric for a Top-N leaderboard.

![Configuring a Graph widget](images/pro_dashboard_v2_widget_config.png)

#### Graph options

A Graph widget groups its records by one dimension (**Group By**) and can split each group by a second (**Split By**):

- **Split By** draws one line, or one run of bars, per value of a second dimension. Grouping by **Created Date** by month and splitting by **Severity Group** gives new findings per month as two lines, one for Critical and High findings and one for Medium and Low findings. Split By takes any dimension that is not a date and not the Group By, and is available on bar, line and area charts (a pie or doughnut shows one dimension). A chart draws up to 10 series: past that, the smallest values are combined into one **Other** series. A chart that counts unique CWEs or vulnerability IDs cannot combine values that way, so it asks for a filter or a dimension with fewer values instead.
- **Severity Group** is a finding dimension with three values: **Critical and High**, **Medium and Low**, and **Info**. It works as a Group By (a two or three slice doughnut) or as a Split By. Its lines and slices are red for Critical and High and green for Medium and Low unless you pick other colors. Clicking one opens the Findings list filtered to that group's severities.
- **Created Date** is when a finding was created in DefectDojo (when it was imported or added), as opposed to **Discovered Date**, the date the scanner reported. Charting new findings per month by Created Date counts each finding in the month it arrived.
- **Show Values** prints the number on each bar, point or slice. A pie or doughnut also shows each slice's share of the total.
- **Stacked** stacks the series of a split chart on top of each other instead of drawing them side by side. It appears once Split By is set.
- **Colors** sets the color of each series (with Split By) or of each slice or bar (without). **Default** keeps the color the chart would pick, such as the severity colors.

A chart over a date (**Created Date**, **Discovered Date**, **Mitigated Date** and the others) shows every period between its first and last, with 0 for a month in which nothing happened, so a line never skips a gap. When the widget filters on the same date (for example Created Date in the past 180 days), the chart spans that whole window. Records with no value for the date, such as open findings on a Mitigated Date chart, are not counted, so a fixed-findings-per-month chart needs no extra Mitigated filter.

A management pack of three monthly charts, for example, is three Graph widgets over findings:

| Chart | Chart Type | Group By | Split By | Filters |
|-------|------------|----------|----------|---------|
| Open findings by severity | Doughnut, with Show Values | Severity | | Active findings |
| New findings per month | Line, with Show Values | Created Date, by Month | Severity Group | Created Date in the past 180 days |
| Fixed findings per month | Line, with Show Values | Mitigated Date, by Month | Severity Group | Mitigated Date in the past 180 days |

> **💡 Tip:** A widget's data always respects your permissions. If a shared layout includes a "My Work" widget, every viewer sees *their own* assignments and mentions — not the layout author's.

### Step 4: Arrange, then save

Drag widgets to rearrange them and drag a corner to resize. Each widget's title bar holds a **Widget Actions** menu (the three dots beside the refresh button). While editing it offers **Edit Widget** to reconfigure the widget, **Title Style** to set the title's weight and size, **Duplicate Widget** to copy it, and **Remove Widget**, which asks for confirmation. Position and size changes are saved automatically as you go. Click **Done** to leave edit mode.

Duplicating a tile is the fastest way to build a row of related tiles: the copy keeps the original's type, filters, size, title style, and refresh cadence, lands in the next free space on the grid, and gets a **(Copy)** suffix on its title. Choose **Edit Widget** from its menu to rename it and change the one filter that differs.

A **Section Break** is the exception: its header already labels it, so a copy keeps the original's title as it is, with no **(Copy)** suffix. A Section Break's title is optional. Clear the **Title** field in its **Edit Widget** form to leave the widget's title bar blank.

### Putting a widget into a report

Customizable Dashboards and the [Report Builder](../../reports/report-builder/) share one widget catalog, so a figure your team reads on a dashboard can go straight into a document you send out.

Open a widget's **Widget Actions** menu and choose **Add to Report**. Name the block, optionally pick a report Template to append it to, and it is created carrying the widget's current filters. The action appears on widgets a report can draw, when Reporting is enabled and you have permission to add report templates; a widget that offers nothing else shows no menu while you are viewing.

This **copies** the widget rather than linking to it. Editing the dashboard widget later does not change the report block, and the reverse is also true, so a shared dashboard never depends on who can see which report block.

### Managing layouts

The **Manage Layouts** dialog (the gear button on the toolbar) is the hub for everything layout-level:

- **Saved Layouts** — rename, set as default, share/unshare, clone, or delete each layout you own. Collaborative layouts shared with you are listed here too, tagged **Collaborative**, and can be set as your default or copied into a layout of your own; a Maintainer also sees **Make Collaborative** / **Stop Collaborating** on shared layouts, and **Make Read-Only** / **Allow Editing** on collaborative ones. A read-only layout is tagged **Read-Only**.
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

> **💡 Tip:** Cloning a template makes an independent copy. Customize the clone freely — you will not affect the template or anyone else who clones it. A **collaborative** layout is the exception by design: it is used live rather than copied, so edits made to it are visible to everyone. Take your own copy of a collaborative layout only when you want a private version that no longer follows the shared one. A read-only collaborative layout works the same way, except that only a Maintainer or its owner can change it.

### The empty state

A brand-new layout with no widgets shows a **"Build a Dashboard"** prompt. Click **Add Widget** to jump straight into edit mode and start choosing widgets.

![The empty-layout state](images/pro_dashboard_v2_empty_state.png)

## The widget catalog

Customizable Dashboards ship with the following widget types, organized into four categories. Most widgets read one of four models — `finding`, `product` (Assets), `engagement`, or `test` — and are scoped by filters you choose. The fully detailed configuration options for each widget are documented in the [API guide](../custom-dashboards-api/).

### Numbers

Single-glance metrics — counts, KPIs, and gauges.

| Widget | What it shows |
|--------|---------------|
| **Count** | A single number from a filtered query — e.g. "Open Critical Findings" or "Active Engagements." Works with finding / asset / engagement / test. For findings, the **Measure** option can count unique CWEs or unique vulnerability IDs instead of rows. |
| **KPI / Trend** | A headline number plus its change versus the prior period, with an optional sparkline. With the **Snapshot** source it can instead show a chart of open findings at the end of each month or week (see [Open findings at each month end](#open-findings-at-each-month-end)). |
| **Gauge** | A ratio drawn as an arc gauge — a "universe" filter as the denominator and a "pass" filter as the numerator. Use for SLA compliance, mitigation rate, or scan coverage, with configurable warning/OK thresholds. |
| **License Usage** | Your account's license-usage status with a per-signal breakdown (database size, weekly finding volume, and so on). *Requires the Maintainer role.* |
| **Scan Coverage** | What fraction of assets were scanned within 30 / 90 / 180 / 365 days, as a multi-window rollup. |

### Open findings at each month end

A management pack usually reports how many findings were open at the end of each month, split by severity. A **Graph** widget cannot show that: it counts the findings as they are now. The **KPI / Trend** widget can, because its **Snapshot** source reads the nightly metrics snapshots, which record the open findings of every severity each night.

To chart the last six months with Critical and High as one line and Medium and Low as another:

1. Enter edit mode, choose **Add Widget**, and pick **KPI / Trend**.
2. Set **Source** to **Snapshot** and **Show As** to **Chart**.
3. In **Severities**, keep Critical, High, Medium and Low (remove Info if you do not want it).
4. Leave **Series** on **Critical and High, Medium and Low, Info**. Choose **One Series per Severity** instead to draw a line for each severity.
5. Leave **Period** on **Month** and **Periods Shown** at 6. **Week** charts the end of each week instead.
6. Pick **Line** or **Bar** in **Chart Type**, keep **Show Values** to print each count on its point, and change a series color if you need to (by default Critical and High is red, Medium and Low is green, and Info uses the Info severity color).
7. Submit. The widget is saved as soon as you submit; click **Done** to leave edit mode.

How to read the chart:

* Each point is the number of findings open on the last night of that month: the month end for a closed month, and the latest night for the current one. Hover a point to see which night it was read from.
* A month with no snapshot is left as a gap rather than drawn as zero. If the snapshots stopped partway through a month, the point shows the last night that was recorded, and the tooltip names that night.
* The numbers count the findings of the Assets you can view, so two people with different access can see different numbers on the same dashboard.
* History starts with the first nightly snapshot. Until then the widget says that history arrives after it.

### Charts

Time-series and distribution visualizations.

| Widget | What it shows |
|--------|---------------|
| **Graph** | A general-purpose chart over any model and group-by dimension: bar, line, area, pie, or doughnut. E.g. Findings by Severity, Findings by Month. For findings, the **Measure** option charts unique CWEs or unique vulnerability IDs per group, such as unique CWEs by severity for one Asset. **Split By** draws one series per value of a second dimension, such as new findings per month by Severity Group (see [Graph options](#graph-options)). For a chart by month, filter its date with **Full Months** (for example Last 6 Full Months) so that every month on the chart is complete; see [date filters](/navigation/pro__filter_index/#how-date-filters-are-evaluated). |
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
| **Top Root Causes** | The highest-ranked Root Cause clusters, with the number of Findings each groups, the Assets affected, and their priority and risk band. *Requires the Root Cause Correlation feature.* |

An **Embedded Table**'s filters are where the table starts, not a fixed scope. Anyone viewing the dashboard can change them from the table's filter bar or column filters. To keep a change, save it to your own table preference (**Save as New Preference**, then **Save Filters and Sort Order**): the widget opens with your saved filters from then on, for you only. A filter your preference leaves empty keeps the widget's own. To change what every viewer starts from, choose **Edit Widget** and change the filters there.

### Static & Utility

Notes, shortcuts, and structure.

| Widget | What it shows |
|--------|---------------|
| **Favorites** | User-curated quick links to specific pages in the app. |
| **Section Break** | A labeled divider for grouping related widgets under a heading. |
| **Markdown / Notes** | An inline rich-text panel for headers, context notes, or reference links. |
| **Quick Actions** | One-click action buttons that navigate to a chosen page. |

## Charting scans by category

Every Test Type belongs to a **category** that says what kind of scan it is: **SAST**, **DAST**, **SCA**, **API**, **Container**, **IaC**, **Secrets**, **Cloud**, **Infrastructure**, **Mobile** or **Penetration Test**. Charts and lists can group and filter by it, so a report of scans per category does not need a list of tools kept by hand.

- On a **Graph** widget with the **Test** model, choose **Category** as the group-by dimension to count tests (scans) in each category. To count scans per month in each category, group by **Created** with a **Month** time bucket and set **Split By** to **Category** (see [Graph options](#graph-options)); to chart one category on its own, filter the widget on **Category** instead.
- On the **Finding** model, the same breakdown is the **Test Category** dimension: findings grouped by the category of the test that reported them.
- The **Tests** list has a **Category** column (hidden by default; add it from the column picker) and a **Category** filter. The **Findings** list has a **Test Category** filter. Clicking a bar or slice of a chart grouped by category opens the matching list filtered to that category.

### Where a category comes from

Built-in scanners have a default category, chosen from the Test Type's name (for example, **ZAP Scan** is DAST, **Semgrep JSON Report** is SAST, **Trivy Scan** is Container, **Checkov Scan** is IaC). A Test Type whose name no default covers, such as a custom tool, takes **SAST** when it is marked **Static**, **DAST** when it is marked **Dynamic**, and otherwise **Uncategorized**.

**Uncategorized** is a category of its own: its tests show as their own bar or slice and can be selected in a filter, so no test is left out of a chart because its tool is unknown.

### Setting a Test Type's category

1. Go to **Settings > Test Types**. The **Category** column shows each Test Type's category, marked **(default)** when it comes from the default rather than from a choice someone made.
2. Open a Test Type's menu and choose **Edit Test Type**.
3. Pick a **Category** and click **Submit**.

The change applies to every test of that type, including tests imported before it, and charts show it the next time they load. To go back to the default, clear the **Category** field and submit. The placeholder names the default the Test Type returns to.

Changing a category needs permission to edit Test Types.

## Next steps

- **[Automating Dashboards with the API](../custom-dashboards-api/)** — discover the widget catalog, create and update layouts, and render widget data over the REST API, with a complete script.
- **[Building Dashboards with an LLM](../custom-dashboards-llm/)** — let an LLM design and build dashboards for you (the dashboards API was built with AI agents in mind).
- **[MCP Server — Dashboards Toolset](../../ai/mcp_server_pro/#dashboards-toolset)** — connect an AI assistant to the MCP Server with `?toolsets=dashboards` to summarise, diagnose, build and share dashboards from the chat, with no script.
