---
title: "Command Center"
description: "The flagship DefectDojo Pro dashboard family: posture score, instrumented pipeline funnel, honest coverage, TV mode, and the scheduled executive pack"
draft: false
audience: pro
weight: 11
slug: command-center
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: the Command Center is a DefectDojo Pro feature in beta. It builds on [Customizable Dashboards](../custom-dashboards/) and is off by default. A superuser can turn on the <b>command_center</b> flag from <b>Settings &gt; Feature Flags</b> (it requires the <b>dashboard_v2</b> flag).</span>

The Command Center expands DefectDojo Pro's customizable dashboards into a full security command center: one screen that answers, in fixed zones, **what's on fire**, **are we winning**, and **is the machine healthy**. It is not a new page: it ships as a family of preset layouts plus new widget types on the same dashboard system, so everything stays customizable, shareable, cloneable, exportable, and drivable from the [dashboards REST API](../custom-dashboards-api/).

> **💡 Tip:** In DefectDojo Pro, **Assets** were formerly called **Products** and **Organizations** were formerly **Product Types**. The UI follows your instance's naming setting.

## The preset family

Turning the flag on publishes four seeded, cloneable layouts under the **Command Center** group of the Shared Templates picker:

* **Command Center** (the new starter): the flagship screen. New users land on it; existing users keep their current dashboards and defaults, and can clone it whenever they like.
* **Exec Brief**: the board-facing view. The posture score with its why panel, the quarter's trajectory, risk acceptance debt, fix durability, and a fairness-normalized team scorecard.
* **Ops Triage**: queue first. Your work, what breaches next, this week's intake funnel, live activity, backlog aging.
* **Platform Health**: the machinery deep dive. The pipeline funnel at full width, the sensors rail, automation throughput, coverage freshness, license headroom.

With the flag on, the sidebar **Home** entry lands on your default customizable dashboard; the classic dashboard stays reachable as **Legacy Dashboard** while your team migrates.

## The daily snapshot backbone

Every Command Center trend reads from an append-only daily snapshot table that the nightly rollup writes: open findings by severity, SLA state (a five-state model that distinguishes "resolved late" from "still open and late"), the dedupe funnel's flows, scan freshness, automation counts, and the posture score's full input vector. History is kept indefinitely, and a backfill command reconstructs what the ledgers can honestly support so trendlines are not empty on day one. Reconstructed periods are labeled as such; nothing is interpolated or fabricated. Trend charts also carry event markers (a scanner onboarded, an SLA policy change, a score model version change) so a step in a line is never mistaken for a posture change.

## The pipeline funnel, with receipts

The centerpiece widget shows what the platform did with everything your tools submitted, in five exact stages: **ingested**, **unique after dedupe**, **after rules and triage**, **prioritized**, and **actionable now**. Every gap between stages is itemized from a ledger (matched dedupe outcomes, rule actions, the manual remainder), every stage clicks through to the exact findings list behind it with the filter chips visible, and the **receipts export** downloads the raw evidence rows: which findings each stage dropped, and why. It is compliance evidence, not a marketing percentage.

## Honest coverage

The coverage freshness widget buckets assets by days since their last scan, with **never scanned** as its own visually distinct state. Never scanned is not zero findings, and neither is ever rendered green. An optional matrix breaks freshness down by scan type.

## TV / wall mode

Any dashboard (or a playlist of several) can run full screen on a wall monitor: open the **Present on TV** dialog from the dashboard toolbar, pick the layouts and cadences, and bookmark the generated URL on the wall box. The kiosk auto-cycles with a dwell indicator, refreshes data on its own cadence, pins the wall for 90 seconds when a new Critical arrives, reloads itself every 8 hours, shows when its numbers were last true, and says so plainly when the connection is lost. Sign the wall box in as a dedicated read-only user: the screen shows exactly what that user is authorized to see, and nothing more.

## The scheduled executive pack

From the same toolbar you can schedule the **executive posture pack**: a server-rendered PDF (or HTML) of the score with its component breakdown, the funnel, current pressure numbers, and coverage honesty, generated on your cadence and delivered as a link to Generated Reports. Authorization is enforced again at download time, the pack's numbers come from the same snapshot ledger as the screen, and disabling the schedule is one toggle.

## New widget types

The Command Center adds thirteen widget types to the catalog, each wired to real tables and available on any layout: Big KPI, Posture Score, Pipeline Funnel, Coverage Freshness, Ingest Health, Automation Rate, Threat Pulse, Risk Acceptance Debt, Fix Durability, Top Fixes, Morning Brief, Team Scorecard, and Insights Plot. Four existing widgets gained modes: MTTR/MTTD (survival curve), SLA Burndown (five-state model), Recent Activity (live feed), and KPI/Trend (snapshot-backed deltas). Details and configuration schemas are discoverable at `GET /api/v2/dashboards/widget_catalog/`.

**Insights Plot** puts one of three charts from the Insights pages onto a dashboard: noise reduction by category, average EPSS score by tool, or findings past SLA. Pick the plot and a window in the widget's settings. These run the same aggregation as the matching Insights chart rather than a dashboard-side copy of it, so the two screens cannot report different numbers for the same window, and both are scoped to the findings you are authorized to see.

The posture score's scale, weights, and versioning policy are published: see [Posture Score](../posture-score/).
