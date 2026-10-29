---
title: "Ingestion Health"
description: "See every Connector, scheduled Triage Engine rule and API import stream that feeds DefectDojo, flag the ones that go quiet, fall short or stop running, and acknowledge them with a reason"
pro-feature: true
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Upstream Connectors are a DefectDojo Pro-only feature. Ingestion Health is a Beta feature behind the **Ingestion Health** feature flag, which is off by default. Turn it on from [Feature Flags](/admin/feature_flags/pro__feature_flags/).</span>

A Connector that fails tells you so. A Connector that keeps syncing successfully while importing nothing does not: every Operation is green, and the only sign is Findings that stop arriving. The usual causes are a credential whose scope was narrowed, a filter in the tool that now excludes everything, or projects moved out of the Connector's reach. A scheduled rule can go quiet the same way: it simply stops running, and nothing fails. So can a pipeline that uploads scans through the API: when it breaks or is switched off, imports simply stop arriving.

Ingestion Health keeps a record for everything that feeds DefectDojo regularly, compares each run against what that source usually does, and raises an anomaly when it falls short. An operator can acknowledge an anomaly with a reason that stays on record.

Ingestion Health only warns. It never pauses a Connector or a rule, changes a schedule, or blocks a Sync.

## The Ingestion Health page

**Settings > Operations > Ingestion Health** lists every source: each Upstream Connector, each [Triage Engine](/automation/triage_engine/about/) rule that is enabled and runs on a cron schedule, and each [API import stream](#api-import-streams). The **Ingestion Health** button on **Connections > Upstream** opens the same page. You need the **Connector View** permission to open it; scheduled rules are listed for users who also hold **Rule View**, and an API import stream is listed for users who can see its Asset (Product).

Each row shows:

* **Source**: the Connector or the rule, linked to its records and operations or to the rule editor. An API import stream is shown as its Asset and scan type, such as **Payments API / Trivy Scan**, linked to the Asset.
* **Kind**: Connector, Scheduled Rule or API Import.
* **Status**: the worst anomaly still going on (Auth Failed, then Stale, Zero Result and Volume Drop), **Acknowledged** once every anomaly still going on has been acknowledged, **Healthy**, or **Never Ran** for a source with no run on record yet.
* **Last Run** and **Last Run Status**: when the source last ran and how that run ended.
* **Last Result**: the Findings the last settled run submitted: a Connector's Sync, or an API import stream's import.
* **Baseline**: the median Findings per run over the last 30 days, for Connectors and API import streams. Hover it to see how many runs it is based on.
* **Next Expected**: when the schedule fires next, or for an API import stream, when its next import is due going by its usual interval.
* **Open Anomalies**: anomalies nobody has acknowledged yet.

Filter and sort by any of them. The gear menu on each row has **View Source**, **View Anomalies** and, for users who can edit that kind of source, **Thresholds**.

The page is refreshed by an hourly check. Opening it starts a check when none ran in the last hour, so a newly configured Connector appears at once and fills in shortly after.

## Anomaly kinds

* **Zero Result** (Connectors and API import streams). For a Connector, every actively mapped record has returned zero Findings for two Syncs in a row, and the Connector has a baseline above zero. This is the same condition as the [Zero Results](/connectors/upstream/manage_operations/#zero-results) chip. For an API import stream, its last import submitted no Findings while its baseline is above zero.
* **Volume Drop** (Connectors and API import streams). A successful run submitted some Findings, but fewer than half of the source's baseline (the share is a [threshold](#thresholds-and-snooze)). A Connector's Sync is judged once it has been finished for an hour, so a large import that is still landing its last records is not mistaken for a drop.
* **Stale** (every kind). A Connector or scheduled rule missed three scheduled runs in a row: its schedule fired that many times since it last ran. Counting the times the schedule actually fired means a weekday-only schedule never goes stale over a weekend. An API import stream is stale when it has gone without an import for longer than three of its usual intervals and longer than any gap it has had in the last 30 days. A Connector with no sync schedule never goes stale, and a source that has never run shows **Never Ran** rather than Stale.
* **Auth Failed** (Connectors). A Discover or Sync failed because the tool refused the Connector's credential (HTTP 401 or 403).

A source has at most one anomaly of each kind going on at a time.

## What you see on the Connector

A Connector's tile on **Connections > Upstream** shows its most urgent anomaly in place of the **Zero Results** chip, in orange:

* **Returned 0 Findings Against a Baseline of *n*** for a zero result. Hover it to see when the quiet period began and what to check in the tool.
* **Returned *n* Findings Against a Baseline of *n*** for a volume drop.
* **Missed *n* Scheduled Syncs** for a stale Connector.
* **The Tool Refused the Credential** for an authentication failure.

## How the baseline is computed

The baseline is the median number of Findings the Connector returned per Sync over the last 30 days.

* **One Sync is one sample.** A Sync covers every record of the Connector, so the Findings of all its records are added up first. A Connector with nine quiet projects and one busy one still has a baseline above zero. Findings from a large import that finished after its Sync closed still count toward that Sync.
* **Findings are counted as the tool returned them**, before deduplication. A tool that returns nothing is the signal, and deduplication must not hide it.
* **Three Syncs are needed.** Below three Syncs in the last 30 days there is no baseline, and no zero-result or volume-drop anomaly is raised. A new Connector, or one that only recently started syncing, never alerts until it has a history. The **Zero Results** chip still shows in that case.
* **The median, not the average**, so one large backfill does not set the bar. A Sync being judged for a volume drop is left out of its own baseline.

## API import streams

Scans uploaded through the API (`/api/v2/import-scan/`, `/api/v2/reimport-scan/` and their background variants, from a CI pipeline or a script) are tracked as streams: one stream per Asset and scan type. A stream gets a row once it has an import in the last 30 days, and its row goes away after 30 days without one, unless it has an anomaly still going on.

* **Imports close together are one run.** A pipeline that uploads one scan per repository into the same Asset writes several imports within seconds. Imports of one stream less than 15 minutes apart count as a single run, and their Findings are added up, so one quiet repository does not read as a zero result. A run is judged once 15 minutes have passed with no further import.
* **The interval is observed.** Nothing schedules an import, so a stream's usual interval is the median time between its runs over the last 30 days (at least three runs, and never less than 15 minutes). **Next Expected** is the last run plus that interval.
* **A failed import** (one the API refused or could not parse) shows as an error in **Last Run Status** and counts as a run for staleness, but never toward the baseline.
* Imports made by Connectors are not streams: they belong to the Connector's own row.

## Acknowledging an anomaly

Users who can edit Connectors (or rules, for a scheduled rule, or the Asset, for an API import stream) can acknowledge an open anomaly, from the **Acknowledge** button on the Connector's tile or from **View Anomalies** on the Ingestion Health page. The form has one required field, **Reason**: why the anomaly is expected or already handled, such as a project that was retired or a scanner that was paused.

After you submit, the anomaly shows a gray **Acknowledged** tag. Hover it on the tile to see who acknowledged it, when, and the start of the reason; **View Anomalies** shows the reason in full. Acknowledgments are kept in the audit history, so they can be reviewed after the anomaly resolves.

If someone else acknowledged the anomaly first, or a later run resolved it while the form was open, nothing is saved: a message says so, the first reason is kept, and the page updates to show the anomaly as it stands.

Users who can only view a source see its anomalies and their reasons, but cannot acknowledge them.

## How an anomaly resolves

Each kind resolves when the source behaves normally again, whether or not it was acknowledged:

* **Zero Result**: the next Sync that imports any Findings, from any record of the Connector. Mapping a new record, or setting a quiet record to Ignored, imports nothing, so it does not resolve the anomaly. For an API import stream, the next import that submits any Findings.
* **Volume Drop**: a later settled Sync that reaches the threshold again.
* **Stale**: the source runs again.
* **Auth Failed**: the next successful Discover or Sync.

If the source falls short again later, a new anomaly is raised; each period is recorded on its own.

## Thresholds and snooze

**Thresholds** in a source's gear menu changes when that source alerts. It needs the permission to edit that kind of source.

* **Volume Drop Below** (Connectors and API import streams, default 50%): a run that submits fewer Findings than this share of the baseline opens a volume drop.
* **Stale After Missed Runs** (default 3, from 2 to 10): how many scheduled runs in a row the source may miss. For an API import stream, each of its usual intervals that passes with no import is a missed run.
* **Snooze Until**: the source raises no new anomaly through this date. Anomalies already going on stay, and a later run still resolves them.
* **Alert on Zero Results** (Connectors and API import streams, on by default): turn it off for a source that is expected to return nothing for long stretches. On a Connector, the **Zero Results** chip still shows.

## Notifications

The **Ingestion Health Warning** notification goes out once per anomaly when a Connector's or API import stream's volume drops, an API import stream returns no Findings, or any source goes stale. It reaches superusers and everyone who holds the view permission for that kind of source (for an API import stream, everyone who can see its Asset), on **🔔 Alerts** by default. A Connector's zero results and failed runs, refused credentials included, keep the **Connector Health Warning** that already covers them, so no condition sends two messages. See [Notifications](/admin/notifications/about_notifications/#ingestion-health-notifications-pro) for where each message goes and how to route it to Email, Slack or Teams.

## Dashboard widget

The **Ingestion Health Status** widget, under **Numbers** when you add a widget to a dashboard, shows how many of the sources you can see need attention (anomalous or stale), with a count for each status. Each count opens the Ingestion Health page filtered to the sources it counts. It is offered to users who can open the Ingestion Health page.

## API

`GET /api/v2/ingestion_health/sources/` lists the sources you can see, with the same fields and filters as the page, and `GET /api/v2/ingestion_health/sources/{id}/anomalies/` lists a source's anomalies, newest first. Both accept an API token. Thresholds and acknowledgments are set in the UI.

## Turning it off

With the **Ingestion Health** flag off, nothing is checked, no anomaly is raised, the Ingestion Health page and its menu entry are hidden, and the Connector tiles show the **Zero Results** chip as before. Sources and anomalies already recorded are kept and show again if the flag is turned back on.
