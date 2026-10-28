---
title: "Ingestion Health"
description: "Flag a Connector whose Syncs keep succeeding with zero Findings against its usual volume, and acknowledge it with a reason"
pro-feature: true
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Upstream Connectors are a DefectDojo Pro-only feature. Ingestion Health is a Beta feature behind the **Ingestion Health** feature flag, which is off by default. Turn it on from [Feature Flags](/admin/feature_flags/pro__feature_flags/).</span>

A Connector that fails tells you so. A Connector that keeps syncing successfully while importing nothing does not: every Operation is green, and the only sign is Findings that stop arriving. The usual causes are a credential whose scope was narrowed, a filter in the tool that now excludes everything, or projects moved out of the Connector's reach.

Ingestion Health compares each Sync against what the Connector usually returns. When a Connector goes quiet against its baseline, its tile says so, with the number it normally imports, and an operator can acknowledge it with a reason that stays on record.

Ingestion Health only warns. It never pauses a Connector, changes its schedule, or blocks a Sync.

## What you see on the Connector

When every actively mapped record of a Connector has returned zero Findings for two Syncs in a row, and the Connector has a baseline above zero, its tile on **Connections > Upstream** shows an orange line:

**Returned 0 Findings Against a Baseline of *n***

Hover the line to see when the quiet period began and what to check in the tool. This line takes the place of the **Zero Results** chip described in [Managing Operations](/connectors/upstream/manage_operations/#zero-results); the rules for when a Sync counts as empty are the same.

## How the baseline is computed

The baseline is the median number of Findings the Connector returned per Sync over the last 30 days.

* **One Sync is one sample.** A Sync covers every record of the Connector, so the Findings of all its records are added up first. A Connector with nine quiet projects and one busy one still has a baseline above zero.
* **Findings are counted as the tool returned them**, before deduplication. A tool that returns nothing is the signal, and deduplication must not hide it.
* **Three Syncs are needed.** Below three Syncs in the last 30 days there is no baseline, and no anomaly is raised. A new Connector, or one that only recently started syncing, never alerts until it has a history. The **Zero Results** chip still shows in that case.
* **The median, not the average**, so one large backfill does not set the bar.

## Acknowledging an anomaly

Users who can edit Connectors see an **Acknowledge** button beside the line. It opens a form with one required field, **Reason**: why the quiet period is expected or already handled, such as a project that was retired or a scanner that was paused.

After you submit, the tile shows a gray **Acknowledged** tag. Hover it to see who acknowledged the anomaly, when, and the start of the reason. Acknowledgments are kept in full in the audit history, so they can be reviewed after the anomaly resolves.

If someone else acknowledged the anomaly first, or a Sync resolved it while the form was open, nothing is saved: a message says so, the first reason is kept, and the tile updates to show the anomaly as it stands.

Users who can only view Connectors see the line and the tag, but not the button.

## How an anomaly resolves

The next Sync that imports any Findings, from any record of the Connector, resolves the anomaly, whether or not it was acknowledged. The tile goes back to its usual lines. If the Connector goes quiet again later, a new anomaly is raised; each quiet period is recorded on its own.

Nothing else resolves an anomaly. Mapping a new record, or setting a quiet record to Ignored, changes which records are counted but imports nothing, so an anomaly, and an acknowledgment on it, stays until Findings arrive.

## Notifications

Ingestion Health does not add a separate message. The **Connector Health Warning** notification already goes out when a Connector's Syncs return zero results, once per day while the condition lasts, and Ingestion Health records on the anomaly that it was sent. See [Connector health notifications](/admin/notifications/about_notifications/#connector-health-notifications-pro) for where the message goes and how to route it to Email, Slack or Teams.

## Turning it off

With the **Ingestion Health** flag off, no baseline is computed, no anomaly is raised, and the tile shows the **Zero Results** chip as before. Anomalies already raised are kept and show again if the flag is turned back on.
