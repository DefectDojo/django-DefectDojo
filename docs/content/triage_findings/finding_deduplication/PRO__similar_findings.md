---
title: "Similar Findings"
description: "Find related Findings on the View Finding page and manually link them as duplicates"
audience: pro
weight: 3
---

While [Deduplication](../about_deduplication) runs automatically at import time, **Similar Findings** is a manual, interactive tool on the **View Finding** page. It surfaces other Findings in the same Asset that resemble the one you are looking at, and lets you link them into a duplicate cluster by hand.

Use it when automatic deduplication did not group Findings you believe belong together, or when you want to explore what else in an Asset looks like the current vulnerability.

## Where to find it

Open any Finding and scroll to the **Duplicate & Similar Findings** card. It has two tabs:

- **Duplicate Findings** – the Findings already linked to this one as duplicates (the automatic cluster).
- **Similar Findings** – other Findings in the Asset that match the current Finding's values but are not yet part of its cluster.

Select the **Similar Findings** tab to run the query.

![The Duplicate & Similar Findings card on the View Finding page](images/pro_similar_findings.png)

## How Findings are matched

DefectDojo searches the **same Asset** for Findings that resemble the current one, based on values such as Vulnerability IDs (for example, CVE identifiers), CWE, file path, line number, and unique ID from tool. The current Finding is always excluded from its own results, and matching never reaches across Assets.

This is different from the automatic deduplication algorithm, which compares `hash_code` (or Unique ID from tool) to decide matches. Similar Findings deliberately casts a wider net so you can discover related Findings that strict hash matching would miss.

## Working with the results

The Similar Findings tab is a full data table with the same controls you use elsewhere in the Pro UI:

- **Keyword Search** and the per-column filter (funnel) and sort controls let you narrow the list.
- The **saved views** dropdown (**Default**) and the save icon let you store a filter/column layout for reuse.
- The column settings and layout buttons control which columns are shown.
- **Export** downloads the current results, and **Clear Filters** resets the table.

Each row shows the matching Finding's ID, Severity, Priority, Risk, Finding name, CWE, CVSS scores, Vulnerability IDs, EPSS data, exploit intelligence (Known Exploited / Ransomware), status, Asset, and more. Click a Finding name to open it.

## Actions

Open the action menu (the **⋮** button at the start of a row) to manage the duplicate cluster directly from this page:

![The Similar Findings row action menu](images/pro_similar_findings_actions.png)

- **Set As Original Finding** – promote a Finding to be the original (cluster root).
- **Mark As Duplicate** – link the similar Finding into the current Finding's duplicate cluster.

These actions manipulate the same duplicate relationships that automatic deduplication uses, so a Finding you link here behaves exactly like an automatically detected duplicate. Any Finding you mark as a duplicate then appears under the **Duplicate Findings** tab of this card.

An action may be unavailable when it is not valid, for example when the similar Finding is already the original of a different cluster, or when linking it would cross an Engagement boundary while Engagement-level deduplication is enabled.

## Enabling and disabling Similar Findings

Similar Findings is controlled by the global **Enable Similar Findings** system setting, which is enabled by default. Because the query looks across an entire Asset, it can be expensive on large Assets; if you notice slow View Finding pages, this setting can be turned off.
