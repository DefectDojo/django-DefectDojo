---
title: "Similar Findings"
description: "See a Finding's duplicate cluster and the Findings similar to it, and link them as duplicates by hand"
audience: pro
weight: 3
---

While [Deduplication](../about_deduplication) runs automatically at import time, **Similar Findings** is a manual, interactive tool on the **View Finding** page. It surfaces other Findings in the same Asset that resemble the one you are looking at, and lets you link them into a duplicate cluster by hand.

Use it when automatic deduplication did not group Findings you believe belong together, or when you want to explore what else in an Asset looks like the current vulnerability.

## Where to find it

Open any Finding and scroll to the **Duplicate & Similar Findings** card. Its **Duplicates** tab answers one question: what is this Finding the same as? It holds, top to bottom:

- A summary line: how many Findings are in this Finding's duplicate cluster, and how many similar Findings there are.
- **This Cluster**: the duplicate cluster as a tree. The cluster's original comes first, with the Findings deduplicated into it indented under it.
- **Similar, Not in This Cluster**: other Findings in the Asset that match the current Finding's values but are not part of its cluster.
- **Open in Findings**, which opens the Findings list filtered to the cluster.

The card's other tab, **Linked Findings**, lists the Findings a Keep Both Active rule linked to this one, and appears only when there are some. The Duplicates tab is hidden on a Finding with no duplicates and no similar Findings.

![The Duplicates tab on the View Finding page](images/pro_similar_findings.png)

## How Findings are matched

DefectDojo searches the **same Asset** for Findings with the same test type as the current one that also share every one of its values that is set: CWE, file path, line number, unique ID from tool, and Vulnerability IDs (for example, CVE identifiers). The current Finding is always excluded from its own results, and matching never reaches across Assets. Hover over the help icon beside **Similar, Not in This Cluster** to see the values the matches share.

This is different from the automatic deduplication algorithm, which compares `hash_code` (or Unique ID from tool) to decide matches. Similar Findings deliberately casts a wider net so you can discover related Findings that strict hash matching would miss.

## Working with the results

**The cluster tree.** The Finding you are viewing is marked **This Finding**. If it is the cluster's original, it is the first row. If it is a duplicate, the first row is its original, and the Finding itself is one of the rows under it. Each row shows the Finding's severity, title, where it was found (the Test and its tool) and its date. When the original sits in an Asset you cannot open, its row says so and links nowhere.

**Why is this a duplicate.** On a Finding that is a duplicate, **Why Is This a Duplicate** in the summary line opens the deduplication explanation in place: what matched (the hash fields, the scanner's own identifier, or the shared location), the algorithm, and the Dedupe Pool that governed the match. Select it again to close it.

**The Cluster column.** Each similar Finding says which cluster it already belongs to:

- **Not a duplicate**: it is in no cluster.
- **Original of _n_**: it is the original of another cluster with _n_ duplicates.
- **Duplicate of #_id_**: it is a duplicate of another Finding, which the number links to.

A similar Finding that is already in this cluster is listed in the tree, not again under it.

**Open in Findings.** The tab shows up to 100 Findings in each part. Search, filters, sorting, export and bulk actions live in the Findings list: **Open in Findings** opens it filtered to every duplicate in the cluster.

## Actions

Open the action menu (the **⋮** button at the start of a row) to manage the duplicate cluster directly from this page. Each action asks for confirmation before it changes anything.

![The similar Finding row action menu](images/pro_similar_findings_actions.png)

On a similar Finding:

- **Mark as Duplicate**: link the similar Finding into the current Finding's duplicate cluster. It moves into the cluster tree.
- **Set as Original Finding**: make the similar Finding the original of the current Finding's cluster.
- **Reset Duplicate Status**: take a Finding that is a duplicate of another cluster out of that cluster.

These actions manipulate the same duplicate relationships that automatic deduplication uses, so a Finding you link here behaves exactly like an automatically detected duplicate.

An action may be unavailable when it is not valid, for example when the similar Finding is already the original of a different cluster, or when linking it would cross an Engagement boundary while Engagement-level deduplication is enabled. The row then shows an information icon in place of the menu; hover over it to see why.

Rows in the cluster tree carry the same action menu as the Findings list.

## Enabling and disabling Similar Findings

Similar Findings is controlled by the global **Enable Similar Findings** system setting, which is enabled by default. Because the query looks across an entire Asset, it can be expensive on large Assets; if you notice slow View Finding pages, this setting can be turned off. With it off, the Duplicates tab shows the cluster only.

A **Similar Findings** widget, which shows the similar Findings alone with chips for the values they share, can also be added to the View Finding page: select **Edit Layout**, then **Add Widget**, and add a Data Table showing Similar Findings.
