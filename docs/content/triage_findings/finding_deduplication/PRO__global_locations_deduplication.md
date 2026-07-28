---
title: "Global Locations Deduplication (Pro)"
description: "Deduplicate Findings by shared location (URL or dependency) across all Products"
weight: 6
audience: pro
---

Global Locations Deduplication is a DefectDojo Pro algorithm that identifies duplicate Findings across **all Products** based purely on a **shared location**: a URL, or a dependency (identified by its Package URL). Two Findings that share a location of a selected type are treated as duplicates regardless of their title, severity, CWE, or vulnerability IDs — the location alone is the identity.

It is the location-aware counterpart to [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/), applied to the DefectDojo Locations data model. Where Global Component matches only on a component name and version, Global Locations matches on the same dependency **by full Package URL** *and* on shared **URLs** — so it can deduplicate DAST/web Findings across Products, which Global Component cannot.

Unlike the scoped algorithms, Global Locations matching is **not scoped to a single Product or Engagement**. A Finding imported into Product B can be marked as a duplicate of an older Finding in Product A, even if the two Products are unrelated.

## Requirements

Global Locations is defined over the DefectDojo **Locations** data model and is only offered when the **Locations** feature is enabled. On instances where Locations is turned off, the Global Locations feature flag is shown as locked ("Requires Locations to be enabled") and the algorithm does not appear in the Tuner.

## Enabling the Global Locations Algorithm

Global Locations Deduplication is gated behind a feature flag and is **off by default**. Once Locations is enabled, a superuser can turn it on from **Settings > Feature Flags** on both Cloud and On-Premise instances. See [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Once the feature is enabled, **Global Locations** becomes available as an option in the **Deduplication Algorithm** dropdown for both Same Tool and Cross Tool Deduplication settings in the Tuner.

## Configuring Global Locations Deduplication

Global Locations can be applied to Same-Tool Deduplication, Cross-Tool Deduplication, or both, and is configured per security tool from **Settings > Pro Settings > Deduplication Settings**.

When you select **Global Locations**, the Hash Code Fields selector is hidden (it does not apply) and a **Location Types** selector appears instead.

### Location Types

Choose which location types participate in matching:

- **URLs** — two Findings match when they share a URL (compared on the configured endpoint fields, `DEDUPE_ALGO_ENDPOINT_FIELDS`).
- **Dependencies** — two Findings match when they reference the same dependency, by full Package URL identity.

At least one type must be selected; both are selected by default. A tool configured for **URLs** only ignores shared dependencies, and a tool configured for **Dependencies** only ignores shared URLs.

### Same-Tool

Use Same-Tool Deduplication with the Global Locations algorithm when you want to deduplicate Findings from a single tool across multiple Products by shared location.

1. Open the **Same Tool Deduplication** tab.
2. Select the tool from the **Security Tool** dropdown.
3. Set the **Deduplication Algorithm** to **Global Locations**.
4. Choose the **Location Types** to match on.
5. Submit the form.

### Cross-Tool

Use Cross-Tool Deduplication with the Global Locations algorithm when you want to deduplicate Findings that share a location across **different** tools and Products.

Cross-tool matching reads the importing tool's location-type selection, so configure Global Locations on **each** tool that should participate, with matching Location Types.

1. Open the **Cross Tool Deduplication** tab.
2. For each tool to include: select it from the **Security Tool** dropdown, set the algorithm to **Global Locations**, choose the Location Types, and submit.

## How Matching Works

A new Finding is marked as a duplicate of an existing Finding anywhere in the instance when the two share **at least one concrete location of a selected type**:

- **A URL** whose configured endpoint fields (`DEDUPE_ALGO_ENDPOINT_FIELDS`) all match, **or**
- **A dependency** with the same Package URL (an exact purl match, so `pkg:npm/timespan@2.3.0` does **not** match `pkg:npm/timespan@2.3.1`).

The match is **strict and non-vacuous**: two Findings that have no locations of a selected type are **never** deduplicated (unlike scoped location matching, "both empty" is not a match). If endpoint-field comparison is disabled (`DEDUPE_ALGO_ENDPOINT_FIELDS = []`), URLs cannot establish a match at all — only a shared dependency can.

Same-Tool matching stays within a single tool (test type). Cross-Tool matching crosses tools intentionally. The Engagement-scoped deduplication setting is ignored for this algorithm; matching is always global, and the `service` field still partitions deduplication as it does for the other global algorithms.

## Example

Assume Global Locations (both location types) is enabled on a DAST tool (Same Tool) and, for the cross-tool row, on a second DAST tool:

| Step | Import | Into Product | Result |
| --- | --- | --- | --- |
| 1 | DAST Finding at `https://shared.example.com/login` | Application 0 | 1 active Finding created |
| 2 | Same URL, **different** vulnerability (title + severity) | Application 1 | 1 Finding created, marked as duplicate of the Application 0 Finding (location alone matches) |
| 3 | Second DAST tool, same URL | Application 2 | 1 Finding created, marked as duplicate of the Application 0 Finding (cross-tool match) |
| 4 | DAST Finding at `https://other.example.com/admin` | Application 3 | 1 active Finding created — different URL, no shared location |
| 5 | Finding with no URL and no dependency | Application 4 | 1 active Finding created — no location to share |

Each duplicate Finding shows its original at the bottom of the Finding page in the duplicate chain.

## Global Component vs. Global Locations

Both are global (cross-Product) algorithms that ignore the Engagement scope and match on a single identity rather than the hash fields. Choose based on what identifies a duplicate for your tool:

| | Global Component | Global Locations |
| --- | --- | --- |
| Matches on | Component **name + version** | A shared **location**: a URL and/or a dependency |
| Dependency identity | Name and version | Full **Package URL** (type, namespace, name, version, qualifiers) |
| URL / DAST Findings | Not matched | Matched (on the configured endpoint fields) |
| Configurable | No | Yes — choose URLs, Dependencies, or both per tool |
| Data model | Works with or without Locations | Requires **Locations** (Pro) |
| Best for | SCA tools where a package name+version is the identity | Web/DAST tools and SCA under the Locations model, where the URL or exact dependency is the identity |

For a new instance using the Locations data model, Global Locations is the more precise successor to Global Component: it keys dependencies on the exact Package URL and additionally deduplicates URL-based Findings. Global Component remains available and unchanged for tools where component name + version is the identity you want.

## Cross-Product Visibility

Because Global Locations matching crosses Product boundaries, the original Finding in a duplicate chain may live in a Product that the user viewing the duplicate does not have permission to access.

In that case, the Finding is visible and labelled as a duplicate, but the user will not be able to open or navigate to the original. Consider this before enabling Global Locations on tools whose Findings are sensitive to Product-level access controls.

## Reverting

To stop using Global Locations for a given tool, open its Deduplication Settings and switch the algorithm back to one of the scoped options.

For **Same Tool** Deduplication:

- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

For **Cross Tool** Deduplication:

- Hash Code
- Disabled

Changing the algorithm triggers a background recalculation of deduplication hashes for the tool's existing Findings.
