---
title: "EPSS / KEV"
description: "How DefectDojo Pro enriches Findings with EPSS and CISA KEV data, when it syncs, and how it drives priority"
audience: pro
weight: 6
---

DefectDojo Pro automatically enriches your Findings with two external threat-intelligence sources — **EPSS** and **CISA KEV** — so that prioritization reflects how likely a vulnerability is to be exploited, not just its CVSS severity. Both sources match to Findings by **CVE**, refresh on a **daily schedule**, and feed directly into each Finding's computed **priority** score.

On DefectDojo Cloud, enrichment is fully managed: DefectDojo maintains the underlying threat-intelligence data and delivers it to your instance. There is nothing to install, no feed URLs to configure, and no daily job to schedule — it runs for you.

## The two sources

### EPSS — Exploit Prediction Scoring System

[EPSS](https://www.first.org/epss/) is a data-driven model published by FIRST that estimates the probability a given CVE will be exploited in the wild in the next 30 days. DefectDojo Pro stores two EPSS values on each matching Finding:

| Field | Meaning |
| --- | --- |
| **EPSS Score** | Probability of exploitation in the next 30 days, from `0.0` to `1.0` (e.g. `0.94` = 94%). |
| **EPSS Percentile** | Where this CVE ranks against all scored CVEs, from `0.0` to `1.0` (e.g. `0.99` = in the top 1% most likely to be exploited). |

When a single Finding carries **multiple CVEs**, DefectDojo keeps the **highest EPSS score** among them and pairs it with that CVE's percentile.

### KEV — CISA Known Exploited Vulnerabilities

The [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) is the U.S. government's authoritative list of vulnerabilities that are confirmed to have been exploited in the wild. Unlike EPSS (a prediction), KEV is a statement of observed, real-world exploitation. DefectDojo Pro stores three KEV values on each matching Finding:

| Field | Meaning |
| --- | --- |
| **Known Exploited** | `True` when the CVE appears in the CISA KEV catalog. |
| **Ransomware Used** | `True` when CISA notes the CVE has been leveraged in ransomware campaigns. |
| **KEV Date** | The date the vulnerability was added to the KEV catalog. |

When a Finding carries **multiple CVEs**, it is marked **Known Exploited** if **any** of its CVEs is in the catalog, **Ransomware Used** if any qualifies, and the **KEV Date** is the earliest catalog-add date among them.

> **Findings without a CVE are not enriched.** Both sources match strictly on CVE identifiers (`CVE-YYYY-NNNNN`). A Finding with no CVE — or with only a vendor-specific or GHSA-style identifier — receives no EPSS or KEV data.

## When it syncs

Enrichment runs **once per day, automatically**, against your **entire** Finding population — not just newly imported Findings. On each run, every Finding that has at least one CVE is re-matched against the latest EPSS and KEV data, its enrichment fields are refreshed, and its priority is recomputed.

A few consequences worth understanding:

- **Imports are not enriched at import time.** A CVE Finding imported today will show EPSS/KEV values after the next daily enrichment cycle, not the instant it lands. Expect up to roughly a day of lag on brand-new Findings.
- **Values are kept current, not frozen.** Because the whole population is reprocessed daily, EPSS scores drift as the model updates, and a CVE that gets added to the KEV catalog will flip an existing Finding to **Known Exploited** on the next run — no re-import required.
- **KEV removals are respected.** If a Finding's CVEs are no longer KEV-listed, the daily run clears the stale **Known Exploited** / **Ransomware Used** / **KEV Date** values rather than leaving them set.

## How it impacts priority and risk

EPSS and KEV are not just informational badges — they are direct inputs to the DefectDojo Pro **prioritization engine**. Each Finding's `priority` score combines several components (severity, exposure, asset context, and more); EPSS and KEV drive the **external score** component, which rewards vulnerabilities that are likely to be — or are known to be — exploited.

The external score is derived from whichever of the following signals is **strongest**:

- **EPSS** contributes in proportion to its score — a higher probability of exploitation contributes more.
- **KEV listing** contributes a fixed weight: being **Known Exploited** *or* used in **ransomware** applies a meaningful boost, and a CVE that is **both** Known Exploited **and** used in ransomware applies the largest boost.

The larger of the two signals wins, so a Finding gets full credit for either a high EPSS score or a KEV listing without being penalized for lacking the other. This external score is then blended into the Finding's overall priority alongside its severity and exposure. The net effect: **a KEV-listed or high-EPSS Finding rises above an otherwise-comparable Finding that has neither**, focusing remediation on what is genuinely most likely to be attacked.

This flows automatically — priority is recomputed for exactly the Findings updated at the end of each daily enrichment run, so prioritization stays in step with the latest threat intelligence.

> **Note:** EPSS and KEV influence the **priority** score. They do not change a Finding's **Severity** field or its **SLA** clock, which remain severity- and age-driven.

## Filtering and viewing enriched Findings

Once Findings are enriched, the EPSS and KEV values are available throughout the Pro UI:

- **On the Finding** — EPSS score, EPSS percentile, Known Exploited, Ransomware Used, and KEV Date all display on the Finding detail.
- **Sorting** — Finding tables can be ordered by EPSS score / percentile to surface the most likely-to-be-exploited Findings first.
- **Filtering** — the Findings list offers **Known Exploited** and **Ransomware Used** filters, so you can build views or reports scoped to confirmed real-world-exploited vulnerabilities.

A common workflow is to filter to **Known Exploited = true**, then sort by priority, to produce a "fix these first" queue backed by confirmed exploitation.

## Configuration

On **DefectDojo Cloud**, EPSS and KEV enrichment is enabled and maintained for you — there are no source toggles, feed URLs, or thresholds to set, and the daily sync is managed by DefectDojo. The weightings that translate EPSS and KEV into priority are built into the prioritization engine.

If EPSS or KEV data is not appearing on Findings you expect it to (and those Findings do carry CVEs), contact DefectDojo support — the enrichment pipeline reports source-level health, and support can confirm whether the daily sync is delivering data to your instance.

> *On-premise installations* configure enrichment differently — each source can be enabled or disabled and pointed at a custom feed URL under the Tuner's finding-enrichment settings. That configuration does not apply to Cloud, where the data is delivered by DefectDojo.
