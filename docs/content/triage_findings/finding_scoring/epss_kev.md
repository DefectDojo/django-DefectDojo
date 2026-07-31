---
title: "EPSS / KEV"
description: "How DefectDojo Pro enriches Findings with EPSS and CISA KEV data, when it syncs, and how it drives priority"
audience: pro
weight: 2
aliases:
 - /triage_findings/epss_kev/
---

DefectDojo Pro automatically enriches your Findings with two external threat-intelligence sources — **EPSS** and **CISA KEV** — so that prioritization reflects how likely a vulnerability is to be exploited, not just its CVSS severity. Both sources match to Findings by **CVE**, refresh on a **daily schedule**, and feed directly into each Finding's computed **priority** score.

Enrichment data is stored **once per vulnerability**, then applied to every Finding that references it. That means a CVE seen on ten thousand Findings is looked up once, and you can inspect its EPSS and KEV values directly in the **Vulnerability Explorer** — not just Finding by Finding.

On DefectDojo Cloud, enrichment is fully managed: DefectDojo maintains the underlying threat-intelligence data and delivers it to your instance. There is nothing to install, no feed URLs to configure, and no daily job to schedule — it runs for you.

## The two sources

### EPSS — Exploit Prediction Scoring System

[EPSS](https://www.first.org/epss/) is a data-driven model published by FIRST that estimates the probability a given CVE will be exploited in the wild in the next 30 days. DefectDojo Pro stores two EPSS values on each matching Finding:

| Field | Meaning |
| --- | --- |
| **EPSS Score** | Probability of exploitation in the next 30 days, from `0.0` to `1.0` (e.g. `0.94` = 94%). |
| **EPSS Percentile** | Where this CVE ranks against all scored CVEs, from `0.0` to `1.0` (e.g. `0.99` = in the top 1% most likely to be exploited). |

When a single Finding carries **multiple CVEs**, DefectDojo keeps the **highest EPSS score** among them and pairs it with that CVE's percentile. The percentile always belongs to the same CVE as the score — the two are never mixed from different CVEs, because a percentile is only meaningful alongside its own score.

### KEV — CISA Known Exploited Vulnerabilities

The [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) is the U.S. government's authoritative list of vulnerabilities that are confirmed to have been exploited in the wild. Unlike EPSS (a prediction), KEV is a statement of observed, real-world exploitation. DefectDojo Pro stores three KEV values on each matching Finding:

| Field | Meaning |
| --- | --- |
| **Known Exploited** | `True` when the CVE appears in the CISA KEV catalog. |
| **Ransomware Used** | `True` when CISA notes the CVE has been leveraged in ransomware campaigns. |
| **KEV Date** | The date the vulnerability was added to the KEV catalog. |

When a Finding carries **multiple CVEs**, it is marked **Known Exploited** if **any** of its CVEs is in the catalog, **Ransomware Used** if any qualifies, and the **KEV Date** is the earliest catalog-add date among them.

A KEV signal is never suppressed by a higher-EPSS sibling. If a Finding carries one CVE with a high EPSS score that is *not* KEV-listed, and another with a low EPSS score that *is*, the Finding takes the high EPSS score **and** is marked Known Exploited — each field independently reflects the worst case across the Finding's CVEs.

> **Findings without a CVE are not enriched — unless one of their identifiers is linked to a CVE.** Both sources match strictly on CVE identifiers (`CVE-YYYY-NNNNN`), so a Finding whose only identifier is a GHSA, RUSTSEC or vendor-specific advisory has nothing to match on. [Linking equivalent identifiers](#linking-equivalent-identifiers) closes that gap: once `GHSA-jfh8-c2jp-5v3q` is recorded as an alias of `CVE-2021-44228`, Findings carrying only the GHSA inherit that CVE's EPSS and KEV data.

## When it syncs

Enrichment runs **once per day, automatically**. Each run happens in two stages:

1. **Refresh the vulnerability data.** Every CVE DefectDojo knows about is re-checked against the latest EPSS and KEV data, and the per-vulnerability record is updated.
2. **Apply changes to Findings.** Only the vulnerabilities whose values actually *moved* are pushed out to the Findings that reference them, and only those Findings are re-scored.

Because the second stage is driven by what changed, a quiet day is cheap: if neither source has published anything new, the run completes without rewriting your Findings. When something does change — an EPSS score drifts, or a CVE is added to the KEV catalog — every affected Finding picks it up on the next run.

A few consequences worth understanding:

- **Imports are not enriched at import time.** A CVE Finding imported today will show EPSS/KEV values after the next enrichment cycle, not the instant it lands. If you do not want to wait, you can [run a sync on demand](#running-a-sync-on-demand).
- **Values are kept current, not frozen.** A CVE that gets added to the KEV catalog will flip an existing Finding to **Known Exploited** on the next run — no re-import required.
- **KEV removals are respected.** If a Finding's CVEs are no longer KEV-listed, the run clears the stale **Known Exploited** / **Ransomware Used** / **KEV Date** values rather than leaving them set.

## Viewing KEV/EPSS in the Vulnerability Explorer

The **Vulnerability Explorer** lists one row per vulnerability ID, with the same five KEV/EPSS columns you get on the Findings table — **EPSS Score**, **EPSS Percentile**, **Known Exploited**, **Ransomware Used** and **KEV Date**:

![image](images/Pro_EPSS_KEV_Explorer_Columns.png)

These values describe the vulnerability itself, so they are identical no matter how many Findings reference it. EPSS Score, EPSS Percentile, Known Exploited and KEV Date are all sortable, which makes this the fastest way to answer "which vulnerabilities in my environment are actually being exploited?" — sort by **EPSS Score** descending, or sort by **Known Exploited** to bring the catalog-listed CVEs to the top.

Each row's **Total Findings** count links through to the Findings list filtered to that vulnerability, so you can go from "this CVE is KEV-listed" to "here is everything it affects" in one click.

## Telling "no data" apart from "not exploited"

A blank KEV/EPSS column and a red ✗ mean different things:

- **Red ✗ / a score** — this vulnerability *was* checked. A ✗ under Known Exploited means CISA does not list it.
- **Blank** — this vulnerability has **never been enriched**, so its exploitation status is simply unknown.

Here the same Explorer has never been synced, so every KEV/EPSS column is blank rather than showing zeros or ✗ marks:

![image](images/Pro_EPSS_KEV_Explorer_Unenriched.png)

The same distinction appears on the Finding itself. A Finding whose CVEs have not been enriched yet says so plainly, and links to the Explorer where you can start a sync:

![image](images/Pro_EPSS_KEV_Not_Enriched.png)

Once enrichment has run, the same panel reports what was actually found:

![image](images/Pro_EPSS_KEV_Finding_Panel.png)

This matters because "we have not looked yet" and "we looked and it is not exploited" would otherwise be indistinguishable, and only one of them is a reason to relax.

## Linking equivalent identifiers

The same vulnerability is often published under several identifiers. Log4Shell is `CVE-2021-44228`, and it is also `GHSA-jfh8-c2jp-5v3q`. A Rust advisory is `RUSTSEC-2021-0001` and may also carry a CVE. DefectDojo treats each identifier string as its own vulnerability, so by default they look unrelated.

That matters because **EPSS and KEV are only published per CVE**. A Finding whose scanner reported only the GHSA gets no EPSS score, is not marked Known Exploited, and gets no KEV-capped SLA — even though the equivalent CVE has all three.

An **alias link** records that two identifiers describe the same vulnerability. Once linked, a Finding carrying either identifier inherits the other's EPSS and KEV data, exactly as if the CVE had been on the Finding all along.

### Where aliases appear

Each vulnerability's page in the **Vulnerability Explorer** has a **Related Identifiers** section listing the identifiers DefectDojo associates with it, labelled by how strong that association is:

| Label | Meaning |
| --- | --- |
| **Linked** | A recorded alias. This is what drives EPSS/KEV inheritance. |
| **Co-occurring** | Another identifier that merely appears on the same Findings. Suggestive, but drives nothing. |

Only a **Linked** identifier has any effect. A co-occurring identifier is shown because it is often the alias you are looking for — each one carries a **Link as alias** action to promote it — but until it is linked it changes nothing.

On the Finding itself, a **Linked Identifiers** row lists the identifiers its own IDs are aliases of. When a Finding with no CVE of its own shows an EPSS score, that row is where the score came from.

### How aliases get created

Four sources, all of which can be in play at once:

| Source | What it does |
| --- | --- |
| **Import** | When a scanner reports a non-CVE identifier and a CVE on the same Finding, DefectDojo records the link. Several scanners do publish this equivalence (Grype's related vulnerabilities, and the `aliases` arrays from cargo-audit, govulncheck and Dependency-Track), and this recovers it. On by default. |
| **Backfill** | The `backfill_vulnerability_aliases` management command applies the same rule to Findings you already have, so an existing instance benefits without re-importing everything. |
| **Manual** | Link any two identifiers by hand from the Vulnerability Explorer. Requires Tuner edit permission, since an alias is instance-wide. |
| **OSV** | An optional nightly sweep that asks [OSV](https://osv.dev/) which CVEs your non-CVE identifiers are aliases of. Off by default; see [Configuration](#configuration). |

Import-derived links are deliberately conservative: DefectDojo only links a non-CVE identifier to a **CVE**, never CVE-to-CVE or one non-CVE to another, because only the CVE-anchored case unlocks anything. Two identifiers appearing together does not always mean they are the same vulnerability, which is why every link is reviewable and reversible.

### Reviewing and removing a link

A wrong link is consequential: it can mark a Finding Known Exploited and pull in its SLA deadline. So links are visible and revocable. **Unlink** on any linked identifier does two things:

1. Stops the inheritance, immediately.
2. **Withdraws what the link granted** — the Known Exploited, Ransomware Used and KEV Date values it supplied are cleared from the affected Findings, and each Finding is re-evaluated so any *other* valid source can put them back.

An unlinked pair also stays unlinked. None of the automatic sources will re-create it on the next import or nightly sweep, so you do not have to keep removing the same bad link.

> **EPSS scores are not withdrawn on unlink.** DefectDojo never clears an EPSS score, because scanners populate that field directly and clearing it would destroy scanner-reported data. After unlinking, an inherited EPSS score remains until a source supplies a new value. Only the KEV fields are withdrawn.

### Aliases resolve one step, not transitively

Resolution follows exactly **one** link. If `GHSA-x` is linked to `CVE-1`, and `CVE-1` is separately linked to `CVE-2`, then `GHSA-x` inherits from `CVE-1` only — not from `CVE-2`. This keeps resolution predictable and bounded; if you need the second relationship, link it directly.

### Aliases never change deduplication

Linking identifiers does **not** change any Finding's own list of vulnerability IDs. That list feeds DefectDojo's deduplication and reimport matching, so altering it would re-shuffle duplicates across your whole instance. Aliases are applied when enrichment data is read, never by rewriting the Finding — so you can link and unlink freely without disturbing deduplication.

## Running a sync on demand

You do not have to wait for the daily cycle. The **Sync KEV/EPSS data** button at the top of the Vulnerability Explorer starts a sync immediately:

![image](images/Pro_EPSS_KEV_Sync_Started.png)

While a sync is running, the button is disabled and a progress bar appears in its place, along with an estimate of the time remaining once enough work has completed to project one. The status line above it reports what is happening — first that DefectDojo is checking which vulnerabilities changed, then how many Findings have been updated so far. When the run finishes, the line reports the outcome: how many Findings changed, that everything was already up to date, or — if no source is configured — that the sync did not run.

Only one sync runs at a time. Pressing the button while one is already in progress simply attaches to the run that is already going rather than starting a second one, so it is safe to press if you are not sure whether a sync is underway. A sync is also safe to repeat: if nothing has changed since the last run, it rewrites nothing.

This is the fastest way to fill in Findings that were imported since the last daily cycle.

## How it impacts priority and risk

EPSS and KEV are not just informational badges — they are direct inputs to the DefectDojo Pro **prioritization engine**. Each Finding's `priority` score combines several components (severity, exposure, asset context, and more); EPSS and KEV drive the **external score** component, which rewards vulnerabilities that are likely to be — or are known to be — exploited.

The external score is derived from whichever of the following signals is **strongest**:

- **EPSS** contributes in proportion to its score — a higher probability of exploitation contributes more.
- **KEV listing** contributes a fixed weight: being **Known Exploited** *or* used in **ransomware** applies a meaningful boost, and a CVE that is **both** Known Exploited **and** used in ransomware applies the largest boost.

The larger of the two signals wins, so a Finding gets full credit for either a high EPSS score or a KEV listing without being penalized for lacking the other. This external score is then blended into the Finding's overall priority alongside its severity and exposure. The net effect: **a KEV-listed or high-EPSS Finding rises above an otherwise-comparable Finding that has neither**, focusing remediation on what is genuinely most likely to be attacked.

This flows automatically — priority is recomputed for exactly the Findings updated by each enrichment run, so prioritization stays in step with the latest threat intelligence.

> **Note:** EPSS and KEV influence the **priority** score. They do not change a Finding's **Severity** field. They can, however, affect the **SLA** clock: if your SLA configuration has **Cap by KEV due date** enabled, a KEV-listed Finding's SLA deadline is pulled in to CISA's remediation due date for that CVE. Where a Finding carries several KEV-listed CVEs, the earliest due date applies.

## Filtering and viewing enriched Findings

Once Findings are enriched, the EPSS and KEV values are available throughout the Pro UI:

- **On the Finding** — EPSS score, EPSS percentile, Known Exploited, Ransomware Used, and KEV Date all display on the Finding detail.
- **Sorting** — Finding tables can be ordered by EPSS score / percentile to surface the most likely-to-be-exploited Findings first.
- **Filtering** — the Findings list offers **Known Exploited** and **Ransomware Used** filters, so you can build views or reports scoped to confirmed real-world-exploited vulnerabilities.

A common workflow is to filter to **Known Exploited = true**, then sort by priority, to produce a "fix these first" queue backed by confirmed exploitation.

## Configuration

On **DefectDojo Cloud**, EPSS and KEV enrichment is enabled and maintained for you — there are no source toggles, feed URLs, or thresholds to set, and the daily sync is managed by DefectDojo. The weightings that translate EPSS and KEV into priority are built into the prioritization engine.

If EPSS or KEV data is not appearing on Findings you expect it to (and those Findings do carry CVEs), start by checking the status line on the Vulnerability Explorer — it reports the outcome of the most recent sync, including when no source is configured. If that looks healthy and data is still missing, contact DefectDojo support, who can confirm whether the daily sync is delivering data to your instance.

> *On-premise installations* configure enrichment differently — each source can be enabled or disabled and pointed at a custom feed URL under the Tuner's finding-enrichment settings. That configuration does not apply to Cloud, where the data is delivered by DefectDojo.

### Alias discovery against OSV

Automatic alias discovery is the one enrichment source that queries a third party once per identifier, so it is **off by default** and enabled explicitly under the Tuner's finding-enrichment settings:

| Setting | Meaning |
| --- | --- |
| **Vulnerability Alias Lookup Enabled** | When on, a nightly sweep asks OSV which CVEs your non-CVE identifiers are aliases of. |
| **OSV Lookup URL** | The endpoint to query. Defaults to the public OSV API. |

Leaving it off costs you nothing else: the import-derived, backfill and manual sources are all local to your database and keep working regardless. An air-gapped instance should leave this off and rely on those.

When enabled, discovery is a **background sweep and nothing waits on it**. Imports, Finding pages and the link/unlink actions never contact OSV, so an OSV outage cannot slow down or fail anything you do in the UI — only the sweep itself is affected, and it reports its own failure. Each sweep looks at a bounded number of identifiers and re-checks an identifier only occasionally, so a large instance works through its backlog over successive nights rather than in one burst.

You can also start a discovery sweep on demand from the Vulnerability Explorer. It returns immediately and reports progress as it goes, in the same way the KEV/EPSS sync does.
