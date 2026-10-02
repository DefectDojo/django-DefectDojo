---
title: "False Positive History"
description: "Automatically mark new Findings as false positive when a matching Finding was already triaged that way"
weight: 7
---

**False Positive History** saves your team from triaging the same false positive over and over. When it is enabled and a Finding is imported, DefectDojo looks for existing Findings in the same Asset that match it, and if any of those are already marked **False Positive**, the incoming Finding is marked False Positive too.

> **This feature is marked EXPERIMENTAL in the Asset**, and it **cannot be used at the same time as Deduplication.** Read [When you can use it](#when-you-can-use-it) before turning it on.

## What it does

Say a scanner reports a finding your team investigates and marks as a false positive. On every later scan, that same finding comes back. Normally someone has to dismiss it each time. With False Positive History on, DefectDojo recognises the returning finding and marks it False Positive automatically.

Findings marked this way are also set to **inactive** and **unverified**, not just False Positive. This is intentional — the finding drops out of your active queue entirely — but it surprises people who expect only the False Positive flag to change.

The rule DefectDojo maintains is: *within an Asset, if one Finding is a false positive, all matching Findings are too.*

### Retroactive mode

**Retroactive False Positive History** applies the same rule backwards. When you mark a Finding as a false positive, every other matching **active** Finding in that Asset is marked False Positive as well.

This rewrites existing data. There is no preview and no confirmation prompt — the change simply happens across the Asset. Turn it on deliberately.

## When you can use it

**False Positive History and Deduplication are mutually exclusive.** The two solve overlapping problems, so DefectDojo does not let you run both: in System Settings, enabling one greys out the other, and switching Deduplication on clears the False Positive History settings.

This is the single most important thing to understand about the feature. Most instances run Deduplication, and for those, False Positive History is not available. It is intended for instances that have deliberately chosen not to deduplicate.

## Enabling it

Both settings live in **System Settings**, in the deduplication block, and both are **off by default**:

| Setting | What it does |
| --- | --- |
| **Enable False Positive History** | Turns the feature on for the instance. |
| **Enable Retroactive False Positive History** | Also applies the rule backwards, as described above. Requires the setting above. |

These are **instance-wide**. There is no per-Asset or per-Tool override — enabling this affects every Asset on the instance.

## What counts as a match

False Positive History decides whether two Findings are "the same" using **the deduplication algorithm configured for the tool that reported them** — even though the Deduplication feature itself must be switched off.

| Tool's deduplication algorithm | Findings match when they share |
| --- | --- |
| **Hash Code** | the same hash code, built from that tool's configured Hash Code Fields |
| **Unique ID From Tool** | the same unique ID from the tool |
| **Unique ID From Tool or Hash Code** | either one |
| **Legacy** | the same title (case-insensitive) and the same severity |

So the accuracy of this feature is entirely determined by how well that tool's deduplication is configured. **Tune the tool's algorithm and hash fields before enabling False Positive History** — see [Deduplication Tuning](/triage_findings/finding_deduplication/pro__deduplication_tuning/) (Pro) or [Deduplication Tuning](/triage_findings/finding_deduplication/os__deduplication_tuning/) (Open Source).

Matching is scoped **within an Asset**. It never reaches across Assets, and never applies instance-wide.

### Set-based matching (Pro)

In DefectDojo Pro, matching also respects the **set-based Hash Code Fields** — the vulnerability-ID and CWE matchers (`vulnerability_ids_partial`, `vulnerability_ids_subset`, `cwes_partial`, `cwes_subset`, and their exact-match forms), with the same meaning they have in deduplication.

This makes Pro's matching **narrower** than Open Source's, and that is the point: without it, False Positive History could replicate a false positive to Findings that same-tool deduplication would not have considered duplicates at all. The refinement can only ever reduce the set of Findings that get marked — enabling Pro will never cause *more* Findings to be auto-marked.

On Open Source, matching uses the hash code alone, so it is broader. Bear that in mind when tuning.

## Risks worth understanding before you enable it

This feature marks Findings as false positive without a human looking at them. Its blast radius is set by your deduplication configuration, so a loose configuration is dangerous.

* **A loose match key can silently dismiss unrelated Findings.** The **Legacy** algorithm matches on nothing more than title and severity — so a single false-positive call could mark every same-titled, same-severity Finding in the Asset as a false positive, including genuine ones. The same applies to an over-broad set of Hash Code Fields. Tighten the algorithm first.
* **Retroactive mode rewrites existing Findings** with no preview, no prompt, and no summary of what it changed.
* **Findings are deactivated and unverified**, not merely flagged.
* **The bulk update bypasses the usual save-time processing**, so automation that reacts to Findings being updated may not fire for Findings changed this way.
* **It is still labelled EXPERIMENTAL** in DefectDojo itself.

A safer pattern for most teams is to keep Deduplication on and let duplicates inherit status from their original Finding, rather than switching to False Positive History. See [About Deduplication](/triage_findings/finding_deduplication/about_deduplication/).
