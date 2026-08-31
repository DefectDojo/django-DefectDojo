---
title: "Deduplication Tuning"
description: "Configure how DefectDojo identifies and manages duplicate findings"
weight: 4
audience: pro
aliases:
  - /en/working_with_findings/finding_deduplication/tune_deduplication
  - /en/triage_findings/finding_deduplication/matching_configuration
---

Deduplication Tuning is a DefectDojo Pro feature that gives you fine-grained control over how findings are deduplicated, allowing you to optimize duplicate detection for your specific security testing workflow.

## Matching Configuration

In DefectDojo Pro, matching is configured at **Settings > Matching Configuration**.

This page replaced three separate pages (Same Tool Deduplication, Cross Tool Deduplication and Reimport Deduplication). Bookmarks to those pages redirect here. Instead of picking a tool from a dropdown on one of three pages, every tool is listed once with a column for each of the three matching kinds:

- **Same tool**: how repeated scans from one tool are recognised as the same finding.
- **Cross tool**: how findings from different tools are matched against each other.
- **Reimport**: which formula a reimport uses inside its own test.

A tool's row shows the algorithm in force for each kind, how many hash fields it uses, whether anyone has changed it from the shipped default, and whether a [dedupe pool](/triage_findings/finding_deduplication/pro__dedupe_pools/) overrides it.

### Changing a tool's matching

Select a tool's row to change its algorithm, its hash fields, or both. Because a matching change decides which findings are treated as the same finding, it is not saved directly:

1. Choose the new algorithm, the new hash fields, or both. The page explains what each algorithm matches on.
2. Select **Review impact**. DefectDojo reports how many findings of that tool are in scope, and warns you about the two things that are easy to miss (see below).
3. Confirm you understand the change, then select **Apply**.

**The two axes behave very differently, and the impact review says which one you are moving.**

- **Changing the algorithm** selects which stored value candidates are looked up by. Nothing is recomputed, and the change decides what the next import compares; existing duplicate links are left exactly as they are. The review warns you when the new algorithm would leave findings with no identity to match on at all — a tool whose findings carry no unique ID matches nothing once the algorithm requires one, and nothing errors when that happens.
- **Changing the hash fields** changes the value stored on every finding of that tool, so every hash already stored for it becomes stale. Applying queues a background recompute of the tool's whole backlog. Until that finishes, the tool's findings are hashed under two different definitions and may not match each other. The review tells you how many findings will be recomputed before you commit to it.

Two rules are enforced when you save a field selection, for the reasons in [Set-based Hash Code Fields](#set-based-hash-code-fields-vulnerability-ids-and-cwes) below: a vulnerability IDs field may stand on its own, and CWE fields may not be the only criteria.

> **Hash fields are set on the instance default, not per pool.** A [dedupe pool](/triage_findings/finding_deduplication/pro__dedupe_pools/) can give its members a different **algorithm**, but not a different field list. A finding stores one hash, and the classic UI, the v2 API and CSV exports all read that same value, so a pool-specific field list would change what every other view of that finding shows.

## Same Tool Deduplication

Same Tool Deduplication is enabled by default for all security tool parsers. This ensures findings from consecutive scans using the same tool are properly deduplicated.

To adjust Same Tool Deduplication, select the tool's **Same tool** column on **Settings > Matching Configuration** and follow the review-and-confirm steps above.

### Available Deduplication Algorithms

DefectDojo Pro offers the following deduplication methods for same-tool deduplication:

#### Hash Code
Uses a combination of selected fields to generate a unique hash. A tool's row on **Settings > Matching Configuration** shows how many fields make up its hash, and selecting the row lets you change them.

##### Content Fingerprint

**Content Fingerprint** is a selectable hash field (available in all three configuration areas) that provides a *location-invariant* identity for static-analysis findings. It is derived from the vulnerable code snippet a tool includes in the finding — normalized so that indentation, line-number annotations, and formatting differences do not change it. Two findings about the same vulnerable code hash identically even when the code moved to a different line or file.

Content Fingerprint is computed for tools that include a code snippet in the finding description — including **Bandit**, **Gosec**, **Brakeman**, **Checkmarx One**, and any tool whose description carries a fenced code block or SARIF snippet.

> **Before selecting Content Fingerprint as a hash field**, populate fingerprints for existing findings by running `./manage.py backfill_fingerprints`. Findings imported after the feature is present get fingerprints automatically, but pre-existing findings have none — selecting the field without backfilling makes existing and incoming findings hash differently, splitting every match until the backfill runs.

Content Fingerprint pairs well with **CWE** for tools that embed file paths or line numbers inside their titles, where other identity fields change every time the code moves. See [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/#choosing-hash-fields-for-tracked-tools).

#### Unique ID From Tool
Leverages the security tool's own internal identifier for findings, ensuring perfect deduplication when the scanner provides reliable unique IDs.

This algorithm can be useful when working with SAST scanners, or situations where a Finding can "move around" in source code as development progresses.

#### Unique ID From Tool or Hash Code
Attempts to use the tool's unique ID first, then falls back to the hash code if no unique ID is available. This provides the most flexible deduplication option.

#### Global Component
Matches findings by component name and version across **all Assets** in the instance, rather than within a single Asset or Engagement. Intended for SCA tools where the same vulnerable dependency appears in many Assets. This algorithm is off by default and must be enabled by DefectDojo Support. See [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/) for details.

#### Global Vulnerability ID
Matches findings by their **vulnerability IDs** (CVE, GHSA, …) across **all Assets** in the instance, rather than within a single Asset or Engagement. Intended for tools that report the same CVE across many Assets. Off by default and enabled by DefectDojo Support.

> **Two tools on the same instance-wide algorithm become mutual deduplication candidates.** When two *different* tools are both configured with an instance-wide algorithm (Global Component, or Global Vulnerability ID), their findings share a constant grouping hash, so a finding from either tool is considered for deduplication against the other on that shared dimension (component, or vulnerability ID). This is the intended cross-tool behavior — enable it only when you want those tools to dedupe together.

### Set-based Hash Code Fields (Vulnerability IDs and CWEs)

Two finding attributes hold a *set* of values rather than a single value: vulnerability IDs (CVE, GHSA, …) and CWEs. When using the **Hash Code** algorithm (Same Tool or Cross Tool), you can add the following fields to **Hash Code Fields** to control how those sets are compared:

| Field | Findings are duplicates when… |
|-------|-------------------------------|
| `vulnerability_ids` | they have the **exact same set** of vulnerability IDs |
| `vulnerability_ids_partial` | they share **at least one** vulnerability ID |
| `vulnerability_ids_subset` | one finding's vulnerability IDs are a **subset** of the other's |
| `cwes` | they have the **exact same set** of CWEs |
| `cwes_partial` | they share **at least one** CWE |
| `cwes_subset` | one finding's CWEs are a **subset** of the other's |

The `_partial` and `_subset` fields are compared per finding pair rather than folded into the hash: the remaining Hash Code Fields group the candidate findings, and the set comparison then narrows that group. (Exact matching — `vulnerability_ids` and `cwes` — is folded into the hash directly.)

**Empty values.** If a finding has no vulnerability IDs (or no CWEs) for the configured matcher:

- If Hash Code Fields also include an ordinary field (for example `title`), that field carries the identity — the set matcher is skipped for the pair and the findings can still match on the rest of the hash.
- If a set matcher is the **only** field, a finding with no values does not match anything: with nothing else to identify it, an empty set is not treated as matching every other finding.

**Configuration rules** (enforced when you save settings):

- A vulnerability IDs field (`vulnerability_ids`, `vulnerability_ids_partial`, or `vulnerability_ids_subset`) may be used on its own — a CVE or GHSA identifies a specific vulnerability instance.
- CWE fields (`cwes`, `cwes_partial`, `cwes_subset`) may **not** be the only criteria. A CWE is a weakness *class*, not a specific instance, so matching on CWE alone would merge unrelated findings. Pair a CWE matcher with an identifying field such as `title` or `file_path`.

## Cross Tool Deduplication

Cross Tool Deduplication is disabled by default, as deduplication between different security tools requires careful configuration due to variations in how tools report the same vulnerabilities.

To enable Cross Tool Deduplication, select the tool's **Cross tool** column on **Settings > Matching Configuration**, change the algorithm to Hash Code, and select the fields the hash should be built from.

Cross Tool Deduplication supports the Hash Code algorithm, which is suitable for most workflows, as different tools rarely share compatible unique identifiers. For SCA tools reporting the same dependencies, [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/) is also available as a cross-tool option (off by default).

Note that Cross Tool Deduplication is also scoped to individual Assets only.

## Reimport Deduplication

**⚠️ Reimport processes can completely discard Findings before they are recorded.  This can lead to data loss if set incorrectly, so Reimport Deduplication settings should be adjusted with caution.**

Reimport Deduplication Settings can be used to set an algorithm for Universal Parsers, or for a Generic Findings Import Parser.

Reimport Deduplication cannot be adjusted for other tools by default.  Users who want to adjust the Reimport Deduplication algorithm for other tools in their instance should reach out to [DefectDojo Support](mailto:support@defectdojo.com) for assistance.

To configure Reimport Deduplication, select the tool's **Reimport** column on **Settings > Matching Configuration**.

The following algorithm options are available for Reimport Deduplication:
- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

Reimport can completely discard Findings before they are recorded, so Reimport Deduplication settings should be adjusted with caution.

### Track Findings as Locations Change

A tool whose Reimport algorithm is **Hash Code** can also track findings as their locations change. With that enabled, a finding whose location moved between reimports — a line shift or file rename, a URL move, or a dependency version bump — is treated as the *same* finding, even if the tool re-scored its severity. One finding is maintained in place and its location history is preserved, instead of the old finding closing and an identical new one being created.

It is off by default, is set by DefectDojo Support in this release, and applies only to the Hash Code reimport algorithm (tools with a reliable Unique ID From Tool already track movement through their stable IDs). Enabling it automatically re-hashes the tool's existing findings in the background so historical data participates immediately.

See [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/) for how the matching works, what is preserved, and guidance for enabling it on large instances.

## Running Deduplication Retroactively on Existing Data

A common situation when first tuning matching is having a large backlog of Findings that were imported *before* the configuration changed. What happens to them depends on which axis you changed.

**Changing the hash fields re-hashes the backlog.** DefectDojo queues a background job to recompute the stored hash for every Finding from that tool, because the fields determine that value. The impact review tells you how many Findings that is before you apply.

- The job runs asynchronously. On large instances (millions of Findings), this takes time and you will not see immediate changes in the Findings table.
- Until it finishes, that tool's Findings are hashed under two different definitions and may not match each other.
- Existing duplicate links are not revisited. Re-hashing changes what future comparisons produce, not what was already decided.

If you make several changes in quick succession, each queues its own job. Allow the previous one to finish before evaluating results, especially when comparing Finding counts before and after.

> **Note for self-hosted Pro:** the job runs in the Celery worker pool. If workers are starved or backlogged, the re-hash takes longer than expected — check worker health if results do not appear within the timeframe you would expect for your instance size.

**Changing the algorithm re-hashes nothing**, by design: it selects which already-stored value is compared, so there is nothing to recompute. It decides what the next import compares, and existing duplicate links are left as they are.

If you need existing Findings re-evaluated against a new configuration, use a [dedupe pool's](/triage_findings/finding_deduplication/pro__dedupe_pools/) **Apply Now**, which re-runs deduplication over the Findings already in scope and reports what it would link before it does anything.

> **Feature flags do not gate an existing configuration.** A tool's saved matching configuration stays in effect for as long as it is configured; turning off a related feature flag does **not** retroactively revert that tool to default deduplication. To change a tool's behavior, change its algorithm on **Settings > Matching Configuration**.

## Deduplication Best Practices

For optimal results with Deduplication Tuning:

- **Start with defaults**: The preconfigured deduplication settings work well for most scenarios
- **Read the impact review before applying**: it tells you how many findings are in scope, whether a new algorithm leaves any of them with nothing to match on, and how many findings a field change will re-hash.
- **Plan retroactive re-hashes**: changing hash fields recomputes every existing Finding from that tool in the background. See [Running Deduplication Retroactively on Existing Data](#running-deduplication-retroactively-on-existing-data).
- **Test changes carefully**: After adjusting matching configuration, monitor a few imports to ensure proper behavior.
- **Use Hash Code for cross-tool deduplication**: When enabling cross-tool deduplication, select fields that reliably identify the same finding across different tools (such as vulnerability name, location, and severity).  **IMPORTANT** Each tool enabled for cross-tool deduplication **MUST** have the same fields selected.
- **Keep cross-tool sources in the same Asset**: Cross-Tool Deduplication is Asset-scoped.  Findings split across separate Assets will not dedupe even with matching hash fields.  See [Cross Tool Deduplication](#cross-tool-deduplication) above.
- **Avoid overly broad deduplication**: Cross-tool deduplication with too few hash fields may result in false duplicates
- **Backfill before selecting Content Fingerprint**: run `./manage.py backfill_fingerprints` first, then select the field — the triggered re-hash then has fingerprints to work with. See [Content Fingerprint](#content-fingerprint) above.
- **Enable location tracking between scan runs**: the toggle's automatic re-hash covers the tool's whole backlog; on large instances let it finish before the next scheduled reimport. See [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/#enabling-on-existing-data-upgrades).

By tuning deduplication settings to your specific tools, you can significantly reduce duplicate noise.

## Where a tool's matching came from

A tool's row on **Settings > Matching Configuration** marks configuration that has been changed from the shipped default, and names any dedupe pool that overrides it. A test's **Matching Policy** panel shows the same thing from the other direction: the algorithm actually in force for that test, and the pool responsible when it differs from the instance default.

That pairing is what answers "why did these two findings deduplicate differently" without a support ticket: two tests on the same tool showing different algorithms is a pool override, not a fault.