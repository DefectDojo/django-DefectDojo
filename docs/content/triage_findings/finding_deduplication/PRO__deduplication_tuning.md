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

### Changing an algorithm

Select the algorithm in a tool's row to change it. Because a matching change decides which findings are treated as the same finding, it is not saved directly:

1. Choose the new algorithm. The page explains what each one matches on.
2. Select **Review impact**. DefectDojo reports how many findings of that tool are in scope, and warns you when the new algorithm would leave findings with no identity to match on at all: a tool whose findings carry no unique ID matches nothing once the algorithm requires one, and nothing errors when that happens.
3. Confirm you understand the change, then select **Apply**.

The change decides what the next import compares. Existing duplicate links are left exactly as they are, so applying it does not re-link or unlink anything that is already recorded.

> **Hash fields are not editable in this release.** The algorithm is. Changing which fields make up a tool's hash changes how every hash already stored was computed, so it needs a new generation of hashes written behind it before matching can move across; that work is not released yet. To change a tool's hash fields, contact [DefectDojo Support](mailto:support@defectdojo.com).

## Same Tool Deduplication

Same Tool Deduplication is enabled by default for all security tool parsers. This ensures findings from consecutive scans using the same tool are properly deduplicated.

To adjust Same Tool Deduplication, select the algorithm in the tool's **Same tool** column on **Settings > Matching Configuration** and follow the review-and-confirm steps above.

### Available Deduplication Algorithms

DefectDojo Pro offers the following deduplication methods for same-tool deduplication:

#### Hash Code
Uses a combination of selected fields to generate a unique hash. A tool's row on **Settings > Matching Configuration** shows how many fields make up its hash; the fields themselves are not editable in this release (see the note above).

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

To enable Cross Tool Deduplication, select the algorithm in the tool's **Cross tool** column on **Settings > Matching Configuration** and change it to Hash Code.

The hash fields it uses are the ones already configured for that tool; they cannot be changed in this release (see the note above).

Cross Tool Deduplication supports the Hash Code algorithm, which is suitable for most workflows, as different tools rarely share compatible unique identifiers. For SCA tools reporting the same dependencies, [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/) is also available as a cross-tool option (off by default).

Note that Cross Tool Deduplication is also scoped to individual Assets only.

## Reimport Deduplication

**⚠️ Reimport processes can completely discard Findings before they are recorded.  This can lead to data loss if set incorrectly, so Reimport Deduplication settings should be adjusted with caution.**

Reimport Deduplication Settings can be used to set an algorithm for Universal Parsers, or for a Generic Findings Import Parser.

Reimport Deduplication cannot be adjusted for other tools by default.  Users who want to adjust the Reimport Deduplication algorithm for other tools in their instance should reach out to [DefectDojo Support](mailto:support@defectdojo.com) for assistance.

To configure Reimport Deduplication, select the algorithm in the tool's **Reimport** column on **Settings > Matching Configuration**.

The following algorithm options are available for Reimport Deduplication:
- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

Reimport can completely discard Findings before they are recorded, so Reimport Deduplication settings should be adjusted with caution.

### Track Findings as Locations Change

A tool whose Reimport algorithm is **Hash Code** can also track findings as their locations change. With that enabled, a finding whose location moved between reimports — a line shift or file rename, a URL move, or a dependency version bump — is treated as the *same* finding, even if the tool re-scored its severity. One finding is maintained in place and its location history is preserved, instead of the old finding closing and an identical new one being created.

It is off by default, is set by DefectDojo Support in this release, and applies only to the Hash Code reimport algorithm (tools with a reliable Unique ID From Tool already track movement through their stable IDs). Enabling it automatically re-hashes the tool's existing findings in the background so historical data participates immediately.

See [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/) for how the matching works, what is preserved, and guidance for enabling it on large instances.

## What changing an algorithm does to existing findings

Nothing, by design. Changing a tool's algorithm decides what the **next** import compares. Findings already in the instance keep the duplicate links they have, and no hashes are recomputed.

That is a deliberate difference from how a hash-field change behaves. Hash fields determine the value stored on each finding, so changing them requires recomputing that value across the tool's whole backlog; an algorithm change only selects which already-stored value is compared, so there is nothing to recompute.

If you need existing findings re-evaluated against a new configuration, use a [dedupe pool's](/triage_findings/finding_deduplication/pro__dedupe_pools/) **Apply Now**, which re-runs deduplication over the findings already in scope and reports what it would link before it does anything.

> **Feature flags do not gate an existing configuration.** A tool's saved matching configuration stays in effect for as long as it is configured; turning off a related feature flag does **not** retroactively revert that tool to default deduplication. To change a tool's behavior, change its algorithm on **Settings > Matching Configuration**.

## Deduplication Best Practices

For optimal results with Deduplication Tuning:

- **Start with defaults**: The preconfigured deduplication settings work well for most scenarios
- **Read the impact review before applying**: it tells you how many findings are in scope and, more importantly, whether the new algorithm leaves any of them with nothing to match on.
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