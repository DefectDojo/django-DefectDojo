---
title: "Deduplication Tuning (Pro)"
description: "Configure how DefectDojo identifies and manages duplicate findings"
weight: 4
audience: pro
aliases:
  - /en/working_with_findings/finding_deduplication/tune_deduplication
---

Deduplication Tuning is a DefectDojo Pro feature that gives you fine-grained control over how findings are deduplicated, allowing you to optimize duplicate detection for your specific security testing workflow.

## Deduplication Settings

In DefectDojo Pro, you can access Deduplication Tuning through:
**Settings > Pro Settings > Deduplication Settings**

![image](images/deduplication_tuning.png)

The Deduplication Settings page offers three key configuration areas:
- Same Tool Deduplication
- Cross Tool Deduplication
- Reimport Deduplication

## Same Tool Deduplication

Same Tool Deduplication is enabled by default for all security tool parsers. This ensures findings from consecutive scans using the same tool are properly deduplicated.

To adjust Same Tool Deduplication:

1. Select a specific **Security Tool** from the dropdown
2. Choose a **Deduplication Algorithm** from the available options

![image](images/same_tool_deduplication.png)

### Available Deduplication Algorithms

DefectDojo Pro offers the following deduplication methods for same-tool deduplication:

#### Hash Code
Uses a combination of selected fields to generate a unique hash. When selected, a third dropdown will appear showing the fields being used to calculate the hash.

#### Unique ID From Tool
Leverages the security tool's own internal identifier for findings, ensuring perfect deduplication when the scanner provides reliable unique IDs.

This algorithm can be useful when working with SAST scanners, or situations where a Finding can "move around" in source code as development progresses.

#### Unique ID From Tool or Hash Code
Attempts to use the tool's unique ID first, then falls back to the hash code if no unique ID is available. This provides the most flexible deduplication option.

#### Global Component
Matches findings by component name and version across **all Products** in the instance, rather than within a single Product or Engagement. Intended for SCA tools where the same vulnerable dependency appears in many Products. This algorithm is off by default and must be enabled by DefectDojo Support. See [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/) for details.

#### Global Vulnerability ID
Matches findings by their **vulnerability IDs** (CVE, GHSA, …) across **all Products** in the instance, rather than within a single Product or Engagement. Intended for tools that report the same CVE across many Products. Off by default and enabled by DefectDojo Support.

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

![image](images/cross_tool_deduplication.png)

To enable Cross Tool Deduplication:

1. Select a **Security Tool** from the dropdown
2. Change the **Deduplication Algorithm** from "Disabled" to "Hash Code"
3. Select which fields should be used for generating the hash in the **Hash Code Fields** dropdown

Cross Tool Deduplication supports the Hash Code algorithm, which is suitable for most workflows, as different tools rarely share compatible unique identifiers. For SCA tools reporting the same dependencies, [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/) is also available as a cross-tool option (off by default).

Note that Cross Tool Deduplication is also scoped to individual Assets only.

## Reimport Deduplication

**⚠️ Reimport processes can completely discard Findings before they are recorded.  This can lead to data loss if set incorrectly, so Reimport Deduplication settings should be adjusted with caution.**

Reimport Deduplication Settings can be used to set an algorithm for Universal Parsers, or for a Generic Findings Import Parser.

Reimport Deduplication cannot be adjusted for other tools by default.  Users who want to adjust the Reimport Deduplication algorithm for other tools in their instance should reach out to [DefectDojo Support](mailto:support@defectdojo.com) for assistance.

![image](images/reimport_deduplication.png)

When configuring Reimport Deduplication:

1. Select the **Security Tool** (Universal or Generic Parser)
2. Choose the appropriate **Deduplication Algorithm**

The following algorithm options are available for Reimport Deduplication:
- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

Reimport can completely discard Findings before they are recorded, so Reimport Deduplication settings should be adjusted with caution.

## Running Deduplication Retroactively on Existing Data

A common situation when first turning on Deduplication Tuning is having a large backlog of Findings that were imported *before* the dedup configuration changed.  In DefectDojo Pro, you do not need to run a separate command to dedupe this historical data — **changing the Deduplication Settings for a tool automatically triggers a background re-hash of all existing Findings associated with that test type**.

What this means in practice:

- When you change the **Deduplication Algorithm** or the **Hash Code Fields** for a tool, DefectDojo queues a background job to recompute hashes for every Finding from that tool already in the instance.
- The job runs asynchronously.  On large instances (millions of Findings), this can take some time to complete and you will not see immediate changes in the Findings table.
- Newly-computed hashes apply to subsequent dedup decisions across the whole backlog.

If you make several configuration changes in quick succession, each one queues its own re-hash job.  Allow the previous job to finish before evaluating results, especially when comparing Findings counts before and after the change.

> **Note for self-hosted Pro:** The background job runs in the Celery worker pool.  If you have starved or backlogged workers, the re-hash can take longer than expected — check worker health if results don't appear within the timeframe you would expect for your instance size.

> **Feature flags do not gate an existing configuration.** A tool's saved Deduplication Settings stay in effect for as long as they are configured; turning off a related feature flag does **not** retroactively revert that tool to default deduplication. To change or stop a tool's deduplication behavior, update its Deduplication Settings directly (which also queues the background re-hash described above).

## Deduplication Best Practices

For optimal results with Deduplication Tuning:

- **Start with defaults**: The preconfigured deduplication settings work well for most scenarios
- **Test changes carefully**: After adjusting deduplication settings, monitor a few imports to ensure proper behavior.
- **Plan retroactive re-hashes**: Changing dedup settings re-hashes every existing Finding from that tool in the background.  See [Running Deduplication Retroactively on Existing Data](#running-deduplication-retroactively-on-existing-data) above.
- **Use Hash Code for cross-tool deduplication**: When enabling cross-tool deduplication, select fields that reliably identify the same finding across different tools (such as vulnerability name, location, and severity).  **IMPORTANT** Each tool enabled for cross-tool deduplication **MUST** have the same fields selected.
- **Keep cross-tool sources in the same Asset**: Cross-Tool Deduplication is Asset-scoped.  Findings split across separate Assets will not dedupe even with matching hash fields.  See [Cross-Tool Deduplication is Scoped to a Single Asset](#cross-tool-deduplication-is-scoped-to-a-single-asset) above.
- **Avoid overly broad deduplication**: Cross-tool deduplication with too few hash fields may result in false duplicates

By tuning deduplication settings to your specific tools, you can significantly reduce duplicate noise.

## Locked Findings 

Whenever Deduplication Settings are changed for a given tool, Deduplication hashes are re-calculated for that tool across the entire DefectDojo instance.