---
title: "Global Component Deduplication (Pro)"
description: "Deduplicate Software Composition Analysis Findings by component name and version across all Products"
weight: 5
audience: pro
---

Global Component Deduplication is a DefectDojo Pro algorithm that identifies duplicate Findings across **all Products** based on the component name and version they reference. It is intended for Software Composition Analysis (SCA) tools, where the same vulnerable dependency (for example, `timespan@2.3.0`) may appear in many Products, and you want DefectDojo to treat those occurrences as duplicates of a single original Finding.

Unlike the other deduplication algorithms, Global Component matching is **not scoped to a single Product or Engagement**. A Finding imported into Product B can be marked as a duplicate of an older Finding in Product A, even if the two Products are unrelated.

## Enabling the Global Component Algorithm

Global Component Deduplication is gated behind a feature flag and is **off by default**. To request that it be enabled on your instance, contact [DefectDojo Support](mailto:support@defectdojo.com).

Once the feature is enabled, **Global Component** will become available as an option in the **Deduplication Algorithm** dropdown for both Same Tool and Cross Tool Deduplication settings in the Tuner.

## Configuring Global Component Deduplication

Global Component can be applied to Same-Tool Deduplication, Cross-Tool Deduplication, or both, and is configured per security tool from **Settings > Pro Settings > Deduplication Settings**.

### Same-Tool

Use Same-Tool Deduplication with the Global Component algorithm when you want to deduplicate findings from a single SCA tool across multiple Products.

1. Open the **Same Tool Deduplication** tab.
2. Select the SCA tool from the **Security Tool** dropdown (for example, `Dependency Track Finding Packaging Format (FPF) Export`).
3. Set the **Deduplication Algorithm** to **Global Component**.
4. Submit the form.

Hash Code Fields are not used by this algorithm and are hidden when it is selected.

### Cross-Tool

Use Cross-Tool Deduplication with the Global Component algorithm when you want to deduplicate findings of the same component across different SCA tools and Products.

Cross-tool matching requires Global Component to be configured on **each** tool that should participate.

1. Open the **Cross Tool Deduplication** tab.
2. For each tool to include: select it from the **Security Tool** dropdown, set the algorithm to **Global Component**, and submit.

## How Matching Works

A new Finding is marked as a duplicate of an existing Finding when:

- The component name and component version match exactly, **and**
- An older Finding with the same component name and version exists anywhere in the DefectDojo instance — in any Product or Engagement.

Component version matching is exact. A Finding for `timespan@2.3.0` will **not** deduplicate against one for `timespan@2.3.1`.

The Engagement-scoped deduplication setting is ignored for this algorithm; matching is always global.

## Example

Assume Global Component is enabled on `Dependency Track Finding Packaging Format (FPF) Export` (Same Tool) and on a Generic Findings Import tool (Cross Tool):

| Step | Import | Into Product | Result |
| --- | --- | --- | --- |
| 1 | Dependency Track scan for `timespan@2.3.0` | Application 0 | 1 active Finding created |
| 2 | Same Dependency Track scan | Application 1 | 1 Finding created, marked as duplicate of the Application 0 Finding |
| 3 | Generic Findings Import for `timespan@2.3.0` | Application 2 | 1 Finding created, marked as duplicate of the Application 0 Finding (cross-tool match) |
| 4 | Dependency Track scan for `timespan@2.3.1` | Application 3 | 1 active Finding created — different version, no match |

Each duplicate Finding shows its original at the bottom of the Finding page in the duplicate chain.

## Cross-Product Visibility

Because Global Component matching crosses Product boundaries, the original Finding in a duplicate chain may live in a Product that the user viewing the duplicate does not have permission to access.

In that case, the Finding is visible and labelled as a duplicate, but the user will not be able to open or navigate to the original. Consider this before enabling Global Component on tools whose Findings are sensitive to Product-level access controls.

## Reverting

To stop using Global Component for a given tool, open its Deduplication Settings and switch the algorithm back to one of the scoped options.

For **Same Tool** Deduplication:

- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

For **Cross Tool** Deduplication:

- Hash Code
- Disabled

Changing the algorithm triggers a background recalculation of deduplication hashes for the tool's existing Findings.
