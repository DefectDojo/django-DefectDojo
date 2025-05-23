---
title: "Deduplication Tuning (Pro)"
description: "Configure how DefectDojo identifies and manages duplicate findings"
weight: 4
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

DefectDojo Pro offers three deduplication methods for same-tool deduplication:

#### Hash Code
Uses a combination of selected fields to generate a unique hash. When selected, a third dropdown will appear showing the fields being used to calculate the hash.

#### Unique ID From Tool
Leverages the security tool's own internal identifier for findings, ensuring perfect deduplication when the scanner provides reliable unique IDs.

#### Unique ID From Tool or Hash Code
Attempts to use the tool's unique ID first, then falls back to the hash code if no unique ID is available. This provides the most flexible deduplication option.

## Cross Tool Deduplication

Cross Tool Deduplication is disabled by default, as deduplication between different security tools requires careful configuration due to variations in how tools report the same vulnerabilities.

![image](images/cross_tool_deduplication.png)

To enable Cross Tool Deduplication:

1. Select a **Security Tool** from the dropdown
2. Change the **Deduplication Algorithm** from "Disabled" to "Hash Code"
3. Select which fields should be used for generating the hash in the **Hash Code Fields** dropdown

Unlike Same Tool Deduplication, Cross Tool Deduplication only supports the Hash Code algorithm, as different tools rarely share compatible unique identifiers.

## Reimport Deduplication

Reimport Deduplication Settings are specifically designed for reimporting data using Universal Parsers or the Generic Parser.

![image](images/reimport_deduplication.png)

When configuring Reimport Deduplication:

1. Select the **Security Tool** (Universal or Generic Parser)
2. Choose the appropriate **Deduplication Algorithm**

The same three algorithm options are available for Reimport Deduplication as for Same Tool Deduplication:
- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

## Deduplication Best Practices

For optimal results with Deduplication Tuning:

- **Start with defaults**: The preconfigured deduplication settings work well for most scenarios
- **Test changes carefully**: After adjusting deduplication settings, monitor a few imports to ensure proper behavior.
- **Adjustments to deduplication will only affect new imports, and **do not retroactively adjust the hash values for findings already imported**.  Pro subscribers may contact DefectDojo support to assess if deduplcation tunings can be re-executed for findings already imported prior to the deduplcation adjustments.  
- **Use Hash Code for cross-tool deduplication**: When enabling cross-tool deduplication, select fields that reliably identify the same finding across different tools (such as vulnerability name, location, and severity).  **IMPORTANT** Each tool enabled for cross-tool deduplication **MUST** have the same fields selected.
- **Avoid overly broad deduplication**: Cross-tool deduplication with too few hash fields may result in false duplicates

By tuning deduplication settings to your specific tools, you can significantly reduce duplicate noise.
