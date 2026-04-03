---
title: "SARIF"
toc_hide: true
---
OASIS Static Analysis Results Interchange Format (SARIF). SARIF is
supported by many tools. More details about the format here:
<https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=sarif>

Current implementation will aggregate all the findings in the SARIF file into a single report.

## How Test Types Are Determined

Unlike most parsers in DefectDojo, the SARIF parser has a **report-defined Test Type**. When you import a SARIF file with `scan_type=SARIF`, DefectDojo reads the tool name from within the SARIF file at `runs[].tool.driver.name` and uses it to construct the Test Type name.

The naming pattern is: **`{tool name} ({scan_type})`**

For example:

| Tool | `runs[].tool.driver.name` value | Resulting Test Type |
|------|-------------------------------|---------------------|
| Semgrep | `semgrep` | `semgrep (SARIF)` |
| Trivy | `Trivy Scan` | `Trivy Scan (SARIF)` |
| Dockle | `Dockle` | `Dockle Scan (SARIF)` |
| MobSF | `mobsfscan` | `mobsfscan (SARIF)` |

This means that even though all of these tools produce SARIF output and are imported with `scan_type=SARIF`, each tool will create a **distinct Test Type** in DefectDojo. For more information on how report-defined Test Types work, see **[Test Types](/asset_modelling/hierarchy/product_hierarchy#test-types)**.

## Reimporting SARIF Results

When using the `/api/v2/reimport-scan/` endpoint, DefectDojo needs to match incoming results to an existing Test. Understanding how this matching works is important when multiple SARIF-based tools are reporting into the same Engagement.

### One Tool Per Test

Each Test in DefectDojo represents results from a single tool. SARIF results from different tools (e.g. Semgrep, Trivy, MobSF) cannot be combined into the same Test, even though they share the same `scan_type=SARIF`. DefectDojo enforces this by validating that the tool name inside the SARIF file matches the existing Test's Test Type on reimport.

This constraint is what makes reimport's comparison logic reliable: when a Finding is absent from a new report, DefectDojo can safely assume it has been resolved. If results from multiple tools were mixed in a single Test, DefectDojo would not be able to distinguish between a resolved Finding and a Finding that simply isn't covered by the current tool.

## Support for Deduplication (Fingerprinting)

The SARIF parser takes into account data for fingerprinting, based on the `fingerprints` and `partialFingerprints` properties in the SARIF file. It's possible to activate deduplication based on this data by customizing settings:

```Python
# in your settings.py file
DEDUPLICATION_ALGORITHM_PER_PARSER["SARIF"] = DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE
```

### Sample Scan Data
Sample SARIF scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/sarif).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](/ triage_findings/finding_deduplication/about_deduplication):

- title
- cwe
- line
- file path
- description
