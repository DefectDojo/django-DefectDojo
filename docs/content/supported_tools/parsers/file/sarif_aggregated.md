---
title: "SARIF Aggregated"
toc_hide: true
---
Import a SARIF 2.1.0 report with **one Finding per SARIF result**, using the **SARIF Aggregated** scan type.

A SARIF result can list several `locations`, for example a hard-coded secret that appears in six files, or a race condition reported at two lines of the same file. The **[SARIF](../sarif)** scan type makes each of those locations its own Finding. SARIF Aggregated keeps the result whole:

- The Finding's own file path and line come from the result's **first** location.
- With the Locations feature enabled, **every** location of the result is attached to the Finding as a code Location, with its start line, end line and snippet.
- With the Locations feature disabled, every location is listed in the Finding description instead, as `path:startLine-endLine`.

A report with 19 results and 84 locations therefore imports as 19 Findings rather than 84.

Everything else (title, severity, CWE, tags, fixes, suppressions, and the report-defined Test Type) is read exactly as the SARIF scan type reads it. The Test Type is named after the tool in the report, for example `semgrep Scan (SARIF Aggregated)`, so a Test imported with one scan type is not reimported with the other.

### Switching an existing Test from SARIF

SARIF and SARIF Aggregated produce different Test Types, so reimporting an existing SARIF Test with SARIF Aggregated is rejected with a Test type mismatch. Import into a new Test instead and close the old one once the new Findings have been triaged.

### Support for Deduplication (Fingerprinting)

SARIF Aggregated deduplicates on the result's `fingerprints` or `partialFingerprints` (`DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE`) by default. Because a multi-location result is one Finding, its fingerprint is unique inside the report and is always kept. With the SARIF scan type the same fingerprint repeats across the per-location Findings and is dropped from them.

When a result carries no fingerprint, the hash code falls back to these fields:

- title
- cwe
- line
- file path
- description

### Sample Scan Data
A sample report with a multi-location result can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/sarif/multi_location_result.sarif).
