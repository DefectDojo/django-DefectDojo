---
title: "Qualys Webapp Scan"
toc_hide: true
---
Qualys WebScan output files can be imported in XML format.

### Sample Scan Data
Sample Qualys Webapp Scan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/qualys_webapp).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](/triage_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description

### Configuration

Two optional settings change how the parser builds Findings. Both default to `False`, so the parser behaves as described above unless you turn them on.

| Environment variable | Default | Effect |
|---|---|---|
| `DD_QUALYS_WAS_WEAKNESS_IS_VULN` | `False` | Gives "Security Weaknesses" (Information Gathered QIDs outside the `DIAG` and `IG` groups) their Qualys severity instead of importing them as Info. |
| `DD_QUALYS_WAS_UNIQUE_ID` | `False` | Creates one Finding per Qualys `UNIQUE_ID` and stores it in `unique_id_from_tool`. When this is off, all instances of a QID are grouped into a single Finding. |

#### Why pair `DD_QUALYS_WAS_UNIQUE_ID` with a deduplication change

This scan type uses the legacy deduplication algorithm, and on reimport it matches Findings by title and severity. With `DD_QUALYS_WAS_UNIQUE_ID` on, several Findings can share a title and severity (the same QID at different locations), so reimport cannot tell them apart. To match each Finding by its Qualys unique ID instead, also set:

```
DD_DEDUPLICATION_ALGORITHM_PER_PARSER={"Qualys Webapp Scan": "unique_id_from_tool"}
```

Changing the deduplication algorithm affects how existing Findings match, so turn on both settings before the first import into a Product rather than partway through its history.
