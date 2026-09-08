---
title: "Parasoft DTP"
toc_hide: true
---

Import a [Parasoft DTP](https://www.parasoft.com/products/parasoft-dtp/) static-analysis violations
export.

This exists for organisations that cannot grant DTP API credentials — air-gapped networks, procurement
restrictions, a pending security review. The DefectDojo Pro Parasoft connector pulls the same data over
the API; this parser accepts the same data as a file.

### File Types

JSON — the violations response, `{"staticAnalysisViolations": [...]}`. A bare array works, as does an
object naming the list `violations`, `data` or `results`.

### Severity: 1 is the most severe

DTP grades with a numeric severity that runs the **opposite way from a score**:

| `severity` | Severity |
| --- | --- |
| 1 | Critical |
| 2 | High |
| 3 | Medium |
| 4 | Low |
| 5, 0, absent | Info |

Reading it as a score would invert the entire ladder. Severity 5 is DTP's informational tier. Numbers
may arrive quoted.

### Fields worth noting

- **Title** is `<rule>: <message>`, falling back to whichever exists.
- **Identity** prefers DTP's **violation hash** — the value that stays stable as a file is edited around
  the violation — then the violation id, and only then the rule plus the file. That last fallback would
  merge two violations of one rule in one file, which is why it is last.
- **`file_path` and the rule are both in the deduplication hash**, so the same rule firing in two files
  is two violations to fix.
- **Advisory identifiers** named in the rule id or the message are linked. Rare for static analysis, but
  a rule that names a CVE is worth connecting. `CVE-`, `GHSA-`, `GO-` and `RHSA-` forms are recognised,
  and the results come back **sorted** rather than in the order they appear, matching the connector's
  shared extractor.
- **`author`** is present in the response and is not imported, matching the connector.

### Sample Scan Data

Sample Parasoft DTP scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/parasoft).

The samples cover every severity code, a quoted severity and line, a violation identified by hash, one by
id, one by rule-plus-file, a message naming two CVEs out of order, a violation with no rule, one with no
message, one with no line, and one with nothing at all. File paths and rule ids are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- file_path
- vuln_id_from_tool
