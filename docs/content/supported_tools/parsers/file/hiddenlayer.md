---
title: "HiddenLayer"
toc_hide: true
---

Import a [HiddenLayer](https://hiddenlayer.com/) model-scan SARIF log.

This exists for organisations that cannot grant HiddenLayer API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro HiddenLayer connector pulls
the same data over the API; this parser accepts the same data as a file.

### Why not the generic SARIF parser?

DefectDojo already parses SARIF, and HiddenLayer reports SARIF — but importing through the generic
parser records the findings under the **`SARIF` scan type**, where they will not deduplicate against
the HiddenLayer connector's findings. That is the whole reason this parser exists. The mapping is the
connector's, which itself mirrors `dojo/tools/sarif/parser.py`.

### File Types

JSON — a SARIF log, `{"runs": [...]}`. Every run contributes.

Wrap it to supply the **scan id**, which is part of every identity the connector builds and which a
downloaded log does not carry:

```json
{"scan_id": "your-scan-id", "sarif": { "runs": [ ... ] }}
```

`scan_id`, `scanId` and `scanID` are all accepted, and the log may sit under `sarif`, `log` or
`report`. A bare log imports fine, but **its findings will not deduplicate against connector-synced
ones**, because the identities differ by that prefix.

### Results that are not failures are skipped

SARIF's `kind` distinguishes a failure from a `pass`, `open`, `informational`, `notApplicable` or
`review` result. Only failures are imported — the rest are not findings, and importing them would fill
the product with noise. An **absent** `kind` means failure, per the SARIF specification.

### A suppressed result is a false positive

A result carrying `suppressions` is imported **inactive and marked a false positive**. SARIF
suppression is a reviewer saying this one does not count; recording it as inactive alone would leave it
in the open-findings count.

### Severity

| Source | Used when |
| --- | --- |
| the rule's `properties.security-severity`, as a CVSS number | it parses as a number |
| the same property, as a word | it is `critical`/`high`/`medium`/`low`/`info`/`informational` |
| the result's `level` | there is no usable property |

| `level` | Severity |  | CVSS score | Severity |
| --- | --- | --- | --- | --- |
| `note` | Info |  | ≥ 9 | Critical |
| `warning` | Medium |  | ≥ 7 | High |
| `error` | High |  | ≥ 4 | Medium |
| **absent** | **Medium** |  | > 0 | Low |

A result with **no level is Medium, not Info**: SARIF makes `level` optional, and a tool that omits it
is not saying the result is harmless — defaulting to Info would silently bury it.

`cvssv3_score` is only set when the property is a **number**; a word grades the finding but leaves no
score to record.

### Fields worth noting

- **Title** is the result message, then the rule's short description, full description, name and id.
  Shortened to 150 characters with a trailing ellipsis; the full text stays in the description.
- **The description does not repeat itself** — a rule short description that merely restates the
  result message, or a full description that restates the short one, is printed once.
- **CWE** comes from the rule's `relationships` target, then the rule's tags, then the result's tags.
  SARIF has no CWE field, so a tool states the taxonomy one of those ways. `CWE-502`, `cwe-502` and
  `external/cwe/cwe-502` are all read.
- **Tags** are the rule's then the result's, deduplicated, with the `external/cwe/` prefix stripped.
- **A rule id that is itself a CVE** becomes the vulnerability id, uppercased.
- **References** is the rule's `helpUri`, falling back to its help text *only when that text is a
  link*.
- **Mitigation** is every fix description the result carries, one per line.

### Sample Scan Data

Sample HiddenLayer scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/hiddenlayer).

The samples cover a scored critical result, a suppressed one, a result graded by a severity *word*, an
unparseable severity, a `pass` result that must not import, a result whose rule is not defined in the
run, a quoted start line, a location with no region, a result with no location at all, two fixes on one
result, and help text that is not a link. Model, file and rule names are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- file_path
