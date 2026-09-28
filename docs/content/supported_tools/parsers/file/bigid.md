---
title: "BigID"
toc_hide: true
---

Import a [BigID](https://bigid.com/) DSPM case export.

This exists for organisations that cannot grant BigID API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro BigID connector pulls the
same data over the API; this parser accepts the same data as a file.

### Only the count of affected objects is read — never the data

A BigID case is a report about **sensitive data that was found**. Only the case identity, its policy
and data-source context, and the **count** of affected objects are read. No sample, preview or value
of the data itself is read out of the export or written into a finding, even when the file contains
one — so importing a case file does not copy regulated data into DefectDojo.

### File Types

JSON. Each case is one finding. BigID's own samples disagree about the envelope, so all three shapes
its client accepts work here:

- a bare array of cases
- `{"data": {"cases": [...], "totalCount": n}}`
- `{"cases": [...], "totalCount": n}`

The wrapped `data` form wins whenever it carries anything, matching the client's precedence.

A case with **no `caseId` is dropped**: the id is the whole identity, and every row without one would
collapse onto the same finding.

### Severity

BigID has no informational tier of its own, so anything unrecognised lands in Info.

| BigID `severityLevel` | Severity |
| --- | --- |
| `critical` | Critical |
| `high` | High |
| `medium` | Medium |
| `low` | Low |
| unrecognised or absent | Info |

### Status

| BigID `caseStatus` | Imported as |
| --- | --- |
| `resolved`, `remediated`, `closed` | inactive, **mitigated** |
| everything else | active |

Only those three close a case. An unfamiliar status stays **active** — treating it as closed would
silently hide a live exposure.

### Fields worth noting

- **Title** is the case label, falling back to the policy name and then the case id.
- **The data source is the component**, so the same policy failing on two data sources stays two
  findings.
- **Mitigation** is BigID's own remediation steps, when the case carries them.
- **Timestamps** are `updated_at` then `created_at` — **snake_case**, while every other field on a
  case is camelCase. A value that is not a date falls through to the import default rather than
  failing the file.
- **Tags** are the data-source type and the sensitivity classification.

### Sample Scan Data

Sample BigID scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/bigid).

The samples are constructed from BigID's documented cases response and cover all three envelope
shapes, a remediated case, a resolved one, a case in an unfamiliar state, a quoted count, a zero and
a negative count, a case with no id, a timestamp that is not a date, and a case carrying sample
values that must not be read. Data-source and policy names are generic, and the sample-value fields
hold obvious placeholders.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
