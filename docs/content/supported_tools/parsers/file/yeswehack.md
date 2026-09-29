---
title: "YesWeHack"
toc_hide: true
---

Import a [YesWeHack](https://www.yeswehack.com/) reports export.

This exists for organisations that cannot grant YesWeHack API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro YesWeHack connector pulls the
same data over the API; this parser accepts the same data as a file.

### File Types

JSON, from YesWeHack's reports endpoint. The API's `items` envelope is accepted, as is a bare array
of reports.

### The workflow state becomes the DefectDojo state

A YesWeHack report's state carries real triage information, and importing everything as active would
put resolved, rejected and duplicate reports back in front of the team. Each state is translated:

| YesWeHack `workflow_state` | Imported as |
| --- | --- |
| `new`, `under_review` | active |
| `accepted` | active **and verified** |
| `resolved`, `auto_close` | inactive, mitigated |
| `wont_fix` | inactive, risk accepted |
| `invalid`, `rejected` | inactive, false positive |
| `duplicate` | inactive, duplicate |
| `out_of_scope`, `informative` | inactive |
| anything else | active |

An unrecognised state stays **active** — the safe side of the assumption, so a state YesWeHack adds
later cannot silently close a finding.

### Severity

Resolved from the first source that yields a recognised word, in this order:

1. the CVSS block's `criticity`
2. the priority's `name`
3. the priority's `slug`

Falling straight to Info when the criticity is unset would throw away a priority YesWeHack did set.
`critical`/`high`/`medium`/`low` map directly, and YesWeHack's `info`, `informative` and `none` all
become Info.

The CVSS vector is imported, and the score when it is above zero.

### Fields worth noting

- **`vuln_id_from_tool` is the human-facing local id** (`GENERIC-2026-0001`), falling back to the
  numeric id; `unique_id_from_tool` is always the numeric id.
- **Description** is built with the same markdown the connector uses — `* **Prefix** value` bullets
  for the report id, bug type, category, scope and endpoint, then `### Description` and `### Impact`
  sections.
- **CVEs** are extracted from the title, description, impact **and technical information** — YesWeHack
  has no CVE field, and the technical information is the field easiest to overlook.
- **Endpoint** is the reported endpoint, falling back to the programme scope.
- **Dates** — several timestamp layouts are accepted, matching the connector, so a non-RFC3339 stamp
  still dates the finding.

### Scan type and deduplication

The scan type is **`YesWeHack - Connectors Import`** — identical to the string the YesWeHack connector
reports, so a customer who uploads an export *and* later enables the connector gets one set of
findings that deduplicate rather than two copies of everything.

Report ids are globally unique on the platform, so deduplication uses the plain `hash_code` algorithm
over `unique_id_from_tool` alone.

### Sample Scan Data

Sample YesWeHack scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/yeswehack).

The samples are constructed from YesWeHack's documented report schema and cover every workflow state
in the table above plus an unrecognised one, all three severity sources, and each accepted timestamp
layout. Programme names, hosts and local ids are generic placeholders.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- unique_id_from_tool
