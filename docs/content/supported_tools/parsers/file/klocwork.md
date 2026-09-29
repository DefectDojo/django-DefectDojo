---
title: "Klocwork"
toc_hide: true
---

Import a [Klocwork](https://www.perforce.com/products/klocwork) issue export.

This exists for organisations that cannot grant Klocwork API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Klocwork connector pulls the
same data over the API; this parser accepts the same data as a file.

### File Types

**NDJSON** — Klocwork's `search` endpoint answers with one JSON object per line, not an array, so that is
what a saved export looks like and it is what this parser reads first. Calling a whole-document JSON
parser on it fails at the second line.

Also accepted, for an export somebody has already reshaped: a JSON array of issues, an object with an
`issues` list, or a single issue object.

Two lines are skipped rather than parsed, matching the connector's own decoder:

- the trailing **summary** line, which describes the run rather than a finding — a search that matched
  nothing answers with that line alone, and that is an empty result, not a malformed file
- any line that is not a JSON object, or that does not parse

A row with **no `id`** is dropped: the id is the whole identity.

### Severity: 1 is the most severe

Klocwork grades with a severity **code**, which is the inverse of a score:

| `severityCode` | Severity |
| --- | --- |
| 1 | Critical |
| 2 | High |
| 3 | Medium |
| 4 | Low |
| 5–10, 0, absent | Info |

Reading the code as a score would invert the entire ladder. Codes 5–10 are Klocwork's informational
tiers.

Numbers may arrive **quoted** (`"id": "101"`). Both forms are accepted, because the connector's own
decoder silently skips a line it cannot parse — a server quoting its numerics would otherwise produce a
clean, empty sync rather than an error.

### Status

| Klocwork `status` | Imported as |
| --- | --- |
| `Ignore`, `Not a problem`, `Filter` | inactive, **false positive** |
| everything else | active |

The three are all a reviewer saying the issue is not real. The deferred states the connector's query
selects — `Defer`, `Fix in Next Release`, `Fix in Later Release` — stay **active**: a deferred finding is
still a finding.

### Fields worth noting

- **Title** is `<checker>: <name>` — the checker alone is opaque, the name alone is not searchable.
- **`file_path` and the checker are both in the deduplication hash**, so the same checker firing in two
  files is two findings.
- **Dates** are unix milliseconds; reading them as seconds would date every finding in 1970.
- **References** is the issue's own Klocwork review URL, when it has one.

### Sample Scan Data

Sample Klocwork scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/klocwork).

The samples are NDJSON, as Klocwork produces, and cover every severity code, quoted numerics, a triaged
`Ignore`, a deferred finding, a row with no name or checker, a row with no id, and the trailing summary
line. The same issues are also provided as a JSON array to exercise the reshaped path. File paths and
hostnames are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- file_path
- vuln_id_from_tool
