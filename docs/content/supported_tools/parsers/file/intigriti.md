---
title: "Intigriti"
toc_hide: true
---

Import an [Intigriti](https://www.intigriti.com/) submissions export.

This exists for organisations that cannot grant Intigriti API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Intigriti connector pulls the
same data over the API; this parser accepts the same data as a file.

### File Types

JSON. The API's `records` envelope is accepted, as are `submissions`, `data`, `items`, and a bare
array.

Intigriti's API lists submissions and then serves each one's full report separately, so the connector
converts each finding from **two objects** — a list overview and a fetched detail — preferring the
overview wherever both carry a field. An export may nest the detail under `detail`, or carry the report
on the entry itself if it came from the detail endpoint; both are recognised. Missing the merged form
would lose the CWE, impact, recommended solution and the whole description body.

### Severity

Intigriti grades its most severe submissions **`Exceptional`**, not `Critical`. Both map to Critical;
mapping only `critical` would silently drop every top-tier submission to Info. `High`, `Medium` and
`Low` map directly and anything unrecognised becomes Info.

### Status and close reason become the DefectDojo state

For a **closed** or **archived** submission the *close reason* is what distinguishes a fix from a
rejection, so both are read:

| Status | Close reason | Imported as |
| --- | --- | --- |
| `accepted` | — | active, verified |
| anything open (`new`, `triage`, `in progress`, …) | — | active, not verified |
| `closed` / `archived` | `accepted risk` | inactive, verified, risk accepted |
| `closed` / `archived` | `duplicate` | inactive, duplicate |
| `closed` / `archived` | `out of scope` | inactive, out of scope |
| `closed` / `archived` | `not applicable`, `not reproducible`, `false positive`, `spam`, `informative`, `won't fix`, `no` | inactive, false positive |
| `closed` / `archived` | anything else (solved, resolved, fixed, blank) | inactive, verified, mitigated |

Note `no` is Intigriti's terse rejection reason — treating it as "closed without a reason" would mark a
rejected submission as fixed. Hyphenated and spaced spellings of each reason are both accepted.

### Researcher prose is flattened, never rendered

Intigriti submissions are written by external researchers. The proof of concept, impact, recommended
solution, asset and question answers are all flattened to escaped plain text: `script` and `style`
content is dropped, block tags become newlines. Nothing in a submission can be injected into a rendered
finding. Go's `html.EscapeString` entities are matched byte for byte.

### Fields worth noting

- **`unique_id_from_tool` and `vuln_id_from_tool` are both the submission code** (`GENERIC-0001`).
- **CWE** — from the report type's `cwe`, which Intigriti writes lower-cased as `cwe-<n>`; anything
  else leaves it at 0.
- **Asset** — the affected domain, falling back to the vulnerable component Intigriti recorded.
- **Report type** — rendered `<name> (<category>)`, degrading to whichever of the two is present.
- **Question answers** — the researcher's answers to the programme's intake questions are imported;
  empty question/answer pairs are skipped rather than producing an empty heading.

### Scan type and deduplication

The scan type is **`Intigriti - Connectors Import`** — identical to the string the Intigriti connector
reports, so a customer who uploads an export *and* later enables the connector gets one set of findings
that deduplicate rather than two copies of everything.

Submission codes are globally unique on the platform, so deduplication uses the plain `hash_code`
algorithm over `unique_id_from_tool` alone.

### Sample Scan Data

Sample Intigriti scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/intigriti).

The samples are constructed from Intigriti's documented submission schema and cover every row of the
state table above, the `Exceptional` grade, both the nested and merged detail shapes, and researcher
prose containing markup. Programme names, submission codes and hosts are generic placeholders.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- unique_id_from_tool
