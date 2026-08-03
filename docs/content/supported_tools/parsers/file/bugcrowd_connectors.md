---
title: "Bugcrowd (Connectors Import)"
toc_hide: true
---

Import a [Bugcrowd](https://www.bugcrowd.com/) submissions export in the connector's JSON:API shape.

DefectDojo also ships a **`bugcrowd`** parser for Bugcrowd's **CSV** export, under the scan type
`BugCrowd Scan`. That one is unchanged and still the right choice for a CSV. This parser exists for the
connector's own scan type and JSON shape, so that a customer who cannot grant Bugcrowd API
credentials — air-gapped network, procurement hold, pending security review — can upload the same data
the DefectDojo Pro Bugcrowd connector syncs.

### File Types

JSON, from Bugcrowd's submissions endpoint. The API's JSON:API `data` envelope is accepted, as is a
bare array; an already-flattened export works too.

If the export carries a top-level `program_code`, it is used to build the tracker link.

### Submissions still being triaged are not imported

Bugcrowd's state tells you whether anyone has confirmed the submission:

| Bugcrowd `state` | Imported? | As |
| --- | --- | --- |
| `triaging` | **no** | — no confirmed verdict yet |
| `new` | yes | active, not verified |
| `triaged`, `unresolved` | yes | active, verified |
| `resolved` | yes | inactive, mitigated |
| `not_reproducible` | yes | inactive, false positive |
| `out_of_scope` | yes | inactive, out of scope |
| `not_applicable` | yes | inactive, **regraded to Info** |
| `informational` | yes | inactive |

`triaging` is deliberately excluded — importing it would put unvetted researcher claims into the
queue. States are normalised, so Bugcrowd's hyphenated and underscored spellings both match.

`not_applicable` overrides the priority as well as closing the finding: a P1 that Bugcrowd then judged
not applicable must not sit in the queue as Critical.

`informational` is imported but inactive, so a courtesy report is recorded without occupying the open
queue.

### Severity

Bugcrowd's priority: `1`→Critical, `2`→High, `3`→Medium, `4`→Low. **P5 has no mapping and becomes
Info**, as does anything unrecognised.

### Title handling

Bugcrowd titles are researcher-written free text, so the connector rewrites them:

- Titles matching `[a-zA-Z0-9_\s+,\-.]*` are left alone.
- Anything else has `:` and `"` replaced with a space and `@` replaced with `at`.
- Whitespace runs collapse to single spaces, and a title longer than DefectDojo's 511-character column
  is cut and suffixed with `...`.

### Fields worth noting

- **`steps_to_reproduce`** carries the researcher's description as well as the description field —
  that is what the connector does.
- **Endpoint** — the reported `bug_url`. A schemeless value is prefixed with `//` so DefectDojo's URI
  parser keeps it in the host field rather than reading the whole thing as a path.
- **Date** — the leading date portion of `submitted_at`, not a parsed timestamp.
- **Tracker link** — `https://tracker.bugcrowd.com/<program code><self link>`, in both `references` and
  the description. With no programme code in the export the link contains a double slash; that is the
  connector's own concatenation reproduced rather than tidied, since the connector always has a code.

### Scan type and deduplication

The scan type is **`Bugcrowd - Connectors Import`** — identical to the string the Bugcrowd connector
reports, and distinct from the CSV parser's `BugCrowd Scan` (note the capital C). A test asserts both,
so the two parsers cannot start shadowing each other.

Submission ids are globally unique on the platform, so deduplication uses the plain `hash_code`
algorithm over `unique_id_from_tool` alone.

### Sample Scan Data

Sample scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/bugcrowd_connectors).

The samples are constructed from Bugcrowd's documented submission schema and cover every row of the
state table above, all five priorities, a hyphenated state spelling, a schemeless bug URL, an explicit
port, and a title needing character replacement. Programme names and hosts are generic placeholders.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- unique_id_from_tool
