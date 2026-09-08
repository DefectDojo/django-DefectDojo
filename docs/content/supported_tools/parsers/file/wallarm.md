---
title: "Wallarm"
toc_hide: true
---

Import a [Wallarm](https://www.wallarm.com/) vulnerabilities export.

This exists for organisations that cannot grant Wallarm API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Wallarm connector pulls the same
data over the API; this parser accepts the same data as a file.

### File Types

JSON — the `/v1/objects/vuln` response, with rows under `body`. A bare array of rows is accepted too.

### Closed and false-positive rows are skipped

A `status` of `closed` or `falsepositive` means Wallarm has already dealt with the vulnerability, so it
is not imported. Everything else is, including a row with no status at all.

### The threat level is a number *or* a word

Wallarm sends the threat level in a single `threat` field as either form, depending on which API
answered — so both ladders are needed. Reading a number as a label, or the other way round, would drop
everything to Info.

| Numeric `threat` | Severity |
| --- | --- |
| ≥ 5 | Critical |
| 4 | High |
| 3 | Medium |
| 2 | Low |
| 1, 0 | Info |

| Word `threat` | Severity |
| --- | --- |
| `critical` | Critical |
| `high` | High |
| `medium` | Medium |
| `low` | Low |
| `info`, `information`, `informational`, empty | Info |
| anything else | Info |

Note **5 is the most severe**, the inverse of a priority number. This is the one part of the mapping
Wallarm's own documentation does not pin down; it is copied from the connector rather than inferred, and
is worth confirming against a live tenant.

### Identity

`wallarm-<id>`, falling back to `wallarm-<wid>` and then to `wallarm-<domain><path>`. The location
fallback is last because it is the only one that is not an id — two vulnerabilities of different types
on one path would collide — but something stable beats nothing.

### Fields worth noting

- **Mitigation is Wallarm's exploit example**, not advice. It is the only remediation-shaped field
  Wallarm has, and a reviewer can act on a reproduction. Mirrored from the connector; flagged as a
  follow-up for both sides.
- **Only an absolute path is appended to the endpoint.** Wallarm uses the `path` field for a parameter
  location on some vulnerability types, so a value not beginning with `/` is left out of the endpoint —
  it still appears in the description.
- **Dates are unix seconds** (`validate_time`); a row without one keeps DefectDojo's default of today.
- **Vulnerability identifiers** are read from the title, type, template, description and additional
  text, then **sorted** and deduplicated case-insensitively, matching the connector's extractor.
- **Every finding is active, dynamic and not static** — Wallarm watches live API traffic and validates
  against the running service.

### Sample Scan Data

Sample Wallarm scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/wallarm).

The samples are constructed from Wallarm's documented vulnerabilities response and cover a numeric and
a word threat level, an unrecognised label, a null threat, a row with no id (so the wid is used), a row
with neither (so the location is), a non-absolute path, duplicate CVEs in mixed case, and both a closed
and a false-positive row. Hostnames are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
