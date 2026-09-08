---
title: "Halo Security"
toc_hide: true
---

Import a [Halo Security](https://www.halosecurity.com/) issues export.

This exists for organisations that cannot grant Halo Security API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Halo Security connector pulls
the same data over the API; this parser accepts the same data as a file.

### File Types

JSON — the issue-list response, with rows under `list`. A bare array of rows is accepted too.

**Include the per-issue details.** Halo splits an issue across two calls: the list row carries the
issue, target and status, while the **description, category, CVEs and PCI flag exist only on a
per-issue detail**. A row-only import produces findings with no prose at all. Supply the details as:

- a top-level `details` object keyed by issue id, or
- a top-level `details` array of detail objects, or
- a `detail` object nested on each row.

### Severity is an integer level, 5 highest

| Halo `severity` | Severity |
| --- | --- |
| 5 | Critical |
| 4 | High |
| 3 | Medium |
| 2 | Low |
| 1, 0 | Info |
| anything else | Info |

Note this is the **inverse of a priority number** — 5 is the most severe, not the least. The row's
level is used when set, falling back to the detail's, because the list response sometimes omits it.

### One issue per host

Halo reports the same issue once per affected target, so the identity is **`<issue id>:<target id>`**.
Keying on the issue alone would collapse two hosts into one finding — and their statuses often differ,
which is exactly why they are kept apart.

### Status

| Halo `status` | Imported as |
| --- | --- |
| `new`, `investigating` | active, not verified |
| `confirmed`, `fixing` | active, **verified** |
| `fixed` | inactive, mitigated, verified |
| `ack_false_positive` | inactive, false positive |
| `ack_acceptable_risk` | inactive, risk accepted |

Only `confirmed`, `fixing` and `fixed` count as verified — a new or investigating issue has not been
confirmed by anyone yet, and marking it verified would overstate what Halo knows.

### Deduplication hashes the endpoint

This scan type's configuration pairs `unique_id_from_tool_or_hash_code` with a field set that
**includes `endpoints`**, so the parser always records the scanned host. An unpopulated endpoint would
leave the hash computed over nothing and every rescan would reimport.

### Fields worth noting

- **PCI** — when Halo flags an issue as affecting PCI compliance, it becomes both a description line
  and a `pci` tag.
- **Assignee** — Halo writes the literal `Nobody` to mean unassigned, and that is not reported.
- **Scans since found** — how many scans the issue has persisted for, reported even when zero.
- **Date** — Halo's list response carries no discovery date, so findings are stamped with today's
  date. That is the connector's behaviour, mirrored rather than corrected.

### Sample Scan Data

Sample Halo Security scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/halosecurity).

The samples are constructed from Halo's documented issue-list and issue-detail responses and cover the
same issue on two hosts with differing statuses, every status value, a PCI issue, a row with no detail,
a row whose severity is only on the detail, and duplicate CVE identifiers. Hostnames are generic and
addresses are private-range.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- endpoints
