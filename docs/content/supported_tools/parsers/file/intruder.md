---
title: "Intruder"
toc_hide: true
---

Import an [Intruder](https://www.intruder.io/) issues export.

This exists for organisations that cannot grant Intruder API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Intruder connector pulls the
same data over the API; this parser accepts the same data as a file.

### File Types

JSON — the issues response, with rows under `results`. A bare array of rows is accepted too.

**Include each issue's occurrences.** Intruder separates an issue — the weakness, its description and
remediation — from its occurrences, which are the targets it was found on. The occurrence *is* the
finding, so an issue with none produces nothing. Intruder's own issue object carries `occurrences` as a
**URL string**, not a list; that second call is what an export has to include:

- a top-level `occurrences` object keyed by issue id, or
- an `occurrences` array nested on each issue.

### Severity

| Intruder `severity` | Severity |
| --- | --- |
| `critical` | Critical |
| `high` | High |
| `medium` | Medium |
| `low` | Low |
| anything else | Info |

The **occurrence's** CVSS score is preferred over the issue's, because the same weakness scores
differently per target — a service reachable from the internet is not the same risk as one behind a
firewall.

### Snoozing is how Intruder records triage

| Occurrence | Imported as |
| --- | --- |
| not snoozed | active |
| snoozed, `FALSE_POSITIVE` | inactive, false positive |
| snoozed, `ACCEPT_RISK` | inactive, risk accepted |
| snoozed, `MITIGATING_CONTROLS` | inactive, risk accepted |
| snoozed, any other reason | inactive, neither flag |

An unrecognised reason leaves the finding inactive with neither flag set. It is still triaged, just not
in a way DefectDojo has a field for, and guessing would misreport the reviewer's decision.

### Deduplication uses the plain hash algorithm

Intruder is the one connector scan type whose configuration uses **`hash_code`** rather than pairing it
with the unique id. The occurrence id sits *inside* the hash fields instead, with title and severity
guarding against id reuse. Copied from the connector's own settings, not chosen.

### Fields worth noting

- **The description shows the display address; the endpoint records the target.** The display address
  is what a person recognises, the target is what was scanned.
- **A port of `0`** means Intruder had none, and it is not recorded — port zero is not a real port.
- **A target that cannot be a host** (Intruder targets can be labels) is not recorded as an endpoint,
  because an unusable host fails the whole import rather than the one finding. It still appears in the
  description and in a `target:` tag.
- **Extra information** is listed in sorted key order — the connector sorts because a Go map has no
  order, and matching that keeps the two paths identical.
- **CVEs** come from the occurrence, then from any identifier in the issue's title or description.

### Sample Scan Data

Sample Intruder scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/intruder).

The samples are constructed from Intruder's documented issue and occurrence responses and cover one
issue on two targets, every snooze reason including an unrecognised one, an issue with no occurrences,
a port of `0`, an IP target, a target that cannot be a host, an unparseable timestamp, and both the
nested and issue-keyed export shapes. Hostnames are generic and addresses are private-range.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- unique_id_from_tool
- title
- severity
