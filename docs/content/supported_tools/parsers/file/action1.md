---
title: "Action1"
toc_hide: true
---

Import an [Action1](https://www.action1.com/) vulnerability export.

This exists for organisations that cannot grant Action1 API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Action1 connector pulls the
same data over the API; this parser accepts the same data as a file.

### File Types

JSON — the vulnerability-list response, with rows under `items`. A bare array of rows is accepted too.

**Include the endpoints affected by each CVE.** Action1 lists the vulnerability catalogue and the
machines actually affected through two different calls, and the affected endpoint is what makes a
finding: a catalogue entry nothing is running produces nothing at all. Because those rows carry no CVE
of their own, supply them as:

- a top-level `endpoints` object keyed by CVE id, or
- an `endpoints` array nested on each vulnerability.

Optionally include the managed-endpoint list as `managed_endpoints` (a bare array or a paged
`{"items": [...]}` response). It supplies each machine's operating system, which Action1's own
vulnerability response does not carry. It is best-effort: a machine missing from it simply has no OS
line.

### Severity

Action1 reports a `base_severity` and, separately, a `score` — and **`score` is a word, not a
number**: `Critical`, `High`, `Medium`, `Low`. The base severity is used when present, the score is the
fallback, and anything unrecognised is Info. Treating `score` as numeric would drop every finding
whose base severity is missing.

| Bucket | Severity |
| --- | --- |
| `critical` | Critical |
| `high` | High |
| `medium` | Medium |
| `low` | Low |
| anything else, or neither field set | Info |

### One finding per machine

The identity is `action1-<CVE>-<endpoint id>`, so one CVE affecting three machines is three findings.
The installed version differs per machine, which is why the endpoint's own copy of the software is
preferred over the vulnerability's, and why **`component_version` is part of this scan type's
deduplication hash** — a machine that has been patched does not merge with one that has not.

### Fields worth noting

- **Mitigation** lists the updates Action1 already has available for the affected software
  (`Apply: <name> <version>, …`). When Action1 knows of no patch the mitigation is left **empty**
  rather than filled with generic advice — that would be this parser's opinion, not Action1's.
- **The endpoint** is recorded only when the machine name is something DefectDojo accepts as a host.
  Action1 names are free text (`Reception Desk PC` is a normal value), and an unusable host fails the
  whole import rather than the one finding. The name always appears in the description.
- **Every finding is active.** Action1 reports only what is still present on a machine, so the
  connector marks them all active and so does this parser.
- **Description lines are separated by a single newline**, not a blank line, matching the connector.

### Sample Scan Data

Sample Action1 scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/action1).

The samples are constructed from Action1's documented vulnerability, affected-endpoint and
managed-endpoint responses and cover one CVE on two machines with different installed versions, a
score-only severity, an unrecognised bucket, a vulnerability nothing is affected by, an
affected-endpoint row with no id, a machine name that cannot be a host, and both the nested and
CVE-keyed export shapes. Machine names and identifiers are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
- component_version
