---
title: "Dragos"
toc_hide: true
---

Import a [Dragos Platform](https://www.dragos.com/platform/) vulnerability-detection export.

This exists for organisations that cannot grant Dragos API credentials — air-gapped networks,
procurement restrictions, a pending security review. Dragos monitors OT networks, which are often the
most isolated environments an organisation runs, so a file import is frequently the only way the data
can move at all. The DefectDojo Pro Dragos connector pulls the same data over the API; this parser
accepts the same data as a file.

### File Types

JSON — the detections response, `{"content": [...]}`, as Dragos pages it. A bare array is accepted,
as is an object naming the list `detections`, `data` or `results`.

Each detection carries the **asset it was found on** rather than pointing at one, so a single list is
the whole export and nothing has to be joined.

### Severity comes from CVSS, not from Dragos's own scale

| Source | Used when |
| --- | --- |
| `score.base` (CVSS) | present and greater than zero |
| `severity` (Dragos 0–5) | no CVSS score |

| CVSS base score | Severity |  | Dragos `severity` | Severity |
| --- | --- | --- | --- | --- |
| ≥ 9.0 | Critical |  | 5 | Critical |
| ≥ 7.0 | High |  | 4 | High |
| ≥ 4.0 | Medium |  | 3 | Medium |
| > 0 | Low |  | 2 | Low |
|  |  |  | 0–1 | Info |

Dragos's own scale runs the **other way from a score** — 5 is the most severe — so reading one as the
other would invert the entire ladder. CVSS is the more portable signal, so it wins where both exist.

### OT context is a justification, not a regrade

Whether a flaw is actively exploited decides whether it is handled in the next maintenance window or
can wait for the next outage. Dragos's exploitability intel and its own risk score are recorded as
the **severity justification**:

> Dragos OT context: actively exploited; public proof of concept exists; remotely exploitable; Dragos
> risk score 8.5.

The severity itself is not moved, so the same advisory grades the same here as it does through the
API. `active_exploit` is also a tag, for filtering.

### Purdue level 0 is a real level

Dragos leaves `pera_level` **out** when it does not know the level, and level 0 is the physical
process layer — the most sensitive tier in the Purdue model. An absent level and level 0 therefore do
not render alike: the description reports `**Purdue level:** 0` for the latter and omits the line for
the former.

### Fields worth noting

- **Title** is the vulnerability title, then the Dragos advisory id, then the internal id.
- **`vuln_id_from_tool`** prefers the **Dragos advisory** (`report_id`) — that is what an OT engineer
  looks up — then the enumeration, the reference, and only last the internal id.
- **Identity** is `dragos-<vulnerability id>-<asset id>`, so the same advisory on two devices stays
  two findings. In an OT estate those two may sit at different Purdue levels, which is exactly why
  they must not collapse.
- **The asset is the component**, named by its own name, then its first hostname, then its first
  address, then its id — an OT device often has none of the first three.
- **Advisory ids** are read out of the reference, enumeration and title, and come back **sorted**
  rather than in the order they appear: the connector's shared extractor sorts and drops
  case-insensitive duplicates. `CVE-`, `GHSA-`, `GO-` and `RHSA-` forms are recognised.
- **The risk score** renders in its shortest form, so 6.0 reads as `6`.
- **Numbers may arrive quoted**, matching the connector's own decoder.

### Sample Scan Data

Sample Dragos scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/dragos).

The samples are constructed from Dragos's documented detections response and cover a CVSS score that
disagrees with the Dragos severity, a quoted severity and score, Purdue level 0 alongside an absent
level, an asset named only by hostname, one named only by address, one known only by its id, a blank
hostname, two references to the same CVE in different fields, a GHSA identifier, an empty mitigation
list, and a detection with no exploitability intel at all. Asset names, addresses and vendors are
generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
