---
title: "Holm Security"
toc_hide: true
---

Import a [Holm Security](https://www.holmsecurity.com/) vulnerabilities export.

This exists for organisations that cannot grant Holm Security API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Holm Security connector pulls
the same data over the API; this parser accepts the same data as a file.

### File Types

JSON — a Holm paged response, with rows under `results`. A bare array of vulnerabilities is accepted too.

**Say which scan class the rows came from.** Holm scans two ways — a network class and a web class — and
only the web class exercises a running application. The class is a property of the scan rather than of
the row, so state it as a top-level `"class"` (or `"asset_class"`) of `web` or `net`:

| `class` | Imported as | Tag |
| --- | --- | --- |
| `web` | dynamic | `web-scan` |
| `net` | static | `net-scan` |
| absent | static | none |

Absent means static, which is the connector's own default for anything that is not the web class.

### Severity: name first, then Holm's number

| Holm `severity` | Severity |
| --- | --- |
| `critical` / `high` / `medium` / `low` / `info` | as named |

When the name is missing **or unrecognised**, the numeric `severity_level` decides:

| `severity_level` | Severity |
| --- | --- |
| 4 | Critical |
| 3 | High |
| 2 | Medium |
| 1 | Low |
| 0, or anything else | Info |

Note **4 is the most severe** — the inverse of a priority number. The order matters: consulting the
level only as a fallback means an unfamiliar name does not silently become Info while a usable level
sits next to it. Levels may arrive as numbers or numeric strings.

### One finding per host per port

The identity is `holm-<hid>[-<asset>][-<port>]`. Holm reports the same weakness once per host and once
per listening port, and collapsing them would hide a second exposed service. A port of zero is left out
of the identity rather than recorded as port zero.

### The endpoint is the URL alone

This scan type's deduplication hash includes `endpoints`, and the parser records Holm's URL when it has
one. The separately-reported `detected_port` is **not** added to the endpoint — it appears in the
identity and the description instead, matching the connector. A network finding often has no URL at all,
and then nothing is recorded; the details stay in the description.

### Fields worth noting

- **CVSS** is the `cvss_base`, falling back to `cvss_score`.
- **Title** falls back to the first CVE, then to `Holm Security finding <hid>`.
- **`fixed`, `closed` and `resolved`** are inactive; everything else is active.
- **Date** is the last detection, falling back to the first.
- **Impact** and **references** are Holm's own impact statement and vendor reference.

### Sample Scan Data

Sample Holm Security scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/holm_security).

The samples are constructed from Holm's documented vulnerability shape and cover a name that overrides
the level, a missing name with a level sent as a string, an unrecognised name with a usable level, a
fixed finding, a finding with no URL, a URL that cannot be a host, and both scan classes. Hostnames are
generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- endpoints
- vuln_id_from_tool
