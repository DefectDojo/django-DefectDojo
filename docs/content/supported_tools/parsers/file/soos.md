---
title: "SOOS"
toc_hide: true
---

Import a [SOOS](https://soos.io/) issue export.

This exists for organisations that cannot grant SOOS API credentials — air-gapped networks, procurement
restrictions, a pending security review. The DefectDojo Pro SOOS connector pulls the same data over the
API; this parser accepts the same data as a file.

### File Types

JSON — the issues response, `{"entries": [...]}`. SOOS answers some lists as `{"items": [...]}` and its
own client accepts both, so both are read here; a bare array works too, as does an object naming the
list `issues`, `data` or `results`.

### One API, five kinds of scan

SOOS runs SCA, SAST, container, SBOM and DAST scans behind **one** API and stamps each issue with its
scan type, so whether a finding is static or dynamic is decided **per issue** rather than for the file:

| `scanType` | Imported as |
| --- | --- |
| `sca`, `sast`, `csa`, `sbom` | **static** — an artifact is inspected |
| `dast` | **dynamic** — the application is exercised |
| unrecognised or absent | **dynamic** |

An unrecognised scan type arriving as dynamic is the connector's own behaviour — it reads its lookup
table with a Go map access, which yields `false` for a missing key just as it does for the `dast` entry.
Mirrored rather than corrected here, so a file import and an API sync agree; worth raising on the
connector side, because a *new* SOOS scan type would arrive as dynamic.

The scan type is also a tag, so an SCA and a DAST finding on the same product stay distinguishable.

### Severity

| SOOS `severity` | Severity |
| --- | --- |
| `Critical` | Critical |
| `High` | High |
| `Medium` | Medium |
| `Low` | Low |
| `Info` | Info |
| **`Unknown`** | Info |
| anything else | Info |

`Unknown` is a **real SOOS value**, not a gap — a finding it could not grade is still a finding, so it
grades as Info rather than being dropped.

### A SOOS-side dismissal is carried across

Without this, an issue somebody dismissed in SOOS would resurface as an active finding on every sync.
The three kinds are kept apart, because they are three different statements:

| SOOS `status` | Imported as |
| --- | --- |
| `False positive` | inactive, **false positive** — it was never real |
| `Accepted` | inactive, **risk accepted** — it is real and signed off |
| `Ignored`, `Dismissed`, `Resolved`, `Fixed` | inactive, **mitigated** — it is dealt with |
| everything else | **active** |

Spaces are stripped before matching, so `False positive` and `falsepositive` are the same status.

### Fields worth noting

- **Mitigation** prefers SOOS's remediation text; without one it names the fixed version, and the package
  too when SOOS named one.
- **An issue with no prose says which scan reported it** rather than arriving with an empty body, which
  would read as though the data had been lost in transit.
- **A DAST issue's URL becomes the endpoint**; a source issue has a file path and line instead. A URL
  DefectDojo would reject adds no endpoint, since `Endpoint.clean()` raising would fail the whole import.
- **CWE** accepts `CWE-79` or `79`.
- **`cvssv3` is the vector** and `cvssv3_score` the score; SOOS reports both.

### Deduplication

This scan type has **no curated hashcode field list**, so it deduplicates with DefectDojo's default
algorithm — which is what the connector's own findings already do. Choosing hashcode fields here would
also change how those findings deduplicate, so it is left alone.

### Sample Scan Data

Sample SOOS scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/soos).

The samples cover one issue of each scan type, a false positive, an accepted risk, a resolved issue, an
`Unknown` severity, an unrecognised scan type and severity word, a bare CWE number, an unparseable one, a
line of zero, an unparseable timestamp, and a URL DefectDojo cannot accept. Package names, hosts and file
paths are generic.
