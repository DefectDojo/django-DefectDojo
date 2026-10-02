---
title: "Lacework (FortiCNAPP)"
toc_hide: true
---

Import a [Lacework / FortiCNAPP](https://www.lacework.com/) container or host vulnerability export.

This exists for organisations that cannot grant Lacework API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Lacework connector pulls the
same data over the API; this parser accepts it as a file.

### File Types

JSON. Export the rows of a vulnerability query, for example:

```
lacework vulnerability container list-assessments --json > lacework.json
lacework vulnerability host list-cves --json > lacework.json
```

A bare JSON array of rows is accepted, as is the query envelope that wraps them under `data`.

### Two shapes in one export

Lacework reports container/image and host vulnerabilities differently, and the connector maps them
differently, so this parser does too:

| | Container row | Host row |
| --- | --- | --- |
| Flag | `static_finding` | `dynamic_finding` |
| Identity | `imageId\|CVE\|package\|version` | `hostname\|CVE\|package\|version` |
| Version field | `featureKey.version` | `featureKey.version_installed` |
| `fix_available` | integer | string |
| Tags | `image:`, `registry:`, `source:container` | `host:`, `source:host` |

A host row with no hostname falls back to `mid-<machine id>`, as the connector does.

### Scan type and deduplication

The scan type is **`Lacework - Connectors Import`** — identical to the connector's, so a file import
and a later API sync produce one set of findings rather than two.

### Severity and status

`critical`/`high`/`medium`/`low` map straight across; anything else is Info. A row Lacework reports as
`Fixed` or `Resolved` is still imported, but inactive and mitigated — matching the connector's
`applyStatus`. A mitigation is only offered when the row reports both a fix available and a fixed
version.

### Sample Scan Data

Sample Lacework scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/lacework).

Constructed from Lacework's documented row schema and the shapes the connector's converter tests
exercise, with generic registries and hostnames.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
