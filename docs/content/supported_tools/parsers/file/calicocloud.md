---
title: "Calico Cloud Image Assurance"
toc_hide: true
---

Import a [Calico Cloud](https://www.tigera.io/calico-cloud/) Image Assurance export.

This exists for organisations that cannot grant Calico Cloud API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Calico Cloud connector pulls
the same data over the API; this parser accepts the same data as a file.

### File Types

JSON. Each vulnerability on each scanned image is one finding.

Calico serves the image list and a given image's vulnerabilities from **two endpoints**, so an export
carries both. The vulnerabilities may be nested in their image:

```json
{"images": [{"imageID": "img-0001", "repository": "generic-app",
             "vulnerabilities": [{"id": "CVE-2000-0001"}]}]}
```

…or held in a map keyed by image id:

```json
{"images": [{"imageID": "img-0001"}],
 "vulnerabilities": {"img-0001": [{"id": "CVE-2000-0001"}]}}
```

A bare array of images works, as does an object naming the list `images`, `data` or `results`. A file
holding **only** the vulnerability call is accepted too — the identity then carries an empty image
id, which is what the connector would build for an image it knows nothing about, so the findings are
not silently dropped.

### An image still being scanned contributes nothing

Calico reports `Unknown` in `scan_result` or `result` while a registry scan is still being processed.
Those images are **skipped entirely**, matching the connector: their results are not finished, so
importing them would record a partial scan as a complete one.

### Severity comes from CVSS, not from Calico's verdict

| Source | Used when |
| --- | --- |
| `cvss3Score` | present and greater than zero |
| `cvss.base_score` | no `cvss3Score` |
| Calico's `severity` word | no score at all |

| CVSS v3 base score | Severity |
| --- | --- |
| ≥ 9.0 | Critical |
| ≥ 7.0 | High |
| ≥ 4.0 | Medium |
| > 0 | Low |

Calico's Pass/Warn/Fail verdict is **deliberately ignored**, and its severity word is only a
fallback: those thresholds are per-tenant configuration, not a severity, so using them would make the
same CVE a different severity in two tenants. `negligible` and `unknown` are Info.

### Fields worth noting

- **Title** is `<id>: <name>`, or whichever of the two is present. A name that merely repeats the id
  is not doubled.
- **Identity** is `calico-cloud-<image id>-<vulnerability id>`, so the same CVE in two images stays
  two findings — two images to rebuild.
- **Only a CVE becomes a vulnerability id.** Calico issues its own advisory ids too, and those go in
  `vuln_id_from_tool` alone.
- **The package name** comes from `package_name`, falling back to `package`.
- **The fix** is `fixVersions` joined, falling back to the single `fix` string; with no fix there is
  no mitigation.
- **The image reference** is `<registry>/<repository>:<tag>`, falling back to the digest and then the
  image id. The registry is only prefixed when there is a repository to prefix.
- **Numbers may arrive quoted**, matching the connector's own decoder.

### Sample Scan Data

Sample Calico Cloud scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/calicocloud).

The samples are constructed from Calico's documented images and vulnerabilities responses and cover
both export shapes, a score that disagrees with the severity word, a nested and quoted base score, an
unscored Calico advisory, a negligible finding, a single fix string, an image still being scanned, an
image known only by its digest, one known only by its id, and a registry with a trailing slash.
Registry, repository and package names are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
- component_version
