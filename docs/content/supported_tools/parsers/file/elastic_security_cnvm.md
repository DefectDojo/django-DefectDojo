---
title: "Elastic Security CNVM"
toc_hide: true
---

Import an [Elastic Security](https://www.elastic.co/security) export and report its Cloud Native
Vulnerability Management findings.

This exists for organisations that cannot grant Elasticsearch API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Elastic Security connector
pulls the same data over the API; this parser accepts the same data as a file.

### Three scan types, three parsers

Elastic returns CNVM vulnerabilities, posture evaluations and detection alerts from the **same**
`_search` API, with the same ECS asset, host and cloud objects describing where each finding sits. The
connector imports them under three scan types, each behind its own toggle and with its own
deduplication key, so there are three parsers to match:

| Data | Parser |
| --- | --- |
| Software CVEs found in workloads | Elastic Security CNVM (this one) |
| Failing cloud/Kubernetes benchmark rules | Elastic Security Posture |
| Detection-engine alerts | Elastic Security Detections |

Each parser claims only its own documents, so the same export can be uploaded three times without one
document being imported under three scan types. **This parser imports documents carrying a
`vulnerability.id`.**

### File Types

JSON — an Elasticsearch search response (`{"hits": {"hits": [...]}}`). A bare array of documents and a
single document are accepted too. Each document keeps its `_id`, which is the finding's identity.

### Severity

Elastic's own `vulnerability.severity` label is used when it is one of `critical`, `high`, `medium`,
`low`, `informational`, `info`, `none` or `unknown` (case-insensitively). Anything else is **not**
graded by resemblance — the CVSS base score decides instead:

| CVSS base | Severity |
| --- | --- |
| ≥ 9.0 | Critical |
| ≥ 7.0 | High |
| ≥ 4.0 | Medium |
| > 0 | Low |
| 0, or no score at all | Info |

Note the label wins even when the score disagrees, which is the connector's behaviour: Elastic's label
already reflects its own enrichment. Only a **v3** score reaches the `cvssv3_score` field — Elastic
also reports v2 bases — but every score appears in the description with its version, so nothing is
lost.

### Fields worth noting

- **Identity** is the Elasticsearch document id, which is stable across syncs. Only a hand-assembled
  export lacks one; then the asset, the CVE and the package stand in.
- **Asset context** — the resource, host, OS, cluster/namespace and cloud account are rendered into
  the description, and the cloud provider, region and cluster become tags.
- **The endpoint** is the host, falling back to the resource or pod name: a bucket has no hostname but
  is still worth recording.
- **Mitigation** names the fixed version when Elastic reported one, and otherwise says plainly that
  none is published yet.

### Sample Scan Data

Sample Elastic Security scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/elastic_security_cnvm).

The samples are constructed from Elastic's documented CNVM document shape and cover a label that
overrides the score, an unrecognised label graded from a v3 score, a v2-only score, a document with no
score at all, a Kubernetes pod asset, a document with no `_id`, and a document with no CVE id. They
also include posture and detection documents, which this parser must ignore. Hostnames and account
identifiers are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
