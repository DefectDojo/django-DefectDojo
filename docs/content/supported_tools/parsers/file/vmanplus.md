---
title: "ManageEngine Vulnerability Manager Plus"
toc_hide: true
---

Import a [ManageEngine Vulnerability Manager Plus](https://www.manageengine.com/vulnerability-management/)
export.

This exists for organisations that cannot grant VMP API credentials — air-gapped networks, procurement
restrictions, a pending security review. The DefectDojo Pro VMP connector pulls the same data over the
API; this parser accepts the same data as a file.

### File Types

JSON — `{"vulnerabilities": [...]}` alongside VMP's paging metadata. A bare array works, as does an
object naming the list `data` or `results`.

Rows are already **fused**: each carries both the vulnerability and the asset it was found on, so
nothing has to be joined.

### Severity: the MSRC names do not mean what they say

VMP grades on Microsoft's scale, whose names do not match DefectDojo's:

| VMP `severity` | Severity |
| --- | --- |
| `Critical` | Critical |
| **`Important`** | **High** |
| `High` | High |
| **`Moderate`** | **Medium** |
| `Medium` | Medium |
| `Low` | Low |
| `Unrated`, absent | Info |

DefectDojo has neither `Important` nor `Moderate`, so reading them literally would fall through to Info
and drop each a whole tier.

### Status

| VMP `vulnerability_status` | Imported as |
| --- | --- |
| `Close`, `Closed`, `Fixed`, `Remediated` | inactive |
| everything else | active |

An unfamiliar status stays **active** — treating it as closed would silently hide a live vulnerability.

### Fields worth noting

- **Title** is the vulnerability name, falling back to its CVE ids and then the vulnerability id.
- **The host is the component**, not a package — named by resource name, then FQDN, then address — so the
  same vulnerability on two machines stays two findings.
- **`cvss_3_score` wins over `cvss_2_score`**; VMP reports both for older advisories.
- **Every CVE for a vulnerability arrives in one `cveids` string**, so identifiers are extracted from it
  rather than used whole. They come back **sorted**, matching the connector's shared extractor; the raw
  field is still shown in the description as VMP wrote it.
- **Ids are strings that may arrive as numbers.** One read as a float would render as `50124.0` and never
  match the API's `50124`, so integral floats render without the decimal point.
- **Timestamps are epoch MILLIseconds** — reading them as seconds would date every finding to 1970.
- **Mitigation** is the patch description and the patch id, the two things needed to act on the finding.

### Sample Scan Data

Sample VMP scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/vmanplus).

The samples cover an `Important` and a `Moderate` finding, a closed one, a `Mitigated` one that must stay
active, a v3 score of zero falling back to v2, two CVEs in one field out of order, ids sent as numbers, a
zero timestamp, and a row with no patch. Host names and addresses are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
