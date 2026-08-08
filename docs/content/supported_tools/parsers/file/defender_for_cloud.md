---
title: "Microsoft Defender for Cloud"
toc_hide: true
---

Import a [Microsoft Defender for Cloud](https://azure.microsoft.com/products/defender-for-cloud)
sub-assessments export.

This exists for organisations that cannot grant Azure API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Defender for Cloud connector
pulls the same data over the API; this parser accepts the same data as a file.

**Not to be confused with Microsoft Defender for Endpoint**, which DefectDojo already parses as
`ms_defender`. Different product, different scan type, different parser.

### File Types

JSON — the ARM `subAssessments` response, with rows under `value`. A bare array of sub-assessments, or a
single one, is accepted too.

### Only open vulnerabilities are imported

Two filters, both the connector's:

- **Status** — only a `status.code` of `Unhealthy` is an open finding. Healthy and NotApplicable
  sub-assessments are left out so a reimport **closes** them.
- **Kind** — Defender returns every sort of sub-assessment through one endpoint. `SqlServerVulnerability`
  and `GeneralVulnerability` are posture and configuration checks carrying no CVEs, so they are
  excluded; the server and container-registry vulnerability types are imported.

For an **unfamiliar** resource type the presence of a CVE decides. A new Defender scanner should not be
dropped silently, and a configuration baseline should not arrive as a vulnerability.

### One field, two shapes

The same finding is described differently depending on which scanner produced it, and the parser reads
both:

| | Container-registry finding | Server finding |
| --- | --- | --- |
| package | `softwareDetails.packageName` | `softwareName` |
| version | `softwareDetails.version` | `softwareVersion` |
| fixed version | `softwareDetails.fixedVersion` | `recommendedVersion` |

Reading only one shape would leave every finding of the other kind with no component — and the
component is what a reviewer patches. A container finding also names the image and digest in the
description.

### Severity and CVSS

| Defender `severity` | Severity |
| --- | --- |
| `Critical` | Critical |
| `High` | High |
| `Medium` | Medium |
| `Low` | Low |
| anything else | Info |

The raw label is always recorded as the severity justification, together with the CVSS base score and
which version it was — so a value that graded as Info because it was unrecognised is still auditable.

Defender reports a flat `cvssV30Score` on some shapes and a version-keyed `cvss` map on others. The
**highest** base score wins, and only a **v3** base reaches `cvssv3_score`: the same number means
different things on the v2 and v3 scales.

### Deduplication is the ARM id alone

This scan type's configuration pairs `unique_id_from_tool_or_hash_code` with a hash of
**`unique_id_from_tool` and nothing else**. The ARM sub-assessment id already encodes the subscription,
the resource and the finding, so it is the whole identity; adding a volatile field would split a finding
that had merely been regraded.

### Fields worth noting

- **Title** appends the package only when the display name is a bare CVE — `CVE-2000-0001` alone says
  nothing about what is affected, and one CVE usually appears against several packages on one host. A
  descriptive name is left as it is.
- **CVE ids** are matched against an **anchored** pattern, so a reference title like
  `supersedes CVE-2000-0009` does not contribute another finding's identifier.
- **Defender's TVM `cve` field** arrives as a list, a single object, or a bare string. All three are
  accepted, matching the connector's decoder.
- **Mitigation** keeps both the version to update to and Defender's own remediation text: they answer
  what to do and how, and neither is always present.
- **The assessed resource** falls back to the last segment of an ARM or native resource id — the whole
  path would bury the one part a reader needs.
- **Impact** is Defender's own impact statement, imported as-is.

### Sample Scan Data

Sample Defender for Cloud scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/defender_for_cloud).

The samples are constructed from Azure's documented sub-assessment shape and cover a server finding with
both CVSS versions, a container finding with an image and digest and only a v2 score, a posture
recommendation, a healthy finding, an unfamiliar resource type that does carry a CVE, and one that does
not. Subscription ids, registries and hostnames are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- unique_id_from_tool
