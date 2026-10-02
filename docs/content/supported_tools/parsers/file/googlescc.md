---
title: "Google Cloud Security Command Center"
toc_hide: true
---

Import a [Google Cloud Security Command Center](https://cloud.google.com/security-command-center)
findings export.

This exists for organisations that cannot grant a GCP service account to DefectDojo — air-gapped
networks, procurement restrictions, a pending security review. The DefectDojo Pro Google Cloud SCC
connector pulls the same data over the API; this parser accepts the same data as a file.

### File Types

JSON — the SCC `ListFindings` response:

```
gcloud scc findings list ORGANIZATION_ID --format=json > scc.json
```

Results live under `listFindingsResults`. A bare array is accepted too.

**Each result pairs the finding with the resource it was found on, as siblings rather than nested:**

```json
{"listFindingsResults": [{
  "finding":  {"name": "...", "category": "PUBLIC_BUCKET_ACL", "severity": "HIGH"},
  "resource": {"displayName": "generic-app-assets", "type": "google.cloud.storage.Bucket"}
}]}
```

Both halves matter — the resource carries the display name and type that make the finding readable,
while the category and severity are on the finding. An export somebody has already flattened (the
finding's own fields at the top level) is also accepted.

### Severity

SCC's severity level: `CRITICAL`→Critical, `HIGH`→High, `MEDIUM`→Medium, `LOW`→Low. SCC's own
`SEVERITY_UNSPECIFIED` is not a DefectDojo severity and falls through to **Info**, as does anything
unrecognised.

### Fields worth noting

- **Title** is `<category> - <resource display name>`, falling back to the category alone, and to
  `Security Command Center finding` when SCC set no category — an empty title would be useless in the
  finding list.
- **`vuln_id_from_tool` is the SCC category**, which is its rule identifier (`PUBLIC_BUCKET_ACL`,
  `MFA_NOT_ENFORCED`).
- **`unique_id_from_tool` is the finding's full resource name**
  (`organizations/…/sources/…/findings/…`), which is globally unique across the organisation — and is
  the entire dedup hash for this scan type.
- **CVE and CVSS are only present on vulnerability-class findings.** SCC reports several classes —
  misconfiguration, threat, observation — and only some carry a `vulnerability.cve` block, nested two
  objects deep. The score is recorded only when above zero.

### Scan type and deduplication

The scan type is **`Google Cloud SCC - Connectors Import`** — identical to the string the Google Cloud
SCC connector reports, so a customer who uploads an export *and* later enables the connector gets one
set of findings that deduplicate rather than two copies of everything.

### Sample Scan Data

Sample Google Cloud SCC scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/googlescc).

The samples are constructed from SCC's documented `ListFindings` response and cover a misconfiguration
with no CVE, a vulnerability with a CVE and score, one with a zero score, a finding with no category and
`SEVERITY_UNSPECIFIED`, and an empty vulnerability block. Organisation, project and bucket identifiers
are numeric or generic placeholders.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- unique_id_from_tool
