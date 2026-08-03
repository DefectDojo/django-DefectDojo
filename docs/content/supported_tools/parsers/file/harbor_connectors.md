---
title: "Harbor (Connectors Import)"
toc_hide: true
---

Import a [Harbor](https://goharbor.io/) vulnerability report in the connector's shape.

DefectDojo also ships a **`harbor_vulnerability`** parser under the scan type
`Harbor Vulnerability Scan`. That one is unchanged. This parser exists for the connector's own scan
type, so a customer who cannot grant Harbor API credentials can upload the same data the DefectDojo Pro
Harbor connector syncs.

### File Types

JSON. Harbor's scan endpoint keys the report by the **scanner's MIME type**, so a saved export is
usually an object with a single key like:

```json
{"application/vnd.security.vulnerability.report; version=1.1": {"vulnerabilities": [...]}}
```

That envelope is unwrapped automatically. A bare report object (`{"vulnerabilities": [...]}`) and a
bare array of vulnerabilities are also accepted.

### Include the artifact context in your export

**The artifact's identity is not in Harbor's report body.** The connector supplies it from the
repository and artifact it fetched, and it feeds both the finding's identity and the image context in
the description. So an export should carry these alongside the report:

| Field | Used for |
| --- | --- |
| `repository` (or `repository_name`) | the finding's `service`, the identity, and the image line |
| `digest` | the identity, and the digest line |
| `tag` (or `tags[].name`) | the image line, and the identity when there is no digest |

Without them a finding still imports, but its identity has empty repository and artifact segments —
which is what the connector itself produces when those fields are blank.

The identity is `<repository>@<digest or tag>:<vulnerability id>:<package>:<version>`, and the
**digest is preferred over the tag** because a tag can be moved to a different image, which would
silently merge findings from two artifacts.

### Severity

Harbor's severity word: `Critical`→Critical, `High`→High, `Medium`→Medium, `Low`→Low, and anything
unrecognised→Info.

### Fields worth noting

- **Only a CVE id becomes a vulnerability id.** Harbor also reports GHSA and distro advisory ids; the
  connector records only CVEs, since putting a GHSA in the CVE field would have DefectDojo try to
  resolve it as one. The advisory id still appears in the title.
- **A missing description is reported as `No description found`** rather than left blank — Harbor omits
  it on plenty of advisories, and an empty field reads as a parser bug.
- **CWE** is the first entry of `cwe_ids`, parsed from `CWE-<n>`; anything unparseable leaves it at 0.
- **Mitigation** is set only when Harbor reports a `fix_version`.
- **Service** carries the repository, so findings can be grouped by image in DefectDojo.

### Scan type and deduplication

The scan type is **`Harbor - Connectors Import`** — identical to the string the Harbor connector
reports, and distinct from `Harbor Vulnerability Scan`. A test asserts both.

The composed identity already carries the repository, artifact, vulnerability and package, so
deduplication uses the plain `hash_code` algorithm over `unique_id_from_tool` alone.

### Sample Scan Data

Sample scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/harbor_connectors).

The samples are constructed from Harbor's documented report schema inside the real MIME-type envelope,
and cover a fully-populated CVE, an advisory with no description or fix, a GHSA id, an unparseable CWE
and an unrecognised severity. Project, repository and digest values are generic placeholders.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- unique_id_from_tool
