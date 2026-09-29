---
title: "Ostorlab"
toc_hide: true
---

Import an [Ostorlab](https://www.ostorlab.co/) scan export.

This exists for organisations that cannot grant Ostorlab API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Ostorlab connector pulls the
same data over the API; this parser accepts the same data as a file.

### File Types

JSON — Ostorlab answers GraphQL, and its own shape **doubles the key**: the outer `vulnerabilities` is
the connection, the inner one is the list.

```json
{"data": {"scan": {"id": 4001, "assetType": "WEB", "createdTime": "2024-06-03T09:30:00Z",
                   "vulnerabilities": {"vulnerabilities": [ ... ]}}}}
```

The unwrapped forms and a bare array of vulnerabilities are accepted too. One export is one scan, so
the scan is stated once for the file. An export with no scan context still imports — the identity then
carries scan `0` and every finding is dynamic, because the asset type that would say otherwise is
missing.

### A SECURE rating is a passed check

Ostorlab reports checks that **passed** with a `SECURE` risk rating. Those are skipped: importing one
would file a passing check as a finding. Matched case-insensitively.

### Severity

| `riskRating` | Severity |
| --- | --- |
| `CRITICAL` | Critical |
| `HIGH` | High |
| `MEDIUM` | Medium |
| `LOW`, **`POTENTIALLY`** | Low |
| `HARDENING`, `IMPORTANT`, `INFO`, unrecognised, absent | Info |

`POTENTIALLY` is a finding Ostorlab could not fully confirm, which it grades as Low.

Note that **`IMPORTANT` grades as Info**. That reads oddly, and it is mirrored rather than corrected —
changing it here would make a file import disagree with an API sync of the same finding. Raised as a
follow-up on the connector side.

### The asset type decides static versus dynamic

Ostorlab scans mobile applications, web targets and networks from one platform. An asset type
containing `ANDROID`, `IOS`, `APP`, `FILE` or `STORE` is read **statically**; a web, network or domain
target is **exercised**. Deciding this per scan rather than for the tool is what keeps both honest.

### Ostorlab has no CVE field

Identifiers appear in the prose and the references, so they are extracted from the technical detail, the
title, the description, the summary, and every reference title and URL. `CVE-`, `GHSA-`, `GO-` and
`RHSA-` forms are recognised. The results come back **sorted** rather than in the order they appear,
matching the connector's shared extractor.

### Fields worth noting

- **Title** is the detail's title, falling back to `Ostorlab finding <id>`. The detail is optional, so a
  finding without one still imports rather than being dropped.
- **`cvssv3` is a vector string, not a score** — Ostorlab publishes no numeric score, so `cvssv3_score`
  stays unset.
- **Location metadata is rendered under its own type** as the label, so whatever context Ostorlab
  attached — a URL, a file path, a code location — reaches the reader without the parser knowing the
  names in advance. Metadata with no type is skipped.
- **The endpoint** is the affected asset's name, falling back to its host. A mobile scan names a package
  rather than a host, so it has no endpoint; a host DefectDojo would reject is left out too, since
  `Endpoint.clean()` raising would fail the whole import.
- **Identity** is `ostorlab-<scan id>-<vulnerability id>`, so the same finding in two scans of one app is
  two records — one per scan. Ids may arrive quoted.
- **Deduplication**: the copied hashcode list names `component_name`, and Ostorlab reports no component,
  so that field hashes as empty and the hash is effectively title plus severity. Copied as it stands
  rather than trimmed, because changing it would change how the connector's own findings hash.

### Sample Scan Data

Sample Ostorlab scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/ostorlab).

The samples cover a static Android scan and a dynamic web scan, a `SECURE` check that must not import,
`POTENTIALLY`, `HARDENING` and `IMPORTANT` ratings, two CVEs named out of order in the prose, a
reference with only a URL and one with only a title, a finding with no detail block, location metadata
under several types, and a host DefectDojo cannot accept. Package names, hosts and identifiers are
generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
