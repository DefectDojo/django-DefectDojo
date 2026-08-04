---
title: "NetRise"
toc_hide: true
---

Import a [NetRise](https://www.netrise.io/) firmware-analysis export.

This exists for organisations that cannot grant NetRise API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro NetRise connector pulls the
same data over the API; this parser accepts the same data as a file.

### File Types

JSON. NetRise answers GraphQL in **Relay shape**, so each row arrives wrapped in a `node`:

```json
{
  "asset": {"id": "artifact-0001", "name": "generic-firmware.bin",
            "vendor": "Generic Networks", "product": "GN-1000", "version": "1.4.0"},
  "vulnerabilities": {"edges": [{"node": {"cve": "CVE-2000-0001", "name": "example-tls"}}]}
}
```

The edges are unwrapped, and a row that is already the node is used as-is — so a file somebody has
already flattened still imports. A `data` envelope is accepted, as is the artifact arriving in its own
`assetsRelay` envelope from the other query.

### The artifact scopes the identity

The identity is `netrise-<artifact id>-<CVE or component>`, so **the same CVE in two firmware builds
stays two findings** — two builds to re-release. Merging them would hide that one of the two is still
shipping.

One export is one artifact, so the artifact is stated once for the file; a row carrying its own `asset`
overrides it. An export with no artifact still imports, with an empty artifact in the identity.

### Severity

| NetRise `severity` | Severity |
| --- | --- |
| `critical` | Critical |
| `high` | High |
| `medium` | Medium |
| `low` | Low |
| `info`, `informational`, `none` | Info |
| **anything else** | derived from `cvssScore` |

An unrecognised word falls through to the **score**, not to Info: a finding NetRise graded with an
unfamiliar word still lands where its score says. Score bands are the standard ≥ 9 / ≥ 7 / ≥ 4 / > 0.
Scores may arrive quoted.

### Reachability and CISA KEV are justifications, not regrades

A reachable, actively-exploited flaw in firmware is more urgent than its score alone says. Both signals
are recorded as the **severity justification** and as tags (`reachable`, `cisa-kev`), and both appear in
the description — but neither moves the severity, which would make the finding disagree with an API
sync of the same data.

### Fields worth noting

- **Title** is `<CVE> in <component>`, falling back to whichever of the two exists.
- **The component is the affected package**, and it is in the deduplication hash.
- **Mitigation** names the fixed versions NetRise lists; with none, there is no mitigation.
- **Vendor and product** come from the artifact and are also tags.

### Sample Scan Data

Sample NetRise scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/netrise).

The samples cover a reachable KEV-listed critical finding, an unrecognised severity word with a quoted
score, a finding with no CVE, one with no component, one with neither, and empty fix versions. Artifact,
vendor, product and component names are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
