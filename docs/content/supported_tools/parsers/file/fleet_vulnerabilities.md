---
title: "Fleet Vulnerabilities"
toc_hide: true
---

Import a [Fleet](https://fleetdm.com/) host export and report the CVEs in each host's installed
software.

This exists for organisations that cannot grant Fleet API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Fleet connector pulls the same
data over the API; this parser accepts the same data as a file.

Failing compliance policies in the same export are a **separate scan type**, imported by the Fleet
Policies parser. Fleet's own API models software vulnerabilities and policy results as different
things, and the connector imports them under two scan types with different deduplication keys, so
splitting them keeps a file import deduplicating against an API sync.

### File Types

JSON — a Fleet host response. A host list (`{"hosts": [...]}`), a single host (`{"host": {...}}`), a
bare array of hosts and a bare host object are all accepted.

Fleet nests the software inventory inside the host and the CVEs inside each software row, so one file
produces a finding per host per software per CVE. Ask Fleet for the software and vulnerability detail
when exporting — `GET /api/v1/fleet/hosts/{id}` includes it, the summary host list does not.

### Severity

| CVSS score | Severity |
| --- | --- |
| ≥ 9.0 | Critical |
| ≥ 7.0 | High |
| ≥ 4.0 | Medium |
| > 0 | Low |
| 0 | Info |
| **not scored** | **Medium** |

An unscored CVE is Medium rather than Info: Fleet enriches from the NVD, so a missing score means
"not scored yet" rather than "no risk". An explicit zero is still Info. Note the difference between
a `null` score, which means unscored, and an empty string, which the connector's decoder reads as a
zero — this parser reads them the same way. Scores and probabilities may arrive as numbers or as
numeric strings, and both are accepted.

A CVE on CISA's Known Exploited Vulnerabilities list is flagged in the description and tagged
`cisa-known-exploited`, but its severity still comes from the CVSS score — the connector does not
raise it, so neither does this parser.

### One finding per host

The identity is `<host id>:<software>:<version>:<CVE>`, so the same CVE on two machines is two
findings. Collapsing them would hide a machine still running the vulnerable version.

### Sample Scan Data

Sample Fleet scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/fleet_vulnerabilities).

The samples are constructed from Fleet's documented host and software schemas and cover every
severity floor, an unscored CVE, a score sent as a string, EPSS, a CISA KEV entry, a CVE with and
without a fixed version, the same CVE on two hosts, and a vulnerability row with no CVE id. Hostnames
are generic and addresses are private-range.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
