---
title: "Fleet Policies"
toc_hide: true
---

Import a [Fleet](https://fleetdm.com/) host export and report the compliance policies that are failing.

This exists for organisations that cannot grant Fleet API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Fleet connector pulls the same
data over the API; this parser accepts the same data as a file.

Software CVEs in the same export are a **separate scan type**, imported by the Fleet Vulnerabilities
parser. Fleet's own API models policy results and software vulnerabilities as different things, and
the connector imports them under two scan types with different deduplication keys, so splitting them
keeps a file import deduplicating against an API sync.

### File Types

JSON — a Fleet host response. A host list (`{"hosts": [...]}`), a single host (`{"host": {...}}`), a
bare array of hosts and a bare host object are all accepted.

Fleet nests each host's policy results inside the host, so one file produces a finding per host per
failing policy.

### Only failing policies are imported

Fleet reports every policy's outcome for every host, not just the failures. A policy whose `response`
is `fail` (in any casing) becomes a finding; `pass` does not, and neither does an empty response,
which means the query has not run on that host yet. A policy with no name is skipped — there would be
nothing to report.

### Severity

| Fleet policy | Severity |
| --- | --- |
| `critical: true` | High |
| everything else | Medium |

Fleet has no severity scale for policies; `critical` is the only signal it gives, and a critical
policy is also tagged `critical-policy`.

### One finding per host

The identity is `<host id>:policy:<policy id>`, so a policy failing on two machines is two findings —
remediating one does not fix the other. Both carry the same `vuln_id_from_tool`
(`fleet-policy-<policy id>`), which is what this scan type's deduplication hash keys on instead of a
component: a policy is not about a package.

### Fields worth noting

- **Mitigation** is the policy's own resolution text, which is where Fleet puts the remediation step.
- **The policy query** is included in the description as a SQL block, so a reviewer can see exactly
  what was checked.
- **Tags** carry both the policy's platform and the host's platform, sorted and deduplicated as the
  connector does — an unordered tag list would read as a change on every reimport.

### Sample Scan Data

Sample Fleet scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/fleet_policies).

The samples cover a critical and a non-critical failing policy, a passing policy, a policy with no
result yet, a policy with no name, the same policy failing on two hosts with different platforms, and
an uppercase `FAIL`. Hostnames are generic and addresses are private-range.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- vuln_id_from_tool
