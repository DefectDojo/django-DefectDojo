---
title: "Group-IB ASM"
toc_hide: true
---

Import a [Group-IB](https://www.group-ib.com/products/attack-surface-management/) Attack Surface
Management issue export.

This exists for organisations that cannot grant Group-IB API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Group-IB connector pulls the
same data over the API; this parser accepts the same data as a file.

### Two fields called "status" mean different things

This is the trap worth knowing about:

| Field | Meaning |
| --- | --- |
| the issue's own `status` | its **lifecycle** state — `Detected`, `Under review`, `Solved`, `Ignored`, `False positive` |
| `body.status` | its **severity** label — e.g. `Critical severity` |

Reading one for the other would grade every finding Info *and* leave every solved issue open.

### Severity is matched by containment

Group-IB writes the severity as a phrase, so equality would never match:

| `body.status` contains | Severity |
| --- | --- |
| `critical` | Critical |
| `high` | High |
| `medium` | Medium |
| `low` | Low |
| `info` | Info |
| none of them | Info |

The order matters: `critical` is tested before `high`, so a label naming both is graded by the worse.

### Lifecycle status

| Issue `status` | Imported as |
| --- | --- |
| `Solved` | inactive, **mitigated** |
| `False positive` | inactive, **false positive** |
| `Ignored` | inactive, **out of scope** |
| `Detected`, `Under review`, anything unrecognised | **active** |

The three closing states are kept apart because they mean different things: a solved issue was fixed,
an ignored one was accepted, and a false positive was never real. Anything unrecognised stays active,
the safe direction to be wrong in.

### The asset is either an endpoint or the component

Group-IB reports hosts, addresses and URLs **in the same field** as software names and SSL or
login-form descriptors. So an asset that looks like a host becomes an **endpoint**, and anything else
becomes the **component name** — never both, and never lost. Recording a software name as an endpoint
would make `Endpoint.clean()` raise and fail the whole import.

An asset counts as host-shaped when it is a URL, an IP address (optionally with a port), an already
scheme-relative `//host`, or a dotted name whose last label is alphabetic and at least two characters.
Anything containing whitespace or a path separator is not.

Group-IB sends bare hosts with no scheme. The connector prefixes `//` so DefectDojo reads the value as
an authority rather than a path; this parser builds the endpoint from its parts instead, reaching the
same result without the string trick.

### Fields worth noting

- **Title** is the issue type, falling back to its reason, then its category, then the issue id.
- **ASM findings are dynamic** — they come from external scanning.
- **MITRE ATT&CK techniques** become `mitre-attack:<technique>` tags, sorted. Group-IB sends them as a
  map keyed by technique, so sorting is what makes the order stable.
- **An issue with no informative fields says so** rather than arriving with an empty description, which
  would read as though the data had been lost in transit.
- **The hash is only the title and severity** — an ASM issue has neither a file nor a package.

### Sample Scan Data

Sample Group-IB ASM scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/groupib).

The samples cover a critical detected issue with two MITRE techniques, a solved one, a false positive, an
ignored one, an issue under review with no details at all, an unrecognised severity label, an address
with a port, a URL asset, and a software name that must become the component rather than an endpoint.
Hosts, addresses and company names are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
