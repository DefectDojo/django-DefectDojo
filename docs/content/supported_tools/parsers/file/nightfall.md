---
title: "Nightfall AI"
toc_hide: true
---

Import a [Nightfall AI](https://www.nightfall.ai/) violations export.

This exists for organisations that cannot grant Nightfall API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Nightfall AI connector pulls
the same data over the API; this parser accepts the same data as a file.

### File Types

JSON — the violation-list response, with rows under `violations`. A bare array of rows is accepted
too.

**Include each violation's detections.** Nightfall splits a violation across two calls: the violation
itself, and the detections that make it up, which carry the redacted evidence, the confidence and the
API-key verdict. The verdict is what raises a violation to Critical and what names the credential in
the title, so a violation-only import loses all three. Because a detection carries no violation id of
its own, supply them as:

- a top-level `findings` (or `detections`) object keyed by violation id, or
- a `findings` array nested on each violation.

### No sensitive data is imported

Nightfall's API returns **redacted** detection text only — that is the field this parser reads, and
the only text field it reads from a detection. There is no field in the API carrying the raw secret,
and the parser ignores the surrounding redacted context.

### Severity

| Nightfall `risk` | Severity |
| --- | --- |
| `CRITICAL` | Critical |
| `HIGH` | High |
| `MEDIUM` | Medium |
| `LOW` | Low |
| `NO_RISK`, `UNSPECIFIED` | Info |
| anything else, or absent | Info |

**A verified live credential is always Critical**, whatever the policy's risk says — Nightfall marks
a key `ACTIVE` when it successfully authenticated with it and `SIGNATURE_VERIFIED` when it verified
the key's signature, and either means a working secret is sitting somewhere it should not be. The
numeric `riskScore` is recorded as the severity justification rather than driving the grade.

### Status

| Nightfall `state` | Imported as |
| --- | --- |
| `ACTIVE` | active, verified |
| `PENDING` | active, **not** verified |
| `RESOLVED` | inactive, mitigated, verified |
| `EXPIRED` | inactive, **out of scope**, verified |
| absent | inactive, not verified |

A pending violation has not been triaged by anyone yet, so marking it verified would overstate what
Nightfall knows. An expired one is out of scope rather than mitigated: Nightfall can no longer see the
resource, so it can confirm neither that the data is gone nor that it is still there.

### Title and location

The title reads `<what was found> exposed in <integration> (<location>)`. The subject is the kind of
credential the detections identified, falling back to the policy that matched and then to a generic
label — a violation is worth reporting even when Nightfall cannot say what kind of secret it saw. A
credential of unspecified kind is called an `API` credential.

Every integration nests its own metadata block under a different key and describes a location with
different fields, so `location` is a per-integration mapping — a Slack workspace and channel, a
GitHub `org/repo:path`, a Drive name and file, a Jira project and ticket, and so on. GitHub
violations are also the only ones with a code location, so they are the only ones that set
`file_path` and `line`.

Three integrations report a sharing state that makes an exposure external, and it becomes an
`Exposure` line in the description: a Drive permission setting, a Notion page shared externally, and
a GitHub repository that is not private. Following the connector, a repository Nightfall did not call
private is treated as public.

### Sample Scan Data

Sample Nightfall AI scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/nightfall).

The samples are constructed from Nightfall's documented violation and detection schemas and cover
every state, a live credential, an unrecognised risk label, detections keyed by violation id and
nested on the violation, a violation with no metadata block, and one with no creation time. All
detection values are redacted placeholders and all hostnames are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- description
