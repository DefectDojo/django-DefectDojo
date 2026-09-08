---
title: "Datadog Cloud Security"
toc_hide: true
---

Import a [Datadog Cloud Security](https://www.datadoghq.com/product/cloud-security-management/)
findings export.

This exists for organisations that cannot grant Datadog API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Datadog connector pulls the
same data over the API; this parser accepts the same data as a file.

### File Types

JSON — the `/api/v2/posture_management/findings` response, with rows under `data`. A bare array of
rows, or a single row, is accepted too.

Note the attributes are nested **twice**: `data[].attributes.attributes` holds the finding itself,
while the outer `attributes` object carries the row's tags and timestamp. Reading the outer object as
the finding yields nothing.

### One endpoint, several kinds of finding

Datadog returns everything it calls a security finding through that one endpoint —
misconfigurations, library and code vulnerabilities, attack paths, identity risks, API security —
distinguished only by `finding_type`. So **static versus dynamic is decided per row, not per file**:

| `finding_type` | Imported as |
| --- | --- |
| `runtime_code_vulnerability`, `api_security`, `attack_path`, `workload_activity`, `identity_risk` | dynamic |
| everything else | static |

A runtime finding is something Datadog watched happen; everything else is something it read from a
configuration or an inventory.

### Findings Datadog has already dealt with are skipped

Three independent signals, all honoured — otherwise a queue somebody has already triaged comes
straight back:

- `status` of `muted`, `resolved` or `auto_closed`
- an explicit `workflow.mute.is_muted`
- for a compliance rule, `compliance.evaluation` of `pass` — a passing rule is the tool reporting that
  nothing is wrong

A **failing** evaluation is imported and appears in the description.

### Severity

| Datadog `severity` | Severity |
| --- | --- |
| `critical` | Critical |
| `high` | High |
| `medium` | Medium |
| `low` | Low |
| anything else | Info |

`base_severity` is deliberately **not** consulted: it is the rule's default before Datadog adjusts for
the environment, and the adjusted `severity` is the one worth importing.

### Fields worth noting

- **Dates are unix milliseconds**, not seconds — `first_seen_at`, falling back to
  `detection_changed_at`. Reading them as seconds would date every finding in 1970. A row with
  neither keeps DefectDojo's default of today.
- **CVSS** comes from `severity_details.base`, falling back to `.adjusted`. The first block carrying
  either a vector or a positive score supplies **both** values — mixing a vector from one with a score
  from the other would describe a scoring that never existed.
- **Vulnerability identifiers** come from the advisory (its CVE and aliases) *and* from the title and
  description, because Datadog names them in the prose for some finding types and only in the advisory
  object for others. The recognised forms are CVE, GHSA, Go (`GO-YYYY-N`) and RHSA.
- **Service** is read out of Datadog's own `service:` tag.
- **Tags are deduplicated but not sorted.** The connector preserves the order it built them in;
  sorting would be tidier and wrong, since a tag list that reorders on every sync reads as a change.

### Sample Scan Data

Sample Datadog scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/datadog).

The samples are constructed from Datadog's documented findings response and cover a library
vulnerability with full CVSS and advisory data, a failing compliance rule, an API-security finding with
no row id, an unrecognised severity, and one row for each of the five ways Datadog says a finding is
not actionable. Hostnames, account identifiers and resource names are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
