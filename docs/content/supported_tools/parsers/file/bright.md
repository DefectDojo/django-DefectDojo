---
title: "Bright Security"
toc_hide: true
---

Import a [Bright Security](https://brightsec.com/) scan export.

This exists for organisations that cannot grant Bright API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Bright connector pulls the same
data over the API; this parser accepts the same data as a file.

### File Types

JSON. Bright's issues endpoint answers with a **bare array**, so an export is either that array or an
object carrying it — `{"issues": [...]}`, `{"items": [...]}`, or a scan object with the issues nested
under `scan`/`data`.

### Severity

| Bright `severity` | Severity |
| --- | --- |
| `Critical` | Critical |
| `High` | High |
| `Medium` | Medium |
| `Low` | Low |
| anything else | Info |

Read case-insensitively. The CVSS score is recorded when Bright reports a non-zero one, and may arrive
as a number or a numeric string.

### Deduplication hashes the endpoint

This scan type's configuration pairs `unique_id_from_tool_or_hash_code` with a field set that
**includes `endpoints`**, so an endpoint is always recorded: the entry point Bright attacked, falling
back to **every** affected resource. The fallback is a list because Bright reports one issue against
several resources when the same weakness is reachable from more than one URL.

An entry point that DefectDojo will not accept as a host is left out of the endpoints — an unusable host
fails the whole import rather than the one finding — but it still appears in the description.

### The request and response are fenced, not rendered

Both are raw HTTP captured from the target, so they go in fenced code blocks: they must not be read as
markup, and a reviewer needs them verbatim to reproduce the issue.

### Fields worth noting

- **CWE** is read from `CWE-79` or a bare `79`. An unparseable value leaves the CWE unset but still
  appears in the description.
- **References** are the affected resources, one per line.
- **Mitigation** is Bright's own remediation text, left unset when it has none.
- **Every finding is active, dynamic and not static** — Bright attacks a running application.

### Sample Scan Data

Sample Bright Security scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/bright).

The samples are constructed from Bright's documented scan and issue shape and cover a full issue with
request and response, a score sent as a string, a bare CWE number, an unparseable CWE, an unrecognised
severity, an issue with no entry point (so the resources are used), an issue with several resources, and
an entry point that cannot be a host. Hostnames are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- endpoints
