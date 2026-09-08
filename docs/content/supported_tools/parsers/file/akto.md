---
title: "Akto"
toc_hide: true
---

Import an [Akto](https://www.akto.io/) API-security export.

This exists for organisations that cannot grant Akto API credentials — air-gapped networks, procurement
restrictions, a pending security review. The DefectDojo Pro Akto connector pulls the same data over the
API; this parser accepts the same data as a file.

### File Types

JSON — the `fetchIssuesFromCollections` response, with rows under `issueDetails`. A bare array of issues
is accepted too.

### One finding per endpoint per test

Akto runs every test against every endpoint it knows, so neither alone identifies a finding. The
identity is `akto-<collection>-<method>-<url>-<test sub-category>`, and **both** the endpoint and the
test are in this scan type's deduplication hash: the same test against two paths is two findings, and
two different tests against one path are as well.

Akto has no package to report, so `component_name` is **`<METHOD> <url>`** — the tested endpoint. That
is what the component slot of the hash means here.

### Severity

| Akto `severity` | Severity |
| --- | --- |
| `CRITICAL` | Critical |
| `HIGH` | High |
| `MEDIUM` | Medium |
| `LOW` | Low |
| `INFO`, or anything unrecognised | Info |

Read case-insensitively.

### Status

| Akto `status` | Imported as |
| --- | --- |
| `IGNORED` | inactive, **false positive** |
| `FIXED` | inactive |
| anything else | active |

`IGNORED` is how a reviewer marks a false positive in Akto. `FIXED` is inactive but **not** flagged as a
false positive — "fixed" is not a judgement about whether the finding was real.

### A relative path is not an endpoint

Akto's `apiUrl` is often just a path (`/v1/reports`). The connector records an endpoint only for an
absolute URL, rather than inventing a host, and this parser does the same. The path is still the
component and appears in the description, so nothing is lost.

### Fields worth noting

- **CWE** is read from `CWE-639` or a bare `639`; anything else leaves it unset.
- **Vulnerability identifiers** come from Akto's free-text `testCve`, sorted and deduplicated
  case-insensitively — an API-security test usually has none, but a dependency-related one may name
  several.
- **References** are Akto's own issue link, then the test's reference links.
- **Dates** are unix seconds; a zero keeps DefectDojo's default of today.

### Sample Scan Data

Sample Akto scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/akto).

The samples are constructed from Akto's documented issue shape and cover a full BOLA finding, a relative
path, a collection id sent as a string, duplicate CVEs in mixed case, an ignored issue, a fixed one, an
unrecognised severity, an unparseable CWE, and an issue with no name, method or path at all. Hostnames
are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- endpoints
- vuln_id_from_tool
