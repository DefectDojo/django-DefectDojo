---
title: "Escape"
toc_hide: true
---

Import an [Escape](https://escape.tech/) API-security scan export.

This exists for organisations that cannot grant Escape API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Escape connector pulls the same
data over the API; this parser accepts the same data as a file.

### File Types

JSON. Escape nests issues under the scan that produced them, and the connector reads an application's
**latest** scan, so all of these are accepted:

- a scan: `{"issues": [...]}`
- an application carrying one: `{"lastScan": {"issues": [...]}}` (or `scan`)
- an applications response: `{"applications": [{"lastScan": {"issues": [...]}}]}`
- the issue list itself: `[...]`

### Severity

| Escape `severity` | Severity |
| --- | --- |
| `critical` | Critical |
| `high` | High |
| `medium` | Medium |
| `low` | Low |
| `info` | Info |
| anything else | Info |

Escape rates by OWASP API category and a severity word; an unrecognised label becomes Info rather than
a guess.

### Deduplication hashes the endpoint

This scan type's configuration pairs `unique_id_from_tool_or_hash_code` with a field set that
**includes `endpoints`**, so the parser always records the tested URL — scheme, host, port, path and
query. An unpopulated endpoint would leave the hash computed over nothing and every rescan would
reimport.

The description's endpoint line carries the **method** alongside the URL (`POST https://…`) when Escape
reported one, because the same URL behaves differently per verb — which is the point of an API
scanner. The method also becomes an uppercased `method:` tag, while the description keeps Escape's own
casing, matching the connector.

### Fields worth noting

- **CWE** is read from `CWE-89` or a bare `89`. An unparseable value leaves the CWE unset but still
  appears in the description, so nothing is lost.
- **Mitigation** is Escape's own remediation text and is left unset when it has none, rather than
  filled with generic advice.
- **Every finding is active, dynamic and not static** — Escape exercises a running API.

### Sample Scan Data

Sample Escape scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/escape).

The samples are constructed from Escape's documented scan and issue shape and cover a full issue with
CWE and remediation, a bare CWE number, an unparseable CWE, an unrecognised severity, an issue with no
method, an issue with no URL at all, and both the scan and application export shapes. Hostnames are
generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- endpoints
