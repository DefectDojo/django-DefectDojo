---
title: "Socket"
toc_hide: true
---

Import a [Socket](https://socket.dev/) full-scan artifact export.

This exists for organisations that cannot grant Socket API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Socket connector pulls the same
data over the API; this parser accepts the same data as a file.

### File Types

JSON. Export the artifacts of a full scan from the Socket API or UI, for example:

```
curl -H "Authorization: Bearer $SOCKET_TOKEN"   "https://api.socket.dev/v0/orgs/<org>/full-scans/<full_scan_id>" > socket.json
```

A bare JSON array of artifacts is accepted, as is an object wrapping them under `artifacts` or
`results`.

One finding is created per **alert**, so an artifact carrying several alerts produces several findings.

### Scan type and deduplication

The scan type is **`Socket - Connectors Import`** — identical to the string the Socket connector
reports. That is deliberate: a customer who uploads an export *and* later enables the connector gets one
set of findings that deduplicate, rather than two copies of everything.

Deduplication identity is the Socket alert key, carried as `unique_id_from_tool`, matching the
connector's `UniqueIDFromTool`.

### Severity

Socket grades alerts `low`, `middle`, `high`, `critical` — note **`middle`**, not `medium`. The mapping
mirrors the connector's: `critical`→Critical, `high`→High, `middle`/`medium`→Medium, `low`→Low, and
anything unrecognised→Info.

### Sample Scan Data

Sample Socket scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/socket).

The samples are constructed from Socket's documented full-scan artifact schema and the shapes the
connector's own converter tests exercise, with generic package scopes.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
