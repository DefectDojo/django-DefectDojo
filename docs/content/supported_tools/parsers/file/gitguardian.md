---
title: "GitGuardian"
toc_hide: true
---

Import a [GitGuardian](https://www.gitguardian.com/) secret-incidents export.

This exists for organisations that cannot grant GitGuardian API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro GitGuardian connector pulls the
same data over the API; this parser accepts the same data as a file.

### File Types

JSON, from GitGuardian's secret-incidents endpoint:

```
curl -H "Authorization: Token $GITGUARDIAN_API_KEY" "https://api.gitguardian.com/v1/incidents/secrets" > gitguardian.json
```

A bare JSON array of incidents is accepted, as is an object wrapping them under `incidents`,
`results` or `data`.

### One finding per incident

A GitGuardian incident is one distinct exposed credential, however many times it appears. The parser
creates one finding per incident, not per occurrence, and reports the occurrence count in the
description — which is what the connector does.

### No secret value is imported

GitGuardian's incidents endpoint does not return the matched secret, and nothing here reconstructs
one. A test asserts it, so a future change that starts pulling occurrences cannot quietly begin
copying credentials into the DefectDojo database.

### Validity: the useful part

GitGuardian actively checks whether a discovered credential still authenticates, and that verdict is
the most actionable thing it reports. It is spelled out in the description rather than left as a bare
enum value:

| GitGuardian `validity` | Reported as |
| --- | --- |
| `valid` | confirmed still live and actively exploitable |
| `invalid` | the credential no longer authenticates |
| `no_checker`, `not_checked`, `failed_to_check` | unverified — could not be checked automatically, verify manually |

A finding is marked **verified** only when GitGuardian confirmed the credential is `valid`. An
unchecked credential is not evidence either way, so marking it verified would overstate what
GitGuardian knows.

Whether the secret has since been marked revoked in GitGuardian is also reported.

### Severity

GitGuardian's own incident severity: `critical`→Critical, `high`→High, `medium`→Medium, `low`→Low, and
anything unrecognised→Info.

### Mitigation

Every incident is an exposed credential, so the remediation is always the same sequence — revoke and
rotate, remove from the codebase, purge from version-control history, and review the incident in
GitGuardian for the affected locations. The connector hardcodes that text and so does this parser.

### Scan type and deduplication

The scan type is **`GitGuardian - Connectors Import`** — identical to the string the GitGuardian
connector reports, so a customer who uploads an export *and* later enables the connector gets one set
of findings that deduplicate rather than two copies of everything.

Incident ids are stable, so deduplication hashes on `unique_id_from_tool`
(`gitguardian-incident-<id>`) alone. Note this scan type uses the plain `hash_code` algorithm rather
than `unique_id_from_tool_or_hash_code`, matching the connector's configuration.

### Sample Scan Data

Sample GitGuardian scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/gitguardian).

The samples are constructed from GitGuardian's documented secret-incident schema, with generic
incident names and a generic dashboard host. No sample contains a credential-shaped value.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- unique_id_from_tool
