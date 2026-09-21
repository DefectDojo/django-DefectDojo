---
title: "DeepSource"
toc_hide: true
---

Import a [DeepSource](https://deepsource.com/) export.

This exists for organisations that cannot grant DeepSource API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro DeepSource connector pulls the
same data over the API; this parser accepts the same data as a file.

### File Types

JSON — a **saved GraphQL response**. DeepSource has no REST API; everything goes through
`POST /graphql/`, so the file to upload is whatever that endpoint returned:

```
curl -H "Authorization: Bearer $DEEPSOURCE_TOKEN" -H "Content-Type: application/json"   -d '{"query": "query { repository(login: \"org\", vcsProvider: GITHUB, name: \"repo\") { issueOccurrences(first: 100) { edges { node { id path beginLine endLine title issue { shortcode title shortDescription category severity analyzer { name shortcode } } } } } analysisRuns(first: 1) { edges { node { runUid createdAt finishedAt } } } } }"}'   https://api.deepsource.io/graphql/ > deepsource.json
```

The response is wrapped in `data.repository`, with each collection behind a GraphQL
connection (`edges[].node`):

```json
{"data": {"repository": {
  "analysisRuns": {"edges": [{"node": {"runUid": "...", "finishedAt": "..."}}]},
  "issueOccurrences": {"edges": [{"node": {"id": "...", "path": "...", "issue": {...}}}]},
  "dependencyVulnerabilityOccurrences": {"edges": [{"node": {...}}]}}}}
```

Both of DeepSource's queries return that same repository envelope, so one file may carry
**issue occurrences**, **dependency vulnerabilities**, or both. The `data` wrapper may be omitted if
you saved just the repository object.

DeepSource reports two different things and they are mapped differently:

- **Analysis issue occurrences** (`issueOccurrences`) — static issues found in the code
- **Dependency vulnerabilities** (`dependencyVulnerabilityOccurrences`) — advisories against your
  dependencies

The latest `analysisRuns` entry dates the issue findings.

### Severity: two ladders, because the category decides

DeepSource grades **every** issue `CRITICAL`, `MAJOR` or `MINOR` regardless of what the issue actually
is — a missing docstring can be `MAJOR`. So the category decides which ladder applies:

| Category | `CRITICAL` | `MAJOR` | `MINOR` |
| --- | --- | --- | --- |
| `SECURITY` | Critical | High | Medium |
| `BUG_RISK`, `PERFORMANCE`, `TYPECHECK`, `ANTI_PATTERN` | High | Medium | Low |
| `STYLE`, `DOCUMENTATION`, `COVERAGE` | Info | Info | Info |
| anything else | Info | Info | Info |

A security issue keeps its grade; a bug-risk issue drops a step, because it describes a defect rather
than a weakness. Applying one ladder to both would either inflate every lint finding or bury the real
ones.

**A hit from the `secrets` analyzer is Critical whatever DeepSource graded it** — a committed
credential is a committed credential.

### Dependency advisories

A separate mapping, since these carry a CVE, a component and a score that analysis issues do not:

- **Severity** — the CVSS v3 band when the advisory is scored (≥9.0 Critical, ≥7.0 High, ≥4.0 Medium,
  otherwise **Low**; a scored advisory is never Info). Unscored, its `cvssV3Severity` then `severity`
  word decides, accepting GitHub's `MODERATE` spelling of medium.
- **Identifiers** — the advisory id followed by its aliases, upper-cased and deduplicated, so a CVE
  and its GHSA both land on the finding.
- **Mitigation** — the fixed versions offered as alternatives, or an explicit note that none has been
  published. "No fix published" is useful triage information; an empty field just reads as unfinished.
- **Reachability and fixability** — imported into the description when DeepSource supplies them.

### Scan type and deduplication

The scan type is **`DeepSource - Connectors Import`** — identical to the string the DeepSource
connector reports, so a customer who uploads an export *and* later enables the connector gets one set
of findings that deduplicate rather than two copies of everything.

Identity is the occurrence or vulnerability id, carried as `unique_id_from_tool`.

### Sample Scan Data

Sample DeepSource scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/deepsource).

The samples are real GraphQL response envelopes — `data.repository` with `edges[]`/`node` connections —
built from DeepSource's documented schema. They cover both severity ladders, the secrets-analyzer
override, and both scored and unscored advisories, with generic file paths and placeholder advisory
identifiers. A test pins the envelope shape, because an earlier draft of this parser read an invented
flat `{"occurrences": [...]}` structure that no DeepSource user could have produced.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- file_path
