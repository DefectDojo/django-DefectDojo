---
title: "Quay"
toc_hide: true
---

Import a [Quay](https://quay.io/) container security report.

This exists for organisations that cannot grant Quay API credentials — air-gapped networks, procurement
restrictions, a pending security review. The DefectDojo Pro Quay connector pulls the same data over the
API; this parser accepts the same data as a file.

### File Types

JSON, from Quay's image security endpoint. Quay's scanner is **Clair**, so the report nests
vulnerabilities under the *features* (packages) they affect, and the keys are **capitalised**:

```json
{"status": "scanned", "data": {"Layer": {"Features": [
  {"Name": "openssl", "Version": "3.0.11-1", "Vulnerabilities": [{"Name": "CVE-...", "Severity": "High"}]}
]}}}
```

A bare `Layer` object and a bare `Features` list are also accepted. One finding is created per
**feature/vulnerability pair**, so a package with three advisories produces three findings.

If the export carries a top-level `tag`, it is reported as the image tag — Clair's output does not
include it, and the connector supplies it from the tag it scanned.

### Severity

Clair's severity word, with one addition worth knowing: **Clair grades `Defcon1` above `Critical`**,
and DefectDojo has nothing higher, so both map to Critical. Not mapping it would drop Clair's most
severe grade to Info.

| Clair `Severity` | Severity |
| --- | --- |
| `Defcon1`, `Critical` | Critical |
| `High` | High |
| `Medium` | Medium |
| `Low` | Low |
| `Negligible`, `Unknown`, anything else | Info |

### Fields worth noting

- **Impact is always `No impact provided`.** Clair supplies no impact assessment, and the connector
  states that rather than leaving the field blank.
- **The identity is the advisory id concatenated with the feature name, with no separator**
  (`CVE-2000-0001openssl`). That is exactly what the connector builds; inserting a separator here
  would give every finding a different tool id from the connector's and break the merge.
- **The fix, namespace and CVE lines appear even when empty**, because the connector writes them
  unconditionally — a file import has to read the same way as an API sync for the same finding.
- **Advisory text is flattened, never rendered.** Clair advisory text comes from upstream distro
  trackers; `script`/`style` content is dropped, block tags become newlines, and the result is escaped
  with Go's entity spellings.

### Scan type and deduplication

The scan type is **`Quay - Connectors Import`** — identical to the string the Quay connector reports, so
a customer who uploads an export *and* later enables the connector gets one set of findings that
deduplicate rather than two copies of everything.

### Sample Scan Data

Sample Quay scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/quay).

The samples are constructed from Quay's documented Clair-shaped report and cover a feature with two
advisories, a `Defcon1` grade, an advisory containing markup, one with no fix or namespace, an
unrecognised severity, and a feature with no vulnerabilities at all. Package names, digests and hosts
are generic placeholders.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
- component_version
