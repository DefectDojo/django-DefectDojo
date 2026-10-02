---
title: "Codacy"
toc_hide: true
---

Import a [Codacy](https://www.codacy.com/) security-items export.

This exists for organisations that cannot grant Codacy API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Codacy connector pulls the same
data over the API; this parser accepts the same data as a file.

### File Types

JSON, from Codacy's security-items search endpoint. The API's `data` envelope is accepted, as is a
bare array of items.

### One endpoint, several scan types

Codacy surfaces the output of several underlying scanners through a single security-items endpoint —
SCA, container scanning and DAST among them — and reports which in each item's `scanType`. This
parser flags a finding from that field rather than assuming:

- **`DAST`** → `dynamic_finding`, since it looked at something running
- everything else (SCA, container, …) → `static_finding`

The scan type, security category and the underlying detector (`Trivy`, `ZAP`, …) are imported as tags
so findings can be filtered by which scanner actually produced them.

### Severity

Codacy's own item priority: `Critical`→Critical, `High`→High, `Medium`→Medium, `Low`→Low, and anything
unrecognised→Info.

### Findings Codacy has already dismissed

An item can be ignored in Codacy with a reason. When that reason is *false positive*, the finding is
imported with `false_p` set, so triaged noise does not go back in front of the team. Any other ignore
reason — "acceptable risk", for instance — is **not** treated as a false positive: that is a real
finding somebody accepted.

### Fields worth noting

- **Component** — the vulnerable package is the **last** entry of the first non-empty dependency
  chain, not the first. The first entry is the project itself, so taking it would name the application
  as the vulnerable component on every SCA finding. The full path is written into the description.
- **CVE** — Codacy's `cve` is a typed string documented as possibly holding several identifiers, so it
  is scanned for all of them and deduplicated. `vuln_id_from_tool` takes the first, falling back to
  Codacy's own `itemSourceId` when there is no CVE at all.
- **CWE** — parsed from the first `CWE-<number>` in the field; anything unparseable leaves it at 0.
- **Target** — a DAST item's scanned application, falling back to `affectedTargets` (which is where a
  container item names its image).
- **Date** — Codacy's `openedAt`. The connector falls back to today when the timestamp will not parse,
  so a finding always carries a date; that is mirrored here rather than corrected.

### Scan type and deduplication

The scan type is **`Codacy - Connectors Import`** — identical to the string the Codacy connector
reports, so a customer who uploads an export *and* later enables the connector gets one set of findings
that deduplicate rather than two copies of everything.

Identity is Codacy's internal item id, carried as `unique_id_from_tool`.

### Sample Scan Data

Sample Codacy scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/codacy).

The samples are constructed from Codacy's documented security-item schema, covering an SCA, a DAST and
a container item, with generic package names, a generic host and placeholder CVE identifiers.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- vuln_id_from_tool
