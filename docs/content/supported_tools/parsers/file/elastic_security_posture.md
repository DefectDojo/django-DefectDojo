---
title: "Elastic Security Posture"
toc_hide: true
---

Import an [Elastic Security](https://www.elastic.co/security) export and report the cloud and
Kubernetes benchmark rules that failed evaluation.

This exists for organisations that cannot grant Elasticsearch API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Elastic Security connector
pulls the same data over the API; this parser accepts the same data as a file.

### Three scan types, three parsers

Elastic returns CNVM vulnerabilities, posture evaluations and detection alerts from the **same**
`_search` API. The connector imports them under three scan types, each behind its own toggle and with
its own deduplication key, so there are three parsers to match — see the Elastic Security CNVM page
for the table. **This parser imports documents carrying a `rule` whose `result.evaluation` is
`failed`.**

### File Types

JSON — an Elasticsearch search response (`{"hits": {"hits": [...]}}`). A bare array of documents and a
single document are accepted too.

### Only failed evaluations are imported

Elastic writes a document for every rule evaluation, passed or failed. A passing rule is not a
finding, and a rule with no name has nothing to report, so both are skipped. The evaluation is read
case-insensitively.

### Severity

Elastic's own `rule.severity` label is used when it is one of `critical`, `high`, `medium`, `low`,
`informational`, `info`, `none` or `unknown`. Anything else — including an absent label — becomes
**Medium**, not Info: a posture document has no score to fall back on, and a failing benchmark rule is
a real finding whatever Elastic called its severity.

### Fields worth noting

- **Identity** is the Elasticsearch document id, which is stable across syncs. Without one, the asset
  and the rule stand in, which keeps the same rule failing on two assets apart.
- **`vuln_id_from_tool`** is the rule id, which is what this scan type's deduplication hash keys on
  instead of a component — a benchmark rule is not about a package. Elastic's cloud benchmarks do not
  always carry a rule id, so the benchmark's own numbering (`<benchmark>:<rule number>`) stands in
  before the rule name does.
- **The benchmark** is recorded as the component, with its version.
- **A repeated rationale is not printed twice.** Elastic often copies the rationale into the
  description; printing the same paragraph twice reads as a rendering error.
- **The impact of remediating** is included — Elastic documents the cost of the fix, and it belongs
  with the finding rather than being dropped.

### Sample Scan Data

Sample Elastic Security scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/elastic_security_posture).

The samples are constructed from Elastic's documented posture document shape and cover a Kubernetes
benchmark rule, a cloud benchmark rule with no rule id, an uppercase `FAILED`, a passing rule, an
unnamed rule, and a rule whose description repeats its rationale. They also include CNVM and detection
documents, which this parser must ignore. Hostnames and account identifiers are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- vuln_id_from_tool
