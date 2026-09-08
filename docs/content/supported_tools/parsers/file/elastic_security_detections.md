---
title: "Elastic Security Detections"
toc_hide: true
---

Import an [Elastic Security](https://www.elastic.co/security) export and report its detection-engine
alerts.

This exists for organisations that cannot grant Elasticsearch API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Elastic Security connector
pulls the same data over the API; this parser accepts the same data as a file.

### Three scan types, three parsers

Elastic returns CNVM vulnerabilities, posture evaluations and detection alerts from the **same**
`_search` API. The connector imports them under three scan types, each behind its own toggle and with
its own deduplication key, so there are three parsers to match — see the Elastic Security CNVM page
for the table. **This parser imports documents carrying an alert**, under either `kibana.alert` (the
current detection engine) or a top-level `signal` object (the older one); an export taken from an
existing index may carry either.

### File Types

JSON — an Elasticsearch search response (`{"hits": {"hits": [...]}}`). A bare array of documents and a
single document are accepted too.

### A detection is not a defect

Detections describe observed activity rather than a fixable weakness. Two consequences, both the
connector's:

- Findings are imported as **neither static nor dynamic** — no test found them; a rule matched a
  stream of events.
- The mitigation is a **triage instruction**, not a fix. Closing a detection means completing an
  investigation, and saying so keeps a triage queue from being read as a remediation backlog.

### Severity

The alert's own `severity` is used, falling back to the rule's. Recognised values are `critical`,
`high`, `medium`, `low`, `informational`, `info`, `none` and `unknown`; anything else — including an
absent label — becomes **Medium**.

Elastic's `risk_score` is a 0-100 scale rather than a severity, so it is reported in the description
instead of being converted into one. It is taken from the alert, falling back to the rule that raised
it.

### Fields worth noting

- **Title** is the detection rule's name, falling back to the alert's own reason. An alert with
  neither says nothing and is skipped.
- **Identity** is the Elasticsearch document id, falling back to the alert uuid.
- **`vuln_id_from_tool`** is the rule uuid, which is what this scan type's deduplication hash keys on:
  it groups repeated firings of the same rule.
- **The workflow status** Elastic holds for the alert (`open`, `acknowledged`, `closed`) is recorded in
  the description. It is deliberately not mapped onto the finding's own status — the connector leaves
  DefectDojo's triage to DefectDojo.
- **Event categories** and rule tags become finding tags, so a detection can be filtered by what it
  was about.

### Sample Scan Data

Sample Elastic Security scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/elastic_security_detections).

The samples are constructed from Elastic's documented alert shape and cover a `kibana.alert` document
with a full rule, a legacy `signal` document with an unrecognised severity and a risk score sent as a
string, and an alert with neither a rule name nor a reason. They also include CNVM and posture
documents, which this parser must ignore. Hostnames and account identifiers are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- vuln_id_from_tool
