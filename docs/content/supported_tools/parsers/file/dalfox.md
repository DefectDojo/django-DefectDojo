---
title: "Dalfox"
toc_hide: true
---
Import Dalfox reports in JSON format. Dalfox is an XSS scanner: it finds injectable parameters,
fires payloads at them and reports what came back.

Generate a report with:

```
dalfox url https://example.com/?q=test --format json -o dalfox.json
```

Each result becomes one Finding, recording the injectable parameter, the payload used, the evidence
Dalfox saw reflected and the proof-of-concept URL. The proof-of-concept URL becomes the Finding's
location, with the query string dropped: it holds the payload, which differs on every attempt, so
keeping it would make every payload look like a different endpoint. The payload itself is on the
Finding.

Dalfox tries many payloads against one parameter and reports each attempt separately. All of them
are imported, and deduplication then folds them together on the parameter and the endpoint, so a
parameter that took forty payloads becomes one Finding with the rest recorded as duplicates. The
parameter is stored as the component name, which is what keeps two parameters on the same URL apart.

Note that Dalfox terminates its JSON array with an empty object. That is not a result and is
skipped.

### Severity Mapping
Dalfox sets a severity on every result, derived from how strong its evidence is, and that is used
directly:

| Dalfox severity | Result type | DefectDojo severity |
| --- | --- | --- |
| High | `V` — verified, the payload executed in a browser | High |
| Medium | `R` — reflected, the payload came back unencoded but was not verified | Medium |
| Low | `G` — grep, a configured pattern matched | Low |
| Critical / Info | as reported | Critical / Info |

The distinction between `V` and `R` is the useful one and is preserved in both the severity and the
description: a verified result is a demonstrated XSS, while a reflected result is a strong
indication that still needs a human to confirm exploitability in context. The result type is also
part of `vuln_id_from_tool`, so the two never deduplicate into each other.

CWE comes from Dalfox's own `cwe` field, which is CWE-79 for its XSS findings.

### Sample Scan Data
Sample Dalfox scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/dalfox).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
- endpoints
