---
title: "Dalfox"
toc_hide: true
---
Import Dalfox reports in JSON format. The parser accepts both the v2 array of results (including
its trailing empty object) and the v3 object containing a `findings` list and scan `meta`.
An empty findings list imports no Findings. JSONL is not supported.

Generate a v3 report with:

```bash
dalfox scan <target> -f json -o report.json
```

For v2, use:

```bash
dalfox url <target> --format json -o report.json
```

Each result becomes one Finding, recording the parameter, payload, evidence and proof-of-concept
URL. The report's `type_description` is used when available; otherwise a label for the result type
is used. The v3 fields `detection_method`, `location`, `confidence` and `confidence_reason` are
included in the description when present. Scan metadata is not imported as a Finding.

The proof-of-concept URL becomes the Finding's location, with the query string dropped: it holds
the payload, which differs on every attempt. The payload itself is on the Finding.

### Result Types and Severity

| Type | v2 | v3 |
| --- | --- | --- |
| `V` | Verified payload execution | Vulnerable: Dalfox asserts the input is exploitable |
| `R` | Reflected payload, not verified | Reflected payload, exploitability needs confirmation |
| `G` | Matched a configured grep pattern | Not used |
| `A` | Not used | DOM XSS detected by static JavaScript analysis |
| `I` | Not used | Informational observation, such as an outdated JavaScript library |

Dalfox v3 has no headless browser. Its `V` label does not mean it observed the payload executing
in a browser. The detection method and evidence explain how the finding was produced.

Severity is taken directly from the report, independently of its type. Critical, High, Medium,
Low and Info map to the same DefectDojo severities. Missing or unrecognized severities retain the
legacy default of Medium. An `I` library advisory can therefore have a severity above Info.

CWE comes from Dalfox's `cwe` field: typically CWE-79 for XSS and CWE-1104 for outdated libraries.
A library advisory keeps the report's message as its title and does not acquire a fake parameter
or payload.

### Sample Scan Data
Sample Dalfox scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/dalfox).
The `v3_*.json` samples were generated with Dalfox 3.3.0 against a local Python HTTP server:
a clean page, a page referencing jQuery 1.7.2, and a page reflecting a query parameter with an
inline `document.write(location.hash)` flow and the same library reference.

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
- endpoints

Existing v2 identities are unchanged. Repeated payloads for the same type, injection point,
parameter and endpoint can deduplicate together. The parameter is stored as the component name.
For v3 informational findings without a parameter, the advisory title is used as the component
name so different library advisories on one endpoint remain distinct.
