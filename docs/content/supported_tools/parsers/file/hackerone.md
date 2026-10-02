---
title: "HackerOne"
toc_hide: true
---

Import a [HackerOne](https://www.hackerone.com/) reports export.

This exists for organisations that cannot grant HackerOne API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro HackerOne connector pulls the
same data over the API; this parser accepts the same data as a file.

### File Types

JSON, from HackerOne's reports endpoint:

```
curl -u "$H1_USER:$H1_TOKEN" "https://api.hackerone.com/v1/reports?filter%5Bprogram%5D%5B%5D=your-program" > hackerone.json
```

HackerOne's API is **JSON:API**, so the reports arrive under `data` and severity, weakness and
reporter are **relationships**, not attributes — each nested under
`relationships.<name>.data.attributes`. Reading them off the top level, or off `attributes`, would
leave every finding at Info with no CWE and no reporter. An already-flattened export is accepted too,
for anyone exporting through a script.

One finding per report.

### Severity

The severity relationship's `rating`: `critical`→Critical, `high`→High, `medium`→Medium, `low`→Low.
HackerOne also reports a rating of `none`, which is not a DefectDojo severity and falls through to
Info along with anything else unrecognised. The comparison is case-insensitive.

The severity relationship's CVSS `score` is imported when HackerOne attached one above zero.

### Fields worth noting

- **CWE** — parsed from the weakness relationship's `external_id`, which HackerOne lower-cases as
  `cwe-<n>`. Not every HackerOne weakness maps to a CWE (some are CAPEC), and those leave the CWE at 0.
- **The report link is always present**, in both `url` and the description, even for a report with no
  prose at all — a bug-bounty finding is not actionable without a way back to the report and its
  comment thread.
- **`vuln_id_from_tool` and `unique_id_from_tool` are both the report id**, which is what the
  connector does.

### Scan type and deduplication

The scan type is **`HackerOne - Connectors Import`** — identical to the string the HackerOne connector
reports, so a customer who uploads an export *and* later enables the connector gets one set of
findings that deduplicate rather than two copies of everything.

Report ids are globally unique on the platform, so deduplication uses the plain `hash_code` algorithm
over `unique_id_from_tool` alone.

### Sample Scan Data

Sample HackerOne scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/hackerone).

The samples are constructed from HackerOne's documented JSON:API report schema, covering a report with
full relationships, one with a `none` rating, one whose weakness is not a CWE, and one with no
relationships at all. Researcher usernames are generic placeholders.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- unique_id_from_tool
