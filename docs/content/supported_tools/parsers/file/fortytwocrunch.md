---
title: "42Crunch"
toc_hide: true
---

Import a [42Crunch](https://42crunch.com/) Security Audit or Conformance Scan report.

This exists for organisations that cannot grant 42Crunch API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro 42Crunch connector pulls the
same data over the API; this parser accepts the same data as a file.

### Two reports, one scan type

42Crunch produces two different reports for the same API, and the connector converts both under a
single scan type:

| Report | What it examines | Imported as |
| --- | --- | --- |
| **Security Audit** | the OpenAPI definition | **static** findings, one per issue occurrence |
| **Conformance Scan** | the running API | **dynamic** findings, one per scan issue |

A file is one or the other, and the shape decides: a scan report has a per-path/method issue tree
under `data.paths`, an audit report has an `index` table and its category sections.

### Give the report the API id

Every identity the connector builds begins with the **API id**, and a downloaded report does not
carry one. Wrap the report to supply it:

```json
{"apiId": "your-api-id", "report": { ... }}
```

`apiId`, `api_id` and `apiID` are all accepted, and the report may sit under `report`, `audit` or
`scan`. An unwrapped report imports fine, but **its findings will not deduplicate against
connector-synced ones**, because the identities differ by that prefix.

### Both reports refer to their strings by integer

Neither report stores its text inline. An audit occurrence's `pointer` is an index into the report's
`index` array; a scan issue's `injectionDescription` and `jsonPointer` are indexes into
`data.index.injectionDescriptions` and `data.index.jsonPointers`. A finding built from the integers
alone would carry no text at all, so each is looked up.

An index that is **out of range resolves to nothing** rather than failing the import. For an audit
occurrence, the identity then keeps the raw index (`.../#99`) — without it, two occurrences of one
issue with no resolvable location would collapse into a single finding.

Scan descriptions are **templates**: each `%s` is filled from `injectionDescriptionParams` in turn,
one substitution per parameter. A template with more placeholders than parameters keeps the leftovers
verbatim.

### Severity

42Crunch grades both report types on one integer scale where **5 is the most severe**:

| `criticality` | Severity |
| --- | --- |
| 5 | Critical |
| 4 | High |
| 3 | Medium |
| 2 | Low |
| 1, 0, out of range, absent | Info |

Criticality 1 is 42Crunch's informational tier.

### Fields worth noting

- **Audit titles prefer the shared issue description; audit bodies prefer the specific one.** That is
  deliberate: the title groups every occurrence of an issue type under one name, while the body says
  what is wrong at this particular location.
- **Titles are truncated to 250 characters** with a trailing ellipsis, as the connector does. The full
  text stays in the description.
- **`file_path`** on an audit finding is the JSON Pointer into the OpenAPI definition — an audit
  finding *is* a place in a definition.
- **A scan issue's own id is a per-scan UUID**, so it is not stable across scans. The identity is the
  operation plus the check index instead, which is the same for the same issue — so rescanning updates
  a finding rather than creating a new one each time.
- **The endpoint is the URL's origin only** (scheme and host, no path): a conformance scan hits many
  paths on one host, and the operation is already in the description and the identity. A URL with no
  scheme, or a host DefectDojo would reject, adds no endpoint — the URL is still in the description.
- **`steps_to_reproduce`** is 42Crunch's own curl command, on scan findings.

### Deduplication

This scan type has **no curated hashcode field list**, so it deduplicates with DefectDojo's default
algorithm — which is what the connector's own findings already do.

### Sample Scan Data

Sample 42Crunch scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/fortytwocrunch).

The samples cover an audit report with all five categories, one issue type firing at two locations, an
out-of-range pointer, a negative pointer, criticality 0, and a group with no description; plus a scan
report with a two-parameter template, a template with no parameters, an unresolvable description, a
zero response status, and a URL that is not a URL. API paths, hosts and identifiers are generic.
