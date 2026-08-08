---
title: "Probely"
toc_hide: true
---

Import a [Probely](https://probely.com/) findings export.

This exists for organisations that cannot grant Probely API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Probely connector pulls the same
data over the API; this parser accepts the same data as a file.

### File Types

JSON, from Probely's findings endpoint. The API's `results` envelope is accepted, as is a bare array
of findings.

### Scan type

The scan type is **`Probely API Import`** — identical to the string the Probely connector reports.
Note it does **not** follow the `<Vendor> - Connectors Import` pattern the other connector scan types
use, so it cannot be guessed from the vendor name. Matching it exactly is what lets a customer upload
an export *and* enable the connector without getting two copies of every finding.

### Findings Probely has closed out are not imported

Probely records a state per finding, and three of them mean the finding is done with:

| State | Imported? |
| --- | --- |
| `fixed` | no — resolved |
| `invalid` | no — judged not a real issue |
| `accepted` | no — risk accepted |
| `retesting` | **yes** |
| anything else | yes |

`retesting` is deliberately imported. A re-test means somebody is actively working the issue, so it is
assumed still open; skipping it would drop live findings whenever a re-test was queued.

### Severity

Probely reports severity as an **integer**, and only three values exist:

| Probely `severity` | Severity |
| --- | --- |
| `30` | High |
| `20` | Medium |
| `10` | Low |
| anything else | Info |

There is no Critical. The integer is not a score and not an index — treating it as either would
misgrade every finding.

### Deduplication hashes the endpoint

This scan type's configuration pairs the plain `hash_code` algorithm with a wide field set that
**includes `endpoints`**. The parser therefore always records the scanned origin (scheme, host and
port, reduced from the finding URL as the connector does). If the endpoint were left unpopulated the
hash would be computed over nothing and every rescan would reimport.

### Fields worth noting

- **Insertion point** — rendered as a readable label, so `url_query` becomes `**URL Query:**`. The
  acronym fixes (`URL`, `JSON`, `GraphQL`) are the connector's; plain title casing gives "Url" and
  "Json".
- **Mitigation** — Probely's `fix` text and its `extra` notes, joined with a newline exactly as the
  connector joins them.
- **CWE** — read from the finding definition's `cwe_id` when the export carries one. The connector
  fetches this separately per definition, so an export without it leaves the CWE at 0.
- **Description** — Probely names the definition's prose field `desc`, not `description`.

### Sample Scan Data

Sample Probely scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/probely).

The samples are constructed from Probely's documented findings schema, covering all three severity
integers, each of the closed-out states, and a finding under re-test, with a generic scanned host.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
- severity
- vuln_id_from_tool
- unique_id_from_tool
- endpoints
- cwe
- mitigation
