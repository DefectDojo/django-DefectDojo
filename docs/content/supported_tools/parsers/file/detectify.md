---
title: "Detectify"
toc_hide: true
---

Import a [Detectify](https://detectify.com/) vulnerabilities export.

This exists for organisations that cannot grant Detectify API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Detectify connector pulls the
same data over the API; this parser accepts the same data as a file.

### File Types

JSON, from Detectify's vulnerabilities endpoint. The API's `vulnerabilities` envelope is accepted, as
is a bare array.

### Scan type

The scan type is **`Detectify Scan`** — identical to the string the Detectify connector reports. Note
it does **not** follow the `<Vendor> - Connectors Import` pattern the other connector scan types use,
so it cannot be guessed from the vendor name. Matching it exactly is what lets a customer upload an
export *and* enable the connector without getting two copies of every finding.

### Which findings are imported

| Detectify `status` | Imported? |
| --- | --- |
| `patched` | no — resolved |
| `false_positive` | no — dismissed |
| `accepted_risk` | **yes**, flagged `risk_accepted` |
| anything else | yes |

An accepted risk is deliberately kept rather than skipped: discarding it would lose the record that
somebody accepted the risk. It is imported and flagged instead.

### Severity

Detectify's own severity word: `critical`→Critical, `high`→High, `medium`→Medium, `low`→Low, and
`information` / `info` / `informational`→Info. Anything unrecognised becomes Info.

### CVSS

Detectify reports separate 2.0, 3.0 and 3.1 blocks. The **3.1** block is preferred, falling back to
**3.0**; the 2.0 block is ignored, because `cvssv3` is a v3 field and putting a v2 vector in it would
be wrong. A block counts as present when it carries either a score *or* a vector, so a vector-only
entry is not discarded.

### CVE identifiers come from prose

Detectify has no dedicated CVE field. Identifiers are extracted from the finding title, the
definition's title, description and risk text, and every reference name and link — then deduplicated
in order. That is what the connector does.

### Fields worth noting

- **Impact** — the definition's `risk` text, which is Detectify's description of what an attacker
  gains.
- **Mitigation** — Detectify supplies no remediation prose, only reference links, so the finding
  points at them rather than leaving the field empty.
- **CWE** — reported by Detectify as a plain integer, not a `CWE-<n>` string.
- **`vuln_id_from_tool`** — the definition's title, which is Detectify's stable rule name.
- **Endpoint** — the request URL where there is one; otherwise the host, with the location appended
  only when it starts with `/` (otherwise it is not a path and concatenating it would produce a
  nonsense host); otherwise the location alone.

### Sample Scan Data

Sample Detectify scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/detectify).

The samples are constructed from Detectify's documented vulnerability schema, covering all three CVSS
blocks with deliberately different values, each of the closed-out statuses, an accepted risk, and each
branch of the endpoint preference order, with generic hosts and placeholder CVE identifiers.

### Default Deduplication Hashcode Fields

Detectify findings carry a stable uuid, which is imported as `unique_id_from_tool` and used as the
primary deduplication identity. By default, DefectDojo falls back to these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
