---
title: "Beagle Security"
toc_hide: true
---

Import a [Beagle Security](https://beaglesecurity.com/) test report.

This exists for organisations that cannot grant Beagle Security API credentials — air-gapped
networks, procurement restrictions, a pending security review. The DefectDojo Pro Beagle Security
connector pulls the same data over the API; this parser accepts the same data as a file.

### File Types

JSON. Beagle returns a report as a JSON **string** inside an envelope — `{"result": "{...}"}` — so
both the envelope and the report body it carries are accepted.

### The report schema is only partly published

Beagle documents the report-level keys (`project_name`, `application_name`, `url`,
`generated_date`, `approved_date`) and the occurrence block, but **not the names of the per-finding
fields**, and their only sample report cuts the finding array out. The connector handles this by
reading each field from a set of plausible aliases, and this parser accepts exactly the same set:

| Field | Accepted keys, in preference order |
| --- | --- |
| name | `name`, `title`, `vulnerability_name`, `vulnerabilityname`, `signature`, `signature_name`, `vulnerability` |
| severity | `severity`, `risk`, `risk_level`, `risklevel`, `severity_level`, `severitylevel`, `priority` |
| score | `cvss_score`, `cvssscore`, `score`, `cvss`, `risk_score`, `riskscore` |
| vector | `cvss_vector`, `cvssvector`, `vector`, `cvss` |
| CWE | `cwe`, `cwe_id`, `cweid`, `cwes` |
| description | `description`, `details`, `detail`, `summary`, `impact`, `vulnerability_description` |
| remediation | `remediation`, `solution`, `recommendation`, `recommendations`, `fix`, `mitigation` |
| occurrences | `occurences`, `occurrences`, `instances` |

Keys are matched case-insensitively. `occurences` — one `r` — leads the list because that is the
vendor's own spelling. Inside an occurrence, `Method` and `Url` really are capitalised.

The finding array itself is located by name (`vulnerabilities`, `signatures`, `vulnerability_list`,
`issues`, `findings`, `results`) and, failing that, by shape: the first key, in sorted order, whose
value is an array of objects. A documented report key is never mistaken for the finding list.

### Severity

The severity label is used when there is one:

| Label | Severity |
| --- | --- |
| `critical` | Critical |
| `high` | High |
| `medium` | Medium |
| `low` | Low |
| `info`, `informational`, `information` | Info |
| anything else | Info |

An unrecognised label becomes Info rather than a guess, and the original label is kept as a tag so
the real value is not lost. A tenant that scores reports with CVSS instead of OWASP sends a bare
number under the same key, which is graded against the connector's floors — 9.0 Critical, 7.0 High,
4.0 Medium, anything lower Low.

### One finding per occurrence

An occurrence is one place a finding was observed — a method and a URL — so a finding reported on
three URLs becomes three findings. Their statuses often differ, which is exactly why they are kept
apart: an occurrence Beagle marks `Fixed` is imported as inactive and mitigated, and every other
status counts as open. `Fixed` is the only status value Beagle documents, so the rest of the enum is
treated as open rather than guessed at. A finding with no occurrences still produces one finding,
aimed at the application's own URL.

### Deduplication hashes the endpoint

This scan type's configuration pairs `unique_id_from_tool_or_hash_code` with a field set that
**includes `endpoints`**, so the parser always records the tested URL. That matters more here than
usual: the connector's unique id is a SHA-256 over the **application token**, which is a parameter of
every Beagle API call and is *not* part of a report. An export that happens to carry the token gets
connector-identical unique ids; otherwise no unique id is set at all, and the hash over title,
severity and endpoints is what matches a file import to an API sync. Inventing a token-less id would
produce something that deduplicates against nothing.

### Fields worth noting

- **Date** — every finding in a report is stamped with the report's `generated_date`, falling back to
  `approved_date` and then to today, matching the connector.
- **Param** — the HTTP method the occurrence was found with.
- **Test session** — the connector adds the Beagle test-session id to each description. A report body
  does not carry it, so that line is absent from a file import.

### Sample Scan Data

Sample Beagle Security scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/beagle).

The samples are constructed from Beagle's documented report shape and cover a label severity, a
numeric CVSS severity, both occurrence spellings, a `Fixed` occurrence, a finding with no
occurrences, an unrecognised severity label, a finding array found by shape rather than by name, and
an unreadable report date. Hostnames are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- endpoints
