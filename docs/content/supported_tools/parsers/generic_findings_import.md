---
title: "Using Generic Findings Import"
toc_hide: true
weight: 2
aliases:
  - "/en/connecting_your_tools/parsers/generic_findings_import/"
---

Generic Findings Import lets open-source and Pro users bring findings from a tool DefectDojo has no parser for. You convert the tool's output into DefectDojo's own CSV or JSON format, then import it like any other scan.

This page covers when and how to use it. The [Parser Guide](/supported_tools/parsers/file/generic/) is the field reference: every CSV column and JSON field with its data type, example values and notes.

DefectDojo Pro users can also use the [Universal Parser](/import_data/pro/specialized_import/universal_parser/), which maps a tool's own JSON, CSV or XML output onto findings without converting it first.

## Choosing CSV or JSON

DefectDojo picks the format from the file name: a name ending in `.csv` is read as CSV, and any other file is read as JSON.

- **CSV** covers the basics: title, severity, description, date, CWE, CVE, a URL, CVSS, EPSS, KEV and fix fields. Rows that share a severity, title and description are merged into one finding. See [CSV format](/supported_tools/parsers/file/generic/#csv-format) and the [example CSV](/supported_tools/parsers/file/generic/#example-csv).
- **JSON** supports everything CSV does, plus components, SAST source and sink data, tags, several endpoints per finding, attached files, and report-level metadata such as the tool name. See [JSON format](/supported_tools/parsers/file/generic/#json-format) and the [example JSON](/supported_tools/parsers/file/generic/#example-json).

Use JSON when you can. A JSON report can also set its own Test Type, which matters for deduplication (see below).

## Importing a report

Choose the scan type **Generic Findings Import**, then upload the file:

- in the UI, with the Import Scan form ([open source](/import_data/import_scan_files/os__import_scan_ui/), [Pro](/import_data/import_scan_files/pro__import_scan_ui/));
- through the API, with `scan_type` set to `Generic Findings Import` on `/api/v2/import-scan/` (see [Import from API](/import_data/import_scan_files/api_pipeline_modelling/)).

To update an existing Test with a newer report, use [Reimport](/import_data/import_intro/reimport/). A JSON report's `type` must resolve to the same Test Type as the Test you reimport into, or the reimport is rejected with a `Test type mismatch` error.

### What stops an import

These problems make the import fail with an error:

- **CSV:** a missing `Date`, `Title`, `Description` or `Severity` column, a row with no `Date`, or a non-numeric value in a numeric column such as `CweId`. An empty numeric or date cell is fine; the field is left unset. See [File rules](/supported_tools/parsers/file/generic/#file-rules).
- **JSON:** a finding without `title`, `severity` or `description`, a key that isn't a supported field, a severity other than `Critical`, `High`, `Medium`, `Low` or `Info` (case is ignored, and `Informational` and `None` count as `Info`), or a quoted boolean such as `"false"`. See [Finding fields](/supported_tools/parsers/file/generic/#finding-fields) and [Value rules](/supported_tools/parsers/file/generic/#value-rules).

In CSV, an unrecognized severity does not stop the import: it is imported as `Info`.

## Test Types

Every import creates or reuses a Test Type, which DefectDojo uses to group findings by tool and to choose deduplication settings.

- A **CSV** report always uses the Test Type **Generic Findings Import**.
- A **JSON** report takes its Test Type from the optional report-level `type` field.

| JSON report | Resulting Test Type |
|---|---|
| `{"findings": []}` (no `type`) | `Generic Findings Import` |
| `{"type": "Tool1", "findings": []}` | `Tool1 Scan (Generic Findings Import)` |
| `{"type": "Tool1 (Generic Findings Import)", "findings": []}` | `Tool1 (Generic Findings Import)`, used as-is so the suffix is never doubled |

Give each tool its own `type`. Findings from different tools then stay in separate Test Types, and each tool gets its own deduplication and metadata settings. The report-level `name` field is accepted but has no effect. See [Test Type naming](/supported_tools/parsers/file/generic/#test-type-naming).

A JSON report can also set `static_tool`, `dynamic_tool` and (in Pro) `soc` on its Test Type. These flags are shared by every Test of that Test Type, and a report without `type` changes them on the built-in `Generic Findings Import` Test Type for the whole instance. Read [Test Type metadata](/supported_tools/parsers/file/generic/#test-type-metadata) before using them.

## Deduplication

By default, Generic Findings Import findings are deduplicated by a hash of title, CWE, line, file path and description. See [Default Deduplication Hashcode Fields](/supported_tools/parsers/file/generic/#default-deduplication-hashcode-fields) and [About Deduplication](/triage_findings/finding_deduplication/about_deduplication/).

Deduplication settings are looked up by Test Type name, so a JSON report with its own `type` can be tuned separately from other generic imports. Use the resulting Test Type name, such as `Tool1 Scan (Generic Findings Import)`, as the key:

- **Open source:** in the `HASHCODE_FIELDS_PER_SCANNER` and `DEDUPLICATION_ALGORITHM_PER_PARSER` settings. See [Deduplication Tuning](/triage_findings/finding_deduplication/os__deduplication_tuning/).
- **Pro:** in the Deduplication Tuning settings. See [Deduplication Tuning (Pro)](/triage_findings/finding_deduplication/pro__deduplication_tuning/).

If the tool gives each finding a stable identifier, send it as `unique_id_from_tool` and consider a deduplication algorithm that uses it. An identifier that repeats inside one report is dropped from those findings.

## Sample reports

The DefectDojo repository has [sample Generic Findings Import reports](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/generic) in both formats, including files with endpoints, attached images, multiple CWEs, KEV fields and custom Test Types.
