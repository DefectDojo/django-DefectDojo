---
title: "Zimperium zScan"
toc_hide: true
---

Import a [Zimperium zScan](https://www.zimperium.com/zscan/) assessment SARIF report.

This exists for organisations that cannot grant Zimperium API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Zimperium connector pulls the
same data over the API; this parser accepts the same data as a file.

### The SARIF mapping is shared

On the Go side the Zimperium connector calls the same shared SARIF utility the other SARIF-reporting
connectors use, parameterised by an identity prefix and a static/dynamic flag. This parser extends the
same shared mapping rather than restating it — the way the shipped `invicti` parser extends
`netsparker` — so a change to that mapping lands in one place, exactly as it does upstream.

That means the SARIF behaviour is identical to the other SARIF-backed parsers: a result whose `kind` is
anything other than `fail` is skipped, an absent `kind` means failure, a **suppressed result is inactive
and a false positive**, and a result with **no `level` is Medium, not Info**. Severity prefers the rule's
`security-severity` property (as a CVSS number, then as a word) over the result level.

### File Types

JSON — a SARIF report. Wrap it to supply the app and build context a SARIF document does not carry:

```json
{
  "assessment": {"id": "assess-0001", "appVersion": "3.2.0", "buildUploadedAt": "2024-06-02T09:00:00Z"},
  "app": {"name": "Generic Mobile App", "platform": "android"},
  "sarif": { "runs": [ ... ] }
}
```

Each field may also sit at the top level, and the log may be under `sarif`, `log` or `report`. A bare
SARIF report imports fine — it simply carries no component, version or platform.

### The decoration is what makes a mobile finding actionable

A SARIF document says nothing about **which app** or **which build** it came from. Two builds of one app
land in the same DefectDojo product, and without the version there is no telling them apart. So after
the shared mapping runs, the export's context supplies:

- **`component_name`** — the app's name
- **`component_version`** — the build's `appVersion`
- **`date`** — the date the build was uploaded
- a **platform tag**, appended *after* the SARIF tags

Each is only filled when the SARIF mapping left it empty, as the connector does.

### Give the report the assessment id

The identity is `zimperium-<assessment id>-<rule id>-<file>:<line>`. One assessment is one scan of one
build, so the same rule firing in two builds stays two findings — which is what lets a reader see that a
problem survived a release. `assessment_id`, `assessmentId` and `id` are all accepted. Without one,
findings **will not deduplicate against connector-synced ones**.

### Sample Scan Data

Sample Zimperium scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/zimperium).

The samples cover a scored high-severity Android finding, an iOS assessment with a hard-coded-secret
result, a suppressed weak-crypto result, a note-level result with no score, and a `pass` result that must
not import. App, bundle and file names are generic, and no fixture contains a real credential — the
"hard-coded secret" result names no value at all.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- file_path
- vuln_id_from_tool
