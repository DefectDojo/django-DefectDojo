---
title: "AccuKnox"
toc_hide: true
---

Import an [AccuKnox](https://accuknox.com/) findings export.

This exists for organisations that cannot grant AccuKnox API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro AccuKnox connector pulls the
same data over the API; this parser accepts the same data as a file.

### File Types

JSON, from AccuKnox's findings endpoint. Rows live under `results` (also accepted: `findings`, `data`,
`rows`, or a bare array).

### The column names vary by data type

AccuKnox returns **container, IaC, cloud-posture and runtime** findings through one endpoint, and the
column names differ per type — AccuKnox does not publish this part of its schema. So each field is
resolved by probing a list of candidate keys, which is what the connector does. Assuming one set of
names would silently import empty findings for every type but one.

| Field | Candidate columns |
| --- | --- |
| identity | `finding_id`, `id`, `uuid` |
| title | `name`, `title`, `finding_name`, `vulnerability_name` |
| severity | `risk_factor`, `severity` |
| status | `status`, `finding_status` |
| description | `description`, `details`, `summary`, `message` |
| remediation | `solution`, `remediation`, `recommendation`, `fix` |
| asset | `asset_name`, `resource_name`, `asset`, `resource` |
| component | `package_name`, `component_name`, `package`, `component` |
| version | `package_version`, `component_version`, `installed_version`, `version` |
| CVE | `cve`, `cve_id`, `cve_ids` |

Every candidate is also tried with AccuKnox's **`vulnerability__` column prefix**, because some rows
nest their vulnerability columns that way.

### Severity

AccuKnox's risk factor: `critical`→Critical, `high`→High, `medium`→Medium, `low`→Low. Anything
unrecognised, including an empty value, is Info.

### Status

Only three statuses close a finding — `fixed` (mitigated), `accepted risk`, and `duplicate`. The
working states (`active`, `in progress`, `waiting for 3rd party`, `exception requested`,
`waiting for verification`) all stay **open**, so something being actively worked is not hidden.

A finding is **verified unless** its status is empty or `potential` — note a blank status counts as
verified, which is the opposite of what a plain truthiness check would give.

A row AccuKnox has **ignored** is imported and marked out of scope rather than dropped, so the
suppression is recorded. That flag arrives as a boolean *or* a string, and both are handled.

### Fields worth noting

- **`vuln_id_from_tool` is the `data_type`**, which is AccuKnox's finding class (`container_image`,
  `iac`, `cloud_posture`, `runtime`); it is also imported as a tag alongside the asset type.
- **CVEs** come from the CVE column — which may be an array — falling back to the finding title, since
  AccuKnox often carries the identifier only there. Values are scanned and deduplicated.
- **Dates** accept several formats, so a non-RFC3339 timestamp still dates the finding.
- A row with no recognisable title imports as `AccuKnox finding <id>`, or just `AccuKnox finding`.

### Scan type and deduplication

The scan type is **`AccuKnox - Connectors Import`** — identical to the string the AccuKnox connector
reports, so a customer who uploads an export *and* later enables the connector gets one set of findings
that deduplicate rather than two copies of everything.

### Sample Scan Data

Sample AccuKnox scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/accuknox).

The samples are constructed from AccuKnox's observed row shapes and deliberately mix column
conventions: one row uses `finding_id`/`name`/`risk_factor`/`status`, another `id`/`title`/`severity`/
`finding_status`, and a third the `vulnerability__` prefix. They also cover every closing status, a
`potential` row, a blank status, a string-valued `ignored` flag and a `cve_ids` array. Asset and
package names are generic placeholders.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- description
