---
title: "Nozomi Networks"
toc_hide: true
---

Import a [Nozomi Networks Vantage](https://www.nozominetworks.com/products/vantage) `node_cves` export.

This exists for organisations that cannot grant Vantage API credentials — air-gapped networks,
procurement restrictions, a pending security review. OT networks are often the most isolated
environments an organisation runs, so a file import is frequently the only way the data can move at
all. The DefectDojo Pro Nozomi connector pulls the same data over the API; this parser accepts the same
data as a file.

### File Types

JSON — the `node_cves` query response, `{"result": [...]}`. A bare array works, as does an object naming
the list `results` or `data`.

A `node_cves` record is **denormalised**: every row carries its own asset context, so nothing has to be
joined and one file is enough.

### Resolved records are skipped

The connector asks Vantage for `node_cves | where resolved != true`, so a resolved record is something
an API sync can **never** produce. A hand-run query can return them, and importing one would open a
finding Nozomi has already closed — so the query filter is mirrored here, not just the converter. Only
`resolved: true` skips a row; an absent or false flag is an open vulnerability.

### Severity

Nozomi sends no severity word, so the CVE's CVSS base score is the only signal:

| `cve_score` | Severity |
| --- | --- |
| ≥ 9 | Critical |
| ≥ 7 | High |
| ≥ 4 | Medium |
| > 0 | Low |
| 0 or absent | Info |

An unscored record is Info rather than dropped — in an OT estate the asset context is worth recording
even when the score is missing. Scores may arrive quoted.

### Fields worth noting

- **Title** is `<CVE> on <asset>`, then the CVE alone. There is deliberately **no asset-only form**: a
  record with no CVE has nothing to name it by, and titling it after the device would read as though the
  device itself were the finding.
- **Identity** is `nozomi-<record id>`, falling back to `nozomi-<CVE>-<asset id>`.
- **The component is the OT product** and its version is the firmware version, so the same CVE on two
  different devices stays two findings.
- **Mitigation** names the latest hotfix, falling back to the minimum one — the floor a device has to
  reach.
- **The CVE summary** is separated from the asset context by a blank line.
- **Nothing is recorded as a dynamic finding.** Vantage builds its inventory passively, which is why it
  is usable in OT at all; marking a finding dynamic would imply the device had been probed.
- **`likelihood`** is present in the response and is not imported, matching the connector.

### Sample Scan Data

Sample Nozomi scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/nozomi).

The samples cover a scored critical record with two references, a quoted score with a bare CWE number, an
unscored record with no CVE, a resolved record that must not import, a record with no `resolved` key at
all, and an empty reference list. Asset labels, vendors, products and zones are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
