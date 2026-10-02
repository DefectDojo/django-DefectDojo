---
title: "Xygeni"
toc_hide: true
---
### About Xygeni
[Xygeni](https://xygeni.io) is a Software Supply Chain Security platform whose
scanners produce JSON reports for code vulnerabilities (SAST), open-source
dependency vulnerabilities (SCA), hard-coded secrets, IaC flaws, web-application
vulnerabilities (DAST), CI/CD and SCM misconfigurations, and malicious or
suspect components.

This parser handles three Xygeni scan kinds in phase 1: **SAST**, **SCA**, and
**Secrets**. All three share a common `metadata` envelope; the parser
dispatches on `metadata.scanType`.

### Scan Types
| Scan type                | `metadata.scanType` | Xygeni CLI command (typical) |
| ------------------------ | ------------------- | ---------------------------- |
| `Xygeni SAST Scan`       | `sast`              | `xygeni scan --scan-type=sast --format=json` |
| `Xygeni SCA Scan`        | `deps`              | `xygeni scan --scan-type=deps --format=json` |
| `Xygeni Secrets Scan`    | `secrets`           | `xygeni scan --scan-type=secrets --format=json` |

See the Xygeni documentation at <https://docs.xygeni.io> for installation and
the full set of CLI options.

### Acceptable JSON Format
All three scan types share the same envelope:

~~~
{
  "metadata": {
    "uuid": "...",
    "timestamp": "2026-04-26T07:08:29Z",
    "projectName": "...",
    "scanType": "sast" | "deps" | "secrets",
    "format": "<scanType>-xygeni",
    "reportProperties": {
      "tool.name": "Xygeni",
      "tool.version": "..."
    }
  },
  ...
}
~~~

The kind-specific payload then follows:

- **SAST** — `vulnerabilities[]` — each entry carries `detector` (the rule id),
  `severity`, `location.{filepath, beginLine, endLine, code}`, `cwe` /
  `cwes[]`, `tags[]`, `explanation`, `uniqueHash`, `issueId`, and an optional
  `codeFlows[]` block describing source / sink frames and the data path.
- **SCA** — `dependencies[]` — each dependency has `name`, `version`,
  `ecosystem`, and a nested `vulnerabilities[]` of CVE/GHSA advisories with
  `cve`, `cwes`, `fixedVersion`, `aliases`, `overallCvssScore`, `references`,
  `description`, `uniqueHash`, `issueId`.
- **Secrets** — `secrets[]` — each entry has `type` (e.g.
  `aws_access_key`), `detector`, `severity`, `location` (same shape as SAST),
  `description`, `tags`, `uniqueHash`, `issueId`. The `secret` value and
  `location.code` are already redacted by the Xygeni CLI before serialisation.

### Sample Scan Data
Sample Xygeni JSON reports can be found
[here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/xygeni).

### Deduplication

Every finding carries both `unique_id_from_tool` and `vuln_id_from_tool`. All
scan types deduplicate on `unique_id_from_tool`, keyed on Xygeni's `uniqueHash`:

| Scan type            | Algorithm             | `unique_id_from_tool` | `vuln_id_from_tool`        |
| -------------------- | --------------------- | --------------------- | ------------------------- |
| Xygeni SAST Scan     | `unique_id_from_tool` | `uniqueHash`          | `detector`                |
| Xygeni SCA Scan      | `unique_id_from_tool` | `uniqueHash`          | `userId` (CVE / GHSA / OSV) |
| Xygeni Secrets Scan  | `unique_id_from_tool` | `uniqueHash`          | `detector`                |

`uniqueHash` is Xygeni's location-independent identity for a finding. For SAST
it hashes the detector and the normalized code with the line deliberately
excluded, so two findings on the same line with different code stay distinct,
while the same code that shifts lines keeps its identity across scans. For SCA
it encodes CVE + package + version, and for Secrets it hashes the secret value,
type, detector, file and key.

`vuln_id_from_tool` is a non-unique grouping label only — never a dedup key. It
is the `detector` (the rule that fired or the kind of secret) for SAST and
Secrets, and the user-friendly vulnerability id (`userId`: CVE / GHSA / OSV) for
SCA.

The same secret value can be leaked on several lines of one file. Because
`uniqueHash` excludes the line, those occurrences share one identity, so the
Secrets parser aggregates them into a single Finding and lists every line where
the secret appears in the description.
