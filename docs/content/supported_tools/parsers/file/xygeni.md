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

Every finding carries both `unique_id_from_tool` and `vuln_id_from_tool`, and
the deduplication algorithm is configured per scan type:

| Scan type            | Algorithm                          | `unique_id_from_tool` | `vuln_id_from_tool` | Hash-code fields (fallback)                               |
| -------------------- | ---------------------------------- | --------------------- | ------------------- | --------------------------------------------------------- |
| Xygeni SAST Scan     | `unique_id_from_tool`              | `issueId`             | `uniqueHash`        | n/a                                                       |
| Xygeni SCA Scan      | `unique_id_from_tool_or_hash_code` | `uniqueHash`          | `issueId`           | `vulnerability_ids`, `component_name`, `component_version` |
| Xygeni Secrets Scan  | `unique_id_from_tool`              | `issueId`             | `uniqueHash`        | n/a                                                       |

For SAST and Secrets the dedup key is the per-occurrence `issueId` (which
encodes the file path and line). The same secret value or code pattern can
appear several times in one file; Xygeni reuses a single `uniqueHash` across
those occurrences, so keying dedup on `uniqueHash` would collapse them into one
Finding and underreport the occurrences. Keying on `issueId` keeps each
occurrence as its own Finding, while `uniqueHash` is retained as the
`vuln_id_from_tool` that groups occurrences of the same value.

For SCA the dedup key stays `uniqueHash` (it encodes CVE + package + version,
unique per finding) and the hash-code fallback enables cross-tool
deduplication: the same CVE on the same package@version reported by Xygeni and
another SCA scanner (Snyk, Trivy, etc.) collapse into a single Finding.
