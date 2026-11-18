---
title: "zizmor"
toc_hide: true
---
Import the JSON output of [zizmor](https://docs.zizmor.sh/), a static analysis tool for GitHub Actions workflows, composite actions and Dependabot configuration.

### File Types
This parser accepts the JSON report zizmor writes with `--format json` (the current `v1` JSON format: a flat array with one object per finding). Run zizmor from the root of the repository so that file paths in the report are relative to it:

```bash
zizmor --format json . > zizmor.json
```

Every persona (`--persona regular`, `auditor` or `pedantic`) and audits of remote repositories (`zizmor owner/repo`) produce the same format. zizmor's SARIF output (`--format sarif`) can be imported with the SARIF parser instead, but it does not carry zizmor's confidence, persona or suggested fixes.

### Field Mapping
| zizmor field | DefectDojo field |
| --- | --- |
| `ident` (the audit id, such as `template-injection`) | Vulnerability Id From Tool |
| `desc`, first letter capitalized | Title |
| `determinations.severity` | Severity (see below) |
| path of the primary location (a leading `./` is removed) | File Path |
| start row of the primary location (zizmor counts rows from 0; DefectDojo stores row + 1, the line number in the file) | Line |
| `url`, the audit's documentation | References |
| titles of the suggested `fixes` | Mitigation; Fix Available is set when there is at least one |
| repository slug of a remote input (`owner/repo`) | Service |

The description holds the audit id and description, severity, confidence, persona, the primary location with its YAML route (for example `jobs.build.steps[0]`), zizmor's annotation for it, the flagged code, the related locations with their annotations, and the link to the audit's documentation, which explains the risk and how to remediate it. zizmor's hidden locations are not listed.

zizmor leaves findings silenced by an ignore comment or configuration out of its report. When it is run with `--no-ignores`, such findings are reported with `"ignored": true`; they are imported like any other finding, with a note in the description.

All findings are static findings.

### Severity
zizmor rates findings on its own four-level scale, which maps one to one onto DefectDojo's:

| zizmor severity | DefectDojo severity |
| --- | --- |
| `High` | High |
| `Medium` | Medium |
| `Low` | Low |
| `Informational` | Info |

zizmor has no critical level, so no finding is imported as Critical. A value outside this table is imported as Info.

### Sample Scan Data
Sample zizmor scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/zizmor). They were produced by zizmor 1.32.0 on a small repository of deliberately insecure workflows.

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate findings using these [hashcode fields](/triage_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- file_path
- line

zizmor's JSON output has no fingerprint, so the audit id, the workflow file and the line identify a finding. Severity is not part of the hash because audits can be re-rated between zizmor releases. Editing a workflow so that a flagged line moves makes that finding a new one on the next import. When a report covers remote repositories, the repository slug is stored in the Service field, which DefectDojo always adds to the hash, so the same workflow path in two repositories does not deduplicate.

### Link To Tool
- [zizmor](https://github.com/zizmorcore/zizmor)
- [zizmor audit documentation](https://docs.zizmor.sh/audits/)
