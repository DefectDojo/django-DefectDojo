---
title: "poutine"
toc_hide: true
---
Import the JSON output of [poutine](https://github.com/boostsecurityio/poutine), a supply chain security scanner for build pipelines (GitHub Actions and GitLab CI).

### File Types
This parser accepts the JSON report poutine writes with `--format json`. A local analysis run from the root of the repository gives file paths relative to it:

```bash
poutine analyze_local . --format json --quiet > poutine.json
```

Reports from `analyze_repo` and `analyze_org` use the same format. The report has three sections: `findings`, `rules` (the definition of every rule, keyed by rule id) and `packages` (one entry per analyzed repository). poutine's SARIF output (`--format sarif`) can be imported with the SARIF parser instead.

### Field Mapping
| poutine field | DefectDojo field |
| --- | --- |
| `rule_id` (such as `injection`) | Vulnerability Id From Tool |
| `title` of the rule | Title (the rule id when the rule is missing from `rules`) |
| `level` of the rule | Severity (see below) |
| `meta.path` | File Path |
| `meta.line` | Line (left empty for workflow-level findings, which have no line) |
| `meta.osv_id` (for known-vulnerability rules) | Vulnerability Ids |
| the rule's documentation page and the rule's `refs` | References |
| repository of a remote `purl` (such as `pkg:github/owner/repo`) | Service |

The description starts with the rule's description and lists the finding's details, location, repository purl, job, step, advisory, event triggers, injection sources, referenced secrets and living-off-the-pipeline tool and targets when poutine reports them, followed by the link to the rule's documentation page (`https://boostsecurityio.github.io/poutine/rules/<rule_id>`), which explains how to remediate it. The JSON report carries no remediation text of its own, so Mitigation is left empty.

All findings are static findings.

### Severity
poutine rules carry a SARIF level rather than a severity. It maps as follows:

| poutine level | DefectDojo severity |
| --- | --- |
| `error` | High |
| `warning` | Medium |
| `note` | Low |
| `none` | Info |

A level outside this table, or a finding whose rule is missing from the report, is imported as Info.

### Sample Scan Data
Sample poutine scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/poutine). They were produced by poutine 1.1.6 on a small repository of deliberately insecure workflows.

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate findings using these [hashcode fields](/triage_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- file_path
- line

poutine's JSON output has no fingerprint, so the rule id, the workflow file and the line identify a finding. Severity is not part of the hash because rule levels can change between poutine releases. Editing a workflow so that a flagged line moves makes that finding a new one on the next import. When a report covers remote repositories (`analyze_repo`, `analyze_org`), the repository is stored in the Service field, which DefectDojo always adds to the hash, so the same workflow path in two repositories does not deduplicate. Local analyses leave Service empty.

### Link To Tool
- [poutine](https://github.com/boostsecurityio/poutine)
- [poutine rule documentation](https://boostsecurityio.github.io/poutine/)
