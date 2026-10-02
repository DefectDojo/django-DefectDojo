---
title: "cfn-lint"
toc_hide: true
---

[cfn-lint](https://github.com/aws-cloudformation/cfn-lint) validates AWS CloudFormation templates
against the resource specification and a rule set covering both correctness and best practice —
invalid properties, references to attributes a resource does not have, unused parameters, needless
intrinsic functions.

### Field mapping

| cfn-lint | DefectDojo |
|---|---|
| `Rule.ShortDescription` | `title` |
| `Rule.Id` (e.g. `W2001`) | `vuln_id_from_tool` |
| `Id` | `unique_id_from_tool` |
| `Level` (`Fatal` / `Error` / `Warning` / `Informational`) | `severity` (Critical / High / Medium / Info) |
| `Message`, `Rule.Description`, `Location.Path`, `Rule.Source` | `description` |
| `Filename` | `file_path` |
| `Location.Start.LineNumber` | `line` |

The rule's **name** is the title, so every instance of a rule groups under one heading, and the
**message** — which names the offending parameter or property — is the first line of the description.

`Location.Path` is reported too: for a deeply nested resource property, the template path
(`Resources/ApplicationBucket/Properties/NotARealProperty`) locates the problem far better than a line
number does.

**Severity is template correctness, not exploitability.** An `Error` means the template is invalid or
will fail to deploy; a `Warning` means it is valid but questionable. The mapping preserves cfn-lint's
own ordering and should not be read as a security rating.

### `Id` is a real finding identifier

Each match carries an `Id`, and it is used as `unique_id_from_tool` because it is genuinely per-match:
running the same template twice produces the same Ids, and the Ids in one report are distinct. That is
worth stating because the equivalent field is not always trustworthy — Infer's `hash`, for instance,
identifies a *bug site* and repeats across distinct issues, so the Infer parser deliberately does not
key on it.

cfn-lint reports no CWE.

### Sample Scan Data

Sample cfn-lint files are available at
[unittests/scans/cfn_lint](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/cfn_lint).

### Generating an importable file

```bash
pip install cfn-lint
cfn-lint --format json template.yaml > cfn-lint.json
```

cfn-lint exits non-zero when it finds anything, so a CI step that fails the build on a non-zero exit
will stop before the report is uploaded. Only the `json` format is parsed here; cfn-lint also offers
`sarif`, `junit`, `parseable`, `pretty` and `quiet`.

The fixtures committed with this parser were produced with **cfn-lint 1.53.3** by three separate runs
against the templates committed alongside them in `unittests/scans/cfn_lint/`:

| Fixture | Findings |
|---|---|
| `cfn_lint_no_vuln.json` | 0 — `clean.yaml` |
| `cfn_lint_one_vuln.json` | 1 — `single.yaml`, an unused parameter |
| `cfn_lint_many_vuln.json` | 5 — `many.yaml`: two unused parameters, an invalid property, a needless `Fn::Sub`, a bad `GetAtt` |

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — the legacy default, used as the fallback behind
`unique_id_from_tool`.
