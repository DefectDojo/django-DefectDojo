---
title: "Secretlint"
toc_hide: true
---

[Secretlint](https://github.com/secretlint/secretlint) is a pluggable CLI secret scanner. Unlike
history-scanning tools it looks only at the files you point it at, and its rules are npm packages, so a
project can add organisation-specific rules alongside the bundled ones. The recommended preset carries
28 rules covering cloud provider keys, private keys, database connection strings, package registry and
CI tokens, and API keys for a long list of SaaS products.

Secretlint's filter rules — the mechanism behind `secretlint-disable` comments — remove a detection from
the report entirely, so a suppressed secret produces no finding.

### Field mapping

| Secretlint | DefectDojo |
|---|---|
| `messages[].messageId` + short rule name | `title`, `vuln_id_from_tool` |
| `messages[].message` (masked by Secretlint) | `description` |
| `messages[].severity` (`error` / `warning` / `info`) | `severity` (High / Medium / Info) |
| `filePath` | `file_path` |
| `messages[].loc.start.line` | `line` |
| — | `cwe` 798, Use of Hard-coded Credentials |

`vuln_id_from_tool` combines the rule with the message id — `aws/AWSSecretAccessKey` — because a
`messageId` is scoped to its rule and is not unique on its own. Rule ids shorten from
`@secretlint/secretlint-rule-aws` to `aws`; a third-party rule that does not follow that naming keeps
its name unchanged.

The `title` carries the file's base name rather than its full path. Secretlint always reports an
absolute path, so a title built from it would tie every finding to one checkout location and change for
no reason when the same repository is scanned elsewhere. `file_path` still records exactly what the tool
reported.

### Scanned file content is not imported

A Secretlint report embeds the entire content of every file it read under `sourceContent`, including the
secret itself in the clear — masking applies to the rule's message, not to that field. **None of it is
copied into the finding**, because importing a report would otherwise republish the source of every
scanned file into DefectDojo.

One consequence is worth knowing: Secretlint masks secret values by default, but running it with
`--no-maskSecrets` puts the raw value into the rule's message, and that message *is* imported into the
finding description. Leave masking on unless you intend the secret to be stored in DefectDojo.

### Sample Scan Data

Sample Secretlint files are available at
[unittests/scans/secretlint](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/secretlint).

### Generating an importable file

Secretlint needs a rule set. The quickest route is the recommended preset:

```bash
npx secretlint --secretlintrcJSON '{"rules":[{"id":"@secretlint/secretlint-rule-preset-recommend"}]}' --format json "**/*" > secretlint.json
```

With a committed `.secretlintrc.json`, the flag is unnecessary:

```bash
npx secretlint --format json "**/*" > secretlint.json
```

Two notes on the invocation:

* Keep the glob in quotes — Secretlint's own documentation calls for it, so that the pattern reaches the
  tool instead of being expanded by the shell first.
* Secretlint exits **1** when it finds a secret and **0** when it does not, so a CI step that fails the
  build on a non-zero exit will stop before the report is uploaded.

Only the `json` formatter is supported. Secretlint also ships `stylish`, `compact`, `checkstyle`,
`junit`, `jslint-xml`, `unix`, `table`, `pretty-error`, `github` and `mask-result` formatters; none of
those are parsed here.

The fixtures committed with this parser were produced with **Secretlint 13.0.4** and the recommended
preset, by three separate runs:

| Fixture | Findings |
|---|---|
| `secretlint_no_vuln.json` | 0 — one scanned file, no secrets |
| `secretlint_one_vuln.json` | 1 — an AWS secret access key |
| `secretlint_many_vuln.json` | 4 — AWS and GitHub secrets across three files, one carrying both, plus one clean file |

The scanned files are not committed separately, because each report already contains them verbatim in
its `sourceContent` fields — that is enough to reproduce a run exactly. Every secret in the fixtures is
an obviously-fake placeholder, and the rule families were chosen so that no fixture carries a string
shaped like a credential that GitHub's secret scanning treats as live.

### Default deduplication hashcode fields

`file_path`, `line`, `vuln_id_from_tool` — the same key the Bandit parser uses, which is the right one
for a finding identified by a rule at a source position. The masked value is deliberately excluded, so
rotating a secret to one of a different length does not create a second finding for the same hard-coded
credential.
