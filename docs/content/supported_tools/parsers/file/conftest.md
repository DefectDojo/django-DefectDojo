---
title: "Conftest"
toc_hide: true
---

[Conftest](https://www.conftest.dev/) tests structured configuration against policies written in
[Rego](https://www.openpolicyagent.org/docs/latest/policy-language/), the Open Policy Agent language. It
is policy-agnostic: it will evaluate Kubernetes manifests, Terraform plans, Dockerfiles, CI config or
anything else it can parse, against whatever rules you write.

Because the policies are yours, so are the findings — there is no built-in rule set to map.

### Field mapping

| Conftest | DefectDojo |
|---|---|
| `failures[].msg` / `warnings[].msg` | `title` |
| which array the result came from | `severity` (High for `deny`, Medium for `warn`) |
| `metadata.query` (e.g. `data.main.deny`) | `vuln_id_from_tool` |
| `namespace`, `metadata`, result kind | `description` |
| `filename` | `file_path` |

**Which array a result lands in is the only severity signal Conftest gives.** A Rego `deny` rule is
reported under `failures` and a `warn` rule under `warnings`, so the two map to different severities and
the description records which it was. There is nothing else to grade on.

Rego `deny` and `warn` rules are **anonymous** — they have no identifier — so the rule's own message is
the only name a finding has, and `vuln_id_from_tool` gets the query (`data.main.deny`), which names the
rule *set* rather than the individual rule. That is the closest thing to a rule id the language offers.
Anything else a policy attaches to `metadata` is preserved in the description, so a policy that adds its
own `severity` or `control` field will still show it.

Conftest reports the file it evaluated but never a line inside it.

### What is not imported

- **`exceptions`** — results a policy author explicitly allowed through an `exception` rule. An accepted
  risk is not a new finding.
- **`skipped`** — policies that were not evaluated at all.
- **`successes`** — a **count**, not a list. Conftest reports how many rules passed, not which, so
  passing rules could not become findings even if that were wanted.

### A clean run omits the keys entirely

A file with no violations is reported as `{"filename": ..., "namespace": ..., "successes": 4}` — the
`failures` and `warnings` keys are **absent**, not empty arrays. Anything consuming the report has to
fetch them defensively or it will fail on precisely the clean case.

### Sample Scan Data

Sample Conftest files are available at
[unittests/scans/conftest](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/conftest).

### Generating an importable file

```bash
conftest test --output json --policy ./policy ./manifests > conftest.json
```

Conftest exits non-zero when a `deny` rule matches, so a CI step that fails the build on a non-zero exit
will stop before the report is uploaded.

The fixtures committed with this parser were produced with **Conftest 0.62.0** by three separate runs
against the manifests and the Rego policy committed alongside them in `unittests/scans/conftest/`:

| Fixture | Findings |
|---|---|
| `conftest_no_vuln.json` | 0 — `clean.yaml`, four rules passed |
| `conftest_one_vuln.json` | 1 — `single.yaml`, a missing memory limit |
| `conftest_many_vuln.json` | 4 — `many.yaml`: three `deny` and one `warn` |

The policy in `unittests/scans/conftest/policy/` is deliberately small and self-explanatory — four rules
over a Deployment — so the fixtures can be regenerated and understood without pulling a policy bundle.

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — the legacy default. With no line number and no rule
id, findings are distinguished by the message and the file, which is exactly what a Rego message is for.
