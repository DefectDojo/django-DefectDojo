---
title: "DevSkim"
toc_hide: true
---

[DevSkim](https://github.com/microsoft/DevSkim) is Microsoft's CLI static analyser. Its rules look for
dangerous API use and weak cryptography — banned C functions, broken hash algorithms, non-cryptographic
random number generators, `eval` on untrusted data — across a wide range of languages in one pass.

SARIF is DevSkim's native and default output format, so this parser reuses DefectDojo's SARIF parsing
logic and only declares its own scan type. That keeps DevSkim findings separable from every other SARIF
producer's, which matters when the same repository is scanned by more than one tool.

### Field mapping

| DevSkim / SARIF | DefectDojo |
|---|---|
| `ruleId` (e.g. `DS185832`) | `vuln_id_from_tool` |
| `message.text` | `title` |
| SARIF `level` (`note` / `warning` / `error`) | `severity` (Info / Medium / High) |
| `physicalLocation.artifactLocation.uri` | `file_path` |
| `physicalLocation.region.startLine` | `line` |
| result `properties.tags` | tags |

### Two things to know about severity

DevSkim publishes **two** severities and only one of them is imported. Every result carries a SARIF
`level`, and also a `DevSkimSeverity` property using DevSkim's own vocabulary (`Critical`, `Important`,
`Moderate`, `ManualReview`). DevSkim's rules do not carry a `security-severity` property, so the shared
SARIF logic reads `level` alone. The practical consequence: a rule DevSkim grades `Critical` — the weak
hash rule, for instance — imports as **High**, because its SARIF level is `error`. Nothing is lost, but
the numbers will not line up with a DevSkim console report.

DevSkim's SARIF carries no CWE taxonomy at all, so findings have an empty `cwe` and the scan type is
registered in `HASHCODE_ALLOWS_NULL_CWE`.

### Sample Scan Data

Sample DevSkim files are available at
[unittests/scans/devskim](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/devskim).

### Generating an importable file

DevSkim ships as a .NET tool:

```bash
dotnet tool install --global Microsoft.CST.DevSkim.CLI
devskim analyze -I <path-to-source> -O devskim.sarif -f sarif
```

`-f sarif` is the default and can be omitted; `-f text` and `-f vs` are not supported here. With no
`-O`, DevSkim writes to stdout instead.

The fixtures committed with this parser were produced with **DevSkim 1.0.90** by three separate runs
against the source files committed alongside them in `unittests/scans/devskim/`. Each run used
`-I .` from inside the directory, so the SARIF `uri` values are bare file names rather than container
paths:

| Fixture | Findings |
|---|---|
| `devskim_no_vuln.sarif` | 0 — `app.py` |
| `devskim_one_vuln.sarif` | 1 — `hash.py`, a weak hash |
| `devskim_many_vuln.sarif` | 7 — `legacy.c`, `crypto.py` and `render.js` |

One note if you write your own clean fixture: DevSkim treats `printf` as a banned C function, so a C
file that prints anything is not a zero-finding scan.

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — inherited from the SARIF parser, which is the right
key for a source-position finding.
