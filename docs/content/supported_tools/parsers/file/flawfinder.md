---
title: "Flawfinder"
toc_hide: true
---

[Flawfinder](https://dwheeler.com/flawfinder/) is a CLI static analyser that scans C and C++ source for
calls to functions with a history of misuse — `strcpy`, `gets`, the `printf` family and similar — and
reports each hit with a risk level and a CWE mapping.

Flawfinder emits SARIF natively, so this parser reuses DefectDojo's SARIF parsing logic and only
declares its own scan type. That keeps Flawfinder findings separable from every other SARIF producer's,
which matters when the same repository is scanned by more than one tool.

### Field mapping

| Flawfinder / SARIF | DefectDojo |
|---|---|
| `ruleId` (e.g. `FF1001`) | `vuln_id_from_tool` |
| rule `name` + message text | `title` |
| SARIF `level` (`note` / `warning`) | `severity` (Info / High) |
| rule `relationships` → CWE taxonomy | `cwe` |
| `physicalLocation.artifactLocation.uri` | `file_path` |
| `physicalLocation.region.startLine` | `line` |

Flawfinder publishes its CWE mapping through SARIF rule *relationships* rather than rule properties.
Where a rule maps to several CWEs — `gets` is both CWE-120 and CWE-20 — the finding carries the last one
extracted, which is the shared SARIF parser's documented behaviour.

### Sample Scan Data

Sample Flawfinder files are available at
[unittests/scans/flawfinder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/flawfinder).

### Generating an importable file

```bash
flawfinder --sarif <path-to-source> > flawfinder.sarif
```

The fixtures committed with this parser were produced with **flawfinder 2.0.20** by three separate runs
against the C files committed alongside them in `unittests/scans/flawfinder/`:

```bash
flawfinder --sarif clean.c      > flawfinder_no_vuln.sarif    # 0 findings
flawfinder --sarif single.c     > flawfinder_one_vuln.sarif   # 1 finding
flawfinder --sarif vulnerable.c > flawfinder_many_vuln.sarif  # 4 findings
```

Flawfinder can also emit CSV (`--csv`) and HTML (`--html`), but only the SARIF output is supported here.

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — inherited from the SARIF parser, which is the right
key for a source-position finding.
