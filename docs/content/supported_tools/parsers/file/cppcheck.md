---
title: "Cppcheck"
toc_hide: true
---

[Cppcheck](https://cppcheck.sourceforge.io/) is a CLI static analyser for C and C++. It targets defects
a compiler will not catch — memory leaks, out-of-bounds array access, uninitialised reads, null
dereferences — and aims for a low false-positive rate rather than exhaustive coverage.

Cppcheck can emit SARIF, so this parser reuses DefectDojo's SARIF parsing logic and only declares its own
scan type. That keeps Cppcheck findings separable from the other C/C++ analysers DefectDojo supports.

### ⚠️ Cppcheck writes its report to stderr

This trips people up: `cppcheck --output-format=sarif file.c > report.sarif` produces an **empty** file,
because findings go to standard error. The redirect must be `2>`. A run captured from stdout imports
cleanly as zero findings, which looks like a passing scan rather than a mistake.

### Field mapping

| Cppcheck / SARIF | DefectDojo |
|---|---|
| `ruleId` (e.g. `memleak`, `arrayIndexOutOfBounds`) | `vuln_id_from_tool` |
| message text | `title` |
| SARIF `level` — cppcheck `error` / `warning` | `severity` (Critical / Medium) |
| `physicalLocation.artifactLocation.uri` | `file_path` |
| `physicalLocation.region.startLine` | `line` |

**No CWE.** Cppcheck's SARIF output carries no CWE taxonomy, so findings have an empty `cwe`. The scan
type is registered in `HASHCODE_ALLOWS_NULL_CWE` for that reason.

**One finding per location.** A cppcheck result can list several locations — the same
null-dereference-on-allocation-failure reported at more than one line — and each becomes its own
finding, so every affected line is visible. A report with 7 results can therefore yield 10 findings.

### Sample Scan Data

Sample Cppcheck files are available at
[unittests/scans/cppcheck](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/cppcheck).

### Generating an importable file

```bash
cppcheck --enable=warning,style --output-format=sarif <path-to-source> 2> cppcheck.sarif
```

The fixtures committed with this parser were produced with **Cppcheck 2.17.1** by three separate runs
against the C files committed alongside them in `unittests/scans/cppcheck/`:

```bash
cppcheck --enable=warning,style --output-format=sarif cc_clean.c  2> cppcheck_no_vuln.sarif    # 0 findings
cppcheck --enable=warning,style --output-format=sarif cc_single.c 2> cppcheck_one_vuln.sarif   # 1 finding
cppcheck --enable=warning,style --output-format=sarif cc_many.c   2> cppcheck_many_vuln.sarif  # 7 results, 10 findings
```

Cppcheck's older XML output (`--xml --xml-version=2`) is not supported; use `--output-format=sarif`.

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — inherited from the SARIF parser, which is the right
key for a source-position finding.
