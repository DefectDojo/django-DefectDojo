---
title: "cwe_checker"
toc_hide: true
---

[cwe_checker](https://github.com/fkie-cad/cwe_checker) finds vulnerable patterns in **compiled
binaries**. It lifts the executable with Ghidra and then runs a set of checks named after the weakness
they look for — use of dangerous functions, double free, use after free, unchecked allocation, integer
overflow before an allocation, externally controlled format strings.

It is the only supported tool in this family that analyses a binary rather than source, which shapes the
mapping below.

### Field mapping

| cwe_checker | DefectDojo |
|---|---|
| the parenthetical at the start of `description` | `title` |
| `name` (e.g. `CWE676`) | `vuln_id_from_tool`, and `cwe` (the integer) |
| the rest of `description` | `description` |
| `symbols`, `addresses`, `tids`, `other` | `description` |
| — | `severity`, a fixed value; see below |

**There is no source position.** A binary has no file or line, so `file_path` and `line` are left
empty. A finding is located by symbol and virtual address instead, and both are kept in the
description. Addresses arrive as decimal strings; the description prints hexadecimal alongside, so a
finding can be matched against a disassembly without converting by hand.

**There is no severity.** cwe_checker reports no severity, score or confidence anywhere in its output.
Rather than invent a per-check ranking, every finding imports at **Medium** and triage is by CWE. Bear
in mind the check set deliberately mixes genuine memory-safety defects (`CWE415` double free, `CWE416`
use after free) with advisory observations (`CWE215`, which fires whenever the binary retains debug
symbols).

Some warnings apply to the whole file rather than a call site — `CWE215` is one — and arrive with empty
`addresses`, `tids` and `symbols`. Those sections are omitted from the description rather than shown
empty.

### Sample Scan Data

Sample cwe_checker files are available at
[unittests/scans/cwe_checker](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/cwe_checker).

### Generating an importable file

```bash
docker run --rm -v "$(pwd):/work" fkiecad/cwe_checker:latest --json --quiet --out /work/report.json /work/<binary>
```

`--quiet` matters: without it, log messages are written to stdout alongside the report. Using `--out`
avoids the problem entirely.

The fixtures committed with this parser were produced with the **`fkiecad/cwe_checker:latest` image
(Ghidra 11.2)** from the C sources committed alongside them in `unittests/scans/cwe_checker/`. The
compiled executables are deliberately not committed; rebuild them with:

```bash
gcc -O0 -no-pie -o clean  clean.c  && strip clean    # 0 warnings
gcc -O0 -no-pie -o single single.c && strip single   # 1 warning
gcc -O0 -g -no-pie -o many many.c                    # 9 warnings
```

Two things that make a difference to the output, both learned while producing these fixtures:

* **`-g` adds a finding.** Debug symbols trigger `CWE215` on their own, so a binary built for debugging
  never scans clean. `many` is built with `-g` on purpose, to exercise that warning.
* **Stripping changes the symbol names.** With no symbol table, Ghidra synthesises names, so the
  `single` fixture reports the function as `FUN_00401126` rather than `main`. That is expected for
  stripped production binaries.

`strncpy` and `strlen` are on the dangerous-function list as well as `strcpy`, so a "safe" rewrite that
still calls them will not scan clean either. The `clean` fixture avoids libc string calls altogether.

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — the legacy default. With no file or line, findings
are distinguished by title, CWE and the description, which carries the address. One consequence worth
knowing: recompiling shifts addresses, so findings from a rebuilt binary do not deduplicate against the
previous scan.
