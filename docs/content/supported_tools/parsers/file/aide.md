---
title: "AIDE"
toc_hide: true
---

[AIDE](https://aide.github.io/) (Advanced Intrusion Detection Environment) is a file integrity monitor.
It records a baseline of the filesystem — permissions, ownership, size, timestamps, checksums — and a
later `--check` reports every path that has since been added, removed or changed.

It compares a baseline against a **live filesystem**, so findings are `dynamic_finding`. Unlike Lynis,
rkhunter and chkrootkit, though, AIDE does report a **path**, so `file_path` is populated.

### Field mapping

| AIDE | DefectDojo |
|---|---|
| the section a path appears under | `added` / `removed` / `changed` in the `title` |
| the path | `file_path`, and part of the `title` |
| the attribute-change mask (`f > ... ....H`) | `description` |
| the attribute diffs from the detail section | `description` |
| — | `severity`, a fixed value; see below |

AIDE groups its differences into three sections — **Added entries**, **Removed entries** and **Changed
entries** — and repeats the changed paths in a fourth, **Detailed information about changes**, with the
old and new value of every attribute that moved. Those two halves are keyed by path rather than printed
together, so the parser joins them up; a changed file otherwise arrives with no detail.

The attribute mask is kept verbatim so a reader can cross-reference the original report.

**There is no severity.** AIDE reports that something moved, not whether it matters — a new file under
`/tmp` is routine, the same change to a system binary is not. Everything imports at **Medium**; triage
by path.

### Wrapped checksums

AIDE wraps a long value onto a continuation line, keeping the old and new values in their own columns:

```
 SHA256    : LIsI2lzmA5jh8Zrw5dzMdE3ydLgmq+WF | 0IFvw2s8tDLvDb9O4laQJmpbU1/cnvVk
             6rpoxSVDSAY=                     | djr25SQHGV0=
```

The continuation is joined **column by column**. Appending the whole line instead would splice the tail
of the old checksum onto the head of the new one and produce two values that are both wrong.

### Sample Scan Data

Sample AIDE files are available at
[unittests/scans/aide](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/aide).

### Generating an importable file

AIDE needs a baseline before it can report anything:

```bash
aide --init                                  # writes aide.db.new
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check > aide.txt                      # compares the live filesystem against it
```

With `report_url=stdout` in the configuration the report goes to stdout, which is what these fixtures
captured. AIDE exits non-zero when it finds differences, so a CI step that fails on a non-zero exit will
stop before the report is uploaded.

The fixtures were produced with **AIDE 0.19.1** on Debian 13, against a small watched directory rather
than a whole filesystem so the reports stay readable:

| Fixture | Findings |
|---|---|
| `aide_no_vuln.txt` | 0 — baseline matches, "found NO differences" |
| `aide_one_vuln.txt` | 1 — one file's contents modified |
| `aide_many_vuln.txt` | 5 — two added, one removed, one modified, one with changed permissions |

The report contains a start timestamp and the database's own checksums, so two runs are never
byte-identical. As with the rkhunter fixtures nothing is pinned here — the values are as they came.

Note that the clean report is **not** empty: it is almost entirely a Summary block and a block of
database checksums, and those contain lines that look much like attribute diffs. Only the three entry
sections yield findings.

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — the legacy default. The path is in both the title
and `file_path`, and the description carries the attribute diffs, so a file that changes twice in
different ways is reported as a change to the existing finding rather than a new one.
