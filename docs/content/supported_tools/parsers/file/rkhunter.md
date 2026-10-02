---
title: "rkhunter"
toc_hide: true
---

[rkhunter](https://rkhunter.sourceforge.net/) (Rootkit Hunter) checks a running Unix host for rootkits,
backdoors and local misconfiguration — known rootkit signatures, replaced system binaries, suspicious
file properties, kernel module state, network and logging configuration.

Like Lynis it inspects a **live system**, so findings are `dynamic_finding` and carry no file path or
line.

### Field mapping

`rkhunter.log` is a line-oriented log. Every line carries a `[HH:MM:SS]` prefix, and every check ends
with a bracketed outcome:

| rkhunter | DefectDojo |
|---|---|
| a line ending `[ Warning ]` | one finding |
| the check's wording on that line | `title` |
| the following `Warning: …` lines | `description` |
| header version / host / O/S | `description` |
| — | `severity`, a fixed value; see below |

**Only `[ Warning ]` is a finding.** rkhunter marks every check it runs, and the overwhelming majority
pass — a default container run produces over 1100 `[ Not found ]` and 230 `[ OK ]` results against four
warnings. A parser matching brackets loosely would import the whole log.

rkhunter has **no check identifiers**, so the check's own wording is the only name a finding has, and
there is no `vuln_id_from_tool` to set.

**There is no severity.** A warning can be a genuine rootkit indication or an artefact of the
environment — "the kernel modules directory is missing or empty" is normal inside a container, not a
compromise. Everything imports at **Medium**; triage by check.

### Three log quirks the parser handles

* **Not every flagged check has an explanation.** Two of the four warnings in a default run have no
  `Warning:` line at all, so the description says the check was flagged without one rather than leaving
  the reader wondering whether something was lost.
* **`Info:` lines are interleaved between warnings.** They begin a new statement, so they are not glued
  onto the preceding warning as a continuation. Genuinely indented continuation lines *are* joined.
* **One line is both a result and its own warning** — `Warning: Suckit Rootkit additional checks
  [ Warning ]`. The leading `Warning:` is dropped from the title.

### Sample Scan Data

Sample rkhunter files are available at
[unittests/scans/rkhunter](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/rkhunter).

### Generating an importable file

```bash
rkhunter --check --sk --nocolors --noappend-log
# then import /var/log/rkhunter.log
```

`--sk` skips the keypresses rkhunter otherwise waits for, which matters in CI. `--noappend-log`
overwrites rather than appending, so the log holds exactly one run — without it a report accumulates
several audits and the same warning imports repeatedly.

rkhunter must run as root, and it audits **the machine it runs on**: in a container it audits the
container.

The fixtures were produced with **Rootkit Hunter 1.4.6** on Debian 13, narrowed with `--enable` to
control how much each one covers:

| Fixture | Findings |
|---|---|
| `rkhunter_no_vuln.log` | 0 — `--enable known_rkts`, 1106 lines of passing checks |
| `rkhunter_one_vuln.log` | 1 — `--enable system_configs`, no logging daemon running |
| `rkhunter_many_vuln.log` | 4 — a full default check |

The log carries a clock time on **every** line plus start and end dates, so two runs are never
byte-identical. Unlike the other fixtures in this set nothing is pinned here: rewriting 1800 timestamps
would be a larger change to the output than leaving them as they came.

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — the legacy default. With no file, line or check id,
findings are distinguished by the check's wording and its warning text.
