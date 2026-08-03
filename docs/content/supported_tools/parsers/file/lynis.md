---
title: "Lynis"
toc_hide: true
---

[Lynis](https://cisofy.com/lynis/) audits the hardening of a running Unix host — kernel settings,
authentication, logging, package state, file permissions — and writes a machine-readable
`lynis-report.dat` alongside its human-readable log.

Unlike the rest of the tools in this family it inspects a **live system** rather than files, so its
findings are `dynamic_finding` and carry no file path or line.

### Field mapping

`lynis-report.dat` is a flat `key=value` file. Findings live under two repeated keys, whose values are
pipe-delimited as `test id | text | details | solution |`:

| Lynis | DefectDojo |
|---|---|
| `warning[]=` | severity **Medium** |
| `suggestion[]=` | severity **Low** |
| field 1, the test id (e.g. `KRNL-5820`) | `vuln_id_from_tool` |
| field 2, the text | `title` |
| field 3, the details | `description` |
| field 4, the solution | `mitigation` |

**Which key a result used is the only severity signal Lynis gives.** A `warning[]` is something Lynis
believes is wrong; a `suggestion[]` is hardening advice. There is no score per finding — the report's
`hardening_index` grades the whole host, not individual results.

A bare `-` means the field is empty. A test's text is free to contain a pipe, so the split keeps the
text intact rather than truncating at the first delimiter.

### Host identity is copied onto every finding

Nothing in an individual result says which machine it came from, and a Lynis report describes exactly
one host. The header's `hostname`, `os_fullname`, `lynis_version` and `hardening_index` are therefore
attached to every finding's description — without that, two hosts' findings would be
indistinguishable after import.

### Sample Scan Data

Sample Lynis files are available at
[unittests/scans/lynis](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/lynis).

### Generating an importable file

```bash
lynis audit system --quick --no-colors
# then import /var/log/lynis-report.dat
```

Lynis must run as root to reach most of what it checks, and it audits **the machine it runs on** — so
running it in a container audits the container, not the host.

Two things about the report:

* It contains `report_datetime_start` and `report_datetime_end`, so two runs are never byte-identical.
  The committed fixtures have those pinned; nothing else was altered.
* The `LYNIS` self-update suggestion ("This release is more than 4 months old") fires on **every** run
  once the installed version ages. It is advice about Lynis itself rather than about the audited host,
  and it is the reason a real Lynis report is never empty.

The fixtures were produced with **Lynis 3.1.4** on Debian 13:

| Fixture | Findings |
|---|---|
| `lynis_one_vuln.dat` | 1 — `--tests "BOOT-5104"`, leaving only the self-update suggestion |
| `lynis_many_vuln.dat` | 38 — a full `--quick` audit: one warning, thirty-seven suggestions |
| `lynis_no_vuln.dat` | 0 — the one-finding report with its `suggestion[]` line removed |

`lynis_no_vuln.dat` is the only fixture in this set that is not verbatim tool output. Because the
self-update suggestion always fires, a zero-finding report cannot be captured from a real run, so the
real header was kept and the single result line removed.

Note that `--tests` reliably accepts **one** test id. Passing several, space- or comma-separated, ran
nothing at all in testing.

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — the legacy default. With no file or line, findings
are distinguished by the test's text and the description, which carries the test id.
