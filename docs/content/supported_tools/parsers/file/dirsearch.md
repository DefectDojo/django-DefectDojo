---
title: "Dirsearch"
toc_hide: true
---

[dirsearch](https://github.com/maurosoria/dirsearch) brute-forces web paths from a wordlist and reports
the ones that exist — exposed admin areas, forgotten backups, `.git` directories, unlinked endpoints.
It covers the same ground as ffuf with a different interface and its own report format.

### Field mapping

| dirsearch | DefectDojo |
|---|---|
| `status` and the URL path | `title` |
| `url` | an **endpoint** |
| `content-length`, `content-type` | `description` |
| `redirect` | `description` |
| `info.args` | `description` |
| — | `severity`, always Info |

**Severity is always Info.** dirsearch reports paths that *exist*, not paths that are *wrong* — whether
one matters depends on which path it is, and dirsearch cannot make that call. This is the same treatment
the ffuf parser gives, and what DefectDojo already does for an open port from nmap.

The invocation from `info.args` is kept in every finding: the wordlist and status filters decide what
counted as a hit.

`redirect` is always present and is `null` for a direct hit, so it is omitted rather than rendered as
"Redirects to: None".

### Two things that will bite you

**dirsearch needs Python 3.11 or an explicit `setuptools`.** On Python 3.12 it fails at import with
`ModuleNotFoundError: No module named 'pkg_resources'` — 3.12 removed that module from the default
install. This is the same trap the njsscan parser documents, and it is worth knowing because a
CI image that has moved to 3.12 will stop producing reports.

**dirsearch writes no report file at all when it finds nothing.** There is no empty report to import,
which is why `dirsearch_no_vuln.json` below is not verbatim tool output.

### Sample Scan Data

Sample Dirsearch files are available at
[unittests/scans/dirsearch](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/dirsearch).

### Generating an importable file

```bash
pip install dirsearch
dirsearch -u https://target.example.com/ -w wordlist.txt --format=json -o dirsearch.json
```

`--format` also accepts `simple`, `plain`, `csv`, `html`, `xml`, `sqlite` and `mysql`; only `json` is
parsed here.

The fixtures were produced with **dirsearch on Python 3.11** against a small nginx target run on a
private Docker network for the purpose; nothing outside the local network was scanned. The wordlists are
committed alongside:

| Fixture | Findings |
|---|---|
| `dirsearch_no_vuln.json` | 0 — hand-trimmed; see above |
| `dirsearch_one_vuln.json` | 1 — `/admin` |
| `dirsearch_many_vuln.json` | 4 — `/admin`, `/backup`, `/.git`, `/robots.txt` |

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — the legacy default. The path is in the title and
the URL in the description, so two hosts scanned with the same wordlist stay distinct.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- endpoints

The description is deliberately left out: it records what the scan saw at the time (a response size,
a detected version, a timestamp, a payload) and that changes between two scans of an unchanged
target, which would import the same finding again on every rescan.
