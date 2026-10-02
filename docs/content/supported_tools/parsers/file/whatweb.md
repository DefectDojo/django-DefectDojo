---
title: "WhatWeb"
toc_hide: true
---

[WhatWeb](https://github.com/urbanadventurer/WhatWeb) fingerprints websites. It requests a URL and
reports what it can identify — web server and version, frameworks, CMS, analytics, page title,
`meta generator`, and at higher aggression levels a good deal more.

### One finding per target, not per plugin

WhatWeb fingerprints anything it can reach — even a 404 page yields five plugin matches — and several
of those plugins report the *network* it reached over rather than the technology it found. A finding per
plugin would both flood DefectDojo and, worse, present `Country: RESERVED` as though the site were
running it.

So each scanned URL becomes **one** finding with its technologies listed in the description. The three
URLs in the `many_vuln` fixture carry eighteen plugin matches between them and produce three findings.

`IP` and `Country` are reported under a separate **Network** heading for the same reason.

### Field mapping

| WhatWeb | DefectDojo |
|---|---|
| `target` | `title`, and an **endpoint** |
| `http_status` | `description` |
| `plugins` | `description`, grouped into Technologies and Network |
| `request_config.headers.User-Agent` | `description` |
| — | `severity`, always Info |

A plugin reports what it matched in whichever of `version`, `string`, `module`, `account`, `filepath`,
`model` and `firmware` apply; a bare detection such as `HTML5` populates none of them and is still
reported.

**Severity is always Info.** Knowing a URL runs nginx 1.31.3 is inventory, not a weakness — the same
treatment ffuf's discovered paths and nmap's open ports get. The disclosed **versions** are the part
worth triaging, and they are in the description.

### `--log-json` appends

WhatWeb **appends** to its JSON log rather than overwriting it. Running two scans into the same file
produces a report with both sets of targets, which imports as duplicate findings. Delete the file, or
use a fresh name, between runs.

### Sample Scan Data

Sample WhatWeb files are available at
[unittests/scans/whatweb](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/whatweb).

### Generating an importable file

```bash
whatweb --log-json=whatweb.json --no-errors https://target.example.com/
```

Higher aggression (`-a 3` and above) sends extra requests to confirm guesses; `-a 1` is passive. Only
`--log-json` is parsed — WhatWeb also writes `--log-brief`, `--log-verbose`, `--log-xml`,
`--log-sql` and `--log-magictree`.

The fixtures were produced with **WhatWeb 0.5.5** against a small nginx target run on a private Docker
network for the purpose; nothing outside the local network was scanned:

| Fixture | Findings |
|---|---|
| `whatweb_no_vuln.json` | 0 — an unreachable host, which yields `[]` |
| `whatweb_one_vuln.json` | 1 — the site root |
| `whatweb_many_vuln.json` | 3 — root, `/admin/` and `/robots.txt` at `-a 3` |

An empty report needs an **unreachable** target. Any URL that answers — including one that answers
404 — is fingerprinted, so pointing WhatWeb at a live host always produces at least one finding.

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — the legacy default. The URL is in the title and the
detected technologies in the description, so a version change on a tracked host updates the existing
finding.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- endpoints

The description is deliberately left out: it records what the scan saw at the time (a response size,
a detected version, a timestamp, a payload) and that changes between two scans of an unchanged
target, which would import the same finding again on every rescan.
