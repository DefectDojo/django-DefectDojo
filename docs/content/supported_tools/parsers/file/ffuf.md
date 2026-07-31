---
title: "ffuf"
toc_hide: true
---

[ffuf](https://github.com/ffuf/ffuf) is a fast web fuzzer. Given a wordlist and a URL containing a
keyword, it substitutes each entry and reports the requests whose responses match its filters — which
makes it a content-discovery tool: exposed admin paths, forgotten backups, `.git` directories,
unlinked endpoints.

### Field mapping

| ffuf | DefectDojo |
|---|---|
| `status` and the URL path | `title` |
| `url` | an **endpoint** |
| the wordlist entry (`input.FUZZ`) | `description` |
| `length`, `words`, `lines`, `content-type` | `description` |
| `redirectlocation` | `description` |
| `commandline` | `description` |
| — | `severity`, always Info; see below |

ffuf reports a **URL**, so a finding carries an endpoint rather than a file path or line — the first
DAST-shaped tool in this family.

### Severity is always Info

ffuf reports what it **found**, not what is wrong. A 200 on `/index.html` is not a weakness; an exposed
`/.git` or `/backup` is — and ffuf cannot tell them apart, because to ffuf both are just responses that
matched a filter. Everything therefore imports at **Info** and triage is by path, which is how
DefectDojo already treats an open port reported by nmap.

The **command line is kept** in every finding. ffuf's matchers and filters decide what counted as a
hit, so without it a reader cannot tell whether a status was matched deliberately or by ffuf's defaults.

`FFUFHASH` is dropped: it identifies a request for ffuf's own replay feature, not a finding. A run using
a named keyword (`-w list.txt:DIRS`) has its payload labelled with that keyword instead of `FUZZ`.

### Sample Scan Data

Sample ffuf files are available at
[unittests/scans/ffuf](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/ffuf).

### Generating an importable file

```bash
ffuf -u https://target.example.com/FUZZ -w wordlist.txt -of json -o ffuf.json
```

`-of json` selects the machine-readable format; ffuf also writes `html`, `csv`, `ejson`, `md` and
`all`, none of which are parsed here.

The fixtures were produced with **ffuf 2.2.1** against a small nginx target run on a private Docker
network for the purpose — nothing outside the local network was scanned. The wordlists are committed
alongside the reports:

| Fixture | Findings |
|---|---|
| `ffuf_no_vuln.json` | 0 — a wordlist of paths the target does not serve |
| `ffuf_one_vuln.json` | 1 — `/admin` |
| `ffuf_many_vuln.json` | 5 — `/admin`, `/backup`, `/.git`, `/robots.txt`, `/index.html` |

Note that a clean ffuf report is **not** an empty file: it still contains the command line, a
timestamp and the full `config` block, with an empty `results` array. The reports carry a `time` stamp,
which is pinned in the fixtures so they are byte-stable; nothing else was altered.

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — the legacy default. The path is in the title and
the URL in the description, so two hosts fuzzed with the same wordlist stay distinct.
