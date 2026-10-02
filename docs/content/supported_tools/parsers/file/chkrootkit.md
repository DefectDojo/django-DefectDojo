---
title: "chkrootkit"
toc_hide: true
---

[chkrootkit](https://www.chkrootkit.org/) checks a running Unix host for known rootkits — replaced
system binaries, hidden processes and directories, LKM trojans, sniffer logs, suspicious open ports.
Like Lynis and rkhunter it inspects a **live system**, so findings are `dynamic_finding` and carry no
file path or line.

### chkrootkit has two output shapes, and both are supported

Full output pairs each check with a verdict:

```
Checking `basename'...                                      not infected
Searching for for hidden directories using chkdirs...       WARNING
WARNING: chkdirs: Possible LKM Trojan installed (or chkdirs failed):
```

`chkrootkit -q` prints **only** the `WARNING:` lines — no check lines at all.

The parser handles both. A `WARNING:` line following a failed check is attached to it as an
explanation; one with no check to attach to becomes a finding in its own right. Supporting only the
full shape would mean a quiet report — the one most likely to be collected in CI — imported as clean.

### Field mapping

| chkrootkit | DefectDojo |
|---|---|
| `Checking …` / `Searching for …` plus its verdict | `title` |
| the verdict | `severity` |
| following `WARNING:` lines | `description` |
| a standalone `WARNING:` line | its own finding, the text as `title` |

Verdicts map as `INFECTED` → **High**, `WARNING` → **Medium**, `Vulnerable but disabled` → **Low**,
anything else → Medium. chkrootkit has no check identifiers, so its own wording is the only name a
finding has and there is no `vuln_id_from_tool`.

**Clean verdicts are an explicit list**, because chkrootkit words them several ways — `not found`,
`not infected`, `not tested`, `nothing found`, `no suspect files`, plus `started`/`finished` status
lines bracketing multi-part tests. Anything not on that list is reported rather than dropped, so a
verdict this parser has not seen surfaces instead of hiding.

### Running it in a container produces environment noise

Six of the seven warnings in the `many_vuln` fixture are `chkdirs: WARNING: Skipping unsupported
filesystem (overlayfs)`. That is chkrootkit telling you it could not check a directory, not a finding
about the host, and it happens for every overlayfs mount — which means every Docker container. Expect it,
and read a run inside a container accordingly.

### Sample Scan Data

Sample chkrootkit files are available at
[unittests/scans/chkrootkit](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/chkrootkit).

### Generating an importable file

```bash
chkrootkit > chkrootkit.txt          # full output
chkrootkit -q > chkrootkit.txt       # problems only
```

chkrootkit must run as root, and it audits **the machine it runs on**. Individual tests can be named as
arguments — `chkrootkit lkm` — which is how the narrower fixtures here were produced. Note that not
every internal check is a valid argument: `chkrootkit chkdirs` reports `not a known test`.

The fixtures were produced with **chkrootkit 0.58b** on Debian 13:

| Fixture | Findings |
|---|---|
| `chkrootkit_no_vuln.txt` | 0 — `chkrootkit basename` |
| `chkrootkit_one_vuln.txt` | 1 — `chkrootkit lkm`, one failed check with seven explanations |
| `chkrootkit_many_vuln.txt` | 7 — `chkrootkit -q`, standalone warnings with no check lines |

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — the legacy default. With no file, line or check id,
findings are distinguished by the check and verdict in the title and the explanations in the
description.
