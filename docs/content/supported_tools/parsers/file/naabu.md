---
title: "Naabu"
toc_hide: true
---

[naabu](https://github.com/projectdiscovery/naabu) is a fast port scanner. It reports which TCP (and
with `-scan-type` UDP) ports on a host answer, and optionally whether the port speaks TLS.

### Field mapping

| naabu | DefectDojo |
|---|---|
| `port`, `protocol`, `host` | `title` |
| `host` and `port` | an **endpoint** — host and port, no scheme |
| `host`, `ip`, `port`, `protocol`, `tls`, `timestamp` | `description` |
| — | `severity`, always Info |

**Severity is always Info.** An open port is an observation, not a weakness — whether it *should* be
open is a question about the host, which naabu cannot answer. DefectDojo already treats nmap's open
ports as Info and this follows that precedent.

The endpoint records the host and the port rather than a URL, because an open port has no scheme.
Both are set as separate fields, so nothing has to be parsed back out of a string.

Scanning a hostname makes naabu report both the name and the address it resolved to, and both are kept.

### Output is JSON Lines, and it repeats itself

`naabu -json` writes **one JSON object per line**, not a JSON array. Feeding it to a JSON parser whole
fails; this parser reads it line by line and says so explicitly if handed an array.

More importantly, **naabu reports the same open port once per scan pass**. A single run against four
open ports produced eight lines, and a single-port run produced two. Findings are therefore keyed on
host, port and protocol — without that, every open port imports twice. The committed fixtures keep the
duplicate lines exactly as naabu emitted them, and a test asserts eight lines collapse to four findings.

### Sample Scan Data

Sample Naabu files are available at
[unittests/scans/naabu](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/naabu).

### Generating an importable file

```bash
naabu -host target.example.com -p 80,443,8080 -json > naabu.json
```

Three things worth knowing, all found while producing these fixtures:

* **naabu resolves targets itself**, and it could not resolve a Docker-internal container name even
  though the port was demonstrably reachable — it fails with `no valid ipv4 or ipv6 targets were found`.
  Give it an IP when DNS is unusual.
* **`-o` writes nothing at all when no port is open**, so capture stdout if you want a file to exist
  either way. The clean fixture here is an empty stdout capture.
* The official release binaries are **glibc-linked**. On Alpine they fail with `naabu: not found`, which
  is musl's way of reporting a missing ELF interpreter rather than a missing file.

A SYN scan needs `CAP_NET_RAW`; `-s connect` works unprivileged and is what produced these fixtures.

| Fixture | Findings |
|---|---|
| `naabu_no_vuln.json` | 0 — closed ports, empty output |
| `naabu_one_vuln.json` | 1 — port 80, from two duplicate lines |
| `naabu_many_vuln.json` | 4 — ports 80, 3000, 8080, 8443, from eight lines |

The fixtures were produced with **naabu 2.6.1** against nginx containers on a private Docker network;
nothing outside the local network was scanned. Timestamps are pinned for byte-stability.

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — the legacy default. Host, port and protocol are all
in the title, so a port opening on a second host is a separate finding.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- endpoints

The description is deliberately left out: it records what the scan saw at the time (a response size,
a detected version, a timestamp, a payload) and that changes between two scans of an unchanged
target, which would import the same finding again on every rescan.
