---
title: "httpx"
toc_hide: true
---

Import the JSON Lines output of [httpx](https://github.com/projectdiscovery/httpx), which probes URLs
and reports what answered and what it is running.

### File Types

JSON Lines — one object per line, **not** a JSON array — as written by `httpx -json`:

```
httpx -l urls.txt -json -tech-detect -title -server -o httpx.json
```

`-tech-detect` is worth passing: it is what fills in the technologies (reported as `Name:Version`
where httpx could identify one).

One finding is created per probed URL, at severity **Info**. httpx says what answered and what it is
running, not that anything is wrong — whether a reachable `/admin` or a disclosed server version
matters is a question about the application. This is the same treatment the WhatWeb parser gives the
same kind of fingerprinting, and it follows how DefectDojo treats nmap's open ports.

Because httpx reports the full URL it probed, the endpoint needs no reconstructing, unlike tools that
report a bare path.

Two behaviours worth knowing:

- **A target that does not answer produces no output at all**, so a scan of an unreachable host
  writes an empty file, which parses to zero findings. With `-probe`, httpx instead reports what it
  could not reach as a record with `"failed": true` — that is the absence of a result rather than a
  finding, so those records are skipped.
- The `timestamp` and response-`time` fields are deliberately left out of the finding. Both change on
  every run of an unchanged target and neither says anything about what was found.

### Sample Scan Data

Sample httpx scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/httpx).

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- endpoints

The description is left out on purpose: it records what the scan saw at the time — a content length, a
detected version — which would import the same URL again on every rescan.
