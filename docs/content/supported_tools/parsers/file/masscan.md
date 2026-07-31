---
title: "Masscan"
toc_hide: true
---

Import the JSON output of [masscan](https://github.com/robertdavidgraham/masscan), a port scanner
that reports which TCP and UDP ports answered.

### File Types

JSON, as written by `masscan -oJ`:

```
masscan -p80,443,8080 203.0.113.0/24 --rate 1000 -oJ masscan.json
```

Every open port becomes one finding at severity **Info**, matching how DefectDojo treats nmap's open
ports. Whether a port *should* be open is a question about the host, not something masscan can
answer. A port masscan reports as `closed` (it answered with a RST) is the opposite of a finding and
is not imported.

The endpoint is built as `//host:port`, because an open port has no scheme.

Two masscan behaviours the parser accommodates, both covered by tests:

- **A scan that finds nothing writes an empty file**, not an empty JSON array. That parses to zero
  findings rather than raising, because finding nothing is an ordinary result.
- **Some masscan versions leave a trailing comma** before the closing bracket, which is not valid
  JSON. The rest of the file is fine and the ports in it are real, so the comma is tolerated.

A port answered by more than one probe can appear in more than one record; findings are keyed on
host, port and protocol so it is imported once.

### Sample Scan Data

Sample Masscan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/masscan).

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
