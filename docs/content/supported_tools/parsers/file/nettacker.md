---
title: "OWASP Nettacker"
toc_hide: true
---

Import the JSON report written by [OWASP Nettacker](https://github.com/OWASP/Nettacker), a modular
scanner whose modules range from port and path discovery to individual CVE checks.

### File Types

JSON, as written by Nettacker's `-o` flag:

```
nettacker -i target.example.com -m port_scan -o report.json
```

The report is a flat array of events. One finding is created per target, module and port; a module that
reports the same target and port more than once in a scan produces one finding.

**Severity comes from the module, because the report has no severity field.** Nettacker records what a
module saw but never how bad it is, so:

- A **scan** module (`port_scan`, `admin_scan`, `subdomain_scan`, …) reports that something exists — a
  port answers, a path is served. That is an observation about the target rather than a weakness, so
  those findings are **Info**, matching how the Naabu and Dirsearch parsers treat the same shape.
- A **vulnerability** module — Nettacker names these with a `_vuln` suffix — fired against the target,
  which is different in kind. Those findings are **Medium**.

**The CVE is only in the module name.** Nettacker names its CVE checks
`<product>_cve_<year>_<number>_vuln` (for example `apache_cve_2021_41773_vuln`) and does not repeat the
identifier as a field, so the module name is the only place it can come from. Where one is present it
becomes the finding's vulnerability id. A `_vuln` module that names no CVE is still reported.

The module name becomes `vuln_id_from_tool`, and the endpoint records the host and the port as
separate fields rather than a URL, because an event is a host and a port.

A scan where no module produces an event writes an **empty file**, which parses to zero findings —
that is the ordinary result of scanning a target that answers nothing.

`scan_id` and `date` are deliberately left out of the finding description. Both change on every run,
so carrying them would reimport every event on a rescan of an unchanged target.

### Sample Scan Data

Sample Nettacker scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/nettacker).

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- endpoints

The description is left out for the same reason as the fields above: it records what the scan saw at
the time, which would import the same event again on every rescan.
