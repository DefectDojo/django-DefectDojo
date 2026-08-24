---
title: "Vuls"
toc_hide: true
---
Import Vuls reports in JSON format. Vuls is an agentless vulnerability scanner for Linux and
FreeBSD: it inventories the installed packages on a host and matches them against vulnerability
databases and the distribution's own security tracker.

Generate a report with:

```
vuls scan
vuls report -format-json
```

Vuls writes one ScanResult per scanned host, and a JSON array of several hosts is accepted.

### What one Finding represents
**One Finding per CVE and affected package pair.** Vuls reports a CVE once, with the list of
packages it affects; a CVE affecting `curl` and `libcurl4` is two packages to upgrade, and
DefectDojo tracks the component on the Finding, so it becomes two Findings. A CVE with no package
attributed to it still produces one Finding rather than being dropped.

Each Finding records the installed package, the version that fixes it (or that no fix is
available), the host and platform, how Vuls detected it, and whether the CVE appears in a
known-exploited catalogue or has public exploits — all of which Vuls gathers and which matter more
for prioritisation than the score alone.

### Severity Mapping
Vuls reports real CVSS scores, so severity is taken from them rather than invented. It consults
several sources — NVD, the distribution's tracker, JVN and others — and records a `CveContent` per
source, which routinely disagree. The **highest** score across all sources is used, preferring
newer CVSS versions where scores tie, which matches how Vuls itself orders a report and is the
conservative reading:

| Highest CVSS score | DefectDojo severity |
| --- | --- |
| 9.0 and above | Critical |
| 7.0 to 8.9 | High |
| 4.0 to 6.9 | Medium |
| above 0, below 4.0 | Low |
| no score from any source | Info |

A CVE with no score in any source becomes Info rather than Medium: that means the databases have
not scored it yet, which is a statement about the data rather than about the risk, and inflating it
to Medium would bury genuinely scored findings.

The CVSS v3 vector and score are set on the Finding where a source supplied them, and CWE comes
from the sources' own `cweIDs`.

### Sample Scan Data
Sample Vuls scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/vuls).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vulnerability_ids
- component_name
