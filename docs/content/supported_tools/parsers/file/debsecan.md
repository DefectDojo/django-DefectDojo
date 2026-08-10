---
title: "debsecan"
toc_hide: true
---
Import debsecan output. debsecan is the Debian security analyzer: it reads the packages installed on
a Debian system and lists the CVEs that the Debian security tracker says apply to them.

debsecan has no machine-readable output format. Both of the text formats that carry the information
are accepted, and the format is detected from the file. Generate one with:

```
debsecan --format detail > debsecan.txt
```

- **`--format detail` is the one to prefer.** Each CVE is a block holding a description, the
  installed package and version, the source package it was built from, and where a fix has landed.
- **`--format simple`** (and `summary`) is one `CVE-ID package` pair per line and carries nothing
  else.

One Finding is created per CVE and package pair. Where debsecan reported a fixed version, it becomes
the Finding's mitigation; where it reported none, the description says so explicitly rather than
leaving it ambiguous.

debsecan also emits `TEMP-` identifiers for issues the Debian tracker is following but that have not
been assigned a CVE. Those are kept as the tool's own identifier but are **not** recorded as
vulnerability ids, since no CVE database can enrich them.

### Severity Mapping
debsecan assigns no severity. This is worth being precise about, because it is easy to assume
otherwise: debsecan's job is to answer *does this CVE apply to this installed package on this
suite*, and its output carries applicability and fix availability, not impact. The CVSS score lives
in the CVE databases, which debsecan does not reproduce.

Every Finding is therefore imported as **Medium**, deliberately and uniformly.

The two alternatives were both rejected:

- Deriving severity from fix availability would conflate *urgency of patching* with *severity*, and
  would rate an unfixed low-impact issue above a fixed critical one.
- Guessing from the description text would be inventing a score from a truncated English sentence.

Instead, every Finding carries its CVE in `vulnerability_ids`, so DefectDojo's own CVE enrichment
can supply real scores, and the fix status is recorded in the description and mitigation for
prioritisation.

### Sample Scan Data
Sample debsecan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/debsecan).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vulnerability_ids
- component_name
