---
title: "ClamAV"
toc_hide: true
---

Import the output of [ClamAV](https://www.clamav.net/)'s `clamscan`, which matches files against
malware signatures.

### File Types

Plain text, as printed by `clamscan`:

```
clamscan -r --allmatch /path/to/scan > clamav.txt
```

clamscan writes one line per file — `<path>: <signature> FOUND` for a hit, `<path>: OK` for a clean
file, `<path>: Empty file`, or `<path>: <reason> ERROR` for a file it could not read — followed by a
`SCAN SUMMARY` block. Only `FOUND` becomes a finding; a clean run therefore parses to zero findings
even though it produces plenty of output.

`--allmatch` is worth passing: without it clamscan stops at the first signature that matches a file,
so a file matching several signatures reports only one. With it, each signature on that file is its
own finding.

The signature name becomes `vuln_id_from_tool` and the scanned path becomes `file_path`. Findings are
severity **High** with CWE-506. A signature match is a detection rather than a guess — ClamAV names
what it matched — and a confirmed hit is often triaged up to Critical depending on the artifact, which
is a judgement about the artifact rather than something clamscan measures.

The `.UNOFFICIAL` suffix ClamAV appends to signatures from any database other than its own is kept and
called out in the description, because it says how much the detection is worth.

The `SCAN SUMMARY` block is deliberately not carried into findings: it holds an engine version and a
scan date, both of which change between runs of an unchanged artifact.

### Sample Scan Data

Sample ClamAV scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/clamav).

The captures were produced with the local signature database committed alongside them
(`custom.ndb`), which matches placeholder strings in ordinary local files — so no malware sample is
needed to reproduce them.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file_path
- description
