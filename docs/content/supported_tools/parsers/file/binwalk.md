---
title: "Binwalk"
toc_hide: true
---
Import Binwalk reports in JSON format. Binwalk identifies embedded files, compression,
cryptographic constants and licence strings inside firmware images and binaries.

Generate a report with:

```
binwalk -l binwalk.json firmware.bin
```

### Scope and Severity
Binwalk reports what a file **contains**, not whether it is vulnerable, and it assigns no
severity — it reports a match confidence instead. Every result is therefore imported as
**Info**: this is firmware inventory to review, not a list of defects.

Use it to answer questions like "does this image embed a gzip filesystem, an AES S-box, or a
third-party licence string", then follow up with a tool that judges what it finds.

### Sample Scan Data
Sample Binwalk scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/binwalk).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- file_path
