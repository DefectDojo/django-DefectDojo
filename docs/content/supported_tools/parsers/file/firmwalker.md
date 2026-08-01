---
title: "firmwalker"
toc_hide: true
---

Import the report written by [firmwalker](https://github.com/craigz28/firmwalker), which searches an
extracted firmware filesystem for files and strings worth reviewing.

### File Types

Plain text, as written by firmwalker itself:

```
./firmwalker.sh /path/to/extracted/firmware firmwalker.txt
```

Every hit is severity **Info**. firmwalker reports *where to look*, not that something is wrong — a
private key file is a problem in a shipped image and expected in a development one, and firmwalker
cannot tell which it is looking at. This follows how DefectDojo treats other tools that report
existence rather than judgement.

One finding is created per section-and-hit. A file found by a name search **and** by a content search
is two findings, because those are two different observations; but a file matched by overlapping
patterns *within* one section is a single finding naming each pattern — firmwalker searches both
`authorized_keys` and `*authorized_keys*`, and reporting that file twice would be noise.

Where a hit looks like a path it becomes `file_path`. Hits from the address, URL and email sections
are values found inside files rather than files, so those findings have no `file_path`.

Two parts of the report are deliberately not imported:

- **`***Firmware Directory***`** holds the directory that was scanned. firmwalker writes its whole
  section skeleton whether or not it finds anything, so on a clean image this is the only content line
  in the file — importing it would turn every clean run into one finding.
- **`***List etc/ssl directory***`** is a plain `ls -la` dump. Those lines look like hits and carry a
  modification time that changes between runs of an unchanged image.

One inconsistency in firmwalker's own output is passed through as-is: its file searches print paths
relative to the firmware root, while the Unix-MD5 hash section prints the absolute path it was given.

### Sample Scan Data

Sample firmwalker scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/firmwalker).

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file_path
- description
