---
title: "Open Pentest Format (OPF)"
toc_hide: true
---

Import an [Open Pentest Format](https://cairnsecurity.com/opf) (OPF) file. OPF is
a JSON format for pentest findings.

Upload the `.opf.json` export. Each OPF finding maps to a DefectDojo finding:

- `severity` maps to DefectDojo severity (`informational` becomes `Info`).
- `cvssScore` and `cvssVector` populate the CVSSv3 score and vector.
- The first `cweIds` / `cweId` value populates the CWE.
- `cveIds` populate the finding's vulnerability ids.
- `recommendation` maps to Mitigation, `impact` to Impact, `stepsToReproduce`
  to Steps to Reproduce, and `references` to References.
- URL `affectedAssets` become endpoints; other assets (source paths, ARNs) are
  listed in the description.
- `testType`, `owaspCategory` and `mitreTechniques` are added as tags.

### Sample Scan Data

Sample OPF scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/opf).
