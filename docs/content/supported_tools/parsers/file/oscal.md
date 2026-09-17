---
title: "NIST OSCAL Assessment Results"
toc_hide: true
---
This parser imports NIST OSCAL 1.2.3 (Open Security Controls Assessment Language) `assessment-results` JSON
documents. It evaluates OSCAL `findings` (mapped to NIST SP 800-53 Rev. 5 controls where present) and links each
finding to its related `observations`. A finding is imported as active when its `target.status` indicates
`not-satisfied`/`fail`, and as mitigated when it indicates `satisfied`/`pass`.

### Sample Scan Data
Sample OSCAL assessment-results scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/oscal).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
