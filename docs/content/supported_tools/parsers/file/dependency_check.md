---
title: "Dependency Check"
toc_hide: true
---
OWASP Dependency Check output can be imported in Xml format. This parser ingests the vulnerable dependencies and inherits the suppressions.

* Suppressed vulnerabilities are tagged with the tag: `suppressed`.
* Suppressed vulnerabilities are marked as mitigated.
* If the suppression is missing any `<notes>` tag, it tags them as `no_suppression_document`.
* Related vulnerable dependencies are tagged with `related` tag.

### Sample Scan Data
Sample Dependency Check scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/dependency_check).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- file path
