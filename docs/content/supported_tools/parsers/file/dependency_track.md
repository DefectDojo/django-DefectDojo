---
title: "Dependency Track"
toc_hide: true
---
Dependency Track has implemented a DefectDojo integration. Information about
how to configure the integration is documented here:
https://docs.dependencytrack.org/integrations/defectdojo/

Alternatively, the Finding Packaging Format (FPF) from OWASP Dependency Track can be
imported in JSON format. See here for more info on this JSON format:
<https://docs.dependencytrack.org/integrations/file-formats/>

### Sample Scan Data
Sample Dependency Track scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/dependency_track).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- component name
- component version
- vulnerability ids
