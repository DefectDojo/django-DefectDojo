---
title: "Red Hat Satellite"
toc_hide: true
---
You can import a JSON report which was retrieved through the REST API of Red Hat Satellite. The scanner can be found [here](https://www.redhat.com/en/technologies/management/satellite).

### Sample Scan Data
Sample Red Hat Satellite scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/redhatsatellite).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- description
- severity

### Field fix_availabe
The field 'fix_available' is set to true if the fix is installable. 