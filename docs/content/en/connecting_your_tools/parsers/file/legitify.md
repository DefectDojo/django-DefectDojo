---
title: "Legitify"
toc_hide: true
---
### File Types
This DefectDojo parser accepts JSON files (in flattened format) from Legitify. For further details regarding the results, please consult the relevant [documentation](https://github.com/Legit-Labs/legitify?tab=readme-ov-file#output-options).

### Sample Scan Data
Sample scan data for testing purposes can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/legitify).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- endpoints
- severity
