---
title: "Horusec"
toc_hide: true
---
Import findings from Horusec scan.

```shell
./horusec_linux_x64 start -O=report.json -o json -i="tests/"
```

References:
 * [GitHub repository](https://github.com/ZupIT/horusec)
 
### Sample Scan Data
Sample Horusec scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/horusec).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
- file path
- line
