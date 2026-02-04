---
title: "Arachni Scanner"
toc_hide: true
---
Arachni Web Scanner (https://www.arachni-scanner.com)

Reports are generated with `arachni_reporter` tool this way:

{{< highlight bash >}}
arachni_reporter --reporter 'json' js.com.afr
{{< /highlight >}}

### Sample Scan Data
Sample Arachni Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/arachni).
### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
