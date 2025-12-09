---
title: "CodeQL"
toc_hide: true
---
CodeQL can be used to generate a SARIF report, that can be imported into Defect Dojo:

```shell
codeql database analyze db python-security-and-quality.qls --sarif-add-snippets --format=sarif-latest --output=security-extended.sarif
```

The same can be achieved by running the CodeQL GitHub action with the `add-snippet` property set to true.


### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
