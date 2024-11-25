---
title: "CodeQL"
toc_hide: true
---
CodeQL can be used to generate a SARIF report, that can be imported into Defect Dojo:

```shell
codeql database analyze db python-security-and-quality.qls --sarif-add-snippets --format=sarif-latest --output=security-extended.sarif
```

The same can be achieved by running the CodeQL GitHub action with the `add-snippet` property set to true.

