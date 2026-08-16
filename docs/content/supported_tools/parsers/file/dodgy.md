---
title: "Dodgy"
toc_hide: true
---
Import Dodgy reports in JSON format. Dodgy searches source for hardcoded secrets — passwords,
cloud keys, private key material and connection strings.

Generate a report with:

```
dodgy > dodgy.json
```

Dodgy writes its JSON report to standard output.

### Severity Mapping
Dodgy assigns no severity. A match is a credential committed to source control, which is
treated as **High** regardless of the kind of secret. The rule that fired — `aws_secret_key`,
`secret`, and so on — is kept in `vuln_id_from_tool`.

### Sample Scan Data
Sample Dodgy scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/dodgy).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- file_path
- line
