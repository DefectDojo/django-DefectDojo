---
title: "NPM Audit"
toc_hide: true
---

**Note: This parser only supports import from NPM Audit v6 or older.**

Node Package Manager (NPM) Audit plugin output file can be imported in
JSON format. Only imports the \'advisories\' subtree.

### File Types
This parser expects a JSON file.  Can only import NPM Audit files from NPM Audit v6 or older due to missing relevant fields, including:

- Finding created / updated dates
- Relevant CVE number
- Finding overview (description Field)
- Recommendation
- Issue reference
- CWE
- Exploitability

See NPM's issue on GitHub for more information.  https://github.com/npm/npm-audit-report/issues/45

Attempting to import a file from a later version of NPM Audit will raise an error message.

### Sample Scan Data
Sample NPM Audit scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/npm_audit).

### Link To Tool
See NPM-Audit-Report on GitHub: https://github.com/npm/npm-audit-report/
