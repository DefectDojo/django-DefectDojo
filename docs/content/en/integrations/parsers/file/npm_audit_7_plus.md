---
title: "NPM Audit Version 7+"
toc_hide: true
---

**Note: This parser only supports import from NPM Audit v7 or newer.**

Node Package Manager (NPM) Audit plugin output file can be imported in
JSON format. Only imports the \'vulnerabilities\' subtree.

### File Types
This parser expects a JSON file.  Can only import NPM Audit files from NPM Audit v7 or newer. It aims to provide the same
information as the non-JSON formatted output.

Attempting to import a file from a version less than 7 of NPM Audit will raise an error message.

### Command Used To Generate Output
Either of these commands will work:
- \`npm audit --json\`
- \`npm audit fix --dry-run --json\`

### Sample Scan Data
Sample NPM Audit scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/npm_audit_7_plus).

### Link To Tool
See NPM-Audit-Report on GitHub: https://github.com/npm/npm-audit-report/
