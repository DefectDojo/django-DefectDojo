---
title: "Github SAST Scan"
toc_hide: true
---
Import findings in JSON format from Github Code Scanning REST API:
<https://docs.github.com/en/rest/code-scanning/code-scanning>

It is important to note that DefectDojo creates a hash code for Github SAST Scan findings based on the `html_url` field in the uploaded alert. If your organization goes through an Enterprise Managed Users (EMU) migration, or an Enterprise Cloud or Serve migration, this field could change. This would cause some duplication in findings.

### Sample Scan Data
Sample Github SAST scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/github_sast).