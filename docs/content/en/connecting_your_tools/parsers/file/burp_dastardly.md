---
title: "Burp Dastardly"
toc_hide: true
---
### File Types
DefectDojo parser accepts Burp Dastardly Scans as an XML output.

Dastardly is a free, lightweight web application security scanner for your CI/CD pipeline. It is designed specifically for web developers, and checks your application for seven security issues that are likely to interest you during software development. Dastardly is based on the same scanner as Burp Suite (Burp Scanner).

### Sample Scan Data
Sample Burp Dastardly scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/burp_dastardly).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
