---
title: "MS Defender Parser"
toc_hide: true
---
This parser helps to parse Microsoft Defender Findings and supports two types of imports:
- You can import a JSON output file from the api/vulnerabilities/machinesVulnerabilities endpoint of Microsoft defender.
- You can upload a custom zip file which include multiple JSON files from two Microsoft Defender Endpoints. For that you have to make your own zip file and include two folders (machines/ and vulnerabilities/) within the zip file. For vulnerabilities/ you can attach multiple JSON files from the api/vulnerabilities/machinesVulnerabilities REST API endpoint of Microsoft Defender. Furthermore, in machines/ you can attach the JSON output from the api/machines REST API endpoint of Microsoft Defender. Then, the parser uses the information in both folders to add more specific information like the affected IP Address to the finding.

### Sample Scan Data
Sample MS Defender Parser scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/ms_defender).