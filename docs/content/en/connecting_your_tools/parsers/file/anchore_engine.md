---
title: "Anchore Enterprise Vulnerability"
toc_hide: true
---

### File Types
DefectDojo parser accepts a .json file.

You can generate vulnerability data using the Anchore Enterprise CLI tool, [Anchorectl](https://docs.anchore.com/current/docs/using/cli_usage/images/inspecting_image_content/), or through the Enterprise UI. 

## Generating a Vulnerability Report:
Using Anchorectl: Run the following command to generate a vulnerability report in JSON format

 `anchorectl image vulnerabilities ubuntu:latest -o json `

Using the Anchore UI: Navigate to the desired image in the Anchore Enterprise UI, click on the Vulnerabilities tab, and download the report in JSON format.

### Acceptable JSON Format
All properties are strings and are required by the parser.

~~~

{
   
            "vulnerabilityId": "CVE-2023-24531",
            "cves": "CVE-2023-24531",
            "severity": "Critical",
            "detectedAt": "2025-03-18T08:09:03Z",
            "packageType": "Go",
            "path": "/usr/local/bin/gosu",
            "package": "stdlib-go1.18.2",
            "fixAvailable": "1.21.0-0",
            "fixObservedAt": "2025-03-18T08:09:03Z",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2023-24531",
            "nvdCvssBaseScore": 9.8
    
}
~~~

### Sample Scan Data
Sample Anchore Enterprise Vulnerability scans can be found [here](https://github.com/user-attachments/files/18395292/Vulnerability_Report_2025-01-13T10_09_59.971Z.json).