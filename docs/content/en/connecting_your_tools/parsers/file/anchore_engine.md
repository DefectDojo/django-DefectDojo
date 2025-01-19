---
title: "Anchore-Engine"
toc_hide: true
---

### File Types
DefectDojo parser accepts a .json file.

Using the [Anchore UI](https://docs.anchore.com/current/docs/vulnerability_management/images/ui/) is the most reliable way to generate an Anchore vulnerability report which DefectDojo can parse. 
### Acceptable JSON Format
All properties are strings and are required by the parser.

~~~

{
    "metadata": {
        "registry": "docker.io",
        "repository": "repo/mysbom",
        "tag": "v1",
        "imageDigest": "sha256:83be7a5cc0befe6cf0c44146ba0fadf7b7dea83f9682a36fd2283e48d64e7830",
        "timestamp": "2025-01-15T16:28:29.140Z"
    },
    "securityEvaluation": [
        {
            "vulnerabilityId": "CVE-2024-47535",
            "cves": "CVE-2024-47535",
            "severity": "Medium",
            "detectedAt": "2025-01-14T21:32:01Z",
            "packageType": "Java",
            "path": "/app.jar:BOOT-INF/lib/reactor-netty-core-1.2.1.jar",
            "package": "reactor-netty-core-1.2.1",
            "fixAvailable": "4.1.115",
            "fixObservedAt": "2025-01-14T21:32:01Z",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-47535",
            "nvdCvssBaseScore": 5.5
        },
        {
            "vulnerabilityId": "CVE-2024-47535",
            "cves": "CVE-2024-47535",
            "severity": "Medium",
            "detectedAt": "2025-01-14T21:32:01Z",
            "packageType": "Java",
            "path": "/app.jar:BOOT-INF/lib/reactor-netty-http-1.2.1.jar",
            "package": "reactor-netty-http-1.2.1",
            "fixAvailable": "4.1.115",
            "fixObservedAt": "2025-01-14T21:32:01Z",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-47535",
            "nvdCvssBaseScore": 5.5
        }
    ]
}
~~~

### Sample Scan Data
Sample Anchore Enterprise scans can be found [here](https://github.com/user-attachments/files/18395292/Vulnerability_Report_2025-01-13T10_09_59.971Z.json).