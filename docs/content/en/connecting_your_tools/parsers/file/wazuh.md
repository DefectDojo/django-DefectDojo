---
title: "Wazuh Scanner"
toc_hide: true
---

### File Types
DefectDojo parser accepts a .json file from [Wazuh](https://wazuh.com). The export from Wazuh can be done via 2 ways. Choose the one which you prefer.

- export the Wazuh findings from API and upload them to DefectDojo. This method may be the easiest one but does export all known vulnerabilities at once. It is not possible to sort them after clients or any other categories. You will receive all vulnerabilities in one engagement. It also does not output the endpoint of a finding.
- export the findings via the script [available here](https://github.com/quirinziessler/wazuh-findings-exporter). The script fetches the findings by Wazuh client groups and saves them as json, ready for upload. You will receive one file per group allowing you to separate the clients via engagements in Wazuh. It also exports the endpoints hostname and displays them in DefectDojo UI.

Independent of your above choice: Have in mind to adjust the max file size via "DD_SCAN_FILE_MAX_SIZE" if you see files larger than the default value of 100MB. Depending on the amount and category of integrated devices, the file size jumps rapidly.

### Acceptable JSON Format
Parser expects a .json file structured as below.

~~~
{
  "data": {
      "affected_items": [
          {
            "architecture": "amd64",
            "condition": "Package less than 4.3.2",
            "cve": "CVE-1234-123123",
            "cvss2_score": 0,
            "cvss3_score": 5.5,
            "detection_time": "2023-02-08T13:55:10Z",
            "external_references": [
                "https://nvd.nist.gov/vuln/detail/CVE-YYYY-XXXXX",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-YYYY-XXXXX"
            ],
            "name": "asdf",
            "published": "2022-09-01",
            "severity": "Medium",
            "status": "VALID",
            "title": "CVE-YYYY-XXXXX affects asdf",
            "type": "PACKAGE",
            "updated": "2022-09-07",
            "version": "4.3.1"
        }
      ],
      "failed_items": [],
      "total_affected_items": 1,
      "total_failed_items": 0
  },
  "error": 0,
  "message": "All selected vulnerabilities were returned"
}
~~~

### Sample Scan Data
Sample Wazuh Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/wazuh).