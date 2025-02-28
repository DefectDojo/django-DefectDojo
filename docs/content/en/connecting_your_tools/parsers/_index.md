---
title: "Supported Report Types"
description: "DefectDojo has the ability to import scan reports from a large number of security tools."
draft: false
weight: 5
exclude_search: true
---

DefectDojo can parse data from 180+ security reports and counting.

## DefectDojo Pro Methods
<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users have enhanced methods of import available for certain tools.

**Connactors** allow you to automatically import and sync vulnerabilities from certain tools.

**Smart Upload** allows you to split infrastructure-wide scan files up by component or endpoint, and easily combine those results with other Findings from the same location.

| [Connectors](../connectors/about_connectors): supported tools | [Smart Upload](../import_scan_files/smart_upload/): supported tools |
| --- | --- |
| AWS Security Hub, BurpSuite, Checkmarx ONE, Dependency-Track, Probely, Semgrep, SonarQube, Snyk, Tenable | Nexpose, NMap, OpenVas, Qualys, Tenable | 

# All Supported Tools

All of these listed reports can be ingested via [Import/Reimport](../import_intro) methods. This means that they can be imported to both Open-Source and Pro instances using the UI or API.

If your tool is not in this list, there's a good chance that DefectDojo can still import a report from the tool.  Consider the [Generic Findings Import](./generic_findings_import/) method.

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users can import any JSON or CSV report using the [Universal Parser](../universal_parser).