---
title: "Supported Tools"
date: 2021-02-02T20:46:29+01:00
draft: false
type: docs

cascade:
- type: "blog"
  # set to false to include a blog section in the section nav along with docs
  toc_root: true
  _target:
    path: "/blog/**"
- type: "docs"
  _target:
    path: "/**"
exclude_search: true
---

DefectDojo can parse data from 180+ security reports and counting.

## DefectDojo Pro Methods
<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users have enhanced methods of import available for certain tools.

**Connectors** allow you to automatically import and sync vulnerabilities from certain tools.

**Smart Upload** allows you to split infrastructure-wide scan files up by component or endpoint, and easily combine those results with other Findings from the same location.

| [Connectors](/import_data/pro/connectors/about_connectors/): supported tools | [Smart Upload](/import_data/pro/specialized_import/smart_upload/): supported tools |
| --- | --- |
| AWS Security Hub, BurpSuite, Checkmarx ONE, Dependency-Track, Probely, Semgrep, SonarQube, Snyk, Tenable | Nexpose, NMap, OpenVas, Qualys, Tenable, Wiz | 

# All Supported Tools

All of these listed reports can be ingested via [Import/Reimport](/import_data/import_intro/comparison/) methods. This means that they can be imported to both Open-Source and Pro instances using the UI or API.

If your tool is not in this list, there's a good chance that DefectDojo can still import a report from the tool.  Consider the [Generic Findings Import](/supported_tools/parsers/generic_findings_import/) method.

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users can import any JSON or CSV report using the [Universal Parser](/import_data/pro/specialized_import/universal_parser/).
