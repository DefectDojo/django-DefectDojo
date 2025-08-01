---
title: "Supported Report Types"
description: "DefectDojo has the ability to import scan reports from a large number of security tools."
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

DefectDojo can parse data from 200+ security reports and counting.

All of these listed reports can be ingested via [Import/Reimport](/en/connecting_your_tools/import_intro/) methods. This means that they can be imported to both Open-Source and Pro instances using the UI or API.

If your tool is not in this list, there's a good chance that DefectDojo can still import a report from the tool.  Consider the [Generic Findings Import](/en/connecting_your_tools/generic_findings_import/) method.

## DefectDojo Pro Tool Support

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users can import **any** JSON, XML or CSV report using the [Universal Parser](/en/connecting_your_tools/universal_parser).

Certain tools can also be used with [Connectors](/en/connecting_your_tools/connectors/about_connectors/) or [Smart Upload](/en/connecting_your_tools/import_scan_files/smart_upload/) Pro upload methods: see the table below.

| [Connectors](/en/connecting_your_tools/connectors/about_connectors/): supported tools | [Smart Upload](/en/connecting_your_tools/import_scan_files/smart_upload/): supported tools |
| --- | --- |
| AWS Security Hub, BurpSuite, Checkmarx ONE, Dependency-Track, Probely, Semgrep, SonarQube, Snyk, Tenable | Nexpose, NMap, OpenVas, Qualys, Tenable, Wiz |

## Complete list of supported tools
Reports from these tools can be handled in DefectDojo Pro and OS.