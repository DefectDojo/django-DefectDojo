---
title: "📊 Pro Features List"
description: "List of Pro Features in DefectDojo"
draft: "false"
weight: 4
chapter: true
exclude_search: true
---

DefectDojo Pro comes with many additional features.  Here is list of those features, along with links to documentation to see them in action:

## Improved UX

### Pro UI
DefectDojo's UI has been reworked in DefectDojo Pro to be faster, more functional and to be better at navigating through enterprise-level data volume.  It also includes a dark mode.  
See our [Pro UI Guide](../ui_pro_vs_os) for more information.

![image](images/enabling_deduplication_within_an_engagement_2.png)

### Rules Engine
DefectDojo Pro's Rules Engine allows you to set up a script of automated bulk actions - no programming experience required.
Build custom workflows and bulk actions to handle Findings and other objects.  
See our [Rules Engine Guide](/en/customize_dojo/rules_engine) for more info.

![image](images/rules_engine_4.png)

### Pro Dashboards and Reporting
Generate [instant reports and metrics](../ui_pro_vs_os/#new-dashboards) to share the security posture of your apps and repos.  Evaluate your security tools and your team's performance in addressing security issues.

### Deduplication Tuning
Fine-tune how DefectDojo identifies and manages duplicate findings with advanced deduplication settings. Adjust same-tool, cross-tool, and reimport deduplication for precision matching between all your chosen security tools and vulnerability findings.
See our [Deduplication Tuning Guide](/en/working_with_findings/finding_deduplication/tune_deduplication/) for more information.

![image](images/deduplication_tuning.png)

## Streamlined import

### Background Imports
For enterprise-level reports, DefectDojo Pro offers an optimized upload method which processes Findings in the background.

### CLI Tools
Quickly build a command-line pipeline to import, reimport and export data to your DefectDojo Pro instance using our Universal Importer and DefectDojo CLI apps.  These tools are maintained by the DefectDojo Pro team and can be run in Windows, Macintosh or Linux environments.  
See our [External Tools Guide](/en/connecting_your_tools/external_tools/) for more information.

### Connectors
DefectDojo can instantly connect to supported tools to import new Finding data - get an automated Import pipeline working out-of-the-box, without the need to set up any API calls or cron jobs.  
See our [Connectors Guide](/en/connecting_your_tools/connectors/about_connectors/) for more information.

![image](images/add_edit_connectors_2.png)

Supported tools for Connectors include:

* AWS Security Hub
* BurpSuite
* Checkmarx ONE
* Dependency-Track
* Probely
* Semgrep
* SonarQube
* Snyk
* Tenable
* Wiz

### Universal Parser
Are you using an unsupported or customized scanning tool?  Or do you just wish DefectDojo handled a report slightly differently?

Use DefectDojo Pro's Universal Parser to turn any .json or .csv report into an actionable set of Findings, and have DefectDojo parse the data however you like.  
See our [Universal Parser Guide](/en/connecting_your_tools/parsers/universal_parser/) for more information.

![image](images/universal_parser_3.png)
