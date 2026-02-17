---
title: "📊 Pro Features List"
description: "List of Pro Features in DefectDojo"
draft: "false"
weight: 4
chapter: true
exclude_search: true
audience: pro
aliases:
  - /en/about_defectdojo/pro_features
---
Here is a list of DefectDojo Pro’s many additional features, along with links to documentation to see them in action:

## Improved UX

### Pro UI

DefectDojo's UI has been reworked in DefectDojo Pro to be faster, more functional, fully customizable, and better at navigating through enterprise-level data volume.  It also includes a dark mode.  
See our [Pro UI Guide](../ui_pro_vs_os) for more information.

![image](images/enabling_deduplication_within_an_engagement_2.png)

### Assets/Organizations

DefectDojo Pro allows for improved organizational visualization for large lists of repositories or other business structures.  See [Assets/Organizations documentation](/asset_modelling/hierarchy/pro__assets_organizations/) for details.

![image](images/asset_hierarchy_diagram.png)

### Finding Priority

DefectDojo Pro can pre-triage your Findings by Priority and Risk, allowing your team to identify and fix your most critical issues first.
See our [Finding Priority Guide](/asset_modelling/hierarchy/pro__priority_sla/) for more details.

### Rules Engine

DefectDojo Pro's Rules Engine allows you to script automated bulk actions and build custom workflows to handle Findings and other objects, no programming experience required.

See our [Rules Engine Guide](/automation/rules_engine/about) for more info.

![image](images/rules_engine_4.png)

### Pro Dashboards and Reporting

Generate [instant reports and metrics](../ui_pro_vs_os/#new-dashboards) to share the security posture of your apps and repos, evaluate your security tools and analyze your team's performance in addressing security issues.

The graphics on the landing page can be exported as SVG files, and the data used to create the graphics can also be exported as a table. 

Additionally, DefectDojo Pro includes several new [insights dashboards](/metrics_reports/pro_metrics/pro__overview/), offering enhanced metrics for various audiences of your security program.

### Deduplication Tuning

Advanced Deduplication settings allow you to fine-tune how DefectDojo identifies and manages duplicate findings. Adjust same-tool, **cross-tool**, and reimport Deduplication for precision matching between all your chosen security tools and vulnerability findings. 

See our [Deduplication Tuning Guide](/triage_findings/finding_deduplication/pro__deduplication_tuning/) for more information.

![image](images/deduplication_tuning.png)

## Streamlined import

### More Import Options

DefectDojo Pro includes four additional import methods: [Universal Importer](/import_data/pro/specialized_import/external_tools/), [API Connectors](/import_data/pro/connectors/about_connectors/), [Universal Parser](/supported_tools/parsers/universal_parser/), and [Smart Upload](/import_data/pro/specialized_import/smart_upload/).

![image](images/pro_import_methods.png)


### Background Imports

For enterprise-level reports, DefectDojo Pro offers an optimized upload method which processes Findings in the background.

### CLI Tools

Quickly build a command-line pipeline to import, reimport, and export data to your DefectDojo Pro instance using our Universal Importer and DefectDojo-CLI apps; no API scripting necessary (available for Windows, Macintosh, or Linux).

See our [External Tools Guide](/import_data/pro/specialized_import/external_tools/) for more information.

### Connectors

DefectDojo can instantly connect to enterprise-level scanning tools to import new Finding data, creating an automated Import pipeline that works out-of-the-box without the need to set up any API calls or cron jobs. 

See our [Connectors Guide](/import_data/pro/connectors/about_connectors/) for more information.

![image](images/add_edit_connectors_2.png)

Supported tools for Connectors include:

* Anchore
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

### Universal Parser (Beta)

If you’re using an unsupported/customized scanning tool, or just wish that DefectDojo handled a report slightly differently, use DefectDojo Pro's Universal Parser to turn any .json or .csv report into an actionable set of Findings. Your parser will parse and map the data however you like.

See our [Universal Parser Guide](/import_data/pro/specialized_import/universal_parser//) for more information.

![image](images/universal_parser_3.png)

## Support

DefectDojo Pro subscriptions include world-class support for both on-premise and Cloud installations.  Our team is available to help your organization implement and maximize your use of DefectDojo Pro.  Your subscription includes:

- **Comprehensive Support**: Unlimited support tickets and seats are available to assist your entire team.
- **Dedicated Engineering Focus**: User-reported issues, bugs, and feature requests receive priority attention from our engineering team.
- **SaaS Management**: We provide monitoring, maintenance, and backups for all SaaS instances.
