---
title: "❓ Frequently Asked Questions"
description: "DefectDojo FAQ"
draft: "false"
weight: 2
chapter: true
aliases:
  - /en/about_defectdojo/faq
---
Here are some frequently asked questions about working with DefectDojo - both in DefectDojo Pro or DefectDojo OS.

## General Questions

### How should I organize my security testing in DefectDojo?

While DefectDojo can support any security or testing environment, everyone’s security team and operations look different, so there’s no one-size-fits-all approach to using it. We have a very detailed article on [common use cases](/get_started/common_use_cases/common_use_cases/) that has examples of how different organizations apply RBAC and the DefectDojo data model to support their needs.

### What are the recommended workflows for security testing in DefectDojo?

DefectDojo is meant to be the central source of truth for your organization's security posture, and it can fill different needs depending on your organization's requirements, such as:

- Allowing users to identify duplicate findings across scans and tools, minimizing alert fatigue.
- Enforcing SLAs on vulnerabilities, ensuring that your organization handles each Finding within an appropriate timeframe.
- Sending tickets to [Jira](/issue_tracking/jira/jira_guide/), ServiceNow or other Project Tracking software, allowing your development team to integrate issue remediation into their standard release process without requiring them to learn another project management tool.
- Integrating into automated [CI/CD pipelines](/import_data/import_scan_files/api_pipeline_modelling/) to automatically ingest report data from repositories, even down to the branch level.
- Creating [reports](/metrics_reports/reports/using_the_report_builder/) on any set of vulnerabilities or software context, to quickly share scan results or status updates with stakeholders.
- Establishing acceptance and mitigation workflows, supporting formal risk-management tracking.


DefectDojo is designed to support and standardize your current security workflow. All of these methods can be used to enhance your team’s processes and adapt to how you currently operate.

### What features are available in DefectDojo Pro?

DefectDojo Pro expands on the above workflows further, adding:

- An [improved UI](/get_started/about/ui_pro_vs_os/) designed for speed and efficiency when navigating through enterprise-level data volumes. It also includes a dark mode.
- The ability to [pre-triage your Findings](/asset_modelling/hierarchy/pro__priority_sla/) by Priority and Risk, allowing your team to identify and fix your most critical issues first.
- A [Rules Engine](/automation/rules_engine/about) to script automated bulk actions and build custom workflows to handle Findings and other objects, no programming experience required.
- [Enhanced report and metrics generation capabilities](/get_started/about/ui_pro_vs_os/#new-dashboards) to easily share the security posture of your apps and repos.
- [Advanced deduplication settings](/triage_findings/finding_deduplication/pro__deduplication_tuning/) to fine-tune how DefectDojo identifies and manages duplicate findings.
- Streamlined import capabilities, such as: 
  - An optimized upload method which processes Findings in the background.
  - The ability to quickly build a [command-line pipeline](/import_data/pro/specialized_import/external_tools/) using our Universal Importer and DefectDojo CLI apps, allowing you to easily import, reimport, and export data to your DefectDojo Pro instance.
  - A [Universal Parser](/import_data/pro/specialized_import/universal_parser/) to turn any .json or .csv report into an actional set of Findings and have DefectDojo Pro will parse the data however you like.
  - [Connectors](/import_data/pro/connectors/about_connectors/), which provide an instant connection to supported tools to import new Finding data so you can get an automated Import pipeline established without the need to set up any API calls or cron jobs.

### How does DefectDojo handle access control?

DefectDojo can be used by large teams, and setting up [RBAC (Rule Based Access Control)](/admin/user_management/about_perms_and_roles/) is highly recommended, both to properly establish context for each team member, and to control access to certain parts of Infrastructure.

Role and permission assignment generally happens at the Product Type / Product level.  Each team member can be assigned to one or more Products or Product Types, and can be given a role which governs how they can interact with the vulnerability data within (read only, read-write, or full control).  For more information, see our [RBAC guide](/admin/user_management/about_perms_and_roles/).

### How does DefectDojo handle access control for a team of users?

Whether you’re a one-person security team for a small organization or a CISO overseeing a swath of software projects,you can easily organize [Role-Based Access Control (RBAC)](/admin/user_management/about_perms_and_roles/) in order to properly establish context for each team member and control access to certain parts of Infrastructure.

Generally, role and permission assignment happens at the [Product Type/Product level](/asset_modelling/hierarchy/product_hierarchy/). Each team member can be given a role pertaining to one or more Products or Product Types that governs how they can interact with the vulnerability data within (e.g., read only, read-write, or full control). 

## Import Workflows

### What tools are supported by DefectDojo?

DefectDojo supports reports from [over 200](/supported_tools/) commercial and open-source security security tools.

If you're looking to add a new tool to your suite, we have a list of recommended Open-Source tools which you can check out [here](https://defectdojo.com/blog/announcing-the-defectdojo-open-source-security-awards).

### What is the different between Import and Reimport?

There are two different methods to import a single report from a security tool:

- **Import** handles the report as a single point-in-time record. Importing a report creates a Test containing the resulting Findings.
- **[Reimport](/import_data/import_intro/import_vs_reimport/)** is used to update an existing Test with a new set of results. If you have a more open-ended approach to your testing process, you can continuously Reimport the latest version of your report to an existing Test. DefectDojo will compare the results of the incoming report to your existing data, record any changes, and then adjust the Findings in the Test to match the latest report.

To understand the difference, it’s helpful to think of Import as recording a single instance of a scan event, and Reimport as updating a continual record of scanning.

Here is an analogy; if you were an accountant, you could use Import to track a single receipt, while you would use Reimport to track a continuous ledger of expenses

Both methods also use Deduplication differently: while two discrete Imported Tests in the same Product will identify and label duplicate Findings separately, Reimport will not create any Findings it identifies as [duplicates](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/avoiding_duplicates_via_reimport/) within the Test.

Generally speaking, if a point-in-time report is what you need, Import is the best method to use. If you are continuously running and ingesting reports from a tool, Reimport is the better method for keeping things organized.

### How can I troubleshoot Import errors?

DefectDojo supports a wide variety of tools. If you’re seeing inconsistent behavior when importing a report, we recommend checking if the file structure matches what the tool is expecting. See our [Parser List](/supported_tools/) to confirm that your tool is supported, and check to make sure that the file format matches what the tool expects. You can also compare the structure to our Unit Tests.

DefectDojo Pro has a Universal Parser import method which allows you to handle any JSON, CSV or XML file. DefectDojo OS users can write custom parsers for the same purpose.

Finally, third-party report formats have been known to change without warning: Our OS community greatly appreciates [PRs and contributions](/open_source/contributing/how-to-write-a-parser/) to keep our parsers up to date.

### How should I handle large scan files?

Importing a large report into DefectDojo can be a lengthy process. Reports of 2MB contain substantial amounts of data, which can take a long time to translate into Findings depending on the security tool’s report format.

Our recommended approach is to break down large reports before import to reflect different subsections of available data. If your security tool can filter results by software project, application, or other context, exporting smaller reports makes it easier for DefectDojo to handle and categorize the data. This also has the added benefit of proactively organizing your Findings based on how the data was broken down, which makes for more relevant and faster report generation.

DefectDojo Pro can process reports in the background. However, files still need to be uploaded and validated by DefectDojo before the background Finding creation process can begin.

### How do I connect a CI/CD pipeline to DefectDojo?

Many of DefectDojo's core features can be completely automated.  CI/CD (or any kind of automated import) can be handled by calling the [DefectDojo REST API](/import_data/import_scan_files/api_pipeline_modelling/).

**DefectDojo Pro** users also have access to the **Universal Importer / DefectDojo CLI** [command-line tools](/import_data/pro/specialized_import/external_tools/), which can be installed to run in many automated environments.

## Finding Management

### What does the status of a Finding mean?

Findings can have many statuses. A status of Active or Inactive is always set on a Finding, while other statuses such as Verified, False Positive, or Out Of Scope can be applied at your discretion.

These statuses are described in more detail in our [Finding Status Definitions](/triage_findings/findings_workflows/finding_status_definitions/) guide, along with information about how they can be used.
 
### How can I delete Findings from DefectDojo?

Generally speaking, we recommend retaining Closed Findings as ‘Inactive’ rather than deleting them outright, as it’s important to maintain historical records in AppSec work. Deleting a Finding will remove all notes and metric-tracking from that Finding outright, which can lead to inaccurate reports or an incomplete archive.

Findings from DefectDojo can be deleted in a few ways:
- By running a [Bulk Delete](/triage_findings/findings_workflows/editing_findings/#bulk-delete-findings) action on the Findings that you want to delete
- By calling `DELETE /findings/{id}` through the API
- By deleting a parent object, such as a Test, Engagement, Product Type or Product.
  - Note that subclasses are not preserved independently of their parent object: Deleting a parent object such as a Product Type will delete any Products, Engagements, Tests, Findings, and Endpoints within the Product Type. Conversely, deleting an Engagement will preserve the Products, and Product Types that precede it.

## Reporting and Jira

### How can I generate a report in DefectDojo?

You can quickly create a customized report in DefectDojo using the [Report Builder](/metrics_reports/reports/using_the_report_builder/).

DefectDojo Pro users also have access to [executive-level Metrics dashboards](/get_started/about/ui_pro_vs_os/#new-dashboards) that can report on Product Types, Products or other data in real-time.

### How can I integrate a project management tool with DefectDojo?

In both Pro and Open-Source editions of DefectDojo, Findings in DefectDojo can be pushed to Jira as Issues, which allows you to integrate issue remediation with your development team.  We have a [complete guide to Jira](/issue_tracking/jira/jira_guide/) written which describes the process in detail.

DefectDojo Pro adds support for [Additional Project Tracking Integrations](/issue_tracking/intro/intro/)**: ServiceNow, Azure DevOps, GitHub and GitLab.