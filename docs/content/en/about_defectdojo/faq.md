---
title: "❓ Frequently Asked Questions"
description: "DefectDojo FAQ"
draft: "false"
weight: 2
chapter: true
---

Here are some frequently asked questions about working with DefectDojo - both in DefectDojo Pro or DefectDojo OS.

## General Questions

### How should I organize my security testing in DefectDojo?

DefectDojo can support any security testing or reporting environment, but to optimize your use of DefectDojo you'll need to make sure things are in the right place.

There's no one-size-fits-all solution for DefectDojo, because everyone's security team and operations look different.  We have a very detailed article on [common use cases](/en/about_defectdojo/examples_of_use/) that has examples of how different organizations apply RBAC and the DefectDojo data model to support their needs.

### What are the recommended workflows for security testing in DefectDojo?

DefectDojo is meant to be the central source of truth for your organization's security posture, and it can fill different needs depending on your organization's requirements:

- DefectDojo can enforce SLAs on vulnerabilities, ensuring that your organization handles each within an appropriate timeframe.
- DefectDojo can [push tickets to Jira](/en/share_your_findings/jira_guide/), allowing your development team to integrate issue remediation into their standard release process without requiring them to learn another project management tool.
- DefectDojo can be integrated into automated [CI/CD pipelines](/en/connecting_your_tools/import_scan_files/api_pipeline_modelling/) to automatically ingest report data from repositories - even down to the branch level.
- DefectDojo can [create a report](/en/share_your_findings/pro_reports/using_the_report_builder/) on any set of vulnerabilities or software context, to quickly share many scan results or status updates with stakeholders.

DefectDojo is designed to support and standardize your current security workflow.  All of these methods can be used to enhance your team's processes, depending on how you currently operate.

### How does DefectDojo handle access control?

DefectDojo can be used by large teams, and setting up [RBAC (Rule Based Access Control)](/en/customize_dojo/user_management/about_perms_and_roles/) is highly recommended, both to properly establish context for each team member, and to control access to certain parts of Infrastructure.

Role and permission assignment generally happens at the Product Type / Product level.  Each team member can be assigned to one or more Products or Product Types, and can be given a role which governs how they can interact with the vulnerability data within (read only, read-write, or full control).  For more information, see our [RBAC guide](/en/customize_dojo/user_management/about_perms_and_roles/).

## Import Workflows

### What tools are supported by DefectDojo?

DefectDojo supports reports from over 200 security tools, both commercial and Open Source.  See our [Parser List](/en/connecting_your_tools/parsers/) for more information on these tools.

If you're looking to add a new tool to your suite, we have a list of recommended Open Source tools which you can check out [here](https://defectdojo.com/blog/announcing-the-defectdojo-open-source-security-awards).

### What is the different between Import and Reimport?

There are two different methods to import a report from a security tool into DefectDojo:

- **Import** handles the report as a single point-in-time record.  Importing a report creates a Test within DefectDojo that holds the Findings rendered from that report.
- **Reimport** is used to extend an existing Test.  If you have a more open-ended approach to your testing process, you continuously Reimport the latest version of your report to an existing Test.  DefectDojo will compare the results of the incoming report to your existing data, record any changes, and then adjust the Findings in the Test so that they match the latest report.

Both methods also use **Deduplication** differently: while two discrete Imported Tests in the same Product will identify and label duplicate Findings, Reimport will discard duplicate Findings altogether.

Generally speaking - if a point-in-time report is what you need, Import is the best method to use.  If you are continuously running and ingesting reports from a tool, Reimport is the better method for keeping things organized.

For more information on Reimport, see our [article](/en/connecting_your_tools/import_scan_files/using_reimport/).

### How can I troubleshoot Import errors?

DefectDojo supports a wide variety of tools.  If you're seeing inconsistent behavior when importing a report, we recommend checking to see if the file structure matches what the tool is expecting.  See our [Parser List](/en/connecting_your_tools/parsers/) to see if your tool is supported, and check to make sure that the file format matches what the tool expects.  You can also compare the structure to our Unit Tests.

**DefectDojo Pro** has a Universal Parser import method which allows you to handle any JSON, CSV or XML file.  **DefectDojo OS** users can write custom parsers for the same purpose.

Finally, third-party report formats have been known to change without warning, and our Open Source community greatly appreciates [PRs and contributions](/en/open_source/contributing/how-to-write-a-parser/) to keep our parsers up to date.

### How should I handle large scan files?

Importing a large report into DefectDojo can be a lengthy process.  Reports of 2MB contain substantial amounts of data which can take a long time to translate into Findings.  This depends on the security tool's report format itself

Our recommended approach is to break a large report up before import - rather than ingesting a report of **all** a tool's vulnerabilities at once, split them up by software project, application or by another context.  This makes it much easier for DefectDojo to handle and categorize the data, and has the added benefit of proactively organizing your Findings, which makes for more relevant and faster report generation.

**DefectDojo Pro** can process reports in the background, which makes this process easier.  However, files still need to be uploaded and validated by DefectDojo before the background Finding creation process can begin.

### How do I connect a CI/CD pipeline to DefectDojo?

Many of DefectDojo's core features can be completely automated.  CI/CD (or any kind of automated import) can be handled by calling the [DefectDojo REST API](/en/connecting_your_tools/import_scan_files/api_pipeline_modelling/).  **DefectDojo Pro** users also have access to the **Universal Importer / DefectDojo CLI** [command-line tools](/en/connecting_your_tools/external_tools/), which can be installed to run in many automated environments.

## Finding Management

### What does the status of a Finding mean?

Findings can have many statuses which indicate their status.  A status of Active or Inactive is always set on a Finding, while other statuses such as Verified, False Positive, or Out Of Scope can be applied at your discretion.

These statuses are described in more detail in our [Finding Status Definitions](/en/working_with_findings/findings_workflows/finding_status_definitions/) guide, along with information about how they can be used.
 
### How can I delete Findings from DefectDojo?

It's important to maintain historical records in AppSec work, so generally speaking, we recommend retaining Closed Findings as 'Inactive' rather than deleting them outright.  Deleting a Finding will remove all notes and metric-tracking from that Finding outright, which can lead to inaccurate reports or an incomplete archive.

Findings from DefectDojo can be deleted in a few ways:
- by running a [Bulk Delete](/en/working_with_findings/findings_workflows/editing_findings/#bulk-delete-findings) action on the Findings that you want to delete
- by calling `DELETE /findings/{id}` through the API
- by deleting a parent object, such as a Test, Engagement, Product Type or Product.

## Reporting and Jira

### How can I generate a report in DefectDojo?

You can quickly create a customized report in DefectDojo using the [Report Builder](/en/share_your_findings/pro_reports/using_the_report_builder/).

DefectDojo Pro users also have access to [executive-level Metrics dashboards](/en/about_defectdojo/ui_pro_vs_os/#new-dashboards) that can report on Product Types, Products or other data in real-time.

### How can I integrate Jira with DefectDojo?

Findings in DefectDojo can be pushed to Jira as Issues, which allows you to integrate issue remediation with your development team.  We have a [complete guide to Jira](/en/share_your_findings/jira_guide/) written which describes the process in detail.