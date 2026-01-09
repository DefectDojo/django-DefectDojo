---
title: "☑️ New User Checklist"
description: "Get Started With DefectDojo"
draft: "false"
weight: 3
chapter: true
---

Here's a quick reference you can use to ensure successful implementation, from a blank canvas to a fully functional app.

The essence of DefectDojo is to import security data, organize it, and present it to the folks who need to know.  Here are ways to achieve those things in DefectDojo Pro and Open-Source:

### DefectDojo Pro

1. Start by [importing a file](/en/connecting_your_tools/import_scan_files/import_scan_ui) using the UI.  This is generally the quickest way to see how your data fits into the DefectDojo model.

2. Now that you have data in DefectDojo, learn more about how to organize it with the [Product Hierarchy Overview](/en/working_with_findings/organizing_engagements_tests/product_hierarchy). The Product Hierarchy creates a working inventory of your apps, which helps you divide your data into logical categories, apply access control rules, sort Findings by [Priority and Risk](/en/working_with_findings/finding_priority/) or to segment your reports to the correct team.

3. Check out your [Metrics pages](/en/customize_dojo/dashboards/pro_dashboards/) which can be used to quickly share Finding reports with key stakeholders.

### DefectDojo Open-Source

1. Open-Source users can start by creating their first [Product Type and Product](/en/working_with_findings/organizing_engagements_tests/product_hierarchy).  Once those are created, they can [import a file](/en/connecting_your_tools/import_scan_files/import_scan_ui) to one of those Products using the UI.

2. Now that you have data in DefectDojo, consider expanding your Product layout [Product Hierarchy Overview](/en/working_with_findings/organizing_engagements_tests/product_hierarchy). The Product Hierarchy creates a working inventory of your apps, which helps you divide your data up into logical categories. These categories can be used to apply access control rules, or to segment your reports to the correct team.

3. Use the [Report Builder](/en/share_your_findings/pro_reports/using_the_report_builder/#opening-the-report-builder) to summarize the data you've imported. Reports can be used to quickly share Findings with stakeholders such as Product Owners.

This is the essence of DefectDojo - import security data, organize it, and present it to the folks who need to know.

All of these features can be automated, and because DefectDojo can handle over 200 tools (at time of writing) you should be all set to create a functional security inventory of your entire organizational output.

## Other guides

### Pro Features
- If your organization uses ServiceNow, AzureDevops, GitHub or GitLab for issue tracking, check out our [documentation](/en/share_your_findings/integrations/) on those integrations.
- Customize your [main Dashboard](/en/customize_dojo/dashboards/introduction_dashboard/) with filtered tiles to view your environment at a glance.
- Learn how to rapidly import data and mirror your team's existing security environment with [Connectors](/en/connecting_your_tools/connectors/about_connectors/).

### Open-Source Features
- Does your organization use Jira? Learn how to use our [Jira integration](/en/share_your_findings/jira_guide/) to create Jira tickets from the data you ingest.
- Are you expecting to share DefectDojo with many users in your organization? Check out our guides to [user management](/en/customize_dojo/user_management/about_perms_and_roles/) and set up role-based access control (RBAC).
- Ready to dive into automation? Learn how to use the [DefectDojo API](/en/connecting_your_tools/import_scan_files/api_pipeline_modelling) to automatically import new data, and build a robust CI/CD pipeline.