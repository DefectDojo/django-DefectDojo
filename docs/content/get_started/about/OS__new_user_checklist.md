---
title: "☑️ New User Checklist"
description: "Get Started With DefectDojo"
draft: "false"
weight: 3
audience: opensource
---

Here's a quick reference you can use to ensure successful implementation, from a blank canvas to a fully functional app.  This article assumes you have **DefectDojo Community Edition** installed and running in your environment.

The essence of DefectDojo is to import security data, organize it, and present it to the folks who need to know.  Here are ways to achieve those things in DefectDojo Open-Source:

### DefectDojo Open-Source

1. Open-Source users can start by creating their first [Product Type and Product](/asset_modelling/hierarchy/product_hierarchy/).  Once those are created, they can [import a file](/import_data/import_scan_files/os__import_scan_ui/) to one of those Products using the UI.

2. Now that you have data in DefectDojo, consider expanding your Product layout [Product Hierarchy Overview](/asset_modelling/hierarchy/product_hierarchy/). The Product Hierarchy creates a working inventory of your apps, which helps you divide your data up into logical categories. These categories can be used to apply access control rules, or to segment your reports to the correct team.

3. Use the [Report Builder](/metrics_reports/reports/using_the_report_builder/#opening-the-report-builder) to summarize the data you've imported. Reports can be used to quickly share Findings with stakeholders such as Product Owners.

This is the essence of DefectDojo - import security data, organize it, and present it to the folks who need to know.

All of these features can be automated, and because DefectDojo can handle over 200 tools (at time of writing) you should be all set to create a functional security inventory of your entire organizational output.

### Open-Source Features
- Does your organization use Jira? Learn how to use our [Jira integration](/issue_tracking/jira/jira_guide/) to create Jira tickets from the data you ingest.
- Are you expecting to share DefectDojo with many users in your organization? Check out our guides to [user management](/admin/user_management/about_perms_and_roles/) and set up role-based access control (RBAC).
- Ready to dive into automation? Learn how to use the [DefectDojo API](/import_data/import_scan_files/api_pipeline_modelling/) to automatically import new data, and build a robust CI/CD pipeline.