---
title: "🎨 Pro UI Changes"
description: "Working with different UIs in DefectDojo"
draft: "false"
weight: 5
audience: pro
aliases:
  - /en/about_defectdojo/ui_pro_vs_os
---
In late 2023, DefectDojo Inc. released a new UI for DefectDojo Pro, which is now the default UI for this edition.

The Pro UI brings the following enhancements to DefectDojo:

- Modern and sleek design using Vue.js.
- Optimized data delivery and load times, especially for large datasets.
- Access to new Pro features, including [API Connectors](/import_data/pro/connectors/about_connectors/), [Universal Importer](/import_data/pro/specialized_import/external_tools/), and [Pro Metrics](https://docs.defectdojo.com/metrics_reports/pro_metrics/pro__overview/) views.
- Improved UI workflows: better filtering, dashboards, and navigation.

## Switching To The Pro UI

To access the Pro UI, open your User Options menu from the top-right hand corner.  You can also switch back to the Classic UI from the same menu.

![image](images/beta-classic-uis.png)

## Navigational Changes

![image](images/pro_ui_overview.png)

1. The **Sidebar** has been reorganized into four parent categories: Dashboards, Import, Manage, and Settings.

2. The Homepage, [AI-powered native API connection capabilities](/metrics_reports/ai/mcp_server_pro/), Pro Metrics, and the Calendar view are all accessible under Dashboards.

4. Import methods can be found in the Import section: set up [API Connectors](/import_data/pro/connectors/about_connectors/), use the [Add Findings](/import_data/import_scan_files/pro__import_scan_ui/) form to Add Findings, use [Smart Upload](/import_data/pro/specialized_import/smart_upload/) to handle infrastructure scanning tools, or use our external tools—[Universal Importer and DefectDojo CLI](/import_data/pro/specialized_import/external_tools/)—to streamline both the import and reimport processes of Findings and associated objects.

5. The **Manage** section allows you to view different objects in the [Product Hierarchy](/asset_modelling/hierarchy/product_hierarchy/), with views for Product Types, Products, Engagements, Tests, Findings, Risk Acceptances, Endpoints, and Components.  There are additional sections for generating reports (Report Builder), using surveys (Surveys), as well as a [Rules Engine](/automation/rules_engine/about/). 

5. The **Settings** section allows you to configure your DefectDojo instance, including your Integrations, License, Cloud Settings, Users, Feature Configuration and admin-level Enterprise Settings.

6. The **Pro Settings** section contains the System Settings, Banner Settings, Notification Settings, Jira Instances, Deduplication Settings, and Authentication Settings, including SAML, OIDC, OAuth, Login, and MFA forms.

7. The Pro UI also has a **new table format**, used in the [Product Hierarchy](/asset_modelling/hierarchy/product_hierarchy/) to help with navigation.  Each column can be clicked on to apply a relevant filter, and columns can be reordered to present data however you like.

8. The table also has a **"Toggle Columns"** menu which can add or remove columns from the table.

## Filtering the Table

In this screenshot we are filtering for all Findings that are in “Sam’s Awesome Product.” Once we click Apply, the contents of this Finding list will update to reflect the chosen filter.

![image](images/pro_ui_sams_filter.png)

## New Dashboards

New Metrics visualizations are included in the Pro UI. All of these reports can be filtered and exported as PDFs to share them with a wider audience.

![image](images/program_insights.png)

- The **Executive Insights** dashboard displays the current state of your Products and Product Types.
- **Priority Insights** show the most critical findings with the option to filter for various timelines, Product Types, Products, and Tags.
- The **Program Insights** dashboard displays the effectiveness of your security team and the cost savings associated with separating duplicates and false positives from actionable Findings.
- **Remediation Insights** displays your team's effectiveness at remediating Findings.
- **Tool Insights** displays the effectiveness of your tool suite (and Connectors pipelines) at detecting and reporting vulnerabilities.
