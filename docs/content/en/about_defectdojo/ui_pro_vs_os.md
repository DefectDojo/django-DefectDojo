---
title: "🎨 Beta UI Features"
description: "Working with different UIs in DefectDojo"
draft: "false"
weight: 4
pro-feature: true
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Note: The Beta UI and associated features are only available in DefectDojo Pro.</span>

In late 2023, DefectDojo Inc. released a new UI for DefectDojo Pro, which has since been in Beta for Pro customers to test and experiment with.

The Beta UI brings the following enhancements to DefectDojo:

- Modern and sleek design, built using Vue.js
- Optimized data delivery and load times, especially for large datasets
- Access to new Pro features, including [API Connectors](/en/connecting_your_tools/connectors/about_connectors/), [Universal Importer](/en/connecting_your_tools/external_tools/), and Pro Metrics views
- Improved UI workflows: better filtering, dashboards, and navigation

## Switching To The Beta UI

To access the Beta UI, open your User Options menu from the top-right hand corner.  You can also switch back to the Classic UI from the same menu.

![image](images/beta-classic-uis.png)

## Navigational Changes

![image](images/beta-ui-overview.png)

1. The **Sidebar** has been reorganized: Pro Metrics and the Homepage can be found in the first section.

2. Import methods can be found in the **Import** section: set up [API Connectors](/en/connecting_your_tools/connectors/about_connectors/), use the Import Scan form to [Add Findings](/en/connecting_your_tools/import_scan_files/import_scan_ui/), or use [Smart Upload](/en/connecting_your_tools/import_scan_files/smart_upload/) to handle infrastructure scanning tools.

3. The **Manage** section allows you to view different objects in the [Product Hierarchy](/en/working_with_findings/organizing_engagements_tests/product_hierarchy/), with views for Product Types, Products, Engagements, Tests, Findings, Risk Acceptances, Endpoints and Components.

4. The **Settings** section allows you to configure your DefectDojo instance, including your License, Cloud Settings, Users, Feature Configuration and admin-level Enterprise Settings.

The Enterprise settings section contains the System Settings, Jira Instances, Deduplication Settings, SAML, OAuth, Login and MFA forms.

5. The beta UI also has a **new table format** to help with navigation.  This table is used with all [Product Hierarchy](/en/working_with_findings/organizing_engagements_tests/product_hierarchy/). Each column can be clicked on to apply a relevant filter, and columns can be reordered to present data however you like.

6. The table also has a **"Toggle Columns"** menu which can add or remove columns from the table.

## New Dashboards

New metrics visualizations are included in the Beta UI.  All of these reports can be filtered and exported as PDF to share them with a wider audience.

![image](images/program_insights.png)

- The **Executive Insights** dashboard displays the current state of your Products and Product Types.
- **Program Insights** dashboard displays the effectiveness of your security team and the cost savings associated with separating duplicates and false positives from actionable Findings.
- **Remediation Insights** displays your effectiveness at remediating Findings.
- **Tool Insights** displays the effectiveness of your tool suite (and Connectors pipelines) at detecting and reporting vulnerabilities.
