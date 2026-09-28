---
title: "🎨 Pro UI Changes"
description: "Working with different UIs in DefectDojo"
draft: "false"
weight: 5
audience: pro
aliases:
  - /en/about_defectdojo/ui_pro_vs_os
---
In late 2023, DefectDojo, Inc. released a new UI for DefectDojo Pro, which is now the default UI for this edition.

The Pro UI brings the following enhancements to DefectDojo:

- Modern and sleek design using Vue.js.
- Optimized data delivery and load times, especially for large datasets.
- Access to new Pro features, including [Upstream Connectors](/connectors/upstream/about/), [Universal Importer](/import_data/pro/specialized_import/external_tools/), and [Pro Metrics](/metrics_reports/pro_metrics/pro__overview/) views.
- Improved UI workflows: better filtering, dashboards, and navigation.

## Switching To The Pro UI

To access the Pro UI from the Classic UI, open your User Options menu from the top-right hand corner.  To switch back to the Classic UI, open the same User Options menu in the Pro UI by selecting your name (with the gear icon) at the bottom of the sidebar.

![image](images/beta-classic-uis.png)

## Navigational Changes

![image](images/pro_ui_overview.png)

1. The **Sidebar** is organized into five sections: **Overview**, **Sensei + AI**, **Connect**, **Act**, and **Settings**. See [The Sidebar Menu](/navigation/pro__sidebar/) for the full layout and a table of where each page moved.

2. The **Overview** section holds the Home page and [Dashboards](/metrics_reports/dashboards/custom-dashboards/), the [Pro Metrics](/metrics_reports/pro_metrics/pro__overview/) views (under **Insights**), [My Work](/metrics_reports/dashboards/pro__my_work/), [Reporting](/metrics_reports/reports/report-builder/), and the Calendar view.

3. The **Sensei + AI** section holds [Sensei](/sensei/about_sensei/), Threat Modeling, and the [AI-powered native API connection capabilities](/metrics_reports/ai/mcp_server_pro/) (MCP).

4. The **Connect** section holds everything that moves data in or out of DefectDojo: [Upstream and Downstream Connectors](/connectors/about/) to pull findings in from your scanners or push them out to issue trackers, the legacy Jira integration, Authorization (SSO providers, login and MFA settings), Diagnostics, and **Import**, where you can use the [Add Findings](/import_data/import_scan_files/pro__import_scan_ui/) form to Add Findings, use [Smart Upload](/import_data/pro/specialized_import/smart_upload/) to handle infrastructure scanning tools, or use our external tools—[Universal Importer and DefectDojo CLI](/import_data/pro/specialized_import/external_tools/)—to streamline both the import and reimport processes of Findings and associated objects.

5. The **Act** section is where the work happens: the Triage Engine ([Rules Engine](/automation/rules_engine/about/)), Vulnerability Explorer, Risk Acceptances, and **Explore**, which holds the [Asset Hierarchy](/asset_modelling/os_hierarchy/product_hierarchy/) views for Organizations, Assets, Engagements, Tests, and Findings, along with Surveys and the Attack Surface (Endpoints or Locations, and Components).

6. The **Settings** section holds the administrative pages, grouped as System, Users & Permissions, Finding Workflow, Configuration, Notifications, Operations, and License & Support, with an **All Settings** page that lists and searches all of them. See [The Sidebar Menu](/navigation/pro__sidebar/).

7. The Pro UI also has a **new table format**, used in the [Asset Hierarchy](/asset_modelling/os_hierarchy/product_hierarchy/) to help with navigation.  Each column can be clicked on to apply a relevant filter, and columns can be reordered to present data however you like.

8. The table also has a **"Toggle Columns"** menu which can add or remove columns from the table.

## Filtering the Table

In this screenshot we are filtering for all Findings that are in “Sam’s Awesome Asset.” Once we click Apply, the contents of this Finding list will update to reflect the chosen filter.

![image](images/pro_ui_sams_filter.png)

## New Dashboards

New Metrics visualizations are included in the Pro UI. All of these reports can be filtered and exported as PDFs to share them with a wider audience.

![image](images/program_insights.png)

- The **Executive Insights** dashboard displays the current state of your Assets and Organizations.
- **Priority Insights** show the most critical findings with the option to filter for various timelines, Organizations, Assets, and Tags.
- The **Program Insights** dashboard displays the effectiveness of your security team and the cost savings associated with separating duplicates and false positives from actionable Findings.
- **Remediation Insights** displays your team's effectiveness at remediating Findings.
- **Tool Insights** displays the effectiveness of your tool suite (and Upstream Connector pipelines) at detecting and reporting vulnerabilities.
