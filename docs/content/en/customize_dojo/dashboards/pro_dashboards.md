---
title: "Metrics Dashboards (Pro)"
description: "How to use DefectDojo's Pro Metrics"
weight: 3
---

The <span style="background-color:rgba(242, 86, 29, 0.5)">DefectDojo Pro UI</span> has many Metrics dashboards which are kept up to date in real-time.  Each Dashboard can render a PDF report to share data with key stakeholders.

These dashboards include:

* **Executive Insights**, which displays the current state of your Products and Product Types.
* **Program Insights**, which displays the effectiveness of your security team and the cost savings associated with separating duplicates and false positives from actionable Findings
* **Remediation Insights**, which displays your effectiveness at remediating Findings.
* **Tool Insights**, which displays the effectiveness of your tool suite (and Connectors pipelines) at detecting and reporting vulnerabilities.

## Executive Insights

![image](images/pro_dashboards_1.png)

This dashboard allows you to select any Product Type or Product from the filter list and get a status report on the number of Findings present.  If no filters are selected, this dashboard will display the status of all Product Types and Products.

![image](images/pro_dashboards_2.png)

Graphs are provided to illustrate SLA compliance, active Findings over time, and other metrics relevant to the selected Product/Product Types and timeframe.

## Program Insights

![image](images/pro_dashboards_3.png)

This dashboard shows a report of your team's security program, including quarterly breakdowns on testing, as well as noise reduction through the application of deduplication and reimport features.

## Remediation Insights

![image](images/pro_dashboards_4.png)

This dashboard tracks your remediation performance, charting time to remediation as well as Risk Acceptance over time.  "Highly Exploitable Findings" uses [EPSS scores](/en/working_with_findings/intro_to_findings/#monitor-current-vulnerabilities-using-cves-and-epss-scores-pro-feature) to estimate the likelihood of a Finding's exploit.  DefectDojo Pro comes with a daily-updated EPSS database to which assigns those scores and percentiles to each of your Findings.

## Tool Insights

![image](images/pro_dashboards_5.png)

This dashboard tracks the performance of each security tool used in DefectDojo, based on the count and severity of Findings that it reports.

## Switching To The Pro UI

These Dashboards are available under **Metrics** in the Pro UI.
To access the Pro UI, open the User Options menu from the top-right hand corner.  You can also switch back to the Classic UI from the same menu.

![image](images/beta-classic-uis.png)