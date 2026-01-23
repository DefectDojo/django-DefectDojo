---
title: "DefectDojo Pro Metrics"
description: "How to Leverage Metrics in DefectDojo Pro"
audience: pro
weight: 2
---

## Metrics Overview

The DefectDojo Pro UI has various Metrics dashboards to help visualize your current security posture. Each dashboard allows stakeholders at different levels of the organization to make informed decisions without needing to interpret raw data or navigate individual Findings. These dashboards include:
* [Executive Insights](#executive-insights)
* [Priority Insights](#priority-insights)
* [Program Insights](#program-insights)
* [Remediation Insights](#remediation-insights)
* [Tool Insights](#tool-insights)

![Metrics overview](images/metrics_image1.png)

## Metrics Features

Before elaborating on each particular dashboard, there are some commonalities between all dashboards that are worth reviewing.

### Filtering

All Metrics can be filtered by timeframe, Organization, Asset, and Tag. After adjusting the filter as desired, Apply Filter must be clicked in order for the filter to take effect. If you wish to export a PDF of all charts, tables, and graphs on the dashboard as currently filtered, click Export as PDF. 

The filtering timeframe is limited to the past year, but can otherwise be adjusted to include the past 7, 14, 30, 90, or 180 days. 

### Submenus 

Each graph has a ⋮ kebab menu in the top right of each view with the following features:
* Force Refresh — Manually refreshes to incorporate any new updates in the data. 
* Expand Plot — Opens the same chart in a larger pop-up modal.
* Download Plot as SVG — Downloads the chart as an SVG file.
* View as Table — Shows the data from the chart in table format.
    * Each column of the table can be toggled to appear in ascending or descending order when clicked. You can also download each table.

![Kebab menu contents](images/metrics_image2.png)

### Access

The Metrics section will only represent data from the Organizations and Assets that each User has the appropriate permissions to view. A User with access limited to a single Asset will only be able to see Metrics for that particular Asset, but if they don’t have access to the other Assets within the parent Organization, data from those other Assets won't be represented in Metrics. 

### Viewing Data Within Charts

The X-axis of line charts will always represent the current timeframe filter. Hovering your cursor over a line chart will cause a modal to appear with a count of the figures on the Y-axis at that point in time. 

![Graph pop-up modal](images/metrics_image3.png)

### Toggling Results

Users can toggle certain categories of Findings as viewable and nonviewable in the chart by clicking on their respective color/name at the top of each chart. 

For example, in the Active Findings by Severity chart below, if you only wanted to see Findings with a High or Critical severity, you would click Medium, Low, and Info at the top to remove those results from the chart. Clicking Medium, Low, and Info again would make those results reappear. 

![Toggling graph results gif](images/metrics_image4.gif)

## Executive Insights 

**Executive Insights** provides an aggregated view of application security risk across your organization. As it is design for executive-level consumption, this dashboard focuses exclusively on Organizations and Assets, emphasizing trends and outcomes rather than individual Findings.

Within Executive Insights, Users may select a timeframe, Organization, Asset, or Tag from the filter list, which will populate an adjoining table with the resulting Findings. It will also change the results in various charts and graphs below. 

If no filters are selected, the table will display the status of all Organizations, Assets, and Tags. 

The first table provides a birdseye view of your overall security posture. There are also two separate tables for your Organizations and Assets.

Figures will populate within each table depending on the filters applied. Clicking any hyperlinked figure within a cell will open a separate tab containing all Findings from that cell. From there, Users can investigate and interact with the Findings as desired, such as by: 
* Viewing Finding data within the table 
* Opening a Finding’s Organization and/or Asset
* Downloading the Findings as a CSV file
* Generating a Quick Report of the Findings
* Editing or closing a Finding
* Requesting a review 
* Adding risk acceptance
* Adding a file or a note
* Pushing to Jira or Integrator
* Deleting the Finding
* Opening the Finding history

## Priority Insights

**Priority Insights** shows the most critical Findings as determined by risk, severity, exploitability, or custom scoring, helping teams understand which vulnerabilities pose the greatest threat at any given moment and focus their efforts accordingly. 

Apart from various charts and graphs, Priority Insights includes four clickable modals that will open a separate tab with a table for all of the data those four modals represent: 
* Total Urgent Risk Findings 
* Total Needs Action Risk Findings
* Total Medium Risk Findings 
* Average Finding Priority 

It also includes an integrated table of Prioritized Findings arranged either by AppSec or SOC, allowing Users to further filter, interact with, and view the data associated with individual Findings. The contents can be exported as a CSV file or a Quick Report, and other various columns can be added prior to export. 

![Priority Insights table](images/metrics_image6.png)

## Program Insights 

**Program Insights** evaluates the effectiveness and maturity of the application security program as a whole, focusing on program-level performance rather than individual Findings. It includes breakdowns of testing efforts, as well as how deduplication and reimport features are affecting noise reduction, efficiency increases, and cost savings, ensuring that security processes are working as intended.

## Remediation Insights 

**Remediation Insights** focuses on closure performance and remediation accountability, charting SLA adherence, overdue Findings, and Risk Acceptance over time. It relies on EPSS scores to determine a Finding’s exploitability, the database for which DefectDojo Pro updates daily and applies to each of your Findings.

Similar to Priority Insights, Remediation Insights also includes four clickable modals that will open a separate tab with a table for all of the data those four modals represent: 
* Total Open Findings 
* Critical & High Open Findings 
* Mitigated Within SLA 
* Highly Exploitable Findings 

## Tool Insights 

**Tool Insights** tracks the performance of each security tool used in DefectDojo based on the count and severity of Findings that it reports, helping to evaluate the comparative effectiveness of tools over time. 

Specifically, the Severity by Tool (Top 10 Most Findings) modal will provide a radar chart comparing the severity of the Findings your tools reveal. 

Severity by Tool Monthly will also provide a table arranged by the total Findings a particular scan type revealed on a particular date. Each column of this table can also be toggled to present in ascending or descending order.

Collectively, the suite of available Metrics dashboards enables organizations to move beyond raw vulnerability data and make informed, risk-driven decisions across the entire security lifecycle.