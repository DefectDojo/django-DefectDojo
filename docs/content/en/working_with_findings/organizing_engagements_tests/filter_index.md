---
title: "Filter Index"
description: "Reference for all filters in DefectDojo"
weight: 5
---

**Note: Currently this article only covers Finding Filters available in the DefectDojo Pro Beta UI, but this article will be expanded in the future to govern more object types, along with Open-Source filters.** 

Here is a list of filters that can be applied in the DefectDojo Beta UI to sort lists of Findings.  DefectDojo Filters can be used to assist with navigating through lists of Objects, creating custom [Dashboard Tiles](/en/customize_dojo/dashboard_notifications/about_custom_dashboard_tiles/), or creating automation via [Rules Engine](/en/customize_dojo/rules_engine/).

## Findings
These fields are specific to DefectDojo Findings and are used to organize a Finding.  Each of these filters is a separate column in the All Findings table.

Findings in DefectDojo can be filtered by:

### DefectDojo Metadata
These Filters are related directly to DefectDojo core functionality.

##### Cannot be modified
These Filters are assigned at the time of issue creation, and cannot be directly modified via Edit Finding.

* Finding Severity (any of Info, Low, Medium, High, Critical)
* Product
* Product Type
* Engagement
* Engagement Version
* Test
* Test Type
* Test Version
* Date Created
* Age (Finding age in days)
* SLA Expiration Date
* Mitigated Within SLA (True or False value: was the Finding Mitigated within SLA or not?)
* Reporter (user or service who created the Finding)
* Found by (refers to the Tool)

##### Can be modified
These fields are set when an issue is created, but can be modified as an issue progresses.

* [Status](/en/working_with_findings/findings_workflows/finding_status_definitions/)
* Last Status Update (Timestamp)
* Mitigated (True or False)

##### Additional Model Functions
These DefectDojo functions can be used to further organize your Findings or track remediation.

* Finding Tags
* Reviewers (Assigned User)
* Has Notes (True/False)
* Group (refers to the [Finding Group](/en/working_with_findings/findings_workflows/editing_findings/#finding-group-actions), if one exists)
* Risk Acceptance (select one or more existing Risk Acceptances from the list)

### Tool-Specific Metadata
These fields have no direct impact on the functionality of DefectDojo, but provide additional information to help explain and mitigate issues.  They can be set when a Finding is initially created (using information in an incoming report), or they can be changed by a user.

* CWE Value
* Vulnerability ID (usually a CVE)
* EPSS Score
* EPSS Percentile
* Service
* Planned Remediation Date
* Planned Remediation Version
* Has Component (True/False)
* Component Name
* Component Version
* File Path
* Effort for Fixing

### Jira Metadata
If using the Jira integration, these filters track updates to linked Jira Issues.

* Jira Issue (Can filter by whether the Finding has one, or not)
* Jira Age (Age of Jira Issue)
* Jira Change (Last time changes were pushed to Jira)
