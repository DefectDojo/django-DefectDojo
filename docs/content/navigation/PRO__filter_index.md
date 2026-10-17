---
title: "Filter Index"
description: "Reference for all filters in DefectDojo"
weight: 5
aliases:
  - /en/working_with_findings/organizing_engagements_tests/filter_index
---
**Note: Currently this article only covers Finding Filters available in the DefectDojo Pro UI, but this article will be expanded in the future to govern more object types, along with Open-Source filters.** 

Here is a list of filters that can be applied in the DefectDojo Pro UI to sort lists of Findings.  DefectDojo Filters can be used to assist with navigating through lists of Objects, building custom [dashboards](/metrics_reports/dashboards/custom-dashboards/), or creating automation via [Rules Engine](/automation/rules_engine/about).

## Where filters are applied

Every filter below can be set from a column's header or from the filter bar above the Findings list, which shows each active filter as a chip and offers **Add Filter** for the rest. With more than one filter active, the connective between the chips chooses whether a Finding must match **all** of them (the default) or **any** of them. See [Customizing Tables](/navigation/table_customization/) for the bar, the match mode, and the grid view of the list.

## How date filters are evaluated

Filters that take a date — **Date Created**, **SLA Expiration Date**, **Last Status Update**, **Planned Remediation Date**, and the Jira date filters listed below — offer five operators:

| Operator | Matches |
| --- | --- |
| **On** | The whole of the named day. |
| **Before** | Everything up to the start of the named day. The named day itself is **not** included. |
| **After** | Everything past the start of the named day — so the named day **is** included. |
| **During** | A start day through an end day, both **inclusive**. |
| **Within** | A rolling window ending now: Past 7, 14, 30, 90 or 180 Days, or Past Year. |

Note that **Before** and **After** are deliberately not mirror images of each other: *Before 8 August* excludes 8 August, while *After 8 August* includes it.

### Day boundaries and your timezone

**On**, **Before**, **After** and **During** resolve their day boundaries in **your own timezone**, detected from your browser. A date range therefore covers midnight to midnight as *you* experience it, rather than in UTC or in the server's timezone. Two people in different timezones can see slightly different results from the same filter for Findings falling close to a day boundary.

**Within** is unaffected — it is a rolling window measured back from the current moment, so it has no day boundary to resolve.

> **Where this does not apply.** Only requests from the Pro UI carry your timezone. Anything that runs without a browser — the `/api/v2` REST API, scheduled reports, and the Rules Engine — falls back to the server's configured timezone (`DD_TIME_ZONE`, `UTC` unless your administrator changed it). If your browser timezone differs from the server's, a scheduled report and an on-screen filter using the same date can return slightly different rows. Exports started from a filtered table in the UI are not affected — they use your timezone, matching what you were looking at.

## Selecting every match in a searchable list filter

List filters whose options come from a search box, such as the Asset and Organization filters on the Findings, Engagements, Tests, and Endpoints tables, can hold thousands of options, so checking them one at a time is not practical. Type a search into the filter, and once the results load the filter offers **Select all N matching**, where N is the number of matching options. Selecting it filters the table to every option whose name contains the search text (case-insensitive), not just the options loaded on screen.

- The selection appears as a single **All matching "text"** chip. Remove the chip, or select **Deselect all**, to go back to picking individual options.
- While a match selection is active, the individual options are locked, because the selection covers every match rather than a list of picks.
- The selection is stored as the search text, so a table URL or a saved table preference carries it compactly however many options match.
- **Deselect all** also clears any options you picked one by one.

## Filtering on a list of values

### In List and Not in List on text filters

Text filters such as **Title**, **Component Name** and **File Path** offer **In List** and **Not in List** next to **Contains**, **Exact** and the other operators. Enter the values separated by commas.

- Case is ignored, and so are spaces around each value. Blank entries are skipped.
- Each value is matched exactly as written. Characters such as `%`, `*` and `^` are not wildcards.
- **Not in List** keeps Findings that have no value in that field.

### Include and Exclude on multi-select filters

Every multi-select filter has an **Include** / **Exclude** switch. **Include** keeps the rows that match a selected value. **Exclude** keeps every row except those, so "all but these three scanners" is three picks instead of unticking everything else. Rows with no value in that column are kept under **Exclude**.

### Pasting a list into the Asset and Organization filters

The Asset and Organization filters on the Findings, Engagements, Tests and Endpoints tables have a **Paste List** button. Paste the names or IDs copied from a ticket or a CMDB export into the box it opens, separated by commas, new lines or tabs, then add them. Every Asset or Organization they name joins the filter.

- A name matches whatever its case. A number also matches the Asset or Organization with that ID.
- Only Assets and Organizations you are allowed to see are matched.
- Names that match nothing stay in the box, and a note under it says how many, so you can correct them and add them again.

### Long lists

The table sends its filters in the address of each request, and that address has a size limit. In practice a filter of a few hundred values is the most the table can apply. Past that, it shows **Filter Too Long** and loads nothing until you remove some values. This covers every list filter: In List, a long Paste List, and a large selection under Include or Exclude.

The server takes up to 1,000 values in one In List and refuses a longer list with an error rather than shortening it.

## How number filters are evaluated

Numeric filters — including **Age** and **SLA** — offer a match operator alongside the value: **Equals**, **Not Equals**, **Greater Than**, **Greater Than or Equal To**, **Less Than**, **Less Than or Equal To**, **In List**, and **Not in List**. Entering a value without choosing an operator matches on **Equals**.

## SLA filters

Three filters cover SLA, and they answer different questions:

| Filter | Type | What it matches |
| --- | --- | --- |
| **SLA Expiration Date** | Date, with the operators above | The date the Finding's SLA runs out. |
| **SLA** | Number, with operators | **Days remaining** on the SLA clock. Negative values are overdue, so `Less Than 0` finds everything currently past its deadline, and `Less Than 7` finds what is due within the week. |
| **Mitigated Within SLA** | True / False | Whether a Finding that **has been mitigated** was mitigated before its SLA expired. |

**Mitigated Within SLA is narrower than it sounds, and this catches people out.** Both values only ever match Findings that are **already mitigated** and are **not Info severity**:

* **True** — mitigated on or before the SLA expiration date.
* **False** — mitigated after the SLA expiration date.

An **open** Finding that is already overdue matches **neither** value, because it has not been mitigated yet. To find those, use **SLA** `Less Than 0` instead. Info-severity Findings are excluded from both sides.

> If a Finding's SLA configuration has **Cap SLA by CISA KEV Due Date** enabled, both **SLA** and **SLA Expiration Date** reflect the tightened, KEV-capped deadline rather than the plain severity-based window. There is no separate indicator for this in the filters — see [EPSS / KEV](/triage_findings/finding_scoring/epss_kev/).

## Findings
These fields are specific to DefectDojo Findings and are used to organize a Finding.  Each of these filters is a separate column in the All Findings table.

Findings in DefectDojo can be filtered by:

### DefectDojo Metadata
These Filters are related directly to DefectDojo core functionality.

##### Cannot be modified
These Filters are assigned at the time of issue creation, and cannot be directly modified via Edit Finding.

* Finding Severity (any of Info, Low, Medium, High, Critical)
* Asset
* Organization
* Engagement
* Engagement Version
* Test
* Test Type
* Test Version
* Date Created
* Age (Finding age in days)
* SLA (days remaining on the SLA clock — negative means overdue; see [SLA filters](#sla-filters))
* SLA Expiration Date (see [SLA filters](#sla-filters))
* Mitigated Within SLA (True or False — note this only matches Findings that have already been Mitigated; see [SLA filters](#sla-filters))
* Reporter (user or service who created the Finding)
* Found by (refers to the Tool)

##### Can be modified
These fields are set when an issue is created, but can be modified as an issue progresses.

* [Status](/triage_findings/findings_workflows/finding_status_definitions/)
* Last Status Update (Timestamp)
* Mitigated (True or False)

##### Additional Model Functions
These DefectDojo functions can be used to further organize your Findings or track remediation.

* Finding Tags
* Reviewers (Assigned User)
* Has Notes (True/False)
* Group (refers to the [Finding Group](/triage_findings/findings_workflows/editing_findings/#finding-group-actions), if one exists)
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
