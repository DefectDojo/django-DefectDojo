---
title: "Audit Logs"
description: "Access audit logs for DefectDojo objects"
weight: 1
audience: pro
---
**Audit Logs** provide a chronological record of actions performed within DefectDojo. They ensure accountability and compliance by recording which user performed which action and when.

Audit logs are valuable for:
- **Security investigations**: Determine who performed sensitive actions.
- **Compliance**: Demonstrate an auditable history for standards such as SOC 2, ISO 27001, or internal governance requirements.
- **Troubleshooting**: Identify when a configuration or object changed.
- **Accountability**: Track administrative and user activity across the platform.

In short, Audit Logs provide a centralized record of important events that helps administrators understand their instance’s activity history beyond the history of any single object. 

### Accessing Audit Logs

Audit Logs are accessible from the sidebar under **Settings > Operations > Audit Logs**. 

![image](images/auditlogs_ss2.png)

### Permissions 

Access to Audit Logs is determined by a User’s global role.

The global roles of API Importer, Reader, and Writer do not permit access to Audit Logs, whereas Maintainer and Owner roles do. Superusers also have access to Audit Logs regardless of their global role. The same rule applies to the Audit Log API, including exports and polling, so a non-superuser account (for example, one used by a SIEM collector) can read the audit log through an API token once it holds a global Maintainer or Owner role, or a custom role that grants Audit Log View.

More information about permissions and global roles can be found [here](/admin/user_management/pro_permissions_overhaul/).

## Audit Logs Contents 

Audit Logs track a variety of actions, including, but not limited to:
- Interactions with objects (e.g., creating, updating, or deleting objects).
- Updates to a Finding’s priority and risk score.
- Creation and editing of User profiles.
- EPSS percentile updates. 

- Each [View As User](../pro__view_as_user/) session: an entry when it starts, naming the user who started it and the user viewed, and an entry when it ends, with how it ended.

The full list of changes and actions that are captured in Audit Logs can be found [here](../pro__audit_log_index/).

## Audit Logs Table 

Audit Logs includes multiple columns with various data to improve traceability, including:
- **Timestamp**: The time at which the change took place.
- **User**: The user who performed the action.
- **Action**: What action was performed (e.g., create, update, delete). 
- **Model**: What aspect was modified (e.g., Asset, User, Finding, Location, Firewall, URL, etc.). 
- **Object ID**: DefectDojo’s unique ID for the object that was modified. 
- **Object Name**: The name of the affected object. 
- **Changes**: Specific fields modified by the action, including their previous and updated values.
- **Data**: An exact snapshot of the record at the moment the action was taken, including every field, not just those that were changed. 
- **Context**: Surrounding details of how the change happened, who made it, where in the app it came from, and a label saying what job performed the change (if it was an automated job). 
- **URL**: The URL used to execute the particular operation. These paths could refer to DefectDojo’s Vue UI, or to the REST API. The URL field will not be populated for back-end processes. 
- **IP Address**: The network address of the device that made the change. This will not be populated for back-end processes.

### Audit Logs Timeline

By default, Audit Logs display entries from the previous 31 days. Older entries remain available and can be viewed by adjusting the Timestamp filter. 

![image](images/auditlogs_ss3.gif)

### Filtering Audit Logs

The Audit Logs table includes filters to help narrow the displayed results. For example, if you wanted to see actions pertaining only to Assets, you could filter for Assets within the table. 

![image](images/auditlogs_ss1.png)

The columns within Audit Logs can also be arranged in alphabetical, ascending/descending, or chronological order, depending on the contents of the column in question. Columns may also be dragged left or right depending on their preferred arrangement.

![image](images/auditlogs_ss4.gif)

### Exporting Audit Logs

The **Export** button above the Audit Logs table downloads the entries the table's filters select, as **CSV** or **JSON**, in the table's sort order. Every matching entry is included, not just the page on screen. Like the table, an export with no Timestamp filter covers the previous 31 days.

- One export holds at most 50,000 entries. When the filters select more, the export is refused with a message saying so: narrow the Timestamp filter (for example, export one month at a time), or read the entries through the API as described in [Polling the Audit Log API](#polling-the-audit-log-api).
- In the CSV file, the Changes, Data and Context columns hold JSON text. A value that a spreadsheet would run as a formula (one starting with `=`, `+`, `-` or `@`) is written with a leading `'` so that it is shown as text.
- Exporting needs the same access as viewing Audit Logs.
- Each export is itself recorded in the Audit Logs, as an **Audit Log Export** entry naming the user, the IP address, the filters used and the number of entries exported.

## Audit Log Retention

By default DefectDojo keeps every audit log entry. An administrator can set how long entries are kept in **Settings > System Settings**, under **Delete Audit Log Events After (Months)**:

- **0**, the default, keeps every entry indefinitely.
- Any value from 1 to 120 deletes entries older than that many months. Thirteen months keeps a full year plus a month of overlap, which is what many audit programs ask for.

Entries past the window are deleted by a nightly job, in small batches so the database stays responsive. Entries inside the window are never touched, so lengthening the window loses nothing, and shortening it deletes the older entries on the next nightly run. On a large instance the first run after shortening the window can take more than one night to finish; it continues where it left off. Changing the setting is recorded in the Audit Logs like any other System Settings change.

Self-hosted deployments may also set `DD_AUDITLOG_FLUSH_RETENTION_PERIOD` (in months). That is the open-source flush, and it only deletes events from the open-source audit tables. The System Settings value is the one that limits the Pro tables, so set it even when the deployment variable is set. Entries on **Legacy Audit Logs** (the audit log from before the current one) are not deleted by either.

### Storage Estimate

Next to the retention setting, **Estimated Audit Log Storage** shows how much database space the audit log uses now, how fast it has grown, and about how large it will be with the retention you set. The estimate comes from database statistics, so it is approximate, and it needs at least a month of history to project growth.

The same information is available from the API at `GET /api/v2/audit_log/retention/`:

- `retention_months` and `retained_since`: the System Settings window, which the nightly job applies to every audit event table, and the oldest moment it keeps (null while the setting is 0).
- `deployment_retention_months` and `deployment_retained_since`: `DD_AUDITLOG_FLUSH_RETENTION_PERIOD` and its cutoff, for the open-source tables only (null when the variable is not set).
- `storage`: the size and growth figures behind the estimate.

## Object History 

**Object History** provides a chronological record of changes made to an individual DefectDojo object (e.g., Organization, Asset, Engagement, Test, Findings, Endpoints, and Risk Acceptances). Each entry includes details such as the timestamp, user, action performed, and the associated changes.

Unlike Audit Logs, which record events across an entire instance, Object History pertains strictly to activity for a single object, making it easier to understand an object's history without filtering through unrelated system events.

Object History is useful for:
- Reviewing the progression of an object over time.
- Determining when a change was made.
- Identifying which user made a modification.
- Troubleshooting unexpected changes.

### Accessing Object History 

Object History can be accessed through the gear menu at the top right corner of any object’s view. Only Users with access to the object in question can view the object’s Object History. 

### Audit Logs and Object History 

While the function of Audit Logs and Object History overlaps, they operate at different scopes. Object History focuses on changes made to individual objects, whereas Audit Logs provide a system-wide record of significant events across your DefectDojo instance, offering a broader, bird's-eye view of activity.

## Endpoints 

### Object History Endpoint (Pro Only)

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users have access to a `/history` API path for these objects to view similar data.  For example: `/api/v2/findings/{id}/history/`.

### Audit Log Endpoint (Pro Only)

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users also have access to a dedicated `/api/v2/audit_log/` endpoint for their entire instance. It can be read by users and API tokens with access to Audit Logs (see [Permissions](#permissions)).

* Sending default or empty parameters will return the last 31 days of audit logs.
* Parameter `window_month` takes a month and year in the format MM-YYYY and returns the audit logs for that month.
* You can set the `window_start` parameter to limit these logs to a shorter window, rather than returning the entire month.
* `timestamp_on` and `timestamp_during` filter by whole days and take dates (`YYYY-MM-DD`).
* `timestamp_after` and `timestamp_before` take either a date (`YYYY-MM-DD`, whole days: `timestamp_after` includes the named day) or an ISO 8601 date and time, which is compared to the microsecond.
* `created__gte`, `created__gt`, `created__lte` and `created__lt` take an ISO 8601 date and time and compare to the microsecond, for example `created__gte=2026-10-30T14:05:09Z`.
* Include a UTC offset in a date and time (`Z`, or `+02:00` written as `%2B02:00` in a URL); a value without one is read in the server's time zone.

A filter value the API cannot use is refused with a `400` response that names the parameter, rather than ignored. For example, `timestamp_on` with a date and time is refused with a message pointing to the `created__` filters.

### Polling the Audit Log API

To collect audit log entries continuously, for example into a SIEM, use `GET /api/v2/audit_log/poll/` rather than paging through the list. It returns entries oldest first, and each response carries a `cursor` that marks the last entry returned:

1. Start with a lower bound: `GET /api/v2/audit_log/poll/?created__gte=2026-10-01T00:00:00Z&limit=500`. Without `created__gte` or a cursor, polling starts 31 days back.
2. Store the `cursor` from the response. If `has_more` is `true`, request the `next` URL straight away; it repeats your filters with the new cursor.
3. When `has_more` is `false`, wait (for example, a minute) and request `next` again. A poll that finds nothing new returns the same cursor, so you can keep polling it.

Details:

* `limit` takes 1 to 1000 entries per poll (default 100).
* Every filter of the list endpoint can be added (for example `model_name=dojo_user`). The order is fixed, so the sort parameter `o` is refused.
* An entry is stamped with the time its database transaction started, so a long-running operation can commit entries that are older than ones already returned. To avoid missing them, a poll only returns entries at least `settle_seconds` old (default 60, up to 3600). Each response says up to which moment it returned entries in `settled_before`. Raise `settle_seconds` if long imports run on your instance and you need every entry they write. The wait is measured on the database's clock, the same clock that stamps each entry, so a difference between the application server's clock and the database's does not shorten it.
* The cursor is the position after one specific entry; keep the latest one you received. A cursor the API did not issue is refused with a `400`.
* The poll response has no total `count`. To count entries, use the list endpoint.

### Exporting Through the API

`GET /api/v2/audit_log/export/?export_format=csv` (or `json`) downloads the same file as the **Export** button, with the list endpoint's filters and sort order. See [Exporting Audit Logs](#exporting-audit-logs) for its limits.

### Paging Through Results

Both endpoints return entries one page at a time, with `count`, `next`, `previous` and `results`. `count` is exact for up to 10,000 entries. When more entries match, `count` is a lower bound and the response also includes `"count_is_lower_bound": true`, and the Audit Log page in the UI shows the total with a plus sign (for example, "10,001+"). To read every entry, follow the `next` link until it is empty rather than computing the last page from `count`.

For more information, see the API documentation, located in your instance: `your-instance.cloud.defectdojo.com/api/v2/oa3/swagger-ui/`