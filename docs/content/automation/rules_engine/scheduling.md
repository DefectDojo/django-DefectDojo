---
title: "Scheduling Rules"
description: "Automatically run Rules Engine rules on a recurring or one-time schedule"
weight: 2
audience: pro
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Rules Engine Scheduling is a DefectDojo Pro-only feature.</span>

Rules can be scheduled to run automatically rather than triggered manually each time.  A scheduled rule will execute against all Findings that match its filter conditions at the configured time.

The user setting up the schedule must have the **Change Scheduling Service Schedule** configuration permission.

## Schedule Types

### Single Run

A Single Run schedule executes the rule once at a specific date and time.  After the run completes, the schedule is not repeated.

### Repeated Run

A Repeated Run schedule allows you to trigger a rule on a recurring basis — for example, every day at 9:00 AM, or every Monday at 15:00.

**Note:** Rules Engine schedules are limited to quarter-hour marks.  The minute field of a cron schedule must be one of: **0, 15, 30, or 45**.  Other minute values are not permitted.

Examples of valid schedules:
- Every hour on the hour: `0 * * * *`
- Every day at 9:15 AM: `15 9 * * *`
- Every Monday at 3:00 PM: `0 15 * * 1`
- Every 15 minutes: `0,15,30,45 * * * *`

## Creating a Schedule for a Rule

1. Navigate to the **All Rules** page from the **Rules Engine** menu in the sidebar.
2. Find the rule you want to schedule, and open its action menu (**⋮**).
3. Click **Schedule Rule**.  This option is only visible if the Scheduling Service is enabled and you have the required permission.
4. In the **Schedule Rule** modal, fill in the following fields:

| Field | Description |
|---|---|
| **Name** | A unique name for this schedule (required, max 100 characters). |
| **Description** | Optional description of the schedule's purpose. |
| **Trigger Type** | Choose **Single Run** for a one-time execution, or **Repeated Run** for a recurring cron schedule. |
| **Frequency** | For Repeated Run: use the cron builder to select the period (hourly, daily, weekly, etc.) and the specific minute, hour, and day values. For Single Run: select a date and time using the date picker. |
| **Enable Schedule** | Toggle to enable or disable the schedule.  A disabled schedule will not run until re-enabled. |

5. Click **Submit** to save the schedule.  The rule will run automatically at the next scheduled time.


## Permissions

Access to scheduling within Rules Engine requires Superuser permissions or the appropriate Configuration Permission.  See [User Permission Chart](/admin/user_management/user_permission_chart) for details.  
