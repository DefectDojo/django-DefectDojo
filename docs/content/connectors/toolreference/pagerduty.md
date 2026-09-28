---
title: "PagerDuty"
description: "How to set up the PagerDuty Downstream Connector for DefectDojo"
weight: 102
audience: pro
---
The PagerDuty Integration allows you to push DefectDojo Findings and Finding Groups as PagerDuty Incidents, opened on a PagerDuty Service of your choice.

### Instance Setup

- **Label** should be the label that you want to use to identify this integration.
- **Location** should be set to `https://api.pagerduty.com`.  If your PagerDuty account is hosted in the EU service region, use `https://api.eu.pagerduty.com` instead.
- **API Token** should be set to a PagerDuty REST API key.  An account administrator can create one in the PagerDuty web app under **Integrations > API Access Keys > Create New API Key**.  Leave "Read-only" unchecked - DefectDojo needs to create and update incidents.
- **From Email** should be the email address of a valid user on your PagerDuty account.  PagerDuty requires this address when creating or updating incidents, and it will be shown as the incident requester.

### Issue Tracker Mapping

- **Service ID** should be the ID of the PagerDuty Service that incidents will be opened on.  You can find it at the end of the URL while looking at the Service in PagerDuty, for example `https://{your-subdomain}.pagerduty.com/service-directory/{service id}`.

### Severity Mapping Details

By default this maps to the PagerDuty incident **Urgency** field, which only accepts `high` or `low`:

- **Severity Field Name**: `Urgency`
- **Info Mapping**: `low`
- **Low Mapping**: `low`
- **Medium Mapping**: `low`
- **High Mapping**: `high`
- **Critical Mapping**: `high`

Alternatively, if your PagerDuty account has [Priorities](https://support.pagerduty.com/main/docs/incident-priority) enabled, you can map severities to Priority names instead.  Set the **Severity Field Name** to `Priority` and use your account's Priority names (for example `P1` through `P5`) as the mapping values.  When mapping to Priority, the incident's Urgency is left to your Service's own urgency rules.

### Status Mapping Details

PagerDuty incidents have three statuses: `triggered`, `acknowledged`, and `resolved`.

- **Status Field Name**: `Status`
- **Active Mapping**: `triggered`
- **Closed Mapping**: `resolved`
- **False Positive Mapping**: `resolved`
- **Risk Accepted Mapping**: `acknowledged`

Note that `resolved` is a final status in PagerDuty - a resolved incident cannot be reopened.  Also note that PagerDuty does not allow an incident's title or description to be edited after creation, so pushing an updated Finding will sync its status, urgency, and priority, but not content changes.
