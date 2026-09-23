---
title: "Zendesk"
description: "How to set up the Zendesk Downstream Connector for DefectDojo"
weight: 144
audience: pro
---
The Zendesk Integration allows you to push DefectDojo Findings and Finding Groups as Zendesk tickets, assigned to a Zendesk Group of your choice.

### Instance Setup

- **Label** should be the label that you want to use to identify this integration.
- **Location** should be set to your Zendesk account URL, for example `https://your-subdomain.zendesk.com`.
- **Email** should be the email address of the Zendesk agent the API token belongs to.
- **API Token** should be set to a Zendesk API token.  An administrator can create one in the Zendesk Admin Center under **Apps and integrations > APIs > Zendesk API** (token access must be enabled).

### Issue Tracker Mapping

- **Group ID** should be the numeric ID of the Zendesk Group that tickets will be assigned to.  You can find it in the Admin Center under **People > Team > Groups**, or in the URL while viewing the group.

### Severity Mapping Details

This maps to the Zendesk ticket **Priority** field, which accepts `low`, `normal`, `high`, and `urgent`:

- **Severity Field Name**: `Priority`
- **Info Mapping**: `low`
- **Low Mapping**: `low`
- **Medium Mapping**: `normal`
- **High Mapping**: `high`
- **Critical Mapping**: `urgent`

### Status Mapping Details

Zendesk tickets support the statuses `new`, `open`, `pending`, `hold`, `solved`, and `closed`.  Note that `hold` must be enabled on your account before it can be used.

- **Status Field Name**: `Status`
- **Active Mapping**: `new`
- **Closed Mapping**: `solved`
- **False Positive Mapping**: `solved`
- **Risk Accepted Mapping**: `pending`

A few Zendesk-specific behaviors to be aware of:

- The ticket description is the first comment in Zendesk and cannot be edited after creation, so pushing an updated Finding will sync the ticket's subject, priority, and status, but not description changes.
- Tickets are marked `solved` rather than deleted when a Finding is removed; Zendesk closes solved tickets automatically after a period of time.
- `closed` is a final status - closed tickets cannot be updated at all, and pushing a Finding whose ticket has closed will report an error.
