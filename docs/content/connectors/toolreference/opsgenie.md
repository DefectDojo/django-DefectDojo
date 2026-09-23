---
title: "Opsgenie"
description: "How to set up the Opsgenie Downstream Connector for DefectDojo"
weight: 99
audience: pro
---
The Opsgenie Integration allows you to push DefectDojo Findings and Finding Groups as Opsgenie Alerts, optionally routed to an Opsgenie Team as a responder.

### Instance Setup

- **Label** should be the label that you want to use to identify this integration.
- **Location** should be set to `https://api.opsgenie.com`.  If your Opsgenie account is hosted in the EU service region, use `https://api.eu.opsgenie.com` instead.  If your alerts live in Jira Service Management Operations (Atlassian is folding Opsgenie into JSM), use `https://api.atlassian.com/jsm/ops/integration`.
- **API Key** should be set to an Opsgenie **API integration** key.  An account administrator can create one in the Opsgenie web app under **Settings > Integrations**: add an integration of type **API** and give it *Create and Update Access* (and *Read Access* so DefectDojo can verify the connection).  Note that this is an integration key, not a personal API key - DefectDojo authenticates with `GenieKey` authorization, which only integration keys support.

### Issue Tracker Mapping

- **Team Name** *(optional)* should be the name of the Opsgenie Team to add as a responder on created alerts.  You can leave it empty: if the API integration key is team-scoped, alerts route to that team automatically, and otherwise your account's own routing rules decide the responders.

### Severity Mapping Details

Severities map to the Opsgenie alert **Priority** field, which uses Opsgenie's fixed `P1` (critical) through `P5` (informational) scale:

- **Severity Field Name**: `Priority`
- **Info Mapping**: `P5`
- **Low Mapping**: `P4`
- **Medium Mapping**: `P3`
- **High Mapping**: `P2`
- **Critical Mapping**: `P1`

If a severity is mapped to an unrecognized value, the priority is omitted and Opsgenie applies its own default (`P3`).

### Status Mapping Details

Opsgenie alerts are `open` or `closed`, and an open alert can additionally be `acknowledged`:

- **Status Field Name**: `Status`
- **Active Mapping**: `open`
- **Closed Mapping**: `closed`
- **False Positive Mapping**: `closed`
- **Risk Accepted Mapping**: `acknowledged`

Note that `closed` is a final status in Opsgenie - a closed alert cannot be reopened, and its alias is released.  Unlike some other tools, Opsgenie does allow content edits after creation, so pushing an updated Finding syncs its message, description, and priority alongside the status.

DefectDojo sets each alert's **alias** to a stable key derived from the Finding or Finding Group, and Opsgenie de-duplicates open alerts by alias - so re-pushing the same Finding updates the existing open alert instead of creating a duplicate.
