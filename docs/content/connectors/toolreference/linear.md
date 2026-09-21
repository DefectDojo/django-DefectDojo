---
title: "Linear"
description: "How to set up the Linear Downstream Connector for DefectDojo"
weight: 87
audience: pro
---
The Linear integration allows you to push DefectDojo Findings as [Linear](https://linear.app/) Issues. Issues are created in a Team in your Linear workspace.

### Instance Setup

- **Label** should be the label that you want to use to identify this integration.
- **Location** should be set to `https://api.linear.app/graphql`.
- **API Key** should be set to a Linear personal API key. Keys can be generated in Linear under Settings, then Security & access, then [API](https://linear.app/settings/account/security). The key is sent to Linear's GraphQL API in the `Authorization` header.

### Issue Tracker Mapping

- **Team (Group) ID** should be set to the ID of the Linear Team that Issues will be created for. You can list your Teams and their IDs by calling the Linear GraphQL API:

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ teams { nodes { id name key } } }"}' https://api.linear.app/graphql
```

### Severity Mapping Details

A Linear Issue carries a numeric **priority** rather than a severity field. Each DefectDojo severity maps to a Linear priority, where `1` is Urgent and `4` is Low:

- **Severity Field Name**: `Priority`
- **Info Mapping**: `4`
- **Low Mapping**: `4`
- **Medium Mapping**: `3`
- **High Mapping**: `2`
- **Critical Mapping**: `1`

### Status Mapping Details

Each status value must be set to the ID of a Workflow State in your Linear Team. Workflow State IDs are unique to each workspace, so there are no default values. You can list the Workflow States and their IDs by calling the Linear GraphQL API:

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ workflowStates { nodes { id name type team { key } } } }"}' https://api.linear.app/graphql
```

- **Status Field Name**: `Workflow State ID`
- **Active Mapping**: the ID of a started or unstarted state, for example `Todo` or `In Progress`.
- **Closed Mapping**: the ID of a completed state, for example `Done`. When a Finding is deleted in DefectDojo, its Issue is moved to this state.
