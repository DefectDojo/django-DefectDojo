---
title: "Shortcut"
description: "How to set up the Shortcut Downstream Connector for DefectDojo"
weight: 124
audience: pro
---
The Shortcut integration allows you to push DefectDojo Findings as [Shortcut](https://www.shortcut.com/) Stories. Stories are created with the story type of Bug and assigned to a Team in your Shortcut workspace.

### Instance Setup

- **Label** should be the label that you want to use to identify this integration.
- **Location** should be set to `https://api.app.shortcut.com`.
- **API Token** should be set to a Shortcut API token. Tokens can be generated in Shortcut under Settings, then Your Account, then [API Tokens](https://app.shortcut.com/settings/account/api-tokens).

### Issue Tracker Mapping

- **Team (Group) ID** should be set to the UUID of the Shortcut Team that Stories will be created for. You can find this UUID by opening the Team page in Shortcut and copying the identifier from the URL, or by calling the Shortcut API:

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/groups
```

### Severity Mapping Details

Each severity value is applied to the Story as a label. Labels are created automatically in Shortcut if they do not already exist, so the default values below can be used as they are, or replaced with label names of your choosing. When a Finding's severity changes, the old severity label is removed from the Story and the new one is added.

- **Severity Field Name**: `Label`
- **Info Mapping**: `sev-info`
- **Low Mapping**: `sev-low`
- **Medium Mapping**: `sev-medium`
- **High Mapping**: `sev-high`
- **Critical Mapping**: `sev-critical`

### Status Mapping Details

Each status value must be set to the numeric ID of a Workflow State in your Shortcut workspace. Workflow State IDs are unique to each workspace, so there are no default values. You can list the Workflow States and their IDs by calling the Shortcut API:

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/workflows
```

- **Status Field Name**: `Workflow State ID`
- **Active Mapping**: the ID of the state for open work, for example a Backlog or To Do state.
- **Closed Mapping**: the ID of a Done type state. When a Finding is deleted in DefectDojo, its Story is moved to this state.
- **False Positive Mapping**: the ID of the state to use for False Positive Findings.
- **Risk Accepted Mapping**: the ID of the state to use for Risk Accepted Findings.
