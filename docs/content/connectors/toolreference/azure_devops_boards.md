---
title: "Azure DevOps Boards"
description: "How to set up the Azure DevOps Boards Downstream Connector for DefectDojo"
weight: 21
audience: pro
---
### Instance Setup

- **Label** should be the label that you want to use to identify this integration.
- **Location** should be set to your Azure URL - for example `https://dev.azure.com/{your organization}`
- **Token** should be set to a personal access token from Azure.

Authentication with Azure DevOps requires a [personal access token](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows)
with permissions set to "Read, Write and Manage" for "Work Items" for the Azure Project that you wish to work with.

### Issue Tracker Mapping

These details dictate how DefectDojo will map Finding or Finding Group attributes to a given Project in Azure DevOps:

#### Issue Tracker Mapping Details

The `Project ID` field corresponds to the name or the ID of the Project in Azure.

#### Severity Mapping Details

The attributes in the form are supplied as defaults, and are as follows:

- **Severity Field Name**: `/fields/Microsoft.VSTS.Common.Priority`
- **Info Mapping**: `4`
- **Low Mapping**: `4`
- **Medium Mapping**: `3`
- **High Mapping**: `2`
- **Critical Mapping**: `1`

#### Status Mapping Details

The attributes in the form are supplied as defaults and are as follows:

- **Status Field Name**: `/fields/System.State`
- **Active Mapping**: `To Do`
- **Closed Mapping**: `Done`
- **False Positive Mapping**: `Done`
- **Risk Accepted Mapping**: `Done`

The status values must be states that exist on the work item type in your project's process.
For example, a project using the Scrum process template does not have a `To Do` state on
every type - check the allowed states in Azure DevOps and adjust the mapping to match.

#### Custom Field Mappings

Custom field mappings set additional Azure DevOps fields on the work items DefectDojo
creates or updates. The **Vendor Field** must be the Azure DevOps field's *reference name*
(for example `System.AreaPath`, `System.Tags`, or `Custom.MyField` - not its display name),
and the field must exist on the work item type in your project's process.

Two mappings are especially useful for routing work items to a team:

- **Area Path**: a mapping with Source `Static Value`, Vendor Field `System.AreaPath`, and a
  value such as `My Project\My Team` routes the work item to the team that owns that area.
- **Iteration Path**: a mapping with Vendor Field `System.IterationPath` places the work
  item in a sprint. The value can be a static iteration path, or the special token
  `@CurrentIteration` / `@CurrentIteration(My Team)`, which DefectDojo resolves at push time
  into the named team's currently active sprint (the project's default team when no team is
  given). If the team has no current sprint selected in Azure DevOps, the push fails with an
  error saying so.

Note that Azure DevOps boards and backlogs only display work item types that belong to a
backlog level. DefectDojo creates work items of type **Issue**; if that type is not part of
a backlog level in your project's process, the pushed items are only visible in the
**Boards → Work items** view regardless of their area or iteration.
