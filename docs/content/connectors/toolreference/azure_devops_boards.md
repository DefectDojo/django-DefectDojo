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
