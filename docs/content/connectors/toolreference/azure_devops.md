---
title: "Azure DevOps"
description: "How to set up the Azure DevOps Upstream Connector for DefectDojo"
weight: 20
audience: pro
---
The Azure DevOps connector is an **Asset Connector**: it enumerates the git repositories in every project of your Azure DevOps organization and creates a DefectDojo Asset for each repository, grouped into Organizations by Azure DevOps project. No findings are imported.

#### Prerequisites

You will need a Personal Access Token (PAT) for the organization. We recommend creating the token from a dedicated service account. Only read scopes are required:

1. In Azure DevOps, open **User settings \> Personal access tokens \> New Token**.
2. Click **Show all scopes**, then select **Code: Read** and **Project and Team: Read**.

Only Azure DevOps Services (dev.azure.com) is supported; on-premise Azure DevOps Server is not supported at this time.

#### Connector Mappings

1. Enter your organization URL in the **Location** field: `https://dev.azure.com/{your-organization}`. Legacy `https://{your-organization}.visualstudio.com` URLs are also accepted, and any extra path segments (for example, a link to a specific project) are ignored.
2. Enter the PAT in the **Secret** field.

Each repository becomes a Record named after the repository, grouped by its Azure DevOps **project**. Disabled repositories are skipped, so disabling or deleting a repository flags its Record as `MISSING` on the next Sync.
