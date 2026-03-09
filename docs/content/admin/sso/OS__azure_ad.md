---
title: "Azure Active Directory"
description: "Configure Azure AD SSO and group mapping in Open-Source DefectDojo"
weight: 6
audience: opensource
---

Open-Source DefectDojo supports login via Azure Active Directory (Azure AD), including automatic User Group synchronization. DefectDojo Pro users should refer to the [Pro Azure AD guide](../PRO__azure_ad/).

## Prerequisites

Complete the following steps in the Azure portal before configuring DefectDojo:

1. [Register a new app](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) in Azure Active Directory.

2. Note the following values from the registered app:
   - **Application (client) ID**
   - **Directory (tenant) ID**
   - Under **Certificates & Secrets**, create a new **Client Secret** and note its value

3. Under **Authentication > Redirect URIs**, add a **Web** type URI:
   `https://your-instance.cloud.defectdojo.com/complete/azuread-tenant-oauth2/`

## Configuration

Set the following as environment variables, or without the `DD_` prefix in your `local_settings.py` file (see [Configuration](/get_started/open_source/configuration/)):

{{< highlight python >}}
DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_KEY=(str, 'YOUR_APPLICATION_ID'),
DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_SECRET=(str, 'YOUR_CLIENT_SECRET'),
DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_TENANT_ID=(str, 'YOUR_DIRECTORY_ID'),
DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_ENABLED=True
{{< /highlight >}}

Restart DefectDojo. A **Login with Azure AD** button will appear on the login page.

## Group Mapping

To import User Group membership from Azure AD, set the following variable:

{{< highlight python >}}
DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_GET_GROUPS=True
{{< /highlight >}}

On login, DefectDojo will assign the user to all groups found in the Azure AD token. Any groups not found in DefectDojo will be created automatically. This allows product access to be governed via groups.

### Configuring Azure AD to send groups

The Azure AD token must be configured to include group IDs. Without this, no group information will be present in the token.

To configure this:
1. Add a [Group Claim](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims) to the token. If unsure which group type to select, choose **All Groups**.
2. Do **not** enable **Emit groups as role claims**.
3. Update the application's API permissions to include `GroupMember.Read.All` or `Group.Read.All`. `GroupMember.Read.All` is recommended as it grants fewer permissions.

### Filtering groups

To limit which groups are imported, use a regex filter:

{{< highlight python >}}
DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_GROUPS_FILTER='^team-.*'  # or 'teamA|teamB|groupC'
{{< /highlight >}}

### Automatic Group Cleanup

To remove stale groups when users are removed from them in Azure AD:

{{< highlight python >}}
DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_CLEANUP_GROUPS=True
{{< /highlight >}}

When a user is removed from a group in Azure AD, they are also removed from the corresponding group in DefectDojo. Empty groups are left in place for record purposes.
