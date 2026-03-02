---
title: "Azure Active Directory"
description: "Configure Azure AD SSO and group mapping in DefectDojo Pro"
weight: 5
audience: pro
---

DefectDojo Pro supports login via Azure Active Directory (Azure AD), including automatic User Group synchronization. Open-Source users should refer to the [Open-Source Azure AD guide](../OS__azure_ad/).

## Prerequisites

Complete the following steps in the Azure portal before configuring DefectDojo:

1. [Register a new app](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) in Azure Active Directory.

2. Note the following values from the registered app:
   - **Application (client) ID**
   - **Directory (tenant) ID**
   - Under **Certificates & Secrets**, create a new **Client Secret** and note its value
   - **Application ID URI**

3. Under **Authentication > Redirect URIs**, add a **Web** type URI:
   `https://your-instance.cloud.defectdojo.com/complete/azuread-tenant-oauth2/`

## Configuration

In DefectDojo, go to **Enterprise Settings > OAuth Settings**, select **Azure AD**, and fill in the form:

- **Azure AD OAuth Key** — enter your **Application (client) ID**
- **Azure AD OAuth Secret** — enter your **Client Secret**
- **Azure AD Resource** — defaults to `https://graph.microsoft.com/`. This is the URI DefectDojo uses to read additional information (such as group names) from the [Microsoft Graph Web API](https://docs.azure.cn/en-us/entra/identity-platform/security-best-practices-for-app-registration#application-id-uri). Only change this if your group names are stored on a different API resource.
- **Azure AD Tenant ID** — enter your **Directory (tenant) ID**
- **Azure AD Groups Filter** — optionally enter a regex string to restrict which User Groups are imported (see [Group Mapping](#group-mapping) below)

Check **Enable Azure AD OAuth** and submit the form. A **Login With Azure AD** button will appear on the login page.

## Group Mapping

Group mapping allows DefectDojo to import [User Group](../../user_management/create_user_group/) membership from Azure AD. User Groups in DefectDojo govern product and product type access via [RBAC](../../user_management/set_user_permissions/).

Check **Enable Azure AD OAuth Grouping** to activate this feature. On login, DefectDojo will match the user's Azure AD groups to existing DefectDojo groups. Any groups not found in DefectDojo will be created automatically.

To import only a subset of groups, enter a regex in the **Azure AD Groups Filter** field. For example:
- `^team-.*` — matches any group starting with `team-`
- `teamA|teamB|groupC` — matches specific named groups

### Configuring Azure AD to send groups

The Azure AD token must be configured to include group IDs. Without this, no group information will be present in the token.

To configure this:
1. Add a [Group Claim](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims) in the Azure AD token configuration. If unsure which group type to select, choose **All Groups**.
2. Do **not** enable **Emit groups as role claims**.
3. Update the application's API permissions to include `GroupMember.Read.All` or `Group.Read.All`. `GroupMember.Read.All` is recommended as it grants fewer permissions.

### Group Cleaning

If **Enable Azure AD OAuth Group Cleaning** is enabled, DefectDojo groups created via Azure AD sync will be automatically removed when they have no remaining members. When a user is removed from a group in Azure AD, they are also removed from the corresponding group in DefectDojo.
