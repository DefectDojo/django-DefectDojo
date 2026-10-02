---
title: "Azure Active Directory"
description: "Configure Azure AD / Microsoft Entra ID SSO and group mapping in DefectDojo Pro"
weight: 60
audience: pro
---

DefectDojo Pro supports login via Microsoft Entra ID (Azure Active Directory) over OAuth 2.0, including automatic User Group synchronization. Open-source DefectDojo does not include SSO — see [Authorized Users](/admin/user_management/os__authorized_users/) for open-source access control.

## Callback URL

Entra ID needs the exact redirect URI DefectDojo listens on after a user authenticates. It is your DefectDojo base URL followed by `/complete/azuread-tenant-oauth2/`:

```
https://<your-instance>.cloud.defectdojo.com/complete/azuread-tenant-oauth2/
```

On-premise, replace the host with your own DefectDojo base URL, keeping the `/complete/azuread-tenant-oauth2/` path. Register this under **Authentication > Redirect URIs** as a **Web** platform URI.

## Prerequisites

Complete the following steps in the Azure portal before configuring DefectDojo:

1. [Register a new app](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app) in Microsoft Entra ID.

2. Note the following from the registered app's **Overview**:
   - **Application (client) ID**
   - **Directory (tenant) ID**

3. Under **Certificates & secrets**, create a new **Client secret** and note its **Value** (not the secret ID).

4. Under **Authentication > Redirect URIs**, add a **Web** platform URI set to the [Callback URL](#callback-url) above.

## Configuration

In DefectDojo, go to **Enterprise Settings > OAuth Settings**, select **Microsoft Entra ID**, and fill in the form. The field labels match the Entra portal:

- **Application (client) ID** — the client ID from step 2.
- **Client Secret** — the secret **Value** from step 3.
- **Directory (tenant) ID** — the tenant ID from step 2.
- **Application ID URI** — the resource DefectDojo reads additional information (such as group names) from. Defaults to `https://graph.microsoft.com` and is required; only change it if your group names live on a different API resource.
- **Azure AD Groups Filter** — optionally, a regex that restricts which groups are imported (see [Group Mapping](#group-mapping)).

Check **Enable Azure AD OAuth** and submit the form. (The Enable checkbox unlocks once the client ID and secret are filled in.) A **Login With Azure AD** button will appear on the login page.

Use **Validate Config** at any point to check the settings without saving them. It confirms the settings are complete, checks that the Entra discovery document is reachable for your tenant, and echoes the exact **redirect URI** to register at Entra.

## Group Mapping

Group mapping imports [User Group](../../user_management/create_user_group/) membership from Entra ID. User Groups in DefectDojo govern Asset and Organization access via [RBAC](../../user_management/set_user_permissions/).

Check **Enable Azure AD OAuth Grouping** to activate it. On login, DefectDojo matches the user's Entra groups to existing DefectDojo groups; any group not found is created automatically and its members are given the **Reader** role on the group.

To import only a subset of groups, enter a regex in the **Azure AD Groups Filter** field. For example:
- `^team-.*` — matches any group starting with `team-`
- `teamA|teamB|groupC` — matches specific named groups

### Configuring Entra ID to send groups

The token must be configured to include group IDs, or no group information reaches DefectDojo:

1. Add a [Group Claim](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims) in the app's **Token configuration**. If unsure which group type to select, choose **All groups**.
2. Do **not** enable **Emit groups as role claims**.
3. Grant the app the `GroupMember.Read.All` (recommended) or `Group.Read.All` API permission so DefectDojo can resolve group IDs to names via the Microsoft Graph.

### Group Cleaning

With **Enable Azure AD OAuth Group Cleaning** on, a DefectDojo group created by Azure AD sync is removed automatically once it has no remaining members, and a user removed from a group in Entra is removed from the corresponding DefectDojo group on their next login. Only Azure-AD-provisioned groups are affected; groups you created by hand, or that arrived from another provider, are never touched.

## First login and default access

New users are provisioned automatically on first login (when **Create User on Successful Login** is enabled under **Login Settings**), and existing users are matched by username. A user provisioned without any group membership lands with **no permissions**. To give every new SSO user a baseline, set a **Default group** and **Default group role** on the System Settings page — see [Default access for SSO-provisioned users](/admin/sso/pro__saml/#default-access-for-sso-provisioned-users).

## Troubleshooting

**No groups are created or assigned.** The token is not emitting group claims. Work through [Configuring Entra ID to send groups](#configuring-entra-id-to-send-groups) and confirm the API permission was granted admin consent.

**Login fails immediately after the Microsoft prompt.** A redirect-URI mismatch — confirm the **Web** redirect URI is exactly the [Callback URL](#callback-url).

**The client secret stops working after a while.** Entra client secrets expire. Create a new secret, update the **Client Secret** field, and save.

**Start with Diagnostics.** Rejected sign-ins are recorded under **Connect > Diagnostics** with the reason each was refused. See [Authorization Connectors](/admin/sso/pro__authorization_connectors/) for the difference between what is configured and why a sign-in failed.
