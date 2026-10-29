---
title: "SAML Configuration"
description: "Configure SAML in DefectDojo Pro"
weight: 30
audience: pro
---

DefectDojo Pro supports SAML authentication, configured from **Connect > Authorization > Providers**. Open-source DefectDojo does not include SSO — see [Authorized Users](/admin/user_management/os__authorized_users/) for open-source access control.

## ACS URL (Assertion Consumer Service)

Your Identity Provider needs to know where to POST the SAML response after a user authenticates. DefectDojo's ACS URL is:

```
https://<your-instance>.cloud.defectdojo.com/saml2/acs/
```

On a self-hosted instance it is the same path on your own hostname: `https://<your-hostname>/saml2/acs/`.

A few things to know about this endpoint:

- **The endpoint accepts `POST` requests only.** Opening the ACS URL directly in a browser issues a GET and will return an **HTTP 405 Method Not Allowed**. This is expected behavior — it does not mean SAML is broken or misconfigured. The endpoint is designed to be invoked by your IdP as part of the SAML redirect flow, not by a browser typing the URL.
- **The ACS URL is available on your DefectDojo Cloud instance at all times** — you do not need to enable SAML in DefectDojo first before pointing your IdP at it. You can configure the IdP side and the DefectDojo side in either order.

## Setup

1. Open **Connect > Authorization > Providers** and select **SAML**.

   ![image](images/sso_betaui_1.png)

2. Set an **Entity ID** — a label or URL that your SAML Identity Provider uses to identify DefectDojo. This field is required.

3. Optionally set **Login Button Text** — the text shown on the button users click to begin SAML login.

4. Optionally set a **Logout URL** to redirect users to after they log out of DefectDojo.

5. Choose a **Name ID Format**:
   - **Persistent** — users are consistently identified by SAML across sessions.
   - **Transient** — users receive a different SAML ID on each login.
   - **Entity** — all users share a single SAML NameID.
   - **Encrypted** — each user's NameID is encrypted.

6. **Required Attributes** — specify the attributes DefectDojo requires from the SAML response.

7. **Attribute Mapping** — map the attributes your IdP sends to the DefectDojo user fields they should populate. Each row pairs one **SAML Attribute** with one **DefectDojo Field**; use **Add Attribute Mapping** for additional rows and the bin icon to remove one.

   ![image](images/sso_saml_attribute_mapping.png)

   - **SAML Attribute** is free text and must match the attribute name your IdP actually emits. Some IdPs (e.g. Entra ID / Azure AD) send fully qualified claim URIs such as `http://schemas.microsoft.com/identity/claims/emailaddress` rather than friendly names. If you are not sure what your IdP sends, enable **Enable SAML Debugging** (see [Troubleshooting](#troubleshooting)) and inspect the assertion in the logs.
   - **DefectDojo Field** is chosen from a list: **Username**, **First Name**, **Last Name** and **Email**.
   - A mapping fills user fields. It never decides which account a login lands on: DefectDojo always signs the login in to the account whose username equals the SAML `NameID` (see [Which account a login lands on](#which-account-a-login-lands-on)). A **Username** mapping is not used for that.
   - Mapping an attribute to **Email** is strongly recommended: DefectDojo uses the email address for notifications.
   - The same attribute may feed more than one field. The reverse is not allowed: each DefectDojo field may be mapped from only one attribute.
   - A row with only one half filled in is rejected on save, and the offending cell is highlighted. Rows you add but never fill in are discarded rather than treated as errors.

8. **IdP metadata** — supply one of the two, not both:
   - **Remote SAML Metadata** (the default) — the URL where your SAML Identity Provider metadata is hosted. DefectDojo fetches it, so the instance must be able to reach that URL. Prefer this when it can, because the IdP keeps the metadata current.
   - **Local SAML Metadata** — check **Use Local SAML Metadata** and upload the metadata XML file downloaded from your IdP (up to 1 MB). Use this when the instance cannot reach the IdP's metadata URL, for example a self-hosted instance with no outbound internet access. DefectDojo stores the file as `saml_metadata.xml` in its media directory and shows it on the form the next time you open it. Upload a new file whenever the IdP's signing certificate changes.

9. Check **Enable SAML** at the bottom of the form to activate SAML login. A **Login With SAML** button will appear on the DefectDojo login page.

   ![image](images/sso_saml_login.png).

## Additional Options

* **Create Unknown User** — automatically create a new DefectDojo user if they are not found in the SAML response.
* **Allow Unknown Attributes** — allow login for users who have attributes not listed in the Attribute Mapping.
* **Sign Assertions/Responses** — require all incoming SAML responses to be signed.
* **Sign Logout Requests** — sign all logout requests sent by DefectDojo.
* **Force Authentication** — require users to authenticate with the Identity Provider on every login, regardless of existing sessions.
* **Enable SAML Debugging** — log detailed SAML output for troubleshooting. See [Troubleshooting → SAML Debugging output](#saml-debugging-output) for where the log output appears.

## SAML Group Mapping

DefectDojo can use the SAML assertion to automatically assign users to [User Groups](../../user_management/create_user_group/). Groups in DefectDojo assign permissions to all of their members, so Group Mapping allows you to manage permissions in bulk. This is the only way to set permissions via SAML.

**Group mapping is optional.** Although the **Group Name Attribute** and **Group Limiter Regex Expression** fields appear with a required-field asterisk (`*`) in the UI, the SAML form will submit without them, and SAML login will work without group mapping. You do not need to pre-build groups or roles in your IdP (e.g. Azure AD application roles) before enabling SAML — you only need to configure these fields when you actually want DefectDojo to read group membership from the assertion. If you do not configure group mapping, newly created SSO users will have no permissions by default; see [Default access for SSO-provisioned users](#default-access-for-sso-provisioned-users) below.

The **Group Name Attribute** field specifies which attribute in the SAML assertion contains the user's group memberships. When a user logs in, DefectDojo reads this attribute and assigns the user to any matching groups. To limit which groups from the assertion are considered, use the **Group Limiter Regex Expression** field — this is a regular expression applied to the group names from the assertion, used to filter which ones DefectDojo should act on.

The value must match the attribute name your Identity Provider emits in the assertion exactly, including any namespace prefix. A short, friendly name like `groups` will only work if your IdP is configured to emit that literal attribute name — many IdPs use a fully qualified claim URI instead.

### Group Name Attribute by Identity Provider

| Identity Provider | Default attribute name to use |
|---|---|
| **Entra ID / Azure AD** | `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` |
| **Okta** | `groups` (the attribute name you configured on the SAML app's Group Attribute Statement) |
| **Keycloak** | `groups` (or whatever you set as the "SAML Attribute Name" on the Group List mapper) |
| **PingFederate / generic** | Whatever value you configured on the IdP side — check your IdP's assertion before assuming `groups` |

If group mapping appears to do nothing — users log in successfully but no groups are created or assigned — see [Troubleshooting → SAML group mapping does nothing](#saml-group-mapping-does-nothing--users-log-in-but-no-groups-are-assigned) below.

If no group with a matching name exists, DefectDojo will automatically create one and assign its members the **Reader** role. Note that this Reader role governs the member's access *to the group itself* — it does not grant any access to underlying Assets, Organizations, or other organizational assets. Those permissions are configured separately, and a newly auto-created group still has none of them until a Superuser assigns the group a role on the relevant Assets or Organizations.

To activate group mapping, check the **Enable Group Mapping** checkbox at the bottom of the form.

## AWS IAM Identity Center

IAM Identity Center can act as the SAML IdP through a customer managed SAML 2.0 application.

1. In the IAM Identity Center console, add a **customer managed** application of type **SAML 2.0**.
2. Under **IAM Identity Center metadata**, download the **IAM Identity Center SAML metadata file**. Upload it to DefectDojo as **Local SAML Metadata** (step 8 of [Setup](#setup)), which works whether or not the instance can reach AWS.
3. Under **Application metadata**, enter the values manually: set **Application ACS URL** to DefectDojo's [ACS URL](#acs-url-assertion-consumer-service) and **Application SAML audience** to the **Entity ID** you set in DefectDojo.
4. Under **Attribute mappings**, map the subject and the attributes DefectDojo reads. For example, send `${user:email}` as the subject and as an `email` attribute, and `${user:givenName}` and `${user:familyName}` as first and last name. Then map those attribute names to **Email**, **First Name** and **Last Name** in DefectDojo's **Attribute Mapping**. The subject is the `NameID`, so it decides which DefectDojo account each person signs in to.
5. For group mapping, add an attribute such as `groups` mapped to `${user:groups}`, and enter the same name as DefectDojo's **Group Name Attribute**. DefectDojo names its groups after the exact values in the assertion, so turn on **Enable SAML Debugging** for a test login and check what Identity Center sends before you write the **Group Limiter Regex Expression**.
6. Assign the users or groups who should have access to the application in IAM Identity Center.

To provision and deprovision users from your directory as well, see [SCIM Provisioning](/admin/sso/pro__scim/).

## Default access for SSO-provisioned users

When a new user is created via SAML (or any social-auth provider) and is not added to any group via SAML Group Mapping, they will land on a DefectDojo instance with **no permissions**. They will see zero Organizations, zero Assets, and zero Engagements when they log in — the dashboard will appear empty.

To give every newly provisioned SSO user a sensible baseline, configure a **Default group** + **Default group role** on the System Settings page:

1. Open **Settings > System > System Settings** (Superuser only).
2. Set **Default group** to the [User Group](../../user_management/create_user_group/) that newly created users should join.
3. Set **Default group role** to the role they should hold in that group (e.g. **Reader**).
4. Optionally set **Default group email pattern** to a regex (e.g. `.*@yourcompany\.com$`) so the default group is only applied to users whose email matches.
5. Save.

Both **Default group** and **Default group role** must be set — if either is empty, the default group is not applied.

This setting applies to **every newly created user**, including users created via SAML, OAuth, and other social-auth providers, because it runs on Django's user-creation signal rather than inside a specific authentication backend.

> **Existing users are not affected.** The default group is only applied when a user is first created. Existing DefectDojo users will keep their current group memberships even if you change this setting later.

## Cloud vs On-Premise Differences

DefectDojo Cloud does not have the same level of SAML customization as DefectDojo On-Prem.  The only variables that can be set are through the UI.  Here are some of the key differences:

| Capability | Cloud | On-Premise |
|---|---|---|
| **Username matching** | NameID only | NameID only (the `SAML_USE_NAME_ID_AS_USERNAME` env var applies to Open Source only, not Pro) |
| **SAML assertion encryption** | Not currently supported | Not currently supported |
| **SAML login logs** | Not available in the UI. Contact Support to request logs. | Available via application container logs (`docker logs dojo`) |
| **Configuration method** | Pro UI (**Connect > Authorization > Providers**) only | Pro UI (**Connect > Authorization > Providers**), Django Admin, or Django Shell |
| **Environment variables** | Cannot be set by customers directly. Contact Support for changes. | Can be set via `dojo-compose-cli environment add` |

If you need to match users on an attribute other than NameID (such as `uid` or `email`), configure your Identity Provider to send the desired value as the NameID rather than adjusting DefectDojo settings.

### Which account a login lands on

A SAML login lands on the DefectDojo account whose username equals the `NameID` in the assertion. A mapped attribute never changes that, including one mapped to **Username**: the Attribute Mapping only fills fields such as the email address and the names.

- Have your IdP send each person's DefectDojo username as the `NameID`. Many organizations use the email address as the DefectDojo username and send the email as the `NameID`.
- Use a persistent `NameID` format. **Transient** issues a new `NameID` on every login, so it never matches an existing account.
- With **Create Unknown User** on, a `NameID` that matches no username creates a new account. A `NameID` that differs from the username a person already has therefore creates a second account rather than signing them in to the first.

## Troubleshooting

### SAML Debugging output

When **Enable SAML Debugging** (in [Additional Options](#additional-options)) is checked, DefectDojo writes detailed SAML processing output — including the raw attributes received from the IdP — to the application logs at the `DEBUG` level under the `saml2` logger.

| Where you're running | Where to read the debug output |
|---|---|
| **DefectDojo Cloud** | The SAML debug log is not exposed in the UI. Contact DefectDojo Support to request the logs for a specific time window. |
| **On-Premise (single container)** | `docker logs dojo` (or your Helm/K8s log aggregation) |
| **On-Premise (Helm/K8s)** | `kubectl logs deployment/defectdojo-django -c uwsgi` (or your cluster's log aggregator) |

Turn this option **off** after you've finished troubleshooting — SAML debug logs are verbose and may contain sensitive attribute values from your IdP.

### Users get a "User not found" or "Permission denied" error after a successful IdP login

If the SAML assertion parses successfully (no XML or signature errors) but DefectDojo refuses the login, the most common cause is a **username mismatch** between the IdP and DefectDojo.

DefectDojo looks up the user **by the SAML `NameID`**, which must equal an existing DefectDojo username (see [Which account a login lands on](#which-account-a-login-lands-on)). If the `NameID` your IdP sends does not match, the lookup fails even though the rest of the assertion is valid. Mapping a different attribute to **Username** does not help: a mapped attribute is never used to find the account.

Two remedies, pick whichever fits your environment:

- **Change what the IdP sends as the `NameID`** so it equals the DefectDojo username, for example the user's email address.
- **Align the usernames.** Make sure the usernames in DefectDojo are exactly the `NameID` values your IdP sends. For most organizations the easiest convention is to make DefectDojo usernames equal to the user's email address, and have the IdP send the email as the `NameID`.

If you're not sure what the IdP is actually sending, enable **Enable SAML Debugging** (above) and inspect the parsed attributes in the logs.

### SAML group mapping does nothing — users log in but no groups are assigned

The most common cause is a mismatch between the **Group Name Attribute** field and the attribute name your IdP is actually sending. See the [Group Name Attribute by Identity Provider](#group-name-attribute-by-identity-provider) table above, and enable **Enable SAML Debugging** to see the raw attributes coming back from the IdP.
