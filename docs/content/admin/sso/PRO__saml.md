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
   - Map the attribute that corresponds to the field chosen under **Match Users By** (see [Matching logins to users](#matching-logins-to-users) below). By default that is **Username**.
   - Mapping an attribute to **Email** is strongly recommended: DefectDojo uses the email address for notifications, and it is the field most organizations match logins on.
   - The same attribute may feed more than one field — for example an email claim used for both **Email** and **Username**. The reverse is not allowed: each DefectDojo field may be mapped from only one attribute.
   - A row with only one half filled in is rejected on save, and the offending cell is highlighted. Rows you add but never fill in are discarded rather than treated as errors.

8. **User Identifier Source** and **Match Users By** — how an incoming login is matched to a DefectDojo user. The defaults (NameID, Username) reproduce the historical behavior; see [Matching logins to users](#matching-logins-to-users) for when to change them.

9. **Remote SAML Metadata** — the URL where your SAML Identity Provider metadata is hosted.

10. Check **Enable SAML** at the bottom of the form to activate SAML login. A **Login With SAML** button will appear on the DefectDojo login page.

   ![image](images/sso_saml_login.png).

## Matching logins to users

When a SAML response arrives, DefectDojo takes one value from it (the *identifier*) and compares it against one field of the DefectDojo user table to find the account to log in. Two settings control this:

| Setting | Options | What it does |
|---|---|---|
| **User Identifier Source** | **SAML NameID** (default) / **Mapped attribute** | Where the identifier comes from. **SAML NameID** uses the `NameID` element of the assertion. **Mapped attribute** uses the SAML attribute that the Attribute Mapping feeds into the field chosen under **Match Users By**. |
| **Match Users By** | **Username** (default) / **Email** | Which DefectDojo user field the identifier is compared against. **Email** is matched case-insensitively; **Username** must match exactly. |

The defaults, NameID compared against Username, are what every DefectDojo instance did before these settings existed. Existing configurations keep that behavior until you change them.

**When to use a mapped attribute.** Some Identity Providers emit a NameID that is opaque — a per-tenant random string such as `ADAFDF!#$%^&^%$#`, or a transient value that changes on every login — rather than anything a person would recognise. Such a NameID can never match a DefectDojo username or email, so logins fail (or, with **Create Unknown User** on, provision a fresh account every time). Set **User Identifier Source** to **Mapped attribute**, set **Match Users By** to the field your users are keyed on, and make sure the Attribute Mapping has a row targeting that field. For example, to match on the email claim:

- **Match Users By**: Email
- **Attribute Mapping**: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` → Email

The form refuses to save a **Mapped attribute** configuration whose Attribute Mapping does not target the chosen field, and **Validate Config** reports the same condition, because with nothing to look the user up by every login would fail.

**When to keep the NameID but match on email.** If your IdP sends the email address *as* the NameID (the `emailAddress` NameID format), leave **User Identifier Source** on **SAML NameID** and set **Match Users By** to **Email**. This is often simpler than changing the IdP to send a username.

**Usernames of created users.** When **Match Users By** is **Email** and **Create Unknown User** is on, a newly provisioned account takes its username from the attribute mapped to **Username**, or from the email address itself when no attribute is mapped to Username. The username is assigned once, at creation: later logins never rename an existing account, even if the IdP's username attribute changes. If the username the IdP supplies for a *new* user already belongs to another account, the login is refused and the conflict is logged rather than creating a duplicate.

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
| **User matching** | NameID or a mapped attribute, against Username or Email (see [Matching logins to users](#matching-logins-to-users)) | Same, from the UI; or via the `DD_SAML2_USE_NAME_ID_AS_USERNAME` and `DD_SAML2_USER_MATCH_FIELD` environment variables when SAML is configured from the environment |
| **SAML assertion encryption** | Not currently supported | Not currently supported |
| **SAML login logs** | Not available in the UI. Contact Support to request logs. | Available via application container logs (`docker logs dojo`) |
| **Configuration method** | Pro UI (**Connect > Authorization > Providers**) only | Pro UI (**Connect > Authorization > Providers**), Django Admin, or Django Shell |
| **Environment variables** | Cannot be set by customers directly. Contact Support for changes. | Can be set via `dojo-compose-cli environment add` |

To match users on an attribute other than NameID (such as `uid` or `email`), use the **User Identifier Source** and **Match Users By** settings described in [Matching logins to users](#matching-logins-to-users). Changing what the IdP sends as the NameID is no longer required.

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

If the SAML assertion parses successfully (no XML or signature errors) but DefectDojo refuses the login, the most common cause is an **identifier mismatch**: the value DefectDojo takes from the response does not equal the field it compares it against on any existing user.

With the default settings, DefectDojo compares the SAML **NameID** against the DefectDojo **username**, exactly. If your IdP's NameID is an opaque string, an email address, or anything else that is not literally the DefectDojo username, the lookup fails — even though the rest of the assertion is valid.

Three remedies, pick whichever fits your environment (see [Matching logins to users](#matching-logins-to-users)):

- **Match on email instead.** Set **Match Users By** to **Email**. If the NameID *is* the email address, that is all that is needed; if it is not, also set **User Identifier Source** to **Mapped attribute** and map the IdP's email claim to **Email**.
- **Use a mapped attribute as the identifier.** Set **User Identifier Source** to **Mapped attribute** and map the claim that carries your users' DefectDojo username to **Username**. This is the fix for an opaque or transient NameID.
- **Align the usernames.** Make sure the usernames in DefectDojo are exactly what your IdP sends as the NameID. For most organizations the easiest convention is to make DefectDojo usernames equal to the user's email address, and have the IdP send the email as the NameID.

If you're not sure what the IdP is actually sending, enable **Enable SAML Debugging** (above) and inspect the parsed attributes in the logs, or run **Validate Config**, whose attribute-mapping check reports a **Mapped attribute** source with nothing mapped to the match field.

### SAML group mapping does nothing — users log in but no groups are assigned

The most common cause is a mismatch between the **Group Name Attribute** field and the attribute name your IdP is actually sending. See the [Group Name Attribute by Identity Provider](#group-name-attribute-by-identity-provider) table above, and enable **Enable SAML Debugging** to see the raw attributes coming back from the IdP.
