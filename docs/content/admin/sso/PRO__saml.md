---
title: "SAML Configuration"
description: "Configure SAML in DefectDojo Pro"
weight: 1
audience: pro
---

DefectDojo Pro supports SAML authentication via the **Enterprise Settings** UI. Open-source DefectDojo does not include SSO — see [Authorized Users](/admin/user_management/os__authorized_users/) for open-source access control.

## ACS URL (Assertion Consumer Service)

Your Identity Provider needs to know where to POST the SAML response after a user authenticates. DefectDojo's ACS URL is:

```
https://<your-instance>.cloud.defectdojo.com/saml2/acs/
```

A few things to know about this endpoint:

- **The endpoint accepts `POST` requests only.** Opening the ACS URL directly in a browser issues a GET and will return an **HTTP 405 Method Not Allowed**. This is expected behavior — it does not mean SAML is broken or misconfigured. The endpoint is designed to be invoked by your IdP as part of the SAML redirect flow, not by a browser typing the URL.
- **The ACS URL is available on your DefectDojo Cloud instance at all times** — you do not need to enable SAML in DefectDojo first before pointing your IdP at it. You can configure the IdP side and the DefectDojo side in either order.

## Setup

1. Open **Enterprise Settings > SAML Settings**.

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

7. **Attribute Mapping** — map SAML attributes to DefectDojo user fields. Each mapping is written as `saml_attribute=dojo_field`, and multiple mappings are separated by commas. The left side is the attribute name from the SAML response; the right side is the DefectDojo user field.

   Multiple attributes (typical case):

   ```
   Email=email, UserName=username, Firstname=first_name, Lastname=last_name
   ```

   - Whitespace around the comma is ignored.
   - The right-hand side must be a field on the DefectDojo `User` model — most commonly `email`, `username`, `first_name`, `last_name`.
   - The left-hand side must match the attribute name your IdP actually emits. Some IdPs (e.g. Entra ID / Azure AD) send fully qualified claim URIs like `http://schemas.microsoft.com/identity/claims/emailaddress` instead of friendly names. If you are unsure what your IdP is sending, enable **Enable SAML Debugging** (see [Troubleshooting](#troubleshooting)) and inspect the assertion in the logs.
   - At minimum, you should map the attribute that corresponds to `username`, since DefectDojo looks up users by username when matching SAML logins to existing accounts.

8. **Remote SAML Metadata** — the URL where your SAML Identity Provider metadata is hosted.

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

If no group with a matching name exists, DefectDojo will automatically create one. Note that a newly created group will not have any permissions configured — those can be set later by a Superuser.

To activate group mapping, check the **Enable Group Mapping** checkbox at the bottom of the form.

## Default access for SSO-provisioned users

When a new user is created via SAML (or any social-auth provider) and is not added to any group via SAML Group Mapping, they will land on a DefectDojo instance with **no permissions**. They will see zero Product Types, zero Products, and zero Engagements when they log in — the dashboard will appear empty.

To give every newly provisioned SSO user a sensible baseline, configure a **Default group** + **Default group role** on the System Settings page:

1. Open **⚙️ Configuration → System Settings** (Superuser only).
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
| **Configuration method** | Enterprise Settings UI only | Enterprise Settings UI, Django Admin, or Django Shell |
| **Environment variables** | Cannot be set by customers directly. Contact Support for changes. | Can be set via `dojo-compose-cli environment add` |

If you need to match users on an attribute other than NameID (such as `uid` or `email`), configure your Identity Provider to send the desired value as the NameID rather than adjusting DefectDojo settings.

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

DefectDojo looks up the user **by username** when matching a SAML login to an existing account. If the value your IdP sends as the `username` attribute does not match an existing DefectDojo user's username, the lookup fails — even though the rest of the assertion is valid.

Two remedies, pick whichever fits your environment:

- **Drop `username` from the Attribute Mapping** and let DefectDojo fall back to using the SAML `NameID` as the username instead. This is appropriate if your DefectDojo usernames already match the NameID format your IdP emits.
- **Align the usernames.** Make sure the usernames in DefectDojo are exactly what your IdP sends in the `username` claim. For most organizations the easiest convention is to make DefectDojo usernames equal to the user's email address, and have the IdP send the email as the `username` claim.

If you're not sure what the IdP is actually sending, enable **Enable SAML Debugging** (above) and inspect the parsed attributes in the logs.

### SAML group mapping does nothing — users log in but no groups are assigned

The most common cause is a mismatch between the **Group Name Attribute** field and the attribute name your IdP is actually sending. See the [Group Name Attribute by Identity Provider](#group-name-attribute-by-identity-provider) table above, and enable **Enable SAML Debugging** to see the raw attributes coming back from the IdP.
