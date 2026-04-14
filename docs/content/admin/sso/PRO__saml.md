---
title: "SAML Configuration"
description: "Configure SAML in DefectDojo Pro"
weight: 1
audience: pro
---

DefectDojo Pro supports SAML authentication via the **Enterprise Settings** UI. Open-Source users should refer to the [Open-Source SAML guide](/admin/sso/os__saml/).

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

7. **Attribute Mapping** — map SAML attributes to DefectDojo user fields. For example: `email=email`. The left side is the attribute name from the SAML response; the right side is the DefectDojo user field.

8. **Remote SAML Metadata** — the URL where your SAML Identity Provider metadata is hosted.

9. Check **Enable SAML** at the bottom of the form to activate SAML login. A **Login With SAML** button will appear on the DefectDojo login page.

   ![image](images/sso_saml_login.png).

## SAML Group Mapping

DefectDojo can use the SAML assertion to automatically assign users to [User Groups](../../user_management/create_user_group/). Groups in DefectDojo assign permissions to all of their members, so Group Mapping allows you to manage permissions in bulk. This is the only way to set permissions via SAML.

The **Group Name Attribute** field specifies which attribute in the SAML assertion contains the user's group memberships. When a user logs in, DefectDojo reads this attribute and assigns the user to any matching groups. To limit which groups from the assertion are considered, use the **Group Limiter Regex Expression** field.

If no group with a matching name exists, DefectDojo will automatically create one. Note that a newly created group will not have any permissions configured — those can be set later by a Superuser.

To activate group mapping, check the **Enable Group Mapping** checkbox at the bottom of the form.

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

## Additional Options

* **Create Unknown User** — automatically create a new DefectDojo user if they are not found in the SAML response.
* **Allow Unknown Attributes** — allow login for users who have attributes not listed in the Attribute Mapping.
* **Sign Assertions/Responses** — require all incoming SAML responses to be signed.
* **Sign Logout Requests** — sign all logout requests sent by DefectDojo.
* **Force Authentication** — require users to authenticate with the Identity Provider on every login, regardless of existing sessions.
* **Enable SAML Debugging** — log detailed SAML output for troubleshooting.
