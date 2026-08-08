---
title: "SCIM Provisioning"
description: "Provision and deprovision DefectDojo Pro users from your identity provider"
weight: 19
audience: pro
---

DefectDojo Pro supports SCIM 2.0, which lets your identity provider create, update and deactivate DefectDojo users directly. Without it, DefectDojo only learns about a user when that user signs in, so removing someone from your identity provider stops future logins but leaves their DefectDojo account active.

SCIM is separate from single sign-on and complements it. SSO decides who may sign in; SCIM keeps the account list itself in step with your directory. Most customers configure both: SAML or OIDC for authentication, SCIM for provisioning.

SCIM configuration can only be performed by a **Superuser**.

## What SCIM does in DefectDojo

When you connect an identity provider over SCIM, it can:

* create DefectDojo users when someone is assigned the application
* update names and email addresses when they change in the directory
* deactivate users when they are unassigned or leave the organization
* create groups, and add and remove their members

Deactivating a user through SCIM does two things at once. The account is marked inactive, so the user can no longer sign in, and the user's DefectDojo API tokens are deleted. Offboarding therefore closes both doors in a single step, which is the main reason to use SCIM rather than relying on your identity provider alone.

The user record itself is kept. Findings, notes and history reference the people who created them, so DefectDojo deactivates the account rather than deleting it. If the same person returns, reactivating them through your identity provider restores access without disturbing that history.

## Setup

1. Open **Enterprise Settings > SCIM Provisioning**.

2. Check **Enable SCIM Provisioning** and submit. While this is off, the SCIM endpoints behave as though they do not exist, so a connection test from your identity provider reports the address as not found.

3. Copy the **Tenant URL** shown on the page. It looks like this:

   ```
   https://<your-instance>.cloud.defectdojo.com/scim/v2
   ```

4. In the **SCIM Tokens** panel, give the token a name that says where it will be used, for example "Okta production", then select **Generate Token**.

5. Copy the token from the dialog and paste it into your identity provider. DefectDojo stores only a hash of the token, so it cannot be shown again. If you lose it, generate another and revoke the old one.

You can keep more than one token active at a time. To rotate, generate a new token, update your identity provider, then revoke the old one. There is no window where provisioning stops working.

The token panel records when each token was last used, which is a quick way to confirm your identity provider is actually reaching DefectDojo.

## Okta

1. In the Okta Admin Console, go to **Applications > Browse App Catalog** and add **SCIM 2.0 Test App (Header Auth)**. If you already have a SAML application for DefectDojo, you can enable provisioning on that application instead.

2. Open the **Provisioning** tab and select **Configure API Integration**.

3. Set **SCIM 2.0 Base Url** to the Tenant URL you copied above.

4. Set **API Token** to `Bearer <your token>`, including the word `Bearer` and a single space. This application type sends the value verbatim as the Authorization header.

5. Select **Test API Credentials**, then save.

6. Under **Provisioning > To App**, enable **Create Users**, **Update User Attributes** and **Deactivate Users**.

7. Assign people or groups to the application. Okta looks each person up in DefectDojo by username first and only creates an account when it finds none, so anyone who already has a DefectDojo account is linked rather than duplicated.

To push groups as well, open the **Push Groups** tab and add the groups you want DefectDojo to mirror. See [Groups](#groups) below for what DefectDojo does with them.

## Microsoft Entra ID

1. In the Entra admin center, go to **Enterprise applications > New application > Create your own application**, and choose the non-gallery option. If you already have an application for DefectDojo, use that one.

2. Open **Provisioning** and set **Provisioning Mode** to **Automatic**.

3. Set **Tenant URL** to the Tenant URL you copied above.

4. Set **Secret Token** to your SCIM token. Entra sends it as a bearer token, so do not add the word `Bearer` here.

5. Select **Test Connection**, then save.

6. Assign users and groups under **Users and groups**, and start provisioning.

Entra provisions on a cycle of roughly 40 minutes. While you are setting things up, **Provision on demand** applies a single user or group immediately, which makes it much faster to confirm the configuration works.

## What DefectDojo stores

DefectDojo maps a small set of SCIM attributes and ignores the rest.

| SCIM attribute | DefectDojo field |
|---|---|
| `userName` | Username |
| `name.givenName` | First name |
| `name.familyName` | Last name |
| `emails` | Email address |
| `active` | Whether the account is enabled |
| `externalId` | Kept so your identity provider can match the record later |

Attributes DefectDojo does not model, including phone numbers, job titles and the SCIM enterprise extension, are accepted and ignored rather than rejected. Mapping extra attributes in your identity provider is harmless.

Two attributes deserve particular attention:

**Username.** DefectDojo allows letters, digits and the characters `@ . + - _` in a username. If your identity provider sends a username containing anything else, DefectDojo rejects that user with an error naming the problem rather than quietly storing a different username. Storing an altered username would break your provider's ability to find the account afterwards.

**Email address.** SCIM does not require one, and DefectDojo will create the user without it. Bear in mind that DefectDojo notifications, including scheduled reports and alerts, have nowhere to go for a user with no email address. Map the `emails` attribute unless you have a reason not to.

SCIM never sets passwords, and never grants superuser or staff status. If your identity provider is configured to send passwords, DefectDojo ignores them. Users provisioned this way sign in through SSO.

## Groups

SCIM manages only the groups it created. Groups you made in the DefectDojo UI, or that arrived through SAML or Azure AD group mapping, are invisible to SCIM and cannot be renamed, emptied or deleted by your identity provider.

This matters because group push is a full replacement by nature. If an identity provider could adopt an existing group, its next sync would replace that group's carefully chosen membership with whatever the directory holds. Pushing a group whose name is already taken therefore fails with a message explaining the conflict. To hand an existing group over to your identity provider, either rename one of the two, or delete the DefectDojo group and let the provider recreate it.

Within a SCIM-managed group, membership belongs to your identity provider and roles belong to DefectDojo:

* A newly added member is given the **Reader** role.
* If you promote someone to a higher role in DefectDojo, later syncs leave that role alone.
* Anyone added to a SCIM-managed group by hand is removed on the next sync, because the identity provider is the source of truth for who belongs.

Deleting a group through SCIM removes the group and its memberships. It never deletes the people who were in it.

## Protecting administrator access

By default, SCIM will not deactivate a superuser account. The common failure in any provisioning setup is an identity provider scoped more broadly than intended, and superusers are how you get back into DefectDojo when something goes wrong.

If you want your identity provider to manage superusers as well, enable **Allow SCIM to deactivate superusers** in Enterprise Settings. Even then, DefectDojo refuses to deactivate the last remaining active superuser, so provisioning cannot leave the instance without an administrator.

## Limitations

* One identity provider per DefectDojo instance.
* Filtering is supported on `userName`, `displayName`, `externalId` and `id`, using a single equality comparison. This covers what Okta and Entra send when they match records. More complex filters are rejected with an error that says so.
* Bulk operations, sorting and the `/Me` endpoint are not implemented.
* Group memberships are managed through the Groups endpoint. Sending group membership on a user record has no effect, which matches how both providers behave.

## Troubleshooting

**The connection test reports "not found".** SCIM is switched off, or the instance is not licensed for it. Check that **Enable SCIM Provisioning** is on and that your subscription includes SSO. The whole SCIM address behaves as though it does not exist until both are true.

**The connection test reports an authentication failure.** The token is wrong, or it has been revoked. Generate a new one and update your identity provider. In Okta, check that the value begins with `Bearer ` and a space; in Entra, check that it does not.

**A user fails to provision with an error about the username.** The username contains characters DefectDojo does not permit. Change the attribute your identity provider maps to `userName`, most often to the user's email address or user principal name.

**A group fails to push, reporting that a group of that name already exists.** A DefectDojo group with that name was created elsewhere. See [Groups](#groups) above.

**A group member fails to provision.** The person has not been provisioned to DefectDojo yet. Assign them to the application, and the membership succeeds on the next cycle.

**Everything reports success, but nothing appears in DefectDojo.** Check that the Tenant URL ends in `/scim/v2` with no trailing slash, and that your identity provider is actually reaching your instance. The **Last Used** column in the SCIM Tokens panel shows whether any request has arrived.

**DefectDojo Pro users:** if your instance restricts access by IP address, add your identity provider's addresses to the firewall allowlist before configuring SCIM. See [Firewall Rules](/get_started/pro/cloud/using-cloud-manager/#changing-your-firewall-settings).
