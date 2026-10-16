---
title: "Migrating from Open Source to DefectDojo Cloud"
description: "Move your open source DefectDojo data into a DefectDojo Cloud instance"
draft: false
weight: 6
audience: pro
---

This page explains how to move the data from an open source DefectDojo instance into a DefectDojo Cloud instance.

On Cloud, you export your database and your uploaded files. The DefectDojo team restores them into your Cloud instance and upgrades the schema, so you never need access to the Cloud database. If you are moving to a self-hosted DefectDojo Pro deployment instead, follow [Migrating from Open Source to Self-Hosted DefectDojo Pro](/get_started/pro/onprem/migrating_from_open_source/).

The export is the same for both, so this page links to the self-hosted guide for the commands.

## Which versions can be migrated

Any 2.x release, and 3.0.200 or later, can be migrated. You don't have to upgrade your open source instance first. DefectDojo restores your dump and then runs the database migrations that bring the schema up to the version your Cloud instance runs. A large version gap makes that schema upgrade take longer, and the dry run shows how long it takes for your data.

Two exceptions:

- If you run 3.0.0, 3.0.1, 3.0.2, or 3.0.100, upgrade to [3.0.200](/releases/os_upgrading/3.0.200/) or later before you take the dump.
- If your instance still runs on MySQL, it has to be converted to PostgreSQL first. MySQL support was [removed in 2.37.0](/releases/os_upgrading/2.37/). Contact support if this applies to you.

Also note your PostgreSQL major version. Run `SELECT version();` in `psql`, or read the image tag of your database container. The DefectDojo team uses it to plan the restore. You don't need to change it.

## What you prepare

You produce two files and collect two keys.

1. **A database dump in custom format.** Use `pg_dump -Fc`, as shown in [Step 1: Export your database](/get_started/pro/onprem/migrating_from_open_source/#step-1-export-your-database). That step covers a database in a container and one on a separate host or managed service.
2. **A tarball of your media files.** These are the attachments and other files your users uploaded. See [Step 2: Export your media files](/get_started/pro/onprem/migrating_from_open_source/#step-2-export-your-media-files).
3. **Your version in both file names.** See [Step 3: Name your files](/get_started/pro/onprem/migrating_from_open_source/#step-3-name-your-files). The version tells the DefectDojo team where the schema upgrade starts.
4. **Your encryption keys.** Record the `DD_SECRET_KEY` and `DD_CREDENTIAL_AES_256_KEY` values your open source instance runs with. Credentials saved under Tool Configuration are encrypted with `DD_CREDENTIAL_AES_256_KEY`, and an instance with a different key can't read them. When you send both keys, the DefectDojo team configures your Cloud instance with them, so those credentials keep working. Send them with your dry-run files, so the dry run also shows that stored credentials still work. If you don't send them, re-enter your Tool Configuration credentials after the cutover.

Skip Steps 4 to 6 of the self-hosted guide. On Cloud, the DefectDojo team does the restore and the configuration.

## How to send your files

Support gives you a secure, upload-only link. Upload both files and both keys through it.

Don't send the dump, the media archive, or the keys by email, and don't attach them to a support ticket. The database holds your vulnerability data, user accounts, and password hashes. The credential key decrypts stored credentials, and the secret key signs sessions.

## Users, groups, and single sign-on

User accounts, groups, and group memberships live in the database, so they come across with the dump. Local passwords keep working.

If you ran open source 3.0 or later and changed who can see an Asset or Organization through **Authorized Users**, those changes are not in the Pro permission tables. Ask support to reconcile them during the restore. The reconciled memberships get the Writer role, and you can adjust roles afterwards.

Single sign-on doesn't come across. You set it up again yourself:

- If your open source 2.x instance configured SSO through environment variables, none of that is in the dump. SSO became a DefectDojo Pro feature in 3.0; see [SSO providers are available in DefectDojo Pro only](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only).
- In DefectDojo Cloud, SSO is self-service under **Connect > Authorization > Providers**. The [Single Sign-On](/admin/sso/) section lists every provider, and the [Microsoft Entra ID (Azure AD)](/admin/sso/pro__azure_ad/) and [SAML](/admin/sso/pro__saml/) pages cover the two most common setups.
- The redirect URI (OAuth and OIDC) or ACS URL (SAML) you register with your identity provider uses your Cloud hostname, for example `https://<your-instance>.cloud.defectdojo.com/saml2/acs/`. The old URL points at your open source host, so update the application in your identity provider or register a new one.
- Existing users are matched by username the first time they sign in through SSO. If your identity provider sends the same usernames your open source instance used, people land in their existing accounts with their group memberships. How the username is derived depends on the provider: SAML uses the NameID, and Google uses the part of the email before the @. Check the provider's page before you invite users.
- For OAuth and OIDC providers, **Validate Config** on the provider form checks the settings before you save them and shows the exact redirect URI DefectDojo expects.

Keep at least one superuser with a local username and password until SSO works.

## Planning the cutover

The dump is a snapshot. Anything created in the open source instance after you take it won't be in Cloud.

1. **Do a dry run.** Send a recent dump first and have the DefectDojo team restore it into your Cloud instance. Validate the result and fix whatever comes up. The dry run also tells you how long the restore and schema upgrade take for your data.
2. **Freeze, then take the final dump.** On cutover day, stop all writes to the open source instance: pause CI pipelines, scheduled imports, and anything else that pushes findings. Then take the final dump and media archive and upload them.
3. **Plan for downtime from the freeze until validation.** During that window the open source instance is frozen and the Cloud instance is not yet in use. The dry run tells you roughly how long it lasts.
4. **Validate.** Work through [Step 7: Validate your data](/get_started/pro/onprem/migrating_from_open_source/#step-7-validate-your-data) on your Cloud instance.
5. **Repoint your automation.** Point CI jobs, scripts, and integrations at `https://<your-instance>.cloud.defectdojo.com/api/v2/`. Existing API tokens come across with the database and keep working, subject to their expiry, so rotate any that were shared widely. Automate against `/api/v2/` only. Paths under `/api/vue/` belong to the Pro UI and reject API tokens.
6. **Resume.** Restart the paused pipelines and imports. Retire the open source instance once nothing writes to it.

The final restore replaces whatever is in the Cloud instance, including anything created there during or after the dry run.

## What to send support

Your migration request should include:

- The custom-format database dump, named with your open source version
- The media tarball, named with your open source version
- Your `DD_SECRET_KEY` and `DD_CREDENTIAL_AES_256_KEY` values, through the secure upload link and never in the ticket text
- Your open source version and your PostgreSQL major version
- Rough counts of endpoints and findings, so the team can size the restore
- Written confirmation that the current contents of the target Cloud instance may be replaced
- Your preferred dates for the dry run and the final cutover

## Questions or support

For help at any step, contact your account representative or [support@defectdojo.com](mailto:support@defectdojo.com).
