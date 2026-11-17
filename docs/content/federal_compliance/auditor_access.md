---
title: "Auditor Access"
description: "Give an external auditor time-boxed, read-only access to compliance evidence, with a log of everything they open"
weight: 12
audience: pro
---

An assessment usually ends with somebody outside your organization asking to see the evidence. **Auditor Access** gives that auditor their own sign-in to a read-only portal that shows the compliance evidence of one organization, chosen assets or chosen evidence packs, for up to 90 days. The auditor sees nothing else in DefectDojo, every page they open and every file they download is logged, and the access ends on the server when it expires or is revoked.

## Turning it on

Auditor Access is a beta feature behind the **Auditor Access** feature flag, which is off by default. It depends on **Compliance**, so it stays off while Compliance is off. An administrator turns both on from [Feature Flags](/admin/feature_flags/pro__feature_flags/).

With the flag on, superusers and organization Owners see **Settings > Auditor Access**. The **Grant Auditor Access** walkthrough on that page goes through a first grant step by step.

## Who can grant access

- A **superuser** can grant access to any organization, any assets and any completed evidence pack.
- An **organization Owner** can grant access only to what their own organizations own:
  - an organization they are an Owner of, which covers that organization's own assets;
  - assets whose primary organization is one of theirs. An asset that another organization only shares with yours belongs to its primary organization, so only that organization's Owner (or a superuser) can hand out its evidence;
  - evidence packs whose every asset, both in the assessment's current scope and in the scope frozen into the pack, belongs to one of their organizations. A pack that still carries an asset that has since left the assessment, or no longer exists, is refused.

An Owner's grant stays with the Owner's organizations. If an asset it covers moves to another organization, the grant stops covering that asset (and every evidence pack that holds it), so another organization's evidence never reaches an auditor it did not approve. The Owner who gave the grant can still see, extend and revoke it after the move. A superuser's grant covers its scope wherever its assets go.

## Who can be an auditor

The auditor needs a DefectDojo account of their own, local or single sign-on, that holds nothing else: not a superuser or staff member, not a [service user](/admin/user_management/pro__service_users/), and with no global role, no organization or asset membership, no group and no configuration permission. Because the account holds no other access, every other page and API in DefectDojo already shows it nothing; the portal reads the grant alone.

Create a dedicated account for the auditor if needed. There is no invite flow: the account must exist before you grant access.

When choosing the account in the **Grant Auditor Access** dialog, a superuser can search accounts, and an Owner must type the exact username or email address. An Owner who picks an account that cannot be an auditor is told only "Choose an eligible account.", so the dialog never reveals whether an account exists or what it holds. A superuser is told the reason.

A deactivated account cannot be given access, unless it was deactivated by the end of its own earlier auditor access. Deactivating an auditor account yourself (from the Users page, the API or SCIM) is final: a later grant does not reactivate it.

## Granting access

In **Settings > Auditor Access**, select **Grant Auditor Access** and fill in:

- **Auditor**: the account, as described above.
- **Scope**: one **Organization**, chosen **Assets**, or chosen **Evidence Packs** (completed packs only). The pickers offer only what you are allowed to grant.
- **Expires At**: when the access ends, at most 90 days from now.
- **Reason**: why the auditor needs access, kept with the grant.

Granting access signs out any session the account had open from before its first grant and deletes its API token, so the auditor's next sign-in starts in the portal.

The grant list shows every grant you can manage with its auditor, scope, status (**active**, **expired** or **revoked**), expiry and who granted it. A superuser sees every grant. An Owner sees the grants given for their own organizations, and a superuser's grant whose whole scope lies inside them.

## What the auditor sees

The auditor signs in as usual and lands on the auditor portal, which shows each grant in force with its scope, its expiry, who granted it and why. Each grant has four tabs:

| Tab | What it shows |
| --- | --- |
| **Assessments** | Regulatory assessments whose whole scope lies inside the grant, with their obligation results, narratives and override reasons |
| **Evidence Packs** | Completed evidence packs inside the grant, with each artifact to download and its SHA-256 checksum |
| **POA&M Snapshots** | Completed POA&M snapshots of in-scope assets, with their artifacts (see [ConMon Snapshots](../conmon_snapshots/)). An evidence pack grant shows none |
| **Change History** | The audit history of POA&M items, CMMC assessments, system profiles and regulatory profiles on in-scope assets |

An organization or asset grant shows an evidence pack only while everything the pack holds, in the assessment's current scope and in the scope frozen into it, lies inside the grant. Generated reports are not shown in the portal.

Everything in the portal is read-only.

## What the auditor cannot do

The account is confined to the portal:

- Opening any other page sends the auditor back to the portal. Any other API call is refused (`403`, `auditor_confined`) and logged.
- The account has no API token, and cannot create one or sign in to the API with its password. Only the browser session reaches the portal.
- Only a superuser can use [View As User](/admin/user_management/pro__view_as_user/) on an account that holds or held auditor access, and the portal refuses every View As session. The refusal is logged with the name of the person who signed in.

## Ending, revoking and extending access

Access ends on the server, at the second it expires:

- **At expiry**, the auditor's next request is answered `401` (`auditor_access_ended`), the session is signed out, and the account is deactivated, unless another grant for it is still in force. The portal also refuses an ended grant by name.
- **Revoke Access**, in a grant's gear menu, ends it at once and deactivates the account the same way.
- A background check every 15 minutes deactivates any auditor account with no grant in force, as a backstop.
- The person who granted access is notified 7 days and 1 day before a grant expires.

**Extend Access**, in the gear menu, moves the expiry of an active grant (again, at most 90 days from now) and can reword its reason. Each new expiry gets its own reminders. An expired or revoked grant cannot be extended: give a new grant instead. A new grant reactivates an account that the end of its own auditor access deactivated.

## The access log

Every page the auditor opens, every file they download and every request refused to them is recorded against the grant: when, the action (**Viewed**, **Downloaded** or **Refused**), the object, the path and the IP address. An auditor who holds two grants shows up in the log of each grant in force.

- **View Access Log**, in a grant's gear menu, shows that grant's log, with **Export JSON**.
- **Export Access Log (CSV)**, in the same menu, downloads that grant's log as a CSV file.
- **Export Access Log**, above the grant list, downloads the log of every grant you can see as one CSV file.

An export holds up to 50,000 entries. In the CSV file, a value that a spreadsheet would run as a formula is written so that it is shown as text.

The log cannot be edited or deleted: the database refuses any change to an entry, apart from clearing the link to an auditor account that is deleted (the username stays on the entry).

## Known limit: an auditor account stays an auditor account

Once an account has held a grant, DefectDojo treats it as an auditor account for good. If an administrator later reactivates a former auditor's account and gives it a membership or role, the 15-minute check and every sign-in deactivate it again, and View As of it stays superuser-only.

To give a former auditor ordinary access to DefectDojo, create a new account for them.
