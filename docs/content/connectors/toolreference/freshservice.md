---
title: "Freshservice"
description: "How to set up the Freshservice Downstream Connector for DefectDojo"
weight: 61
audience: pro
---
The Freshservice Integration allows you to push DefectDojo Findings and Finding Groups as Freshservice tickets, assigned to an agent Group of your choice.

### Instance Setup

- **Label** should be the label that you want to use to identify this integration.
- **Location** should be set to your Freshservice URL: `https://yourcompany.freshservice.com`.
- **API Key** should be a Freshservice API key.  Find it by clicking your profile picture (top right) > **Profile settings** - the key appears on the right below the **Delegate Approvals** section, after you complete the captcha.  If no key is shown there, API access may be disabled at the account level and an administrator has to enable it first.
- **Requester Email** should be the email address tickets are requested on behalf of.  Freshservice requires a requester on every ticket, so DefectDojo creates tickets with this address as the requester.

### Issue Tracker Mapping

- **Group ID** should be the numeric ID of the Freshservice agent group tickets will be assigned to.  Find it in the URL while viewing the group under **Admin > Agent Groups**.
- **Workspace ID** (optional) routes tickets to a specific workspace on multi-workspace accounts.  Leave it empty to use the primary workspace.

### Severity Mapping Details

This maps to the Freshservice ticket **Priority** field, which uses numeric codes (`1` Low, `2` Medium, `3` High, `4` Urgent).  The priority names are also accepted:

- **Severity Field Name**: `Priority`
- **Info Mapping**: `1`
- **Low Mapping**: `1`
- **Medium Mapping**: `2`
- **High Mapping**: `3`
- **Critical Mapping**: `4`

### Status Mapping Details

This maps to the ticket **Status** field, which uses numeric codes (`2` Open, `3` Pending, `4` Resolved, `5` Closed).  The status names are also accepted:

- **Status Field Name**: `Status`
- **Active Mapping**: `2`
- **Closed Mapping**: `5`
- **False Positive Mapping**: `5`
- **Risk Accepted Mapping**: `3`

A few Freshservice-specific behaviors to be aware of:

- Updates sync the full ticket content - Freshservice allows the subject and description to be edited after creation.
- Tickets are closed rather than deleted when a Finding is removed; tickets already Resolved or Closed are left untouched.  A resolution note is attached automatically on closure, so accounts that require one (a common business rule) accept the close.
- Some accounts compute a ticket's priority from an Impact/Urgency matrix or a business rule and ignore the priority sent at creation.  DefectDojo detects this and re-applies the mapped priority with a follow-up update, so the mapping still takes effect.
