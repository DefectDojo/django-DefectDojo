---
title: "ServiceDesk Plus"
description: "How to set up the ServiceDesk Plus Downstream Connector for DefectDojo"
weight: 119
audience: pro
---
The ManageEngine ServiceDesk Plus Integration allows you to push DefectDojo Findings and Finding Groups as ServiceDesk Plus requests, assigned to a support Group of your choice.  Both the **cloud** (ServiceDesk Plus OnDemand) and **on-premises** editions are supported by the same integration - the credentials you provide determine which mode is used.

### Instance Setup

- **Label** should be the label that you want to use to identify this integration.
- **Location** should be set to your ServiceDesk Plus URL: `https://sdpondemand.manageengine.com` for the cloud edition (or your regional equivalent), or your server's address for on-premises installs.

Then provide **one** of the two credential sets:

#### On-premises: Technician Key

- **Technician Key** should be an API key generated for a technician on your server, under **Admin > General Settings > API**.  Leave the Zoho OAuth fields empty.

#### Cloud: Zoho OAuth

The cloud edition authenticates through Zoho Accounts OAuth:

1. Open the [Zoho API Console](https://api-console.zoho.com/) and create a **Self Client**.
2. Note the **Client ID** and **Client Secret**.
3. In the Self Client's "Generate Code" tab, enter the scope `SDPOnDemand.requests.ALL`, choose a duration, and generate the code.
4. Exchange the code for a refresh token:

```
curl --request POST \
 --url 'https://accounts.zoho.com/oauth/v2/token' \
 --data 'grant_type=authorization_code' \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'code={{GENERATED_CODE}}'
```

5. Enter the **Client ID**, **Client Secret**, and the returned **Refresh Token** in the instance form.  If your account is hosted outside the US data center, set **Token URL** to your regional Zoho Accounts endpoint (for example `https://accounts.zoho.eu/oauth/v2/token`).

### Issue Tracker Mapping

- **Group Name** should be the name of the ServiceDesk Plus support group requests will be assigned to, exactly as it appears under **Admin > Users > Support Groups**.

### Severity Mapping Details

This maps to the ServiceDesk Plus request **Priority** field by name, using your account's priority names:

- **Severity Field Name**: `Priority`
- **Info Mapping**: `Low`
- **Low Mapping**: `Normal`
- **Medium Mapping**: `Medium`
- **High Mapping**: `High`
- **Critical Mapping**: `High`

### Status Mapping Details

This maps to the request **Status** field by name.  The defaults use the built-in statuses:

- **Status Field Name**: `Status`
- **Active Mapping**: `Open`
- **Closed Mapping**: `Closed`
- **False Positive Mapping**: `Closed`
- **Risk Accepted Mapping**: `On Hold`

A few ServiceDesk Plus-specific behaviors to be aware of:

- Updates sync the full request content - unlike most trackers, ServiceDesk Plus allows the subject and description to be edited after creation.
- Requests are closed rather than deleted when a Finding is removed; requests already Closed or Resolved are left untouched.
- If your account makes fields mandatory on closure (for example a resolution), a close pushed from DefectDojo may be rejected by those rules and will appear in the Integration errors table.
