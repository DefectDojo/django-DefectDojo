---
title: "ServiceNow"
description: "How to set up the ServiceNow Downstream Connector for DefectDojo"
weight: 120
audience: pro
---
The ServiceNow Integration allows you to push DefectDojo Findings as ServiceNow Incidents.

### Instance Setup

DefectDojo authenticates to ServiceNow over OAuth 2.0. How you create the OAuth credentials depends on your ServiceNow release — newer releases (Zurich and later) use a Client Credentials grant, while earlier releases use a refresh token.

#### ServiceNow Zurich and later (client credentials)

Recent ServiceNow releases deprecated the classic "Create an OAuth API endpoint for external clients" option in favor of the **New Inbound Integration Experience**, which issues an OAuth **Client Credentials** grant bound to a service account:

1. In the left-hand navigation bar, search for "Application Registry" and select it.
2. Click **New**, then choose **New Inbound Integration Experience**.
3. Select **New Integration → OAuth - Client credentials grant**.
4. Set the **OAuth Application User** to the service account that will create Incidents. That account's roles determine what DefectDojo is allowed to write.
5. Save the registration. ServiceNow auto-generates the **Client ID** and **Client Secret** (leave those fields blank when creating the registration).

Then, in DefectDojo:

- **Instance Label** should be the label that you want to use to identify this integration.
- **Location** should be set to the URL for your ServiceNow server, for example `https://your-organization.service-now.com/`.
- **Client ID** should be the Client ID from the OAuth registration.
- **Client Secret** should be the Client Secret from the OAuth registration.

Leave the Refresh Token, Username, and Password fields empty — DefectDojo requests a fresh client-credentials token for each sync.

#### Earlier ServiceNow releases (refresh token)

On releases that still offer the classic registration, obtain a Refresh Token associated with the User or Service account that will push Incidents to ServiceNow:

1. In the left-hand navigation bar, search for "Application Registry" and select it.
2. Click "New".
3. Choose "Create an OAuth API endpoint for external clients".
4. Fill in the required fields:
    * Name: Provide a meaningful name for your application (e.g., Vulnerability Integration Client).
    * (Optional) Adjust the Token Lifespan:
    * Access Token Lifespan: Default is 1800 seconds (30 minutes).
    * Refresh Token Lifespan: The default is 8640000 seconds (approximately 100 days).
5. Click Submit to create the application record.
6. After submission, select the application from the list and take note of the **Client ID and Client Secret** fields.

You will then need to use this registration to obtain a Refresh Token, which can only be obtained through the ServiceNow API.  Open a terminal window and paste the following (substituting the variables wrapped in `{{}}` with your user's actual information)

```
curl --request POST \
 --url {{INSTANCE_HOST}}/oauth_token.do \
 --header 'content-type: application/x-www-form-urlencoded' \
 --data grant_type=password \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'username={{USERNAME}}' \
 --data 'password={{PASSWORD}}'
 ```

If your ServiceNow credentials are correct, and allow for admin level-access to ServiceNow, you should receive a response with a RefreshToken.  You'll need that token to complete integration with DefectDojo.

- **Instance Label** should be the label that you want to use to identify this integration.
- **Location** should be set to the URL for your ServiceNow server, for example `https://your-organization.service-now.com/`.
- **Refresh Token** is where the Refresh Token should be entered.
- **Client ID** should be the Client ID set in the OAuth App Registration.
- **Client Secret** should be the Client Secret set in the OAuth App Registration.

### Severity Mapping Details

This maps to the ServiceNow Impact field.
- **Info Mapping**: `1`
- **Low Mapping**: `1`
- **Medium Mapping**: `2`
- **High Mapping**: `3`
- **Critical Mapping**: `3`

### Status Mapping Details

- **Status Field Name**: `State`
- **Active Mapping**: `New`
- **Closed Mapping**: `Closed`
- **False Positive Mapping**: `Resolved`
- **Risk Accepted Mapping**: `Resolved`

Each mapping accepts a standard state label (`New`, `In Progress`, `On Hold`, `Resolved`, `Closed`, `Cancelled`) or a numeric state value. On instances with customized Incident states — or when targeting a table other than `incident` — use the numeric **state value** from your instance's choice list; a numeric value outside the standard set is sent to ServiceNow exactly as configured. The built-in Resolution-code default only accompanies the standard resolved/closed states, so pair custom state values with the close and resolution field mappings below.

### Close and resolution fields

Some ServiceNow instances enforce a Data Policy that makes fields such as the **Resolution code** (`close_code`) mandatory whenever an Incident moves to a resolved or closed state. If DefectDojo closes an Incident without them, ServiceNow rejects the write with an HTTP 403 *"Data Policy Exception"* and the reason is recorded in the integration's Errors view.

Attach the required fields to the state change with **Custom Field Mappings**, setting **Apply On** to the disposition that should carry them:

- **Transition to Closed** — sent when a Finding is mitigated / closed.
- **Transition to False Positive** — sent when a Finding is marked a false positive.
- **Transition to Risk Accepted** — sent when a Finding is risk accepted.

For example, to satisfy a mandatory Resolution code:

| Source | Field Name | Value | Apply On |
|---|---|---|---|
| Static | `close_code` | `Resolved by DefectDojo` | Transition to Closed |
| Static | `close_notes` | `Reviewed by the security team` | Transition to Closed |
| Static | `close_code` | `Not a defect` | Transition to False Positive |

Notes:

- Field Name is the ServiceNow column name — `close_code`, `close_notes`, or a custom `u_...` field.
- Transition mappings fire when the record's state actually changes: a Finding that is already closed when first pushed, an update that closes or reopens the record, and the forced close when a ticket link is deleted. They are not re-sent on routine updates of an unchanged record, so journal fields such as `work_notes` receive one entry per transition.
- Reference fields such as `assignment_group` and `assigned_to` expect a **sys_id**, not a display name.
- Values that parse as JSON are sent typed: `true`, `42`, `[...]`, `{...}` — and `null`, which clears the field. To send such text as a literal string, wrap it in double quotes (e.g. `"null"`).
- `short_description`, `description`, `state`, `impact`, `urgency`, and `priority` are owned by the description template and the severity/status mappings, so they cannot be set through a custom field mapping.
- On tables other than `incident`, state values that match the standard Incident set (`1`, `2`, `3`, `6`, `7`, `8`) are still interpreted with Incident semantics — including the automatic Resolution code default on `6`/`7`/`8`. Prefer state values outside that range on custom tables, or supply the close fields explicitly as above.
