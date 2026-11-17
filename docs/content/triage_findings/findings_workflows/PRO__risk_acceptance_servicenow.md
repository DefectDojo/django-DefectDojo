---
title: "Risk Acceptance Approvals in ServiceNow"
description: "Send risk acceptance requests to ServiceNow and apply the approval decision made there"
audience: pro
weight: 3
---

Many teams already approve exceptions in ServiceNow. With **ServiceNow approvals** turned on, every risk acceptance request opened in DefectDojo Pro also opens a record in ServiceNow. When somebody approves or rejects that record in ServiceNow, DefectDojo applies the same decision to the request, as the DefectDojo user an administrator has linked to that ServiceNow approver. The audit history names the approver.

This feature builds on [Risk Acceptances 2.0](../pro__risk_acceptance/#risk-acceptances-20-beta), so the **Risk Acceptances 2.0** feature flag has to be on.

## How it works

1. A request starts waiting for a decision. That happens when somebody uses **Request Security Exception**, resubmits a rejected request, or asks to extend an expired acceptance. DefectDojo then creates a new record in the ServiceNow table you choose, usually within a minute. The record holds the request's name, who asked, the justification, the Findings it covers, the requested expiry date and a link back to DefectDojo.
2. Your approval flow in ServiceNow asks the approvers. DefectDojo does not choose them; your flow does.
3. Every five minutes DefectDojo reads the **Approval** field of every open record it created.
   - **Approved**: the request moves to Approved and then Active, and its Findings are risk accepted.
   - **Rejected**: the request moves to Rejected.

   Either way, the move is recorded as the DefectDojo user linked to the ServiceNow approver (see [Linking ServiceNow approvers](#linking-servicenow-approvers)). The reason reads, for example, "Approved in ServiceNow by Jane Doe (CHG0031245)", followed by the approver's comment.
4. If the expiry field holds a future date when the record is approved, that date becomes the acceptance's expiry date. The approver can change the date in ServiceNow before approving.

A ServiceNow decision is applied only if the same person could have made it in DefectDojo:

- The ServiceNow approver must be linked to an active DefectDojo user. Approvers are never matched by email address or name.
- That user needs the **Approve** permission for risk acceptances on the Asset the Findings belong to.
- With **Block Self-Approval of Risk Acceptances** on (the default), the person who requested the acceptance cannot approve it in ServiceNow either. Rejecting your own request is allowed.

When a decision cannot be applied, the request keeps waiting and the risk acceptance page says why. DefectDojo checks again on every poll, so linking the approver, granting the permission or correcting the date is enough: the next poll applies the decision. A decision by an approver who is not linked is recorded but not applied, and a DefectDojo approver can decide the request as usual.

### A decision applies only to the request that was sent

When DefectDojo creates the record, it keeps a fingerprint of everything the decision depends on: the name, the expiry date, the recommendation and justification, the decision and its details, who accepted it, the owner, what happens on expiry, the attachment, the Findings and the scope. A decision made in ServiceNow is applied only while the request still matches what was sent.

If the request is changed in DefectDojo after it was sent (for example the expiry date is cleared, the justification is rewritten or a Finding is added), the decision made in ServiceNow is recorded but not applied, and the record is closed as **request changed**. The risk acceptance page names what changed. The request keeps waiting: use **Send to ServiceNow Again** to ask for a decision on the request as it is now, or decide it in DefectDojo.

### DefectDojo only acts on its own records

DefectDojo reads only the records it created itself, and never adopts an existing ServiceNow record, even one that carries the same correlation values. Each record carries a random correlation token that DefectDojo does not show anywhere, so a record made by hand cannot stand in for a request. A record that already carries a decision when ServiceNow creates it is closed and never applied; the request keeps waiting, so send it again or decide it in DefectDojo.

DefectDojo never writes to a record after creating it.

### When things change on either side

| What happens | What DefectDojo does |
| --- | --- |
| The request is approved, rejected or expired in DefectDojo first | Stops waiting for ServiceNow. A later decision in ServiceNow is ignored. DefectDojo does not change the ServiceNow record. |
| The request is changed in DefectDojo after it was sent | Closes the record as request changed. A decision made on it is recorded but not applied. Send the request again, or decide it in DefectDojo. |
| The ServiceNow record is cancelled or deleted | Stops waiting for that record. The request keeps waiting for a decision. Use **Send to ServiceNow Again** to open a new record, or decide in DefectDojo. |
| ServiceNow cannot be reached, or refuses the credentials | Keeps the request waiting and retries. Creating a record backs off up to once an hour. |
| The ServiceNow connection is deleted | A record not yet created is created through the connection selected in the settings now. A waiting record is closed, the risk acceptance page says why, and the request is sent again through the current connection. |
| Applying a decision fails unexpectedly | The request keeps waiting with the reason shown, and the next poll applies the decision. |
| A rejected request is resubmitted, or an expired acceptance is sent back for review | Opens a new record. Each round keeps its own record. |
| ServiceNow approvals are turned off | Opens no new records and stops polling. Open records resume when the feature is turned back on. |

A request raised before ServiceNow approvals were turned on is not sent automatically. Use **Send to ServiceNow** on its risk acceptance page.

## Setting it up in ServiceNow

### 1. Choose the table

The record can go in any table that extends **Task**, because Task provides the **Approval** field that DefectDojo reads. The default is **change_request**. Many teams create a dedicated table for security exceptions instead, for example `u_security_exception` extending Task, so these requests stay out of the change queue.

DefectDojo fills in `short_description`, `description`, `correlation_id` and `correlation_display` (always `DefectDojo`), plus the expiry field if you name one. Use `correlation_display = DefectDojo` to tell these records apart from the rest of the table.

### 2. Build the approval flow

In **Flow Designer**, create a flow:

- **Trigger**: *Created* on your table, with the condition **Correlation display** is `DefectDojo`.
- **Action**: *Ask For Approval* on the trigger record, with the approvers or approval rules your exception policy needs.

*Ask For Approval* sets the record's **Approval** field to *Requested*, and then to *Approved* or *Rejected* once the rules are met. That field is the only one DefectDojo reads to learn the decision. If the flow sets the field to *Cancelled*, DefectDojo treats the record as cancelled.

A record whose **Approval** stays at *Not Yet Requested* waits forever. If requests never get a decision, check that the flow's trigger condition matches.

### 3. Give the integration account access

DefectDojo connects as the account stored in the ServiceNow connection. That account needs to:

- create and read records in the chosen table
- read `sysapproval_approver`, to learn who approved or rejected a record and their comment
- read the approver's `sys_id` and `name` on `sys_user`, which DefectDojo reads through the approver reference

### 4. Pick the expiry field (optional)

The expiry field must be a **Date/Time** field on the table. The default is `end_date` (Planned end date on change_request). DefectDojo writes the requested expiry date into it when it creates the record. Whatever date the field holds when the record is approved becomes the expiry date. Leave the setting blank to always keep the date requested in DefectDojo.

When an expired acceptance is sent back for review, DefectDojo leaves the field empty instead of writing the lapsed date. An approval with the field still empty reinstates the acceptance with the default expiry.

## Setting it up in DefectDojo

1. Create or reuse a **ServiceNow** or **ServiceNow SecOps** connection in Downstream Connectors (see [ServiceNow](/connectors/toolreference/servicenow/)). The approval loop uses the same credentials: Basic, an API key, or OAuth.
2. As a superuser, open **Settings > System Settings**. The **ServiceNow Approvals for Risk Acceptances** section appears below the main form only while Risk Acceptances 2.0 is on (the settings API answers only then too).
3. Check **Send Risk Acceptance Requests to ServiceNow**, choose the **ServiceNow Connection**, and set the **ServiceNow Table** and the **Expiry Field**. Select **Submit**.
4. Link your ServiceNow approvers to DefectDojo users, as described below.

**DefectDojo has to reach your ServiceNow instance.** The loop polls from DefectDojo, so ServiceNow never has to reach DefectDojo, but the deployment's outbound network policy must allow the instance's address.

### Linking ServiceNow approvers

A decision made in ServiceNow is applied only when a superuser has linked its approver to an active DefectDojo user. The link pairs the approver's ServiceNow user `sys_id` (32 characters, 0 to 9 and a to f, shown in the URL of the user record in ServiceNow) with the id of a DefectDojo user. Email addresses and names are never used to match, because they can be changed in ServiceNow by people who should not be able to approve in DefectDojo.

The links are set through the settings API for now; the System Settings form does not show them, and saving the form keeps them. Send the full list each time:

```
PATCH /api/v2/risk_acceptance_servicenow/settings/
{
  "approver_links": [
    {"servicenow_user": "<32-character sys_id>", "user": <DefectDojo user id>}
  ]
}
```

Each ServiceNow user can be linked once, and the DefectDojo user must be active. The linked user still needs the Approve permission on the Asset, and the self-approval rule still applies. Every change to the settings, including the links, is recorded in the audit log with the superuser who made it.

Linking an approver after they decided applies their waiting decision on the next poll, as long as the request has not changed since it was sent.

## Reading the status

With ServiceNow approvals turned on, the **Review** tile of a risk acceptance shows a **ServiceNow** line under the expiry date:

- the status of the request's latest record: *Opening*, *Waiting for a Decision*, *Approved*, *Rejected* or *Closed*. The status turns amber while something stops the decision from being applied.
- the record's number, linking to the record in ServiceNow
- a warning icon whose tooltip says why the request is stuck, or why the record was closed
- **Send to ServiceNow** or **Send to ServiceNow Again**, while the request is still undecided and its record failed to open, was closed or cancelled, or was never sent. It needs the Edit permission on the risk acceptance.

Who decided, and the reason, are in the decisions list of the same tile.

Common reasons, and what to do:

| The tooltip says | Fix |
| --- | --- |
| That ServiceNow user is not linked to an active DefectDojo user | Link the approver's `sys_id` to their DefectDojo user, or decide the request in DefectDojo. |
| does not have permission to approve risk acceptances | Grant the linked user a role with the Approve permission on the Asset. |
| requested this risk acceptance and approved it in ServiceNow | Have somebody else approve it, or turn off **Block Self-Approval of Risk Acceptances**. |
| The request was changed in DefectDojo after it was sent to ServiceNow | Send the request to ServiceNow again, or decide it in DefectDojo. |
| is not a future date | Correct the expiry date on the ServiceNow record. |
| refused the connection's credentials / answered HTTP 403 | Check the integration account's roles and the table name. |

## API

These endpoints are part of the public API and accept an API token. They answer only while Risk Acceptances 2.0 is on.

- `GET /api/v2/risk_acceptance/{id}/servicenow_approval/` returns whether ServiceNow approvals are on, and the request's latest record with its status and any problem.
- `POST /api/v2/risk_acceptance/{id}/servicenow_approval/send/` sends a request that is still waiting for a decision to ServiceNow again. It needs the Edit permission on the risk acceptance. It answers `202`, `400` when ServiceNow approvals are not set up, or `409` when the request was already decided.
- `GET` and `PATCH /api/v2/risk_acceptance_servicenow/settings/` read and change the settings, including `approver_links`. Superusers only.
