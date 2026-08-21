---
title: "ServiceNow SecOps"
description: "How to set up the ServiceNow SecOps Downstream Connector for DefectDojo"
weight: 122
audience: pro
---
The ServiceNow SecOps integration (also known as **ServiceNow SecOps / Vulnerability Response**) pushes DefectDojo Findings and Finding Groups into a ServiceNow security table — a **Security Incident** (`sn_si_incident`) or a **Vulnerable Item** (`sn_vul_vulnerable_item`) — and keeps it in sync as the Finding changes (create, update, and resolve/close). It is the security-operations counterpart to the [ServiceNow](/connectors/toolreference/servicenow/) issue-tracker integration; use ServiceNow SecOps when you run the Security Incident Response (SIR) or Vulnerability Response (VR) applications.

### Instance Setup

- **Instance Label** should be the label that you want to use to identify this integration.
- **Location** should be set to the URL for your ServiceNow server, for example `https://your-organization.service-now.com/`.

ServiceNow SecOps supports three authentication methods; provide **one**:

- **OAuth 2.0** — enter a **Client ID**, **Client Secret**, and **Refresh Token**. Obtain them exactly as described on the [ServiceNow](/connectors/toolreference/servicenow/) page (create an OAuth API endpoint in the Application Registry, then exchange your credentials at `/oauth_token.do` for a refresh token). Alternatively, provide the **Client ID** and **Client Secret** together with a **Username** and **Password** to use the OAuth password grant instead of a refresh token.
- **API Key** — enter an **API Key**, sent as the `x-sn-apikey` header. The key authenticates nothing until an Inbound Authentication Profile and a REST API Access Policy are attached to it on the instance.
- **HTTP Basic** — enter the **Username** and **Password** of the service account.

The service account (or OAuth client) needs write access to the target table.

### Issue Tracker Mapping

- **Target Table** selects the ServiceNow table records are written to: **Security Incident** (`sn_si_incident`, the default) or **Vulnerable Item** (`sn_vul_vulnerable_item`).

### Severity Mapping Details

For a Security Incident this maps to the **Impact** field; ServiceNow derives the incident Priority from Impact and Urgency, so Urgency mirrors the mapped Impact unless you map it yourself. For a Vulnerable Item, map severity to the risk field your instance uses. The defaults below match the standard SIR Impact scale (`1` High, `2` Medium, `3` Low) and are editable.

- **Severity Field Name**: `impact`
- **Info Mapping**: `3`
- **Low Mapping**: `3`
- **Medium Mapping**: `2`
- **High Mapping**: `1`
- **Critical Mapping**: `1`

### Status Mapping Details

This maps to the record's **State** field. State values are numeric codes that differ between the Security Incident and Vulnerable Item tables and can be customized per instance, so review these against your own configuration. The defaults below use the standard SIR state codes (`16` Analysis, `3` Closed).

- **Status Field Name**: `state`
- **Active Mapping**: `16`
- **Closed Mapping**: `3`
- **False Positive Mapping**: `3`
- **Risk Accepted Mapping**: `3`

When a record is closed, DefectDojo also sets the ServiceNow **Close Code** and **Close Notes** (`Resolved` for closed Findings, `False positive` and `Risk accepted` for the corresponding states).

### ServiceNow SecOps-specific behaviors

- **Deduplication** — each record is tagged with the Finding or Finding Group's DefectDojo identifier in its `correlation_id`. Before creating a record DefectDojo looks one up by `correlation_id`; a match is adopted and updated rather than duplicated, so re-syncs are idempotent.
- **Updates** are posted to the record's **Work notes** journal (internal), never to customer-visible Comments.
- **Resolve on delete** — deleting a Finding in DefectDojo resolves/closes the ServiceNow record (State + Close Code) rather than deleting it; records are never hard-deleted.
- **Reference fields** — optional `cmdb_ci`, `assignment_group`, and `assigned_to` values may be supplied as display names; DefectDojo resolves each to its `sys_id`. A name that does not resolve is dropped with a warning rather than failing the push.
