---
title: "BigID"
description: "How to set up the BigID Upstream Connector for DefectDojo"
weight: 24
audience: pro
---
The BigID connector imports **data security posture (DSPM) findings** — exposed sensitive data, over-permissive access, and unprotected PII stores — from BigID's actionable insights. DefectDojo creates a Record for each BigID **data source**.

> **Your sensitive data is never copied into DefectDojo.** Findings carry only identifiers, classifications, and affected-object **counts**. No sample or preview of the underlying sensitive data is read or written into a finding — which is what makes it safe to surface DSPM results alongside your other findings.

#### Prerequisites

A BigID **user token**, from **Administration \> Access Management**. DefectDojo exchanges it for a short\-lived system token on each Sync; the user token is never logged.

#### Connector Mappings

1. Enter your BigID instance URL in the **Location** field.
2. Enter the user token in the **User Token** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each BigID data source becomes a Record, carrying the actionable-insight cases raised against it.
