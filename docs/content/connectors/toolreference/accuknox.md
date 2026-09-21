---
title: "AccuKnox"
description: "How to set up the AccuKnox Upstream Connector for DefectDojo"
weight: 10
audience: pro
---
The AccuKnox connector imports **cloud security posture (CSPM) findings** across your whole AccuKnox tenant. DefectDojo creates a Record for each **connected cloud account**, plus a tenant\-level catch\-all Record — findings that match no specific account land there, so nothing is silently dropped.

#### Prerequisites

An AccuKnox **access key**. An access key inherits the permissions of the user who created it, and the **Viewer** role is sufficient.

**Access keys expire.** When one does, the Sync fails with an authentication error rather than degrading quietly — so an authentication failure on a previously working connector usually means the key needs replacing, not that the connection is misconfigured.

#### Connector Mappings

1. Enter your AccuKnox CSPM host in the **Location** field.
2. Enter the access key in the **Secret** field.
3. Optionally, enter your AccuKnox **Tenant ID** (workspace ID). It is sent with every read request.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each connected cloud account becomes a Record, with AccuKnox's own four severity levels (Critical, High, Medium, Low) carried through.
