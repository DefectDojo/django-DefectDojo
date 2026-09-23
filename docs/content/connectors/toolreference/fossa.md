---
title: "FOSSA"
description: "How to set up the FOSSA Upstream Connector for DefectDojo"
weight: 60
audience: pro
---
The FOSSA connector imports both **security vulnerabilities** and **license-policy violations** from FOSSA. DefectDojo creates a Record for each FOSSA **project**.

#### Prerequisites

A FOSSA **Full** API token.

> **A Push-Only token will not work.** FOSSA's Push-Only tokens cannot read the APIs this connector uses, so the Sync fails to retrieve anything. This is the most common misconfiguration for this connector — make sure the token is a **Full** token.

#### Connector Mappings

1. Enter `https://app.fossa.com/api` in the **Location** field.
2. Enter your FOSSA Full API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each FOSSA project becomes a Record. Only your organization's **active** issues are imported, covering both vulnerability and license-policy findings — so this connector can drive licence compliance work as well as security remediation.
