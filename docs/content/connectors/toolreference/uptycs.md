---
title: "Uptycs"
description: "How to set up the Uptycs Upstream Connector for DefectDojo"
weight: 135
audience: pro
---
The Uptycs connector imports **vulnerability findings** from your Uptycs tenant. DefectDojo creates a Record for each **asset group**.

#### Prerequisites

Three values from Uptycs:

* Your **customer ID**, shown in the API key file.
* An **API key ID**, from **Configuration \> User \> API Keys**.
* The matching **API secret**, which DefectDojo uses to sign a per\-request token. It is never logged.

#### Connector Mappings

1. Enter your Uptycs stack URL in the **Location** field — for example `https://your-stack.uptycs.io`.
2. Enter the customer ID in the **Customer ID** field.
3. Enter the API key ID in the **Key** field.
4. Enter the API secret in the **Secret** field.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each asset group becomes a Record. Uptycs vulnerabilities are read through its osquery-style query engine, so the imported finding set is whatever that query returns for your tenant.
