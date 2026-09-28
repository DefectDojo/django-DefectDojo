---
title: "Chef Automate"
description: "How to set up the Chef Automate Upstream Connector for DefectDojo"
weight: 34
audience: pro
---
The Chef Automate connector imports **InSpec compliance findings**. DefectDojo groups the nodes Chef Automate reports on by their **environment**, and creates a Record for each environment.

#### Prerequisites

A Chef Automate **API token**. It is never logged.

#### Connector Mappings

1. Enter your Chef Automate server URL in the **Location** field.
2. Enter the API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each environment becomes a Record, carrying the **failed** InSpec controls from each of its nodes' **latest** compliance runs. Passing and skipped controls are not imported, so the finding list is your outstanding compliance work rather than a full control inventory.
