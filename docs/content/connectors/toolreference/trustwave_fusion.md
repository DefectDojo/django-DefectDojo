---
title: "Trustwave Fusion"
description: "How to set up the Trustwave Fusion Upstream Connector for DefectDojo"
weight: 134
audience: pro
---
The Trustwave Fusion connector imports findings from the Trustwave Fusion platform. DefectDojo creates a Record for each **asset**, derived from the findings themselves.

#### Prerequisites

A Trustwave Fusion **API token** for the tenant whose findings you want to import.

#### Connector Mappings

1. Enter your Trustwave Fusion API URL in the **Location** field.
2. Enter the API token in the **API Token** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each asset referenced by your findings becomes a Record, grouped by the asset the finding was reported against.
