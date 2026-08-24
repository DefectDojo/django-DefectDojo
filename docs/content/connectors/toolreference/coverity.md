---
title: "Coverity"
description: "How to set up the Coverity Upstream Connector for DefectDojo"
weight: 40
audience: pro
---
The Coverity connector imports findings from a **Coverity Connect** server. DefectDojo creates a Record for each Coverity **project**.

#### Connector Mappings

1. Enter your Coverity Connect server URL in the **Location** field.
2. Enter the Coverity Connect **username** in the **Username** field.
3. Enter the user's password or authentication key in the **Secret** field.
4. Optionally, set a **View Name** to select which saved issues view the connector reads. Leave blank to use the default, **Outstanding Issues**.
5. Optionally, set **Import All Issue Kinds** to `true` to widen the import beyond the default Security and Quality (`RESOURCE_LEAK`) issue filter.
