---
title: "JSM Assets"
description: "How to set up the JSM Assets Upstream Connector for DefectDojo"
weight: 83
audience: pro
---
The JSM Assets connector is an **Asset Connector**: it enumerates the objects in your Jira Service Management Assets (formerly Insight) workspace and creates a DefectDojo Asset for each object, grouped into Organizations by object schema. No findings are imported.

#### Prerequisites

* Assets requires a **Jira Service Management Premium or Enterprise** plan. On Free or Standard plans the Assets API responds with `403 "Access to Assets API was denied"`, even though the rest of the site works.
* The Atlassian account used must have **Jira Service Management product access** (an agent seat) on the site — site access alone is not enough.
* Create a classic Atlassian API token at [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens). We recommend a dedicated service account.

#### Connector Mappings

1. Enter your Atlassian site URL in the **Location** field: `https://{your-site}.atlassian.net`.
2. Enter the Atlassian account email the token belongs to in the **Email** field.
3. Enter the API token in the **Secret** field.

Each Assets object becomes a Record named after the object's label, grouped by its **object schema**.
