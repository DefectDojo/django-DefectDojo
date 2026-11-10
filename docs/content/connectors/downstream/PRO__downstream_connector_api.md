---
title: "Automating Downstream Connectors with the API"
description: "Manage Issue Tracker Mappings, Assignments and Ticket Templates through the DefectDojo Pro REST API"
draft: false
audience: pro
weight: 3
slug: downstream-connector-api
---
You can build and maintain your Downstream Connector setup from code instead of the UI. This is useful when you have many Assets: a script can assign one Issue Tracker Mapping to hundreds of Assets, and run again when your Assets change.

This page covers the objects you work with after a connector exists: Issue Tracker Mappings, Issue Tracker Assignments, Ticket Templates, and the custom field, severity and status mappings that a mapping uses. Create the connector itself, with its credentials, in the UI. See [Downstream Connectors](../about/) for what each object does.

## Authentication

Every request sends your personal API token in the `Authorization` header with the `Token` prefix. Get your token from the user menu (your name at the bottom of the sidebar) under **API v2 Token**, and keep it in an environment variable:

```bash
export DD_API_TOKEN="YOUR_API_TOKEN"
export DD_URL="https://[YOUR-INSTANCE].cloud.defectdojo.com"
```

All paths on this page start with `/api/v2/downstream/`. The full request and response shapes are in the API schema at `/api/v2/oa3/swagger-ui/`, under the `downstream` group.

Permissions:

- To read these objects, your user needs the **Integration View** permission. To create, change or delete them, your user needs **Integration Edit**.
- To assign a mapping to an Asset or an Engagement, you also need edit rights on that Asset or Engagement.

> **⚠️ Security Notice:** Your API token grants access to your DefectDojo data. Never paste it into a chat, screenshot, ticket, or committed file. Read it from an environment variable, and rotate it if it is ever exposed.

## The resources

| Resource | Path | Operations |
|----------|------|------------|
| Connectors | `/api/v2/downstream/connectors/` | `GET` only. Use it to find the id of a connector you created in the UI. |
| Issue Tracker Mappings | `/api/v2/downstream/issue_tracker_mappings/` | `GET`, `POST`, `GET {id}/`, `PUT`/`PATCH {id}/`, `DELETE {id}/` |
| Issue Tracker Assignments | `/api/v2/downstream/issue_tracker_assignments/` | `GET`, `POST`, `GET {id}/`, `PUT`/`PATCH {id}/`, `DELETE {id}/` |
| Ticket Templates | `/api/v2/downstream/ticket_templates/` | `GET`, `POST`, `GET {id}/`, `PUT`/`PATCH {id}/`, `DELETE {id}/`, plus `POST validate/` |
| Custom Field Mappings | `/api/v2/downstream/custom_field_mappings/` | `GET`, `POST`, `GET {id}/`, `PUT`/`PATCH {id}/`, `DELETE {id}/` |
| Severity Mappings | `/api/v2/downstream/severity_mappings/` | `GET`, `POST`, `GET {id}/`, `PUT`/`PATCH {id}/`, `DELETE {id}/` |
| Status Mappings | `/api/v2/downstream/status_mappings/` | `GET`, `POST`, `GET {id}/`, `PUT`/`PATCH {id}/`, `DELETE {id}/` |
| Vendor Capabilities | `/api/v2/downstream/vendor_capabilities/` | `GET` only. Lists what each vendor accepts. |

## Build a setup in order

The objects refer to each other by id, so create them in this order:

1. **Find the connector id.** `GET /api/v2/downstream/connectors/` and note the `id` of your connector.
2. **Create the severity and status mappings.** These tell DefectDojo which vendor values to use for each severity and status. Create any custom field mappings at this point too.
3. **Create a Ticket Template** if you want your own title and description layout. A mapping works without one.
4. **Create the Issue Tracker Mapping.** Send the connector id as `integration`, the ids from steps 2 and 3, and the vendor's own target keys in `identifiers` (for Jira, the project key).
5. **Create one Issue Tracker Assignment for each Asset or Engagement.** Each assignment names the mapping and exactly one of `product` (the Asset id) or `engagement` (the Engagement id).

## Assign a mapping to an Asset

The `config` field sets how Findings are pushed. It takes one of `NO_AUTO_FEATURE`, `AUTO_ADD_LINK`, `AUTO_EDIT_LINK` or `AUTO_ADD_AND_EDIT_LINK`, which match the four options described in [Downstream Connectors](../about/).

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"issue_tracker_mapping": 12, "product": 345, "config": "AUTO_ADD_LINK"}' \
  "${DD_URL}/api/v2/downstream/issue_tracker_assignments/"
```

## Assign one mapping to many Assets

This loop assigns mapping `12` to every Asset id in `asset_ids.txt`, one id per line. Run it again with new ids as your Assets change. To see which Assets already have an assignment, `GET /api/v2/downstream/issue_tracker_assignments/` first, and skip those ids.

```bash
while read -r asset_id; do
  curl -s -o /dev/null -w "%{http_code} ${asset_id}\n" -X POST \
    -H "Authorization: Token ${DD_API_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"issue_tracker_mapping\": 12, \"product\": ${asset_id}, \"config\": \"AUTO_ADD_LINK\"}" \
    "${DD_URL}/api/v2/downstream/issue_tracker_assignments/"
done < asset_ids.txt
```

A `201` means the assignment was created. A `403` means your user can see that Asset but cannot edit it. A `400` that names `product` means the id is wrong or your user cannot see that Asset.

## Other paths to the same objects

The same objects are also served under `/api/connectors/v1/downstream/` and the older `/api/integrators/v1/`. Scripts that use those paths keep working, but automate against the `/api/v2/downstream/` paths on this page. The DefectDojo UI calls an internal mirror under `/api/vue/downstream/`, which does not accept API tokens.
