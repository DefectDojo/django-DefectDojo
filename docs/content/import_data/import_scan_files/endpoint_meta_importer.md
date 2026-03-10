---
title: "Endpoint Meta Importer"
description: "Bulk-apply tags and custom fields to endpoints via CSV"
weight: 4
audience: opensource
---

The **Endpoint Meta Importer** lets you apply tags and custom fields to large numbers of endpoints at once using a CSV file. This is particularly useful for organizations running heavy infrastructure scanning, where endpoints need flexible metadata for filtering, sorting, and reporting.

## CSV Format

The CSV file must have a `hostname` column (required), plus any number of additional columns representing the tags or custom fields you want to apply. Each additional column name becomes the tag/field key, and its row value becomes the tag/field value.

**Example:**

```
hostname,team,public_facing
sheets.google.com,data analytics,yes
docs.google.com,language processing,yes
feedback.internal.google.com,human resources,no
```

This would apply the following metadata:

| Endpoint | Tags / Custom Fields |
|---|---|
| `sheets.google.com` | `team:data analytics`, `public_facing:yes` |
| `docs.google.com` | `team:language processing`, `public_facing:yes` |
| `feedback.internal.google.com` | `team:human resources`, `public_facing:no` |

## Requirements

- The `hostname` column is **required**. It is used to find existing endpoints with a matching host, or to create new endpoints if no match is found.
- All other column names are treated as tag/custom field keys.
- Values are stored in `key:value` format.

## Using the Endpoint Meta Importer

The Endpoint Meta Importer is available from the **Endpoints** tab when viewing a Product. Upload your CSV file there to apply the metadata to your endpoints in bulk.
