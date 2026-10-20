---
title: "Product export"
description: "Export one product with its engagements, tests, findings, notes, files and risk acceptances as NDJSON."
draft: false
weight: 5
---

## What it is

DefectDojo has two API endpoints that export data:

- `GET /api/v2/export/manifest/` describes the instance: its product types and products with their counts, the reference data, and the users.
- `GET /api/v2/export/products/{id}/` streams one product with its engagements, tests, findings, notes, files and risk acceptances.

Use them to back up one product, or to move a product to another DefectDojo instance.
You can also use them to keep a mirror of an instance.
Tools that migrate or mirror a DefectDojo instance read this stream.

Only a superuser can call these endpoints.
Authenticate with an API v2 key in the `Authorization: Token` header, as for every other [API v2](/automation/api/api-v2-docs/) endpoint.
An anonymous request gets a 403. A user who is not a superuser also gets a 403.

Because the caller is always a superuser, the export does not filter by permissions.
Private notes cross. A product id that does not exist gets a 404.

## Before you export

The export does not take a snapshot of the database.
If a user changes the product during the stream, the change can show in one line and not in another.
If the instance has a read-only mode (DefectDojo 3.4.300 or later), turn it on first so the export is consistent.

## The manifest: `GET /api/v2/export/manifest/`

```bash
curl -H "Authorization: Token <your API key>" \
  https://dojo.example/api/v2/export/manifest/
```

The response is one JSON object with these keys:

| Key | What it holds |
|-----|---------------|
| `schema` | The version of the export format. It is `1`. |
| `generated_at` | The time the server built the response, in ISO 8601. |
| `source` | The instance: `version`, `install_id`, `url` and `locations_enabled`. `install_id` is a random id that stays the same for the life of the instance. |
| `max_file_bytes` | The file cap that the `files_over_cap` counts use. |
| `token` | The caller: `username`, `is_superuser` and `expires_at`. `expires_at` is `null` when the API key does not expire. |
| `scan_types` | The scan types of every test on the instance, sorted. |
| `reference` | The lookup tables that the product export refers to by id: `sla_configurations`, `development_environments`, `regulations`, `test_types`, `note_types`, `product_platforms`, `product_lifecycles`, `product_origins` and `users`. Each user carries its `contact_info`. The product carries its platform, lifecycle and origin as the `value` of an entry in these tables. |
| `product_types` | One entry per product type, with `id`, `name` and `counts`. Its `counts` also hold `products`. |
| `products` | One entry per product, with `id`, `name`, `prod_type` (the product type id) and `counts`. |
| `totals` | The counts of all products added together, plus `product_types` and `products`. |

Each `counts` object has the keys `engagements`, `tests`, `findings`, `endpoints`, `notes`, `files`, `files_over_cap`, `risk_acceptances` and `finding_groups`.
An example product entry, with Locations off:

```json
{"id": 2, "name": "Security How-to", "prod_type": 2, "counts": {"engagements": 5, "tests": 10, "findings": 15, "endpoints": 2, "notes": 3, "files": 0, "files_over_cap": 0, "risk_acceptances": 0, "finding_groups": 0}}
```

Four counts need a closer look when you compare the manifest with a product stream:

- `endpoints` in the manifest is the number of endpoints in the product. With Locations on, it is the number of locations in the product. In the stream, `end.counts.endpoints` is the number of endpoint entries on finding lines. One endpoint on three findings counts three times in the stream. The two numbers differ on purpose.
- `notes` counts one entry per owner on both sides. The owners are engagements, tests, findings and risk acceptances. A note on two findings counts twice.
- `files` and `files_over_cap` count the file entries on engagements, tests and findings on both sides. A risk acceptance's proof is not counted.
- `finding_groups` in the manifest is the number of finding groups in the product. In the stream, it is the number of distinct finding groups on finding lines. A finding group with no findings counts in the manifest and not in the stream.

The manifest takes one parameter:

| Parameter | Type | Default | What it does |
|-----------|------|---------|--------------|
| `max_file_bytes` | integer, 0 or more | `10485760` (10 MiB) | The file cap. A file larger than this counts in `files_over_cap`. |

A value that is not a whole number of 0 or more gets a 400.
To count `files_over_cap`, the server reads the size of every file in storage. On an instance with many files, the manifest can take some time.

## The product stream: `GET /api/v2/export/products/{id}/`

```bash
curl -H "Authorization: Token <your API key>" \
  -o product-2.ndjson \
  https://dojo.example/api/v2/export/products/2/
```

The response has the content type `application/x-ndjson`: one JSON object on each line.
The `Content-Disposition` header names the file `defectdojo-product-2-export.ndjson`.
The endpoint takes the same `max_file_bytes` parameter as the manifest.

The lines come in this order:

1. One `header` line.
2. Every `engagement` of the product, by id.
3. Every `test`, by id.
4. Every `finding`, by id.
5. Every `risk_acceptance`, by id.
6. One `end` line.

The product and each engagement, test, finding and risk acceptance have a line of their own.
A line does not nest one of these objects in another. It names them by id.
For example, a test line names its engagement by id, and a finding line names its test by id.
Notes, files, endpoint entries and finding groups are nested in the line that holds them. The product on the header line nests its product type.
A stream that has no `end` line is incomplete. The connection dropped before the export finished, so export the product again.
The number of lines is `1 + engagements + tests + findings + risk_acceptances + 1`, from `end.counts`.

### Line types

| `type` | What the line holds |
|--------|---------------------|
| `header` | `schema` (`1`), `generated_at`, `max_file_bytes`, `source` (as in the manifest) and `product`. `product` is the product as `/api/v2/products/` returns it, with its `prod_type` as a nested object and without `findings_count` and `findings_list`. |
| `engagement` | `data`: the engagement as `/api/v2/engagements/` returns it. `files` holds file entries. |
| `test` | `data`: the test as `/api/v2/tests/` returns it. `files` holds file entries. |
| `finding` | `data`: the finding as `/api/v2/findings/` returns it, with the changes below. |
| `risk_acceptance` | `data`: the risk acceptance as `/api/v2/risk_acceptance/` returns it, with the changes below. |
| `end` | `counts`: what the stream wrote. |

An example `header` line, shortened:

```text
{"type": "header", "schema": 1, "generated_at": "...", "max_file_bytes": 10485760, "source": {"version": "...", "install_id": "...", "url": "...", "locations_enabled": true}, "product": {"id": 2, "name": "Security How-to", "prod_type": {"id": 2, "name": "ebooks", ...}, ...}}
```

User fields, for example `lead`, `reporter` and `mitigated_by`, stay user ids.
Look them up in the manifest's `reference.users`.
Notes are nested on each line, with their author.

### Finding lines

A finding line differs from `/api/v2/findings/` in these fields:

- `endpoints` is a list of endpoint entries, not ids.
- `files` is a list of file entries, not ids.
- `risk_acceptances` is a list of risk acceptance ids.
- `accepted_risks` and `related_fields` are not on the line.

Each endpoint entry has these keys:

| Key | Locations off | Locations on |
|-----|---------------|--------------|
| `id` | The endpoint id. | The location id. |
| `uri` | The endpoint as a URI. | The location value. |
| `location_type` | `null` | The location type, for example `url`. |
| `tags` | The endpoint tags. | The location tags. |
| `status` | The endpoint status object, as `/api/v2/endpoint_status/` returns it. | The location reference object of this finding. |

The header's `source.locations_enabled` tells you which shape `status` has.
An example entry with Locations off:

```json
{"id": 2, "uri": "ftp://localhost", "location_type": null, "tags": [], "status": {"id": 1, "date": "2020-07-01", "last_modified": "2020-07-01T17:45:39.791907Z", "mitigated": false, "mitigated_time": null, "false_positive": false, "out_of_scope": false, "risk_accepted": false, "mitigated_by": null, "endpoint": 2, "finding": 2}}
```

The same entry with Locations on:

```json
{"id": 2, "uri": "ftp://localhost", "location_type": "url", "tags": [], "status": {"id": 1, "location_type": "url", "location_value": "ftp://localhost", "created": null, "updated": null, "relationship": "", "relationship_data": {}, "audit_time": null, "status": "Active", "location": 2, "finding": 2, "auditor": null}}
```

### Risk acceptance lines

A risk acceptance line differs from `/api/v2/risk_acceptance/` in these fields:

- `engagement` is the id of the engagement that holds the risk acceptance.
- `notes` are nested, not ids.
- `proof` replaces `path`. It holds `filename`, `size`, `content_type` and `data_base64`, or it is `null` when there is no proof. The proof follows the same cap and the same missing-file rule as a file entry.

### Files

Engagement, test and finding lines carry their files in `files`. Each file entry has these keys:

| Key | What it holds |
|-----|---------------|
| `id` | The file id. |
| `title` | The file title. |
| `size` | The size in bytes. |
| `content_type` | The content type, from the file name. It is `null` when the file name has no known extension. |
| `data_base64` | The file contents in base64. |

A file of `max_file_bytes` or less carries its contents.
A larger file keeps its `size`, and `data_base64` is `null`. The export has no download link for it.
To carry larger files, raise `max_file_bytes`. For example, `?max_file_bytes=52428800` carries files up to 50 MiB.
While the server writes a line, it holds the files of that line and their base64 in memory. That is about four times the size of the files, for one line at a time.
A file that is gone from storage has `size` and `data_base64` set to `null`, and `"error": "missing"`.

### The end line

`end.counts` holds what the stream wrote, in this order:

| Key | What it counts |
|-----|----------------|
| `engagements` | Engagement lines. |
| `tests` | Test lines. |
| `findings` | Finding lines. |
| `endpoints` | Endpoint entries on finding lines. |
| `notes` | Notes on engagement, test, finding and risk acceptance lines. |
| `files` | File entries on engagement, test and finding lines. |
| `files_over_cap` | File entries over the cap. A missing file is not counted. |
| `risk_acceptances` | Risk acceptance lines. |
| `finding_groups` | Distinct finding groups on finding lines. |

An example `end` line:

```json
{"type": "end", "counts": {"engagements": 5, "tests": 10, "findings": 15, "endpoints": 1, "notes": 3, "files": 0, "files_over_cap": 0, "risk_acceptances": 0, "finding_groups": 0}}
```

## What does not cross

- A finding group with no findings. Finding groups cross on the finding lines, so an empty group has no line.
- Endpoint metadata. Product metadata (`product_meta` on the header) and finding metadata (`finding_meta`) do cross.
- Secrets and instance settings: SSO, JIRA and tool credentials, notifications, API keys and passwords.
