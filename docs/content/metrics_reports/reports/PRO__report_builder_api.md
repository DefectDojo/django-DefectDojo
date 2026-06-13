---
title: "Automating Reports with the API"
description: "Create themes, blocks, and templates, then run reports and download results via the DefectDojo Pro REST API"
draft: false
audience: pro
weight: 2
slug: report-builder-api
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: The Report Builder REST API (report themes, blocks, templates, and generated reports) is a DefectDojo Pro feature, currently in beta.</span>

The Report Builder REST API lets you automate the same Themes, Blocks, and Templates you assemble by hand in the [Report Builder UI](../report-builder/) — and it goes one step further by letting you **run** a template and **download** the finished PDF or HTML. This guide walks the full lifecycle: authenticate, discover the field and filter vocabulary, create the building blocks, then generate and retrieve a report.

## Authentication

Every request authenticates with a personal API token sent in the `Authorization` header using the `Token` prefix (not `Bearer`).

Get your token from the DefectDojo Pro UI under **User Settings → API v2 Key**. Store it in an environment variable so it never lands in your shell history or a committed script:

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
```

The base URL for all calls is your instance plus `/api/v2`:

```
https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2
```

Required headers:

| Header | Value | When |
|--------|-------|------|
| `Authorization` | `Token YOUR_API_TOKEN` | Every request |
| `Accept` | `application/json` | Every request |
| `Content-Type` | `application/json` | `POST` / `PATCH` with a JSON body |

A minimal authenticated request looks like this:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_themes/"
```

List endpoints are paginated with `limit` and `offset` query parameters.

> **⚠️ Security Notice:** Your API token grants full access to your DefectDojo data. Never paste it into a chat, screenshot, ticket, or committed file. Read it from an environment variable, rotate it if it is ever exposed, and scope tokens to service accounts where possible.

## The reporting API at a glance

Four resources make up the Report Builder API. Each supports the standard list (`GET`), create (`POST`), retrieve (`GET {id}/`), update (`PATCH {id}/`), and delete (`DELETE {id}/`) operations, plus a handful of custom actions.

| Resource | Path | What it is | Custom actions |
|----------|------|------------|----------------|
| Themes | `/report_themes/` | Colors, fonts, header/footer images, page numbers | — |
| Blocks | `/report_blocks/` | A single piece of content: a cover page, a table, or a detail section | `field_options/`, `preview/`, `{id}/preview/`, `{id}/duplicate/` |
| Templates | `/report_templates/` | An ordered list of blocks plus a theme | `{id}/duplicate/` |
| Generated reports | `/generated_reports/` | A run of a template that produces a downloadable file | `{id}/download/` |

Two more endpoints help you discover the vocabulary you need:

| Endpoint | Purpose |
|----------|---------|
| `GET /report_blocks/field_options/` | Valid column field paths and ordering options for each model |
| `GET /oa3/schema/?format=json` | The full OpenAPI schema — used to discover valid filter names |

## Step 1: Discover the vocabulary

Two things in a block are easy to get wrong if you guess: the **column fields** you list, and the **filters** you apply. The API gives you a source of truth for both. Fetch them first, then build against what the server actually accepts.

### Column fields and ordering

`field_options` returns the valid `fields` (column paths) and `ordering_fields` for every model you can put in a tabular or detail block:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/field_options/"
```

The response is shaped like this (truncated):

```json
{
  "fields": {
    "finding": [
      {"path": "title", "label": "Title"},
      {"path": "severity", "label": "Severity"},
      {"path": "age_days", "label": "Age (days)"}
    ],
    "asset": [ ... ]
  },
  "ordering_fields": {
    "finding": [ ... ]
  }
}
```

Use only the `path` values returned here for a block's `fields` list. Some paths are long-form or markdown and are intended for **detail** blocks rather than narrow tabular columns — `field_options` is the authoritative list, so confirm against it rather than hardcoding an exhaustive set.

### Filter names from the schema

A block's filters live in `filter_entries`, where each entry is a `{field, value}` pair. The valid `field` names are the **GET query-parameter names** of the underlying entity's REST endpoint — *not* the labels you see in the UI. Discover them by reading the OpenAPI schema:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/oa3/schema/?format=json" \
  > schema.json
```

Then read the GET parameters for the entity you are filtering. For findings, look at `paths` → `/api/v2/findings/` → `get` → `parameters`. The analogous endpoints are `/api/v2/assets/` for **assets** (formerly Products), `/api/v2/organizations/` for **organizations** (formerly Product Types), `/api/v2/engagements/`, `/api/v2/tests/`, `/api/v2/test_types/`, and `/api/v2/risk_acceptance/`. Each parameter `name` is a valid filter `field`.

> **💡 Tip:** In DefectDojo Pro, **Assets** were formerly called **Products** and **Organizations** were formerly **Product Types**. The underlying filter field paths on findings still use the legacy `product` wording (for example, `test__engagement__product`), even though the entities are now Assets and Organizations.

> **🔑 Important:** The server **silently drops** any `filter_entry` whose `field` is not a real GET parameter for that model. No error is raised — the filter simply does not exist on the saved block. Always GET the block back after creating it and compare the returned `filter_entries` to what you sent.

### Common filter fields

The tables below list verified, high-value filters. All values are sent as **single-value strings**; booleans are the literal strings `"true"` / `"false"`.

**Finding filters**

| Field | Example value | Notes |
|-------|---------------|-------|
| `active` | `"true"` | Boolean string |
| `verified` | `"true"` | Boolean string |
| `is_mitigated` | `"false"` | Boolean string |
| `risk_accepted` | `"false"` | Boolean string |
| `duplicate` | `"false"` | Boolean string |
| `false_p` | `"false"` | Boolean string |
| `out_of_scope` | `"false"` | Boolean string |
| `severity` | `"Critical"` | Single value only — **not** comma-separated. Use one block per severity. |
| `known_exploited` | `"true"` | Boolean string |
| `ransomware_used` | `"true"` | Boolean string |
| `outside_of_sla` | `"1"` | **Numeric** string, not a boolean string |
| `priority_min` | `"800"` | Use `_min`/`_max`, not `_greater_than` |
| `priority_max` | `"1000"` | Use `_min`/`_max` |
| `tag` | `"DR"` | A single tag |
| `tags` | `"kev,pci"` | Any-of (matches any listed tag) |
| `tags__and` | `"kev,pci"` | All-of (must match every listed tag) |
| `test__engagement__product` | `"42"` | Asset ID (Assets were formerly Products) |
| `test__engagement__product__prod_type` | `"3"` | Organization ID (formerly Product Type) |
| `cve` | `"CVE-2024-12345"` | |
| `cwe` | `"79"` | |
| `date_after` | `"2025-12-31"` | |
| `date_before` | `"2025-12-31"` | |
| `planned_remediation_date_before` | `"2025-12-31"` | |

**Asset filters** (Assets were formerly called Products; these are the parameters on `/api/v2/assets/`)

| Field | Example value | Notes |
|-------|---------------|-------|
| `business_criticality` | `"very_high"` | |
| `internet_accessible` | `"true"` | Boolean string |
| `lifecycle` | `"production"` | |
| `platform` | `"web"` | |
| `tag` | `"pci"` | A single tag |

**Risk acceptance filters**

| Field | Example value | Notes |
|-------|---------------|-------|
| `decision` | `"Accept (Transfer)"` | |
| `owner` | `"7"` | User ID |
| `expiration_date_before` | `"2025-12-31"` | No `tag` filter exists on this model |

For **engagement**, **test**, **test type**, and **organization** blocks, read the GET parameters straight from the schema as described above. High-value ones include `engagement__product` and `status` on tests, and `name` on test types — but always confirm the exact name in `schema.json` before relying on it.

> **⚠️** These legacy / UI-style names are **silently dropped** and must NOT be used: `status_any`, `priority_greater_than`, `severity__in`, `mitigated_within_sla`, and any **comma-separated `severity`** value (e.g. `"Critical,High"`). Use the real query-parameter names from the schema instead, and split multi-severity needs into separate blocks.

> **🔑 Important:** A `PATCH` that includes `filter_entries` **replaces the entire list** — there is no merge. Always send the full desired set of filters on every update, or you will drop the ones you omit.

## Step 2: Create theme, blocks, and templates

Build the pieces in dependency order: a **theme**, then the **blocks**, then a **template** that references both.

### Create a theme

Colors are 7-character hex strings. Any field you omit falls back to its default (primary `#1e3a5f`, secondary `#4a90a4`, accent `#e67e22`, text `#333333`, background `#ffffff`).

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_themes/" \
  -d '{
    "name": "Quarterly Review Theme",
    "primary_color": "#1e3a5f",
    "secondary_color": "#4a90a4",
    "accent_color": "#e67e22",
    "text_color": "#333333",
    "background_color": "#ffffff",
    "footer_text": "Confidential — Internal Use Only",
    "show_page_numbers": true
  }'
```

The response includes the new theme `id`. Header and footer images are optional and are uploaded as multipart form fields (`header_image` / `footer_image`); the JSON example above skips them.

### Create blocks

A block has a `name`, a `block_type`, and a matching configuration object. The supported `block_type` values are `stock`, `tabular`, and `detail`. (A `chart` type exists in the data model but is not yet exposed through the API.)

**A stock cover page.** Stock blocks hold fixed content. The `stock_type` is one of `cover_page`, `table_of_contents`, `page_break`, `image`, or `text_block`.

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/" \
  -d '{
    "name": "Cover Page",
    "block_type": "stock",
    "header": "Cover",
    "stock_configuration": {
      "stock_type": "cover_page",
      "title": "Quarterly Security Report",
      "subtitle": "Q4 — Active Critical Findings"
    }
  }'
```

**A tabular finding block with filters.** Tabular blocks render rows of a chosen model. `model_choice` is exactly one of `organization`, `asset`, `engagement`, `test`, `finding`, `test_type`, or `risk_acceptance`. The `fields` come from `field_options` (confirm each `path`), and `filter_entries` scope the rows.

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/" \
  -d '{
    "name": "Active Critical Findings",
    "block_type": "tabular",
    "header": "Active Critical Findings",
    "tabular_configuration": {
      "model_choice": "finding",
      "fields": ["severity", "title", "age_days", "sla_days_remaining"],
      "ordering": "-age_days"
    },
    "filter_entries": [
      {"field": "active", "value": "true"},
      {"field": "severity", "value": "Critical"}
    ]
  }'
```

**A detail finding block.** Detail blocks render one expanded section per record and can include long-form / markdown fields that are not suited to a narrow table column. Again, confirm `fields` against `field_options`.

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/" \
  -d '{
    "name": "Critical Finding Detail",
    "block_type": "detail",
    "header": "Critical Findings — Detail",
    "detail_configuration": {
      "model_choice": "finding",
      "fields": ["title", "severity", "description", "mitigation"],
      "ordering": "-severity"
    },
    "filter_entries": [
      {"field": "active", "value": "true"},
      {"field": "severity", "value": "Critical"}
    ]
  }'
```

Each block response includes its `id`. Note that `filter_entries` echoes back what the server actually stored — compare it to what you sent (see [Verify what you built](#verify-what-you-built)).

### Create a template

A template binds a theme to an ordered list of blocks. The read-only field is `template_blocks`; on create and update you **write** `template_blocks_write`. Each entry needs an `order` and a `block_id`, and the same `block_id` may appear more than once.

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_templates/" \
  -d '{
    "name": "Quarterly Critical Report",
    "description": "Cover page, critical findings table, then per-finding detail",
    "theme_id": 1,
    "template_blocks_write": [
      {"order": 0, "block_id": 10},
      {"order": 1, "block_id": 11},
      {"order": 2, "block_id": 12}
    ]
  }'
```

Replace `theme_id` and each `block_id` with the IDs returned in the previous steps. The response includes the template `id`.

## Step 3: Run the report and download the result

Generating a report is asynchronous: you create a run, poll its status, then download the file once it completes.

**Start a run.** POST a `template_id` and a `file_format` of `pdf` or `html`:

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/" \
  -d '{
    "template_id": 5,
    "file_format": "pdf"
  }'
```

The response returns the new report `id` with `status` set to `pending`.

**Poll for status.** Retrieve the report until its `status` reaches a terminal state. The flow is `pending` → `processing` → `completed`. On `failed`, read `error_message` for the reason.

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/7/"
```

**Download the file.** Once `status` is `completed`, the download endpoint returns the file as an attachment. It responds with `404` until then.

```bash
curl -s -L \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/7/download/" \
  -o report.pdf
```

## Putting it together: a full lifecycle script

The script below runs the entire flow using only the Python 3 standard library — no `requests`, no third-party packages. It reads the token from `DD_IMPORTER_DOJO_API_TOKEN`, creates a theme, three blocks, and a template, kicks off a report, polls with backoff until it completes or fails, downloads the result, and writes the created IDs to `created.json`.

Set your instance URL and run it:

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
export DD_BASE_URL="https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2"
python3 build_report.py
```

```python
#!/usr/bin/env python3
"""Build and run a DefectDojo Pro report end-to-end using only the stdlib."""

import json
import os
import time
import urllib.error
import urllib.request

# --- Configuration -------------------------------------------------------
BASE_URL = os.environ.get(
    "DD_BASE_URL",
    "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2",
).rstrip("/")
TOKEN = os.environ["DD_IMPORTER_DOJO_API_TOKEN"]  # fail loudly if unset
FILE_FORMAT = "pdf"  # "pdf" or "html"


def api_request(method, path, body=None, accept_json=True):
    """Make an authenticated request. Returns parsed JSON (or raw bytes)."""
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None

    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Token {TOKEN}")
    if accept_json:
        request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(request) as response:
            payload = response.read()
    except urllib.error.HTTPError as error:
        # Surface the server's error body to make debugging easy.
        detail = error.read().decode("utf-8", errors="replace")
        raise SystemExit(f"{method} {path} failed ({error.code}): {detail}")

    if accept_json:
        return json.loads(payload) if payload else {}
    return payload


def main():
    created = {}

    # 1. Create a theme.
    theme = api_request("POST", "/report_themes/", {
        "name": "Quarterly Review Theme",
        "primary_color": "#1e3a5f",
        "secondary_color": "#4a90a4",
        "accent_color": "#e67e22",
        "text_color": "#333333",
        "background_color": "#ffffff",
        "footer_text": "Confidential - Internal Use Only",
        "show_page_numbers": True,
    })
    created["theme_id"] = theme["id"]
    print(f"Created theme id={theme['id']}")

    # 2. Create a stock cover page block.
    cover = api_request("POST", "/report_blocks/", {
        "name": "Cover Page",
        "block_type": "stock",
        "header": "Cover",
        "stock_configuration": {
            "stock_type": "cover_page",
            "title": "Quarterly Security Report",
            "subtitle": "Q4 - Active Critical Findings",
        },
    })
    created["cover_block_id"] = cover["id"]
    print(f"Created stock block id={cover['id']}")

    # 3. Create a tabular finding block scoped to active criticals.
    #    Confirm the chosen fields against /report_blocks/field_options/.
    table = api_request("POST", "/report_blocks/", {
        "name": "Active Critical Findings",
        "block_type": "tabular",
        "header": "Active Critical Findings",
        "tabular_configuration": {
            "model_choice": "finding",
            "fields": ["severity", "title", "age_days", "sla_days_remaining"],
            "ordering": "-age_days",
        },
        "filter_entries": [
            {"field": "active", "value": "true"},
            {"field": "severity", "value": "Critical"},
        ],
    })
    created["table_block_id"] = table["id"]
    print(f"Created tabular block id={table['id']}")

    # 4. Create a detail finding block.
    detail = api_request("POST", "/report_blocks/", {
        "name": "Critical Finding Detail",
        "block_type": "detail",
        "header": "Critical Findings - Detail",
        "detail_configuration": {
            "model_choice": "finding",
            "fields": ["title", "severity", "description", "mitigation"],
            "ordering": "-severity",
        },
        "filter_entries": [
            {"field": "active", "value": "true"},
            {"field": "severity", "value": "Critical"},
        ],
    })
    created["detail_block_id"] = detail["id"]
    print(f"Created detail block id={detail['id']}")

    # 5. Create a template binding the theme to the ordered blocks.
    #    Note: we WRITE template_blocks_write; template_blocks is read-only.
    template = api_request("POST", "/report_templates/", {
        "name": "Quarterly Critical Report",
        "description": "Cover, critical findings table, then per-finding detail",
        "theme_id": created["theme_id"],
        "template_blocks_write": [
            {"order": 0, "block_id": created["cover_block_id"]},
            {"order": 1, "block_id": created["table_block_id"]},
            {"order": 2, "block_id": created["detail_block_id"]},
        ],
    })
    created["template_id"] = template["id"]
    print(f"Created template id={template['id']}")

    # 6. Kick off a report run.
    report = api_request("POST", "/generated_reports/", {
        "template_id": created["template_id"],
        "file_format": FILE_FORMAT,
    })
    report_id = report["id"]
    created["report_id"] = report_id
    print(f"Started report id={report_id} (status={report['status']})")

    # 7. Poll until completed or failed, backing off up to 10 seconds.
    delay = 2
    while True:
        time.sleep(delay)
        report = api_request("GET", f"/generated_reports/{report_id}/")
        status = report["status"]
        print(f"  status={status}")
        if status == "completed":
            break
        if status == "failed":
            raise SystemExit(
                f"Report failed: {report.get('error_message', 'unknown error')}"
            )
        delay = min(delay + 2, 10)  # linear backoff, capped

    # 8. Download the finished file.
    content = api_request(
        "GET",
        f"/generated_reports/{report_id}/download/",
        accept_json=False,
    )
    out_name = f"report.{FILE_FORMAT}"
    with open(out_name, "wb") as handle:
        handle.write(content)
    print(f"Downloaded {out_name} ({len(content)} bytes)")

    # 9. Record the created IDs for later cleanup or reuse.
    with open("created.json", "w") as handle:
        json.dump(created, handle, indent=2)
    print("Wrote created.json")


if __name__ == "__main__":
    main()
```

## Verify what you built

Because invalid filters are dropped silently, verification is part of the workflow — not an afterthought.

**Confirm a block's filters survived.** GET each block back and compare its `filter_entries` to what you POSTed:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/11/"
```

If a filter you sent is missing from `filter_entries`, its `field` name was not a valid GET parameter for that model — recheck the name in `schema.json`.

**Confirm template order and theme.** GET the template and check that `template_blocks` lists the blocks in the expected `order` and that the bound theme matches:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_templates/5/"
```

**Fix dropped filters with PATCH.** To correct a block's filters, PATCH the **full** desired set — a PATCH replaces `filter_entries` wholesale:

```bash
curl -s -X PATCH \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/11/" \
  -d '{
    "filter_entries": [
      {"field": "active", "value": "true"},
      {"field": "severity", "value": "Critical"},
      {"field": "outside_of_sla", "value": "1"}
    ]
  }'
```

## Next steps

- Build and preview the same Themes, Blocks, and Templates interactively in the [Report Builder UI](../report-builder/).
- Let an LLM assemble report configurations for you with the [Report Builder LLM integration](../report-builder-llm/).
