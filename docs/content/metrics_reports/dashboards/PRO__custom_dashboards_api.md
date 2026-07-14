---
title: "Automating Dashboards with the API"
description: "Discover the widget catalog, create and update dashboard layouts, and render widget data via the DefectDojo Pro REST API"
draft: false
audience: pro
weight: 11
slug: custom-dashboards-api
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: The Customizable Dashboards REST API (layouts, widget catalog, and widget data) is a DefectDojo Pro feature, currently in beta. Beta features are available to DefectDojo Pro Cloud subscriptions — contact DefectDojo support or your customer success advocate to enable it for your instance.</span>

The Customizable Dashboards REST API lets you build the same dashboards you assemble by hand in the [Dashboards UI](../custom-dashboards/) — entirely from code. You can discover the widget catalog, create and update layouts, set your default, share layouts with your team, and even render a widget's data on demand without re-implementing DefectDojo's filtering. The layouts surface was designed as the primary entry point for AI agents building dashboards, so the request shapes are deliberately introspectable.

This guide walks the full lifecycle: authenticate, discover the widget vocabulary, create a layout, then verify and render it.

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
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_catalog/"
```

> **🔑 Important:** The entire Dashboards API is part of the beta. Until it is enabled for your instance, every endpoint returns `403 Dashboard V2 is not enabled.` — see [Enabling the beta](../custom-dashboards/#enabling-the-beta).

> **⚠️ Security Notice:** Your API token grants full access to your DefectDojo data. Never paste it into a chat, screenshot, ticket, or committed file. Read it from an environment variable, rotate it if it is ever exposed, and scope tokens to service accounts where possible.

## The dashboards API at a glance

Three resource groups make up the Dashboards API, all under `/api/v2/dashboards/`.

| Resource | Path | What it is | Operations |
|----------|------|------------|------------|
| Layouts | `/dashboards/layouts/` | Your saved dashboards (and shared team templates) | `GET` list, `POST` create, `GET {id}/`, `PATCH {id}/`, `DELETE {id}/`, plus `{id}/clone/`, `{id}/set_default/`, `shared/`, `for_current_user/` |
| Widget catalog | `/dashboards/widget_catalog/` | The menu of widget types + a config example for each | `GET` (read-only) |
| Widget data | `/dashboards/widget_data/<action>/` | On-demand rendered data for a widget | 21 per-widget actions |

These endpoints accept Token, Session, or Basic authentication. All per-row authorization and data scoping follow DefectDojo's standard role-based access control — sharing a layout never widens what its viewers can see.

> **💡 Tip:** The Vue UI calls an internal mirror of these endpoints under `/api/vue/dashboard_v2/`. Always automate against the stable, customer-facing `/api/v2/dashboards/` paths documented here.

## Step 1: Discover the vocabulary

Three things in a widget are easy to get wrong if you guess: the **widget type**, its **group-by dimension** (for charts), and its **filters**. The API gives you a source of truth for each. Fetch them first, then build against what the server actually accepts.

### The widget catalog

`GET /dashboards/widget_catalog/` returns every widget type, the category it belongs to, the data endpoint(s) it renders against, and — most usefully — a minimal known-good `config_example` you can copy as a starting point:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_catalog/"
```

The response is shaped like this (truncated):

```json
{
  "categories": [
    {"id": "numbers", "label": "Numbers", "description": "Single-glance metrics — counts, KPIs, gauges."},
    {"id": "charts",  "label": "Charts",  "description": "Time-series and distribution visualisations."},
    {"id": "lists",   "label": "Lists & Feeds", "description": "Ranked lists, feeds, and embedded tables."},
    {"id": "static",  "label": "Static & Utility", "description": "Notes, shortcuts, and quick actions."}
  ],
  "widgets": [
    {
      "type": "count",
      "label": "Count",
      "category": "numbers",
      "description": "Single number rendered from a filtered queryset...",
      "data_endpoints": ["/api/v2/dashboards/widget_data/count/"],
      "config_example": {
        "model": "finding",
        "filters": {"status_any": "Active", "severity": "Critical"},
        "icon": "fas fa-ban",
        "color": "danger"
      }
    },
    {
      "type": "graph",
      "label": "Graph",
      "category": "charts",
      "description": "Generic chart over any model + group-by dimension...",
      "data_endpoints": ["/api/v2/dashboards/widget_data/aggregate/"],
      "config_example": {
        "model": "finding",
        "filters": {"duplicate": "false"},
        "group_by": "severity",
        "aggregation": "count",
        "chart_type": "pie",
        "time_bucket": null,
        "limit": null,
        "stacked": false
      }
    }
  ]
}
```

Use a widget's `type` as the widget's `type`, and its `config_example` as the starting point for the widget's `config`. The catalog lists 26 widget types across the four categories.

### Group-by dimensions and record metrics

The chart and leaderboard widgets restrict what you can group or rank by to a curated allowlist. Discover these per model rather than guessing:

```bash
# Valid group_by dimensions for the Graph / Sankey / Sunburst / Top-N (aggregate) widgets:
curl -s -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/dimensions/?model=finding"

# Valid metrics for the Top-N widget in "records" mode:
curl -s -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/record_metrics/?model=product"
```

`dimensions/` returns each dimension's `key` (the value to pass as `group_by`), a human `label`, and a `kind`:

```json
{
  "model": "finding",
  "dimensions": [
    {"key": "severity",  "label": "Severity",        "kind": "categorical"},
    {"key": "status",    "label": "Status",          "kind": "banded"},
    {"key": "date",      "label": "Discovered Date", "kind": "time"},
    {"key": "test_type", "label": "Test Type",       "kind": "categorical"}
  ]
}
```

The `kind` matters: a `time` dimension (like `date`) requires you to also send a `time_bucket` (`day`/`week`/`month`/`quarter`/`year`); a `categorical` or `banded` dimension does not. The `priority` field is intentionally **not** a group-by dimension (it is a continuous score) — use the `risk` dimension for a banded view, or the dedicated **Priority Histogram** widget.

### Filters

A widget's `config.filters` use the **same filter shape as the object's list view** — the values the list page emits to its URL, not the raw REST query parameters. For example, on findings: `{"status_any": "Active"}`, `{"severity": "Critical"}`, `{"duplicate": "false"}`, `{"date_past_days": 7}`, `{"sla_days_remaining_less_than_equal_to": 7}`; on assets: `{"grade": "A,B,C"}`, `{"last_scanned_past_days": 90}`. The quickest way to learn the right filter for a need is to apply it on the relevant list page in the UI and read it back from the widget config dialog, or to copy the filters from the seeded shared templates.

> **🔑 Important:** Unknown filter **keys are silently ignored** — a misspelled or non-existent filter does not raise an error, it simply does not apply, leaving the widget showing a wider population than you intended. Invalid *values* for a real filter return `400`. Always [verify what you built](#verify-what-you-built) by reading the layout back. (Filters are validated through the same FilterSet the list view uses, so list values may be passed as arrays for "any-of" matching: `{"severity": ["Critical", "High"]}`.)

> **💡 Tip:** Most widgets take a `model` of `finding`, `product`, `engagement`, or `test` — note the legacy `product` (the UI calls these **Assets**). The **Embedded Table** widget is the exception: its `model` uses the newer names `finding`, `asset`, `engagement`, `test`, `risk_acceptance`, `organization`, or `test_type`.

## Step 2: Create a layout

A layout is created with a `POST` to `/dashboards/layouts/`. The two fields that carry the dashboard's content are `widgets` and `layout`, and they must agree with each other.

### The widget object

Each entry in the `widgets` array has this shape:

```json
{
  "id": "11111111-1111-4111-8111-111111111111",
  "type": "count",
  "title": "Active Critical Findings",
  "refresh_interval": 0,
  "config": { "model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}, "color": "danger", "icon": "fas fa-ban" }
}
```

- **`id`** — a UUID you generate. It ties the widget to its grid position.
- **`type`** — a `type` value from the widget catalog.
- **`title`** — the heading shown on the widget (up to 200 characters).
- **`refresh_interval`** — auto-refresh seconds; one of `0` (off), `30`, `60`, `300`, or `900`.
- **`config`** — the type-specific configuration. Start from the catalog's `config_example` and adjust. Each widget type validates its own config server-side and returns a descriptive `400` if something is wrong.
- **`title_styling`** *(optional)* — `{"bold": true, "size": "md"}`, where `size` is `sm`, `md`, or `lg`.

### The layout (grid) map

`layout` is a map from each widget's `id` to its position on the 12-column grid:

```json
{
  "11111111-1111-4111-8111-111111111111": {"x": 0, "y": 0, "w": 3, "h": 2, "min_w": 2, "min_h": 2}
}
```

- **`x`, `y`** — top-left grid coordinates (0-indexed; `x` ranges 0–11).
- **`w`, `h`** — width (in columns) and height (in rows).
- **`min_w`, `min_h`** *(optional, default 1)* and **`max_w`, `max_h`** *(optional)* — size bounds.

> **🔑 Important:** The `layout` map and the `widgets` list must be consistent: **every widget needs a position, and every position must reference a widget that exists.** A mismatch returns `400`. The lifecycle script below builds both together so their IDs always line up.

### Create the layout

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/layouts/" \
  -d '{
    "name": "Exec Overview (API)",
    "widgets": [
      {"id": "11111111-1111-4111-8111-111111111111", "type": "count", "title": "Active Critical Findings",
       "refresh_interval": 0, "config": {"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}, "color": "danger", "icon": "fas fa-ban"}},
      {"id": "22222222-2222-4222-8222-222222222222", "type": "graph", "title": "Findings by Severity",
       "refresh_interval": 0, "config": {"model": "finding", "filters": {"duplicate": "false"}, "group_by": "severity", "aggregation": "count", "chart_type": "pie", "time_bucket": null, "limit": null, "stacked": false}}
    ],
    "layout": {
      "11111111-1111-4111-8111-111111111111": {"x": 0, "y": 0, "w": 3, "h": 2, "min_w": 2, "min_h": 2},
      "22222222-2222-4222-8222-222222222222": {"x": 3, "y": 0, "w": 9, "h": 4, "min_w": 3, "min_h": 3}
    },
    "settings": {}
  }'
```

The response echoes the saved layout including its new `id`, plus read-only helper fields (`is_default`, `is_owned`, `is_catalog`, `category`, `icon`, and timestamps).

### Custom actions

| Action | Call | What it does |
|--------|------|--------------|
| Set default | `POST /dashboards/layouts/{id}/set_default/` | Makes this layout the one your home page loads. You can only default a layout you own. |
| Clone | `POST /dashboards/layouts/{id}/clone/` (optional body `{"name": "..."}`) | Copies a layout (yours or a shared template) into your space with fresh widget IDs. Defaults to `"Copy of <name>"`. |
| List shared | `GET /dashboards/layouts/shared/` | Lists every shared layout — curated templates plus team-published ones. |
| Bootstrap | `GET /dashboards/layouts/for_current_user/` | Returns `{"results": [...your layouts...], "default_id": <id>}`. On a first call, it auto-clones the starter template so you always get at least one layout back. |

Publishing a shared layout (`"is_shared": true` on create or update) requires the global **Maintainer** role.

## Step 3: Render widget data (optional)

You usually do not need to render data yourself — the dashboard does that when it displays a widget. But the same `widget_data` endpoints are available directly, which is handy for scripts or chat summaries that want to quote a live number. Send the widget's `config` (or the relevant subset) as the payload.

**A filtered count** (`POST`):

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/count/" \
  -d '{"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}}'
# → {"count": 42}
```

**A group-by aggregation** (`POST`), the data behind a Graph:

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/aggregate/" \
  -d '{"model": "finding", "filters": {}, "group_by": "severity", "aggregation": "count"}'
```

```json
{
  "labels": ["Critical", "High", "Medium", "Low", "Info"],
  "series": [{"name": "count", "data": [15, 23, 8, 12, 5]}],
  "group_by": "severity",
  "group_by_label": "Severity",
  "model": "finding",
  "model_label": "Findings",
  "aggregation": "count",
  "time_bucket": null
}
```

The full set of `widget_data` actions:

| Action | Method | Key payload / params | Returns |
|--------|--------|----------------------|---------|
| `count` | POST | `model`, `filters` | `{count}` |
| `aggregate` | POST | `model`, `filters`, `group_by`, `aggregation`, `time_bucket?`, `limit?` | `{labels, series, ...}` |
| `dimensions` | GET | `?model=` | valid group-by dimensions |
| `top_records` | POST | `model`, `filters`, `metric`, `limit?`, `sort?` | `{labels, series, ...}` |
| `record_metrics` | GET | `?model=` | valid records-mode metrics |
| `rate_chart` | POST | `model`, `filters`, `pass_filters`, `group_by`, `limit?`, `sort?`, `min_denominator?`, `metric_label?` | rate / numerator / denominator series |
| `sankey` | POST | `model?`, `filters`, `source_dim`, `target_dim` | `{nodes, links, ...}` |
| `sunburst` | POST | `model?`, `filters`, `hierarchy` (1–2 dims) | `{tree, ...}` |
| `scan_coverage` | POST | `model?`, `filters`, `windows?` | per-window bands |
| `risk_matrix` | POST | `filters`, `x_dim?` | EPSS × risk cells (finding-only) |
| `priority_histogram` | POST | `filters`, `bin_count?` | histogram bins (finding-only) |
| `treemap` | POST | `filters`, `metric?` | nested portfolio tree |
| `heatmap` | POST | `filters`, `date_field?`, `window_days?` | per-day calendar cells |
| `aging` | POST | `filters`, `boundaries?`, `date_field?`, `severity_filter?` | stacked age-band series |
| `mttr_mttd` | POST | `filters`, `time_bucket?`, `window_days?` | paired MTTR/MTTD series |
| `velocity` | POST | `filters`, `time_bucket?`, `window_days?` | created vs closed series |
| `my_work` | GET | `?buckets=`, `?limit=` | your assignments / mentions / pending reviews |
| `sla_burndown` | GET | `?days_threshold=`, `?severity_filter=`, `?limit=`, `?include_overdue=` | findings nearing SLA breach |
| `recent_activity` | GET | `?model=`, `?limit=` | recent records feed |
| `saved_reports` | GET | `?limit=` | saved Report Templates *(requires Reporting)* |
| `usage` | GET | — | license-usage breakdown *(requires Maintainer)* |

## Putting it together: a full lifecycle script

The script below runs the whole flow using only the Python 3 standard library — no `requests`, no third-party packages. It reads the token from `DD_IMPORTER_DOJO_API_TOKEN`, discovers the widget catalog, builds a two-widget layout (with the `widgets` list and `layout` map generated together so their IDs always match), creates it, sets it as the default, reads it back to verify, and writes the created ID to `created.json`.

Set your instance URL and run it:

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
export DD_BASE_URL="https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2"
python3 build_dashboard.py
```

```python
#!/usr/bin/env python3
"""Build a DefectDojo Pro dashboard layout end-to-end using only the stdlib."""

import json
import os
import urllib.error
import urllib.request
import uuid

# --- Configuration -------------------------------------------------------
BASE_URL = os.environ.get(
    "DD_BASE_URL",
    "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2",
).rstrip("/")
TOKEN = os.environ["DD_IMPORTER_DOJO_API_TOKEN"]  # fail loudly if unset


def api_request(method, path, body=None):
    """Make an authenticated request. Returns parsed JSON."""
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None

    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Token {TOKEN}")
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

    return json.loads(payload) if payload else {}


def make_widget(widget_type, title, config, *, x, y, w, h, min_w=2, min_h=2):
    """Build a (widget, position) pair sharing a freshly generated UUID."""
    widget_id = str(uuid.uuid4())
    widget = {
        "id": widget_id,
        "type": widget_type,
        "title": title,
        "refresh_interval": 0,
        "config": config,
    }
    position = {"x": x, "y": y, "w": w, "h": h, "min_w": min_w, "min_h": min_h}
    return widget_id, widget, position


def main():
    created = {}

    # 1. Discover the catalog so we build against real widget types.
    #    (We don't strictly need the response here, but fetching it first
    #    is the recommended pattern — copy a config_example as a starting
    #    point instead of guessing the config shape.)
    catalog = api_request("GET", "/dashboards/widget_catalog/")
    known_types = {w["type"] for w in catalog["widgets"]}
    for required in ("count", "graph"):
        if required not in known_types:
            raise SystemExit(f"Widget type {required!r} not in catalog.")
    print(f"Discovered {len(known_types)} widget types.")

    # 2. Build two widgets and their grid positions together.
    widgets = []
    layout = {}

    _id, widget, pos = make_widget(
        "count",
        "Active Critical Findings",
        {
            "model": "finding",
            "filters": {"status_any": "Active", "severity": "Critical"},
            "color": "danger",
            "icon": "fas fa-ban",
        },
        x=0, y=0, w=3, h=2,
    )
    widgets.append(widget)
    layout[_id] = pos

    _id, widget, pos = make_widget(
        "graph",
        "Findings by Severity",
        {
            "model": "finding",
            "filters": {"duplicate": "false"},
            "group_by": "severity",
            "aggregation": "count",
            "chart_type": "pie",
            "time_bucket": None,
            "limit": None,
            "stacked": False,
        },
        x=3, y=0, w=9, h=4, min_w=3, min_h=3,
    )
    widgets.append(widget)
    layout[_id] = pos

    # 3. Create the layout.
    created_layout = api_request("POST", "/dashboards/layouts/", {
        "name": "Exec Overview (API)",
        "widgets": widgets,
        "layout": layout,
        "settings": {},
    })
    layout_id = created_layout["id"]
    created["layout_id"] = layout_id
    print(f"Created layout id={layout_id} with {len(created_layout['widgets'])} widgets")

    # 4. Make it the default landing dashboard.
    api_request("POST", f"/dashboards/layouts/{layout_id}/set_default/")
    print(f"Set layout id={layout_id} as the default")

    # 5. Read it back to verify widgets + positions survived intact.
    verified = api_request("GET", f"/dashboards/layouts/{layout_id}/")
    assert verified["is_default"] is True, "Layout did not become the default"
    assert len(verified["widgets"]) == len(widgets), "Widget count mismatch"
    assert set(verified["layout"]) == {w["id"] for w in verified["widgets"]}, \
        "Layout map and widgets are out of sync"
    print("Verified: default set, widgets and positions consistent")

    # 6. Record the created ID for later cleanup or reuse.
    with open("created.json", "w") as handle:
        json.dump(created, handle, indent=2)
    print("Wrote created.json")


if __name__ == "__main__":
    main()
```

## Verify what you built

Because invalid filter keys are dropped silently, verification is part of the workflow — not an afterthought.

**Confirm a layout saved as intended.** `GET` it back and check the `widgets` and `layout`:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/layouts/12/"
```

For each widget, compare the returned `config.filters` to what you sent. If a filter you expected is missing, its key was not a valid filter for that model — recheck it against the object's list-view filters. Confirm `is_default` is `true` if you set it, and that every key in `layout` matches a widget `id`.

**Spot-check a widget's data.** Render its data endpoint and confirm the number is what you expect:

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/count/" \
  -d '{"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}}'
```

**Fix a widget with PATCH.** A `PATCH` to `/dashboards/layouts/{id}/` with the full `widgets` and `layout` replaces them — send the complete desired set, not a partial one.

## Next steps

- Build and arrange the same layouts interactively in the [Customizable Dashboards UI](../custom-dashboards/).
- Let an LLM design and build dashboards for you with the [Dashboards LLM integration](../custom-dashboards-llm/).
