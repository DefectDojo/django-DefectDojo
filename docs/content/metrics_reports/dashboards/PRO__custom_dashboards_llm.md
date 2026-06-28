---
title: "Building Dashboards with an LLM"
description: "Use Claude or another LLM to design, create, and set up DefectDojo Pro customizable dashboards via the API"
draft: false
audience: pro
weight: 12
slug: custom-dashboards-llm
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Automating Customizable Dashboards with the REST API and an LLM is a DefectDojo Pro feature, currently in beta. Beta features are available to DefectDojo Pro Cloud subscriptions — contact DefectDojo support or your customer success advocate to enable it for your instance.</span>

DefectDojo Pro's Customizable Dashboards are fully driven by the REST API — and the layouts surface was designed with AI agents in mind. That means you can hand the whole job to an LLM: paste one self-contained prompt into Claude, ChatGPT, or any other capable model, describe the dashboards you want, and it will interrogate your tenant's live widget catalog, propose layouts, emit a runnable Python script, create the layouts, verify them, and optionally set your default.

The pattern is simple. You provide your base URL, an API token, and a short description of who the dashboards are for. The LLM does the discovery, design, creation, and verification — pausing for your approval before it builds anything against your tenant.

This guide pairs with the [Dashboards API guide](../custom-dashboards-api/), which documents the raw resources and request shapes the LLM is working with. If you want to understand or hand-tune what the LLM produced, keep that reference open.

## Before you start

1. **Get an API token.** In the DefectDojo Pro UI, go to **User Settings → API v2 Key** and copy the token. Then set it as an environment variable so the generated script can read it without the token ever appearing in chat:

```shell
export DD_IMPORTER_DOJO_API_TOKEN=<paste-token-here>
```

2. **Confirm the beta is enabled.** Customizable Dashboards must be enabled for your instance — contact DefectDojo support or your customer success advocate — otherwise every API call returns `403`.

3. **Decide your dashboards.** The LLM will ask what you want. Common choices:

   - **Executive Overview** — headline counts, severity distribution, and SLA compliance at a glance.
   - **Daily Triage** — active criticals/highs, priority histogram, SLA burndown, and your "My Work" queue.
   - **Remediation Velocity** — created-vs-closed velocity, MTTR/MTTD, and aging.
   - **Scanner Effectiveness** — findings by test type, false-positive rate by tool, and recent scan activity.
   - **Portfolio Health** — a treemap of assets by organization, scan coverage, and top/bottom-graded assets.

> **💡 Tip:** You do not have to pick from this list. Tell the LLM your real goals in plain language and it will map them onto the available widget types and filters.

## The prompt

Copy the entire fenced block below and paste it into Claude, ChatGPT, or any other capable LLM. The prompt is self-contained — the model will ask you for your tenant URL, token environment variable, and dashboard goals, then walk you through discovery → design → create → verify.

```
You are helping me build customizable dashboards in DefectDojo Pro using its
REST API ("Dashboards V2" — layouts of widgets on a grid). Work carefully and
pause for my approval before creating anything against my tenant.

================================================================================
WHAT I WILL GIVE YOU
================================================================================
  - A base URL ending in /api/v2 (e.g. https://my-instance.cloud.defectdojo.com/api/v2)
  - The name of an environment variable holding my API token (default:
    DD_IMPORTER_DOJO_API_TOKEN). NEVER ask me to paste the token itself.
  - A description of the dashboard(s) I want and who they are for.

Authenticate every request with the header:  Authorization: Token <token>
Also send  Accept: application/json  (and Content-Type: application/json on writes).

================================================================================
DATA MODEL
================================================================================
A "layout" is one dashboard: a named set of widgets and their grid positions.
It is created/updated under /api/v2/dashboards/ with these resources:

  /api/v2/dashboards/layouts/         CRUD for layouts + actions:
        POST {id}/clone/        copy a layout (fresh widget IDs)
        POST {id}/set_default/  make a layout my home-page default
        GET  shared/            list curated + team-shared templates
        GET  for_current_user/  my layouts + my default_id (bootstrap)
  /api/v2/dashboards/widget_catalog/  GET: every widget type + a config example
  /api/v2/dashboards/widget_data/<action>/  render a widget's data on demand

A layout's two content fields MUST agree with each other:
  widgets : ordered list of widget objects (see below)
  layout  : map of  widget-id -> {x, y, w, h, min_w?, min_h?, max_w?, max_h?}
Every widget needs a position, and every position must reference a real widget,
or the create returns 400.

A widget object:
  {
    "id": "<uuid you generate>",
    "type": "<a type from the catalog>",
    "title": "<heading>",
    "refresh_interval": 0,        # one of 0, 30, 60, 300, 900 (seconds)
    "config": { ...type-specific... }
  }
Optional: "title_styling": {"bold": true, "size": "md"}  # size: sm | md | lg

The grid is 12 columns wide. x is 0..11; w is the column span; y/h are rows.

================================================================================
STEP 1 — DISCOVER (do this BEFORE designing anything; never invent values)
================================================================================
1. GET /api/v2/dashboards/widget_catalog/ . It returns {categories, widgets}.
   Each widget entry has: type, label, category, description, data_endpoints,
   and a minimal known-good config_example. USE THESE config_examples as the
   starting point for each widget's config — do not guess the config shape.
   There are 26 widget types in four categories: Numbers, Charts,
   Lists & Feeds, Static & Utility.

2. For any chart/leaderboard that groups data, fetch the valid dimensions:
     GET /api/v2/dashboards/widget_data/dimensions/?model=<finding|product|engagement|test>
   Each dimension has key, label, and kind (categorical | boolean | time |
   banded). Pass the key as the widget's group_by. A "time" dimension also
   needs a time_bucket (day|week|month|quarter|year); others do not.
   NOTE: "priority" is NOT a group-by dimension (it is a continuous score).
   Use the "risk" dimension for a banded view, or the priority_histogram widget.

3. For the Top-N widget in "records" mode, fetch valid metrics:
     GET /api/v2/dashboards/widget_data/record_metrics/?model=<product|finding|engagement|test>

================================================================================
MODELS AND FILTERS (the most error-prone area — READ CAREFULLY)
================================================================================
MODEL: most widgets take a config "model" of EXACTLY one of:
       finding | product | engagement | test
   (Note the legacy "product" — the UI calls these "Assets", and
    "engagement"/"test" are unchanged.) Some widgets are finding-only and take
    no model (risk_matrix, priority_histogram). The EMBEDDED TABLE widget is the
    exception: its model uses the newer names and a wider set:
       finding | asset | engagement | test | risk_acceptance | organization | test_type

FILTERS: a widget's config.filters use the SAME shape the object's LIST VIEW
   emits — not raw REST query params. Examples that work:
     finding:  {"status_any": "Active"}        # Active | Mitigated | Risk Accepted | ...
               {"severity": "Critical"}         # single value (or a list for any-of)
               {"duplicate": "false"}           # boolean as a string
               {"date_past_days": 7}
               {"sla_days_remaining_less_than_equal_to": 7}
     asset:    {"grade": "A,B,C"}               # passing; "D,F" = failing
               {"last_scanned_past_days": 90}
   An UNKNOWN filter key is SILENTLY IGNORED (no error) — so a typo leaves the
   widget showing a wider population than intended. An invalid VALUE for a real
   filter returns 400. Because of the silent-drop behavior, you MUST verify
   (Step 4). If unsure of a filter name, prefer the values shown in the catalog
   config_examples, or ask me to read the filter off the relevant list page.

================================================================================
STEP 2 — DESIGN, THEN GET MY APPROVAL
================================================================================
Propose, for each dashboard I asked for: a layout name, and a list of widgets
with their type, title, config, and a sensible 12-column grid arrangement
(x/y/w/h). Show me this plan and the exact JSON you intend to POST. Do NOT
create anything yet. Wait for my explicit "go".

================================================================================
STEP 3 — CREATE
================================================================================
After approval, emit a single Python 3 script using ONLY the standard library
(json, os, urllib, uuid — no requests). It must:
  - read the token from the env var,
  - generate a uuid4 per widget and build the widgets list and layout map
    together so their IDs always match,
  - POST each layout to /api/v2/dashboards/layouts/ and surface any error body,
  - optionally POST {id}/set_default/ for the one I choose as my landing page,
  - print the created layout IDs.

================================================================================
STEP 4 — VERIFY
================================================================================
For each created layout, GET /api/v2/dashboards/layouts/{id}/ and check:
  - every key in "layout" matches a widget "id" (and vice versa),
  - each widget's config.filters contains what we sent (flag any dropped keys),
  - is_default is true for the one I chose.
Report what you verified, and offer to PATCH fixes (a PATCH replaces the full
widgets + layout, so always send the complete set).

================================================================================
NOW START
================================================================================
Ask me for: (1) my base URL, (2) the token env-var name (default
DD_IMPORTER_DOJO_API_TOKEN), and (3) the dashboards I want and their audience.
Then begin at Step 1.
```

## What to expect

A well-behaved model will:

1. Ask for your base URL, token environment variable, and dashboard goals.
2. `GET` the widget catalog (and dimensions/record-metrics as needed) and tell you which widget types it plans to use.
3. Propose each layout — name, widgets, filters, and grid arrangement — and **wait for your approval**.
4. Emit a stdlib-only Python script that creates the layouts, optionally sets your default, and verifies the result.
5. Report what it verified and offer to fix anything that did not save as intended.

> **💡 Tip:** If a widget renders an unexpected number, the usual cause is a filter key that was silently dropped. Ask the LLM to read the layout back and compare the saved `config.filters` to what it sent — the [API guide](../custom-dashboards-api/#verify-what-you-built) covers this verification step in detail.

## Next steps

- See the [Dashboards API guide](../custom-dashboards-api/) for the raw resources, request shapes, and the full widget-data action reference.
- Build and arrange dashboards by hand in the [Customizable Dashboards UI](../custom-dashboards/).
