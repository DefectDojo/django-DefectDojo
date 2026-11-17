---
title: "Building Rules with the API"
description: "Create, validate, preview, change, schedule and run Triage Engine rules from scripts with the /api/v2/ rules endpoints"
weight: 7
audience: pro
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Triage Engine is a DefectDojo Pro-only feature.</span>

Everything the rule editor does to a rule can be done from a script. This page covers building a rule from nothing, checking it before it is saved, changing it later, and running it, all with an API token. Moving rules between instances (export, import, versions, sharing and transfer) is covered in [Sharing and Versions](../sharing_and_versions/#using-the-api).

## Before you start

The rules API lives at `/api/v2/rules_engine_v2/rules/`. Authenticate with your API token, the same one the rest of `/api/v2/` uses:

```bash
export DD_URL=https://defectdojo.example.com
export DD_TOKEN=<your API key>

curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/rules_engine_v2/rules/"
```

* **The API answers with the same permissions as the UI.** Creating a rule needs **Rule Add**, changing one needs **Rule Edit**, and placing a node that sends something out of DefectDojo or spends something needs that node family's permission (see [Node family permissions](../building_rules/#node-family-permissions)).
* **Triage Engine must be enabled** on the instance. With it off, every route here answers `403`.
* **Use the `/api/v2/` paths.** The Pro UI calls an internal mirror of these endpoints under `/api/vue/`, which accepts browser sessions only. An API token gets `403` there.

The full request and response schemas are in the instance's interactive API documentation at `/api/v2/oa3/swagger-ui/`, under `rules_engine_v2`.

## Endpoints

| Method and path | What it does |
|---|---|
| `GET /api/v2/rules_engine_v2/rules/` | List rules, newest first. The list leaves out each rule's graph. |
| `POST /api/v2/rules_engine_v2/rules/` | Create a rule. |
| `GET /api/v2/rules_engine_v2/rules/{id}/` | One rule, with its graph. |
| `PUT /api/v2/rules_engine_v2/rules/{id}/` | Replace a rule. |
| `PATCH /api/v2/rules_engine_v2/rules/{id}/` | Change some of a rule's fields. |
| `DELETE /api/v2/rules_engine_v2/rules/{id}/` | Delete a rule that has never run. |
| `POST /api/v2/rules_engine_v2/rules/validate/` | Check a graph without saving it. |
| `POST /api/v2/rules_engine_v2/rules/preview/` | Dry-run a graph and report what it would do, changing nothing. |
| `POST /api/v2/rules_engine_v2/rules/{id}/run/` | Run a saved rule now. |
| `GET /api/v2/rules_engine_v2/rules/{id}/runs/` | The rule's runs, newest first. |
| `GET`, `POST`, `PATCH`, `DELETE /api/v2/rules_engine_v2/rules/{id}/schedule/` | Read, set, change or remove a rule's schedule. |
| `GET /api/v2/rules_engine_v2/rules/templates/` | The rule templates that ship with DefectDojo, graphs included. |
| `POST /api/v2/rules_engine_v2/rules/from-template/` | Create a rule from a template. |
| `POST /api/v2/rules_engine_v2/rules/{id}/detach/` | Stop a webhook receiver managing a rule, so its graph can be edited. |
| `POST /api/v2/rules_engine_v2/rules/{id}/take_ownership/` | Become the owner of an Instance rule someone else owns. |

Only the rules resource is on the public API. The node catalog, the cross-rule run and delivery lists, and the editor's pickers are internal to the UI.

## The rule object

A rule as `GET /api/v2/rules_engine_v2/rules/{id}/` returns it, shortened:

```json
{
  "id": 57,
  "name": "Escalate Log4j findings",
  "description": "",
  "enabled": false,
  "mode": "simulate",
  "trigger_type": "finding",
  "trigger_event": "created",
  "version": 3,
  "owner": {"id": 4, "username": "jdoe"},
  "owner_group": null,
  "visibility": "group",
  "uuid": "2f0f3c3e-5d0b-4f69-9d43-1b8f0a7c2c11",
  "editable": true,
  "deletable": true,
  "runnable": true,
  "managed_by_receiver": null,
  "last_run": null,
  "next_run": null,
  "graph": {"nodes": [], "edges": []}
}
```

These are the fields you write:

| Field | Meaning |
|---|---|
| `name` | Required. Up to 255 characters. Names need not be unique: `id` and `uuid` identify a rule. |
| `description` | Optional free text. |
| `graph` | Required. The nodes and edges, described below. |
| `enabled` | Whether the rule's trigger may start it. Defaults to `false`, so a new rule does nothing until you turn it on. |
| `mode` | `simulate` (the default) or `live`. In Simulate, the rule's changes to Findings and Assets are real, but nothing is sent out of DefectDojo: every outbound send is recorded as a delivery instead. See [Testing a rule safely](../building_rules/#testing-a-rule-safely). |
| `schedule` | Write-only. The rule's schedule, for a rule triggered **On a Schedule**. See [Scheduling a rule](#scheduling-a-rule). |
| `owner_group` | The id of the group the rule belongs to. Leave it out for an **Instance** rule. It can be set only when the rule is created: moving a rule later is a [transfer](../sharing_and_versions/#using-the-api). |

Everything else is read-only. `trigger_type` and `trigger_event` are worked out from the graph's trigger node on every save. `version` goes up by one every time the rule is saved. `owner` is who the rule runs as, which decides what it can see; for a group's rule it is the group's automation identity. `editable`, `deletable` and `runnable` say what you may do with the rule, so a script can check before it tries.

## The graph

A graph is a JSON object with a `nodes` list and an `edges` list. Items (Findings, Assets or Alerts, depending on the trigger) enter at the trigger node and travel along the edges.

```json
{
  "nodes": [
    {
      "id": "trigger",
      "type": "trigger.finding",
      "name": "New Finding",
      "config": {"on": "created", "scope": {"severity": "High"}},
      "position": {"x": 0, "y": 0}
    },
    {
      "id": "tag",
      "type": "finding.add_tags",
      "name": "Tag for review",
      "config": {"tags": "needs-review"},
      "position": {"x": 300, "y": 0}
    }
  ],
  "edges": [
    {"id": "e1", "source": "trigger", "target": "tag"}
  ]
}
```

Each **node** has:

* `id`: a string, unique within the graph, up to 100 characters. Edges and run traces refer to the node by it, so a short readable id (`trigger`, `filter`, `tag`) makes traces easier to read than a UUID.
* `type`: the node type, for example `trigger.finding`, `filter.if` or `finding.set_severity`.
* `name`: optional. What the editor and run traces call the node.
* `config`: the node's settings. Each node type has its own keys. A key you leave out takes its default.
* `position`: optional. Where the editor draws the node, as `{"x": ..., "y": ...}`. The engine ignores it. Include it if anyone will open the rule in the editor.

Each **edge** has an `id`, a `source` node id and a `target` node id. A node with more than one output, such as **If / Filter** with its `true` and `false` outputs, names the output an edge leaves from in `sourceHandle`. An edge without `sourceHandle` leaves from a node's single output.

```json
{"id": "e2", "source": "filter", "target": "escalate", "sourceHandle": "true"}
```

A graph is saved only when it meets every one of the [graph rules](../building_rules/#graph-rules): at least one node, exactly one trigger, unique ids, known node types, edges that connect existing nodes, and no cycle. Saving also refuses a node that nothing connects to the trigger, because nothing would ever reach it. Each node's `config` is checked against its type, and a node from a family you may not use is refused.

### Finding a node's type and settings

The node types and what they do are in the [Node Reference](../node_reference/), and the paths and operators a condition takes are in [Conditions](../building_rules/#conditions). The quickest way to get a node's exact `config` keys is to let the editor write them for you:

1. Build a small rule in the editor with the nodes you need, and save it.
2. Read it back with `GET /api/v2/rules_engine_v2/rules/{id}/`, or export it with `GET /api/v2/rules_engine_v2/rules/{id}/export/`.
3. Use its `graph` as the starting point for your script.

`GET /api/v2/rules_engine_v2/rules/templates/` is another source: it returns every shipped template with its complete graph.

A Finding trigger's `scope` takes the same filters as the original Rules Engine, keyed by filter name, for example `{"severity": "High"}` or `{"engagement": [12], "severity": "Low"}`. An unknown filter name is refused rather than ignored, so a typo cannot widen a rule to every Finding. See [Scope](../building_rules/#scope).

## Building a rule, step by step

This example builds a rule that watches new Findings, and for any whose component name mentions `log4j`, raises the severity to Critical and tags it. It is written as one graph file so each step can reuse it.

Save this as `graph.json`:

```json
{
  "nodes": [
    {
      "id": "trigger",
      "type": "trigger.finding",
      "name": "New Finding",
      "config": {"on": "created", "scope": {}},
      "position": {"x": 0, "y": 0}
    },
    {
      "id": "filter",
      "type": "filter.if",
      "name": "Is it Log4j?",
      "config": {
        "mode": "all",
        "conditions": [
          {"path": "finding.component_name", "op": "contains", "value": "log4j"}
        ]
      },
      "position": {"x": 300, "y": 0}
    },
    {
      "id": "escalate",
      "type": "finding.set_severity",
      "name": "Raise to Critical",
      "config": {"severity": "Critical"},
      "position": {"x": 600, "y": -80}
    },
    {
      "id": "tag",
      "type": "finding.add_tags",
      "name": "Tag it",
      "config": {"tags": "log4j"},
      "position": {"x": 600, "y": 80}
    }
  ],
  "edges": [
    {"id": "e1", "source": "trigger", "target": "filter"},
    {"id": "e2", "source": "filter", "target": "escalate", "sourceHandle": "true"},
    {"id": "e3", "source": "filter", "target": "tag", "sourceHandle": "true"}
  ]
}
```

The examples below use `jq` to put the file into a request body: each endpoint wants the graph wrapped with its own fields (`{"graph": ...}`, plus `limit` or `name`), and `jq` builds that body from the one file without any shell quoting. In `jq -n --slurpfile g graph.json '{graph: $g[0]}'`, `-n` builds the output from the filter alone instead of reading standard input, and `--slurpfile g graph.json` reads the file into the variable `$g` as a list of the JSON values it holds, so `$g[0]` is the graph.

### 1. Validate the graph

```bash
jq -n --slurpfile g graph.json '{graph: $g[0]}' |
  curl -s -X POST -H "Authorization: Token $DD_TOKEN" -H "Content-Type: application/json" \
    -d @- "$DD_URL/api/v2/rules_engine_v2/rules/validate/"
```

Validate always answers `200`. An invalid graph is an answer, not an error:

```json
{"problems": [], "warnings": []}
```

`problems` lists every reason the graph could not be saved, as sentences. `warnings` lists things worth reading that never block a save, such as a condition path that will never resolve. Fix every problem before you go on. Validate checks the graph on its own: permission checks that depend on who the rule will run as happen when you save.

### 2. Preview what it would do

```bash
jq -n --slurpfile g graph.json '{graph: $g[0], limit: 25}' |
  curl -s -X POST -H "Authorization: Token $DD_TOKEN" -H "Content-Type: application/json" \
    -d @- "$DD_URL/api/v2/rules_engine_v2/rules/preview/"
```

Preview runs the real engine over the graph, then rolls everything back. Nothing is written, no run is recorded, and nothing is sent. The response has the shape of a run: a trace per node with how many items went in and out by each output and what the node would have changed, plus `scope_total` (how many items are in scope) and `preview_limit` (how many it looked at). `limit` defaults to 25 and is capped at 100. For a webhook-triggered rule, `sample_payload` previews against a payload you supply instead of the receiver's stored sample.

An invalid graph answers `400` with `{"problems": [...]}`.

### 3. Create the rule

```bash
jq -n --slurpfile g graph.json \
  '{name: "Escalate Log4j findings", graph: $g[0], mode: "simulate"}' |
  curl -s -X POST -H "Authorization: Token $DD_TOKEN" -H "Content-Type: application/json" \
    -d @- "$DD_URL/api/v2/rules_engine_v2/rules/"
```

A created rule answers `201` with the rule, its graph and a `warnings` list. It starts disabled. To create it in a group, add `"owner_group": <group id>`; you must be a member of the group with **Rule Add** there.

A refused save answers `400` with the same sentences the editor shows. A problem in the graph itself comes back under the `graph` field, and a problem with who may save it (a node family you may not use, for example) comes back as a top-level `problems` list:

```json
{"graph": {"problems": ["node trigger config 'scope' filter severty: Unrecognized field."]}}
```

### 4. Try it, then turn it on

Run it by hand while it is still disabled and in Simulate:

```bash
curl -s -X POST -H "Authorization: Token $DD_TOKEN" \
  "$DD_URL/api/v2/rules_engine_v2/rules/57/run/"
```

`run/` answers `202` with `{"run_id": null, "status": "queued"}`. The run happens on a worker, so it has no id yet when the request returns. Read its result from the rule's runs:

```bash
curl -s -H "Authorization: Token $DD_TOKEN" \
  "$DD_URL/api/v2/rules_engine_v2/rules/57/runs/?limit=1"
```

A run started by hand makes its changes to Findings for real. Only outbound sends wait for Live mode. For a **On Finding Event** trigger, a hand-started run replays the rule over up to 500 Findings currently in scope. See [Running a rule by hand](../runs/#running-a-rule-by-hand) for what each trigger does, and which triggers cannot be run by hand.

When the run looks right, enable the rule:

```bash
curl -s -X PATCH -H "Authorization: Token $DD_TOKEN" -H "Content-Type: application/json" \
  -d '{"enabled": true}' "$DD_URL/api/v2/rules_engine_v2/rules/57/"
```

Enabling re-checks the stored graph, so a rule saved with a reference left empty (after an import, for example) cannot be turned on until it is filled in. For a rule that sends messages, tickets or webhooks, leave it in Simulate until its [deliveries](../deliveries/) look right, then switch it with `{"mode": "live"}`.

## Changing a rule

`PATCH` changes the fields you send and leaves the rest. Turning a rule on or off, renaming it, or switching its mode does not touch its graph:

```bash
curl -s -X PATCH -H "Authorization: Token $DD_TOKEN" -H "Content-Type: application/json" \
  -d '{"mode": "live"}' "$DD_URL/api/v2/rules_engine_v2/rules/57/"
```

A graph is always replaced whole. There is no way to change one node on its own: read the rule, change its graph, and send the whole graph back. This adds a second condition to the **If / Filter** node, so the rule also matches a Finding that names the Log4Shell CVE whatever its component, and switches the node's **Match** to `any`:

```bash
curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/rules_engine_v2/rules/57/" |
  jq '{graph: (.graph | (.nodes[] | select(.id == "filter") | .config.conditions) +=
        [{"path": "finding.vulnerability_ids", "op": "has", "value": "CVE-2021-44228"}]
        | (.nodes[] | select(.id == "filter") | .config.mode) = "any")}' |
  curl -s -X PATCH -H "Authorization: Token $DD_TOKEN" -H "Content-Type: application/json" \
    -d @- "$DD_URL/api/v2/rules_engine_v2/rules/57/"
```

Things to know when changing a graph:

* **Secrets come back masked, and you can send the mask back.** A webhook signing secret, token, password or API key in a node's settings reads as `********`. Sending `********` back keeps the stored value, so a read, change and write never loses a credential. To change a secret, send the new value.
* **The last write wins.** A save does not check whether someone else saved the rule since you read it. Compare `version` with what you read if that matters, and remember that every save is a [version](../sharing_and_versions/) you can restore.
* **A rule a webhook receiver manages keeps its graph.** The receiver rebuilds that graph whenever the receiver is saved, so a request that changes it answers `409`. Its name, `enabled` and `mode` stay editable. To edit the graph, detach the rule first with `POST /api/v2/rules_engine_v2/rules/{id}/detach/`; from then on the receiver no longer updates it.
* **Changing or enabling a rule is limited to who may change it.** For an Instance rule, that is its owner (with **Rule Edit**) or a superuser. For a group's rule, a member of the group with **Rule Edit** there. To take over an Instance rule someone else wrote, use `POST /api/v2/rules_engine_v2/rules/{id}/take_ownership/`: the rule is disabled and its credentials are cleared on the way over, so re-enter them before you turn it back on.
* **An older graph shape is accepted.** A script written against an earlier release can keep posting its graph. It is upgraded to the current shape when it is saved, so the graph you read back may differ from the one you sent.

`PUT` replaces the rule, so it needs `name` and `graph` in the body.

## Scheduling a rule

A rule triggered **On a Schedule** needs a schedule, and saving one without it is refused. Send the schedule with the rule. This one tags every Finding past its SLA date, every night at 02:30:

```json
{
  "name": "Tag overdue findings nightly",
  "graph": {
    "nodes": [
      {"id": "trigger", "type": "trigger.schedule", "config": {"entity": "finding", "scope": {}}},
      {
        "id": "filter",
        "type": "filter.if",
        "config": {"conditions": [{"path": "finding.sla_expiration_date", "op": "older_than_days", "value": 0}]}
      },
      {"id": "tag", "type": "finding.add_tags", "config": {"tags": "sla-breached"}}
    ],
    "edges": [
      {"id": "e1", "source": "trigger", "target": "filter"},
      {"id": "e2", "source": "filter", "target": "tag", "sourceHandle": "true"}
    ]
  },
  "schedule": {"trigger_type": "C", "trigger_expression": "30 2 * * *"}
}
```

The trigger's `entity` says what the rule sweeps: `finding` (the default) or `asset`. An Asset sweep takes its filters in `asset_scope` instead of `scope`.

`trigger_type` `C` means a cron expression, and `trigger_expression` is the expression. The minute must be `0`, `15`, `30` or `45`. You can also send `name`, `description` and `enabled` for the schedule; its name defaults to the rule's.

Change a schedule later by sending `schedule` again in a `PATCH`, or through the rule's own `schedule/` route, which takes the same body. Removing a schedule-triggered rule's schedule stops the rule from running.

If the scheduling service cannot register the schedule, creating the rule answers `503` and nothing is saved. Try again later.

## Starting from a template

```bash
curl -s -H "Authorization: Token $DD_TOKEN" \
  "$DD_URL/api/v2/rules_engine_v2/rules/templates/" | jq '.[] | {slug, name}'

curl -s -X POST -H "Authorization: Token $DD_TOKEN" -H "Content-Type: application/json" \
  -d '{"slug": "new-findings-alert", "name": "Alert on new critical findings"}' \
  "$DD_URL/api/v2/rules_engine_v2/rules/from-template/"
```

The new rule is yours, disabled and in Simulate. Each template's `setup` notes say what it needs before it does anything, such as a scope, recipients or a schedule. Fill those in with a `PATCH` as above. `owner_group` creates the rule in a group. An unknown slug answers `400`.

## Deleting a rule

```bash
curl -s -X DELETE -H "Authorization: Token $DD_TOKEN" \
  "$DD_URL/api/v2/rules_engine_v2/rules/57/"
```

Only a rule that has never run can be deleted. A rule's runs, node traces and the provenance it left on Findings are deleted along with it, so a rule with run history answers `409` with `run_count`, and the way to stop it is to disable it: `PATCH` with `{"enabled": false}`. `deletable` on the rule says which applies.

## Responses at a glance

| Status | When |
|---|---|
| `200` | A read, an update, a validate (valid or not), or a preview. |
| `201` | A rule was created. |
| `202` | A run was queued. |
| `204` | A rule was deleted. |
| `400` | The graph, schedule or another field was refused. The body names every problem under the field it belongs to (`graph`, `schedule`, `owner_group`), or in a top-level `problems` list. |
| `403` | Triage Engine is off, the token lacks a permission, or you may not change this rule. |
| `404` | The rule does not exist, or you cannot see it. |
| `409` | A managed rule's graph was changed, a rule with runs was deleted, or `take_ownership/` was used on a group's rule. |
| `503` | The scheduling service could not register the rule's schedule. Nothing was saved. |
