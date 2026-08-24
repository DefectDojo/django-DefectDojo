---
title: "Building Rules"
description: "The graph editor, triggers, scope, conditions and message templates"
weight: 2
audience: pro
aliases:
  - /automation/rules_engine_v2/building_rules/
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Rules Engine 2.0 is a DefectDojo Pro-only feature.</span>

A rule is built on a canvas. You drag nodes out of a palette, wire them together, and configure each one in a side panel. This page covers the parts of that process that are the same whichever nodes you use. The nodes themselves are in the [Node Reference](../node_reference/).

## The editor

Open **Rules Engine 2.0 > All Rules** and choose **New Rule**, or open an existing rule to edit it.

The palette is grouped into four categories, which is also the order items flow through a typical graph:

| Category | What the nodes do |
|----------|-------------------|
| **Triggers** | Decide when the rule wakes up and which Findings enter it. Exactly one per graph. |
| **Logic** | Route, limit and de-duplicate the items flowing through. |
| **Findings** | Change the Findings. |
| **Egress** | Send something outward: a ticket, a message, a report. |

The palette is generated from the engine itself, so what you see in the editor is always exactly what the engine can execute.

### Graph rules

A graph is checked when you save it, and again before every run. It must satisfy all of the following:

* It has at least one node.
* It has **exactly one** trigger node.
* Every node has a unique, non-empty id of 100 characters or fewer.
* Every node is of a type the engine knows.
* Every edge connects two nodes that exist.
* It contains no cycle.

A node with nothing wired into it is legal. It runs with an empty input list, which usually means it does nothing.

A node with several incoming edges receives all of their outputs concatenated.

### Previewing before you save

**Preview** dry-runs the graph you currently have on the canvas and shows you the per-node trace it would produce: how many items entered each node, how many left by each output, and what each node would have changed.

Preview runs the real engine, not a simulation of it, and then rolls the whole thing back. Nothing is written, no run is recorded, and egress is forced to simulate whatever the rule's mode says. It is the fastest way to check that your conditions match what you expected.

Preview is the one execution that caps how many Findings it looks at, so that it stays fast. When it truncates, it says so in the trace. A real run has no such cap.

## Triggers and scope

Every graph starts with one of three triggers.

* **On Finding Event** wakes the rule when Findings are created, updated, closed or reopened. Choose which of those in the node's **Event** setting, or `any` for all four.
* **On a Schedule** sweeps Findings on a recurring schedule.
* **Manual Run** sweeps Findings when you press **Run** on the rule.

### Scope

All three triggers take a **Scope**, and scope is how you narrow what the rule considers. It is the same filter vocabulary the original Rules Engine uses, roughly sixty filters spanning Findings and the objects around them, so a filter you already know how to write there means the same thing here.

Two things about scope are worth understanding:

* **Scope is applied on top of authorization, never instead of it.** The rule runs as its owner, so scope narrows an already-authorized set of Findings. Leaving scope empty does not mean "every Finding in the instance", it means "every Finding the rule owner can see".
* **An invalid scope fails the run rather than widening it.** If a filter key does not exist, or a value is one the filter would silently discard, the run errors out. A rule that does nothing is recoverable. A rule that quietly edits every Finding in the instance is not.

For an event trigger, scope acts as a second gate: the Findings named in the event are matched against it, and only those that pass enter the graph.

### Scheduling

A rule whose trigger is **On a Schedule** is scheduled from the rule itself. Setting the schedule needs Rule Edit, the same permission as editing the rule, because a schedule-triggered rule does nothing at all until it has one.

Schedules are limited to quarter-hour marks. The minute field of a cron expression must be `0`, `15`, `30` or `45`.

Valid examples:

```
0 * * * *     every hour, on the hour
15 9 * * *    every day at 09:15
0 15 * * 1    every Monday at 15:00
30 2 * * *    every day at 02:30
```

## Referring to Finding data

Two places in a rule read values out of the item flowing through it: **conditions** and **templates**. Both use the same dot paths.

```
finding.severity
finding.title
finding.vulnerability_ids.0
product.name
product_type.name
test.scan_type
ctx.rule_name
```

A path that does not resolve produces no value rather than an error.

### Conditioning on an exception

With [Risk Acceptances 2.0](/triage_findings/findings_workflows/pro__risk_acceptance/) enabled,
a rule can condition on what an acceptance is *doing*, not just on the `Risk Accepted` flag:

```
finding.has_pending_exception          somebody asked, nobody has answered
finding.risk_acceptance_state          proposed / under_review / approved / rejected / active / expired
finding.risk_acceptance_expiration_date
finding.risk_acceptance_days_to_expiry negative once the date has passed
finding.risk_acceptance_is_global
```

What that makes possible, for example: chase requests nobody has answered
(`has_pending_exception eq true`), or warn an owner a week before an exception lapses
(`risk_acceptance_days_to_expiry lte 7`). Because days-to-expiry goes negative rather than stopping
at zero, "expired three days ago" is expressible too.

With **Risk Acceptances 2.0** off these read empty — `false` for the boolean, nothing for the rest —
so a rule written against them matches nothing rather than acting on a lifecycle the install does
not use. Where a Finding is covered by more than one Risk Acceptance, they describe the earliest one
it was accepted under.

### Available fields

Each item carries a fixed set of Finding fields. This list is a contract, so it changes only deliberately.

| Group | Fields |
|-------|--------|
| Identity | `id`, `title`, `hash_code`, `unique_id_from_tool` |
| Severity and scoring | `severity`, `numerical_severity`, `cvssv3`, `cvssv3_score`, `epss_score`, `epss_percentile`, `priority`, `risk`, `risk_score` |
| Text | `description`, `mitigation`, `impact` |
| Status | `active`, `verified`, `false_p`, `duplicate`, `is_mitigated`, `out_of_scope`, `risk_accepted`, `under_review` |
| Dates | `date`, `mitigated`, `last_status_update`, `sla_expiration_date` |
| Location | `file_path`, `line`, `component_name`, `component_version`, `service` |
| Classification | `cwe`, `vulnerability_ids`, `tags` |

Alongside `finding`, each item carries `test` (`id`, `title`, `scan_type`), `engagement` (`id`, `name`), `product` (`id`, `name`), `product_type` (`id`, `name`), and `ctx`.

Dates are ISO-8601 strings. That is deliberate: it means `gt` and `lt` order them correctly as text, so `2026-07-28` is correctly greater than `2026-01-01`.

`priority`, `risk` and `risk_score` come from Pro's prioritization. A Finding that has not been scored yet carries no value for them.

### Conditions

An **If / Filter** node holds a list of condition rows. Each row is a path, an operator, and a value. **Match** decides whether every row has to hold (`all`) or just one of them (`any`).

| Operator | Meaning |
|----------|---------|
| `eq` | equals |
| `neq` | does not equal |
| `contains` | contains |
| `not_contains` | does not contain |
| `in` | is one of |
| `not_in` | is not one of |
| `has` | includes (one of a multi-select custom field's stored options) |
| `not_has` | does not include |
| `gt` | is greater than |
| `gte` | is greater than or equal to |
| `lt` | is less than |
| `lte` | is less than or equal to |
| `startswith` | starts with |
| `endswith` | ends with |
| `exists` | is set |
| `not_exists` | is not set |

Comparisons are **loose**. A number is tried first, and if that fails the values are compared as trimmed, case-insensitive text. So a condition written as `finding.severity eq high` matches a Finding whose severity is `High`, which is almost always what the author meant.

#### Custom fields

With [Custom Fields](/asset_modelling/pro__custom_fields/) enabled, every custom field defined for the rule's kind of item is offered as a condition path too, under a `custom_fields` block:

```
finding.custom_fields.cost_center
product.custom_fields.owner_team
```

A rule over Findings reads the Finding's custom fields and a rule over Assets reads the Asset's; there is no cross-kind path. A record holding no value for a field reads as not set, so `exists` and `not_exists` are how you condition on a field being filled in at all. The same paths work as `{{ }}` placeholders in templates.

The field's data type decides which operators the editor offers: numbers take equality, list membership and ordering, dates take equality and ordering (against a `YYYY-MM-DD` value), booleans take equality, and a single-select offers equality and list membership over the field's own options. Text fields keep the full operator list.

A **multi-select** field holds several options at once, and two operators exist for exactly that. `has` (*includes*) matches when the compared option is one of the stored ones, whole and exact: a Finding holding only `gdpr-eu` is not matched by `has gdpr`, where `contains` would match on the fragment. `not_has` (*does not include*) is its negation.

"Includes **any of** several options" is one **If / Filter** node with one `has` row per option and **Match** set to `any`. To combine that with conditions that must all hold, chain two **If / Filter** nodes: the any-of rows in the first (Match `any`), everything else in the second (Match `all`).

#### Transforms

A condition row can post-process the value it read before comparing it.

| Transform | Effect |
|-----------|--------|
| `int` | whole number |
| `float` | decimal number |
| `str` | text |
| `first` | first entry of a list |
| `list` | as a list |
| `join` | joined with commas |
| `upper` | UPPERCASE |
| `lower` | lowercase |
| `strip` | trimmed |
| `cwe_int` | CWE number |
| `severity` | normalized severity, so `critical`, `error` and `warning` style values from different scanners map onto DefectDojo's five levels |
| `numerical_severity` | sortable severity code, for ordering comparisons |

### Templates

Any setting labelled as a message, note, title or value accepts `{{ path }}` placeholders, resolved per item:

```
{{finding.severity}}: {{finding.title}} ({{product.name}})
```

A path with no value renders as an empty string. A list renders comma-joined.

Templates also see a `ctx` block carrying details about the run itself. The keys available depend on the node, but the common ones are:

| Placeholder | Meaning |
|-------------|---------|
| `{{ctx.rule_name}}` | The name of the rule |
| `{{ctx.count}}` | How many Findings the message covers |
| `{{ctx.trigger}}` | The event that started the run |
| `{{ctx.findings_html}}` | The rendered Finding list, in the email node |
| `{{ctx.report_url}}` | The download link, in the report node |
| `{{ctx.template_name}}` | The report template name, in the report node |

Templates are plain substitution. There is no expression evaluation, no code execution, and no attribute access on objects anywhere in a rule config.

## Testing a rule safely

The recommended order for a rule that sends anything:

1. Build the graph and use **Preview** until the item counts look right.
2. Save it. New rules are created disabled.
3. Leave the mode on **Simulate** and enable the rule.
4. Let it run, then read **Deliveries** and check the recorded payloads are what you intended.
5. Switch the mode to **Live**.

Simulate is not a partial run. Every Finding edit in the graph happens for real in simulate mode. Only the outbound sends are held back.
