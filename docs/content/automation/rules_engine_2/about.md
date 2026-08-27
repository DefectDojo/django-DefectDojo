---
title: "About Rules Engine 2.0"
description: "What Rules Engine 2.0 is, how to turn it on, and the concepts it is built from"
weight: 1
audience: pro
aliases:
  - /automation/rules_engine_v2/about/
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Rules Engine 2.0 is a DefectDojo Pro-only feature.</span>

Rules Engine 2.0 is a visual automation builder. Instead of a filter plus a flat list of actions, a rule is a **graph**: a trigger node that decides when the rule wakes up, and any number of logic, Finding and egress nodes wired together to say what happens next.

Rules Engine 2.0 can only be accessed through the [Pro UI](/get_started/about/ui_pro_vs_os/).

## What it adds over Rules Engine

The original [Rules Engine](/automation/rules_engine/about/) applies an ordered list of actions to every Finding that matches one filter. Rules Engine 2.0 keeps that capability and adds four things:

* **Branching.** An **If / Filter** node routes items down a true branch and a false branch, so one rule can treat Critical Findings differently from the rest without being split into two rules.
* **Egress.** A rule can leave DefectDojo: open a JIRA issue or a downstream ticket, post to Slack or Microsoft Teams, send an email, call a webhook, raise an in-app alert, or generate a report.
* **Traceability.** Every execution is recorded node by node as a [Run](../runs/), and every outbound send is recorded as a [Delivery](../deliveries/) that says exactly what was sent, where it went, and how it ended.
* **A simulate mode.** A rule can record precisely what it would send without sending anything, which is how you test one safely before it touches the outside world.

Rules are not limited to Findings. An Asset (Product) rule reacts to Assets being created, updated or tagged, or sweeps them on a schedule, and can set their fields, move them between Organizations, tag and untag them, and place them in the Asset hierarchy. That makes recurring inventory work self-service: instead of a one-off migration to regroup Assets, a rule expresses the grouping and keeps enforcing it as new Assets arrive.

Both engines run side by side. Turning on Rules Engine 2.0 does not disable or convert your existing rules, and there is a [converter](../converting_from_rules_engine/) for when you want to move them across.

## Enabling Rules Engine 2.0

Rules Engine 2.0 is in Beta and is off by default. A superuser turns it on from **Settings > Feature Flags**, on both Cloud and On-Premise instances. See [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Once the flag is on, a **Rules Engine 2.0** section appears in the sidebar with three pages:

| Page | What it is for |
|------|----------------|
| **All Rules** | The rule list. Create, edit, enable, run and delete rules from here. |
| **Runs** | Every execution, with its per-node trace. |
| **Deliveries** | The ledger of everything rules have sent outward. |

### Permissions

Access is governed by four global role permissions, shared with the original Rules Engine:

* **Rule View** is required to see the sidebar section and everything under it.
* **Rule Add** is required to create a rule, including converting one from the original Rules Engine.
* **Rule Edit** is required to change, enable, schedule, run, replay, or take ownership of an existing rule.
* **Rule Delete** is required to delete a rule.

Validating and previewing a rule are accepted with either authoring permission, Rule Add or Rule Edit.

Rule Add and Rule Edit are close to administrative permissions. A rule author can reach any Finding their rule's owner can see, and can direct output at external systems, so grant them deliberately.

All four are strict global permissions: a grant counts only when the role is held as a global role, never when it is held as an Organization or Asset membership role. Superusers keep access regardless.

If you are upgrading, a role that already held Rule Edit keeps the ability to create and delete rules, so nobody loses access. No built-in role gains rule access on upgrade.

## The concepts

### Rules and graphs

A rule is a name, a description, an owner, a mode, an enabled switch, and a graph. The graph is a set of **nodes** and the **edges** between them. It must contain exactly one trigger node and must not contain a cycle. Everything else is up to you, including leaving a node unconnected, which simply means it runs with nothing to work on.

New rules are always created **disabled**, so enabling one is a deliberate act.

### Items

What travels along the edges of a graph is an **item**: a JSON snapshot of one Finding plus its surrounding context.

```json
{
  "finding":      { "id": 1234, "title": "...", "severity": "High", "...": "..." },
  "test":         { "id": 12, "title": "...", "scan_type": "..." },
  "engagement":   { "id": 5,  "name": "..." },
  "product":      { "id": 3,  "name": "..." },
  "product_type": { "id": 1,  "name": "..." },
  "ctx":          { "trigger": "finding.created", "depth": 0, "source": "app" }
}
```

Conditions and message templates are written against the paths in that structure, for example `finding.severity` or `product.name`. The full field list is in [Building Rules](../building_rules/).

### Owner

Every rule runs **as its owner**. It sees exactly the Findings that user can see, through the same authorization used everywhere else in the Asset. Two consequences are worth knowing:

* Narrowing a rule owner's access narrows the rule.
* A rule whose owner's account is deleted has no owner, so it matches nothing at all and does nothing. Assign a new owner, or use **Take Ownership** from the rule list, to bring it back.

### Mode: Simulate or Live

Mode is set per rule, not per node.

* **Simulate** (the default) runs the whole graph for real, including every Finding edit, but egress nodes record what they *would* have sent and stop there. Nothing leaves DefectDojo.
* **Live** performs the sends.

Simulated sends still appear in the Deliveries ledger, marked `simulated`, with their full payload. That is the intended way to review a rule before you let it out.

Mode deliberately applies to the whole rule. A graph where some sends are real and others are not is harder to reason about than two rules.

### Runs

One execution of a rule is a [Run](../runs/). A run records the event that triggered it, its status, its per-node trace, and any error. A rule can only have one run in progress at a time, so a busy rule queues rather than racing with itself.

### Deliveries

Every outbound side effect is one row in the [Deliveries](../deliveries/) ledger, written **before** any network call happens. The row holds the payload, the resolved destination, the status, the retry count, and whatever the destination said back. Skips are recorded too, so "the rule did nothing" and "the rule did nothing because the Finding was already ticketed" are distinguishable.

### Provenance

Every change a rule makes to a Finding is attributed back to the rule, the run and the node that made it. That timeline is visible on the Finding itself, so you can answer "why did this Finding change?" without reading rule definitions.

### Scale

A rule processes everything its scope matches. There is no cap on how many Findings a run handles: it works through them in chunks so that memory stays bounded instead of coverage. Only Preview caps, and it tells you when it does.

### Retention

Runs and deliveries are both kept for 180 days by default, then pruned. The product shows you the window and the date a given record will be deleted rather than leaving it implicit, and both windows are configurable. See [Configuration](../configuration/#retention).

## Where to go next

* [Building Rules](../building_rules/) covers the editor, triggers, scope, conditions and templates.
* [Node Reference](../node_reference/) documents all 37 nodes.
* [Runs](../runs/) covers execution, traces, cascading and limits.
* [Deliveries](../deliveries/) covers channels, statuses, retries and replay.
* [Converting from Rules Engine](../converting_from_rules_engine/) covers moving existing rules across.
* [Configuration](../configuration/) covers the deployment level settings.
