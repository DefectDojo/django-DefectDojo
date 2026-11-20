---
title: "Build a Triage Engine rule with the API"
# The page that embeds this prompt with {{< prompt "triage-engine-rule" >}}.
page: "/automation/triage_engine/building_rules"
weight: 40
---
In DefectDojo Pro, an AI assistant (such as Claude, ChatGPT or Copilot) can turn a rule you describe in plain language into a [Triage Engine](/automation/triage_engine/about/) rule, built with the API. Give it the prompt below, and describe the rule you want in place of the bracketed example. The prompt makes the assistant check the rule with the API before it saves anything, and save it switched off in Simulate, so nothing changes until you have seen what it would do.

```text
Write a [bash script using curl and jq] that builds this rule in DefectDojo
Pro's Triage Engine:

  [Describe the rule. For example: when a new finding is created whose
  component name contains "log4j", set its severity to Critical and tag it
  "log4j".]

Facts about the Triage Engine rules API. Follow them exactly:
- Base URL: [https://dojo.example.com]. Rules live at
  /api/v2/rules_engine_v2/rules/. Never use /api/vue/ paths; they reject API
  tokens.
- Header: "Authorization: Token <key>", with the key read from the DD_TOKEN
  environment variable. Triage Engine must be enabled on the instance, and the
  token's user needs the Rule Add permission; otherwise every route answers 403.
- A rule is {"name", "description", "graph", "enabled", "mode"}. "graph" is
  {"nodes": [...], "edges": [...]}.
  - Each node: "id" (short and readable, unique), "type", "name", "config",
    and "position" ({"x", "y"}, only used by the editor).
  - Each edge: "id", "source", "target". A node with several outputs, such as
    filter.if with "true" and "false", names the output in "sourceHandle".
  - Exactly one trigger node, every node reachable from it, and no cycles.
- Do not invent node types or config keys. Start by reading
  GET /api/v2/rules_engine_v2/rules/templates/, which returns the shipped rules
  with complete graphs, and use the node types and config keys you find there.
  If the rule needs a node no template uses, stop and ask me to build a small
  rule with that node in the editor and paste its graph from
  GET /api/v2/rules_engine_v2/rules/{id}/.
- A finding trigger's "scope" takes Findings filter names, for example
  {"severity": "High"}. An unknown filter name is refused, not ignored.
- Build the rule in this order, and stop at the first failure:
  1. POST /api/v2/rules_engine_v2/rules/validate/ with {"graph": ...}. It
     always answers 200; fix everything in "problems" before going on.
  2. POST /api/v2/rules_engine_v2/rules/preview/ with {"graph": ..., "limit":
     25}. It runs the rule and rolls everything back. Print each node's trace
     and "scope_total", then ask me to confirm before saving.
  3. POST /api/v2/rules_engine_v2/rules/ with "mode": "simulate". A new rule
     starts with "enabled": false. A refused save answers 400 with the reasons
     under "graph" or in "problems".
  4. Do not run or enable the rule. Print its id and tell me how to do that.
- Running a rule changes Findings for real, even in Simulate; Simulate only
  holds back messages, tickets and webhooks. Enabling is
  PATCH {"enabled": true}; going live is PATCH {"mode": "live"}.
- A PATCH that changes the graph must send the whole graph. There is no way to
  change one node on its own.
- A rule triggered on a schedule needs "schedule": {"trigger_type": "C",
  "trigger_expression": "<cron>"} in the same request, and the cron minute must
  be 0, 15, 30 or 45.

Before you write the script, describe the graph you plan to build, node by
node, so I can correct it.
```

The assistant cannot see your instance, so the templates are its only source for node types and settings. The [Node Reference](/automation/triage_engine/node_reference/) and [Conditions](/automation/triage_engine/building_rules/#conditions) describe what each node and condition does. The full request and response schemas are in the interactive API documentation at `/api/v2/oa3/swagger-ui/` on your instance, under `rules_engine_v2`.
