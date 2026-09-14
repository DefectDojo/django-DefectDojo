---
title: "AI Agent Red Teaming"
description: "Onboard a deployed AI agent, attack it automatically to find where it breaks, and vet an agent's actions at runtime"
draft: false
audience: pro
weight: 5
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Sensei is a DefectDojo Pro-only feature. AI Agent Red Teaming is currently in BETA and is gated behind the `agent_redteam` feature flag.</span>

Sensei's capabilities share one hub. **AppSec** scans and fixes source-code repositories, **Cloud Security Posture (CSPM)** does the same for cloud accounts, and **AI Agent Red Teaming** does it for a **deployed AI agent**: point Sensei at your agent's endpoint, and it runs an autonomous attacker that talks to the agent through its normal interface, tries to make it misbehave, and imports each confirmed break as a DefectDojo finding.

> **🧭 One hub, another capability.** Open **Sensei** from the left-hand navigation and choose the **AI Agents** capability card (or **AppSec** / **CSPM**, or **All** to see every target together). An agent target is the analog of an onboarded repository or cloud account: it is the thing you scan, and it is linked to a DefectDojo **Asset** so its findings live alongside the rest of your data.

## How it works

1. **Onboard an agent target** — the endpoint of a deployed agent (an OpenAI-compatible chat endpoint, an OpenAI tool-calling endpoint, or a generic JSON HTTP API), linked to an Asset.
2. **Sensei attacks it** — on demand from the hub, an autonomous attacker runs a multi-turn conversation with the agent, cycling through a library of attack techniques: prompt injection, jailbreaks, system-prompt extraction, tool coercion, indirect injection, data exfiltration, gradual goal-hijacking, improper output handling, retrieval (RAG) injection, and unbounded consumption.
3. **Each confirmed break becomes a finding** — a dynamic DefectDojo finding recorded against the agent's endpoint, carrying the attack technique, the full attacker/agent transcript, an OWASP LLM risk tag, and a CWE.
4. **Reconcile on re-scan** — a finding's identity is the technique, the target, and the objective, so re-scanning updates the same findings rather than duplicating them.

Separately, a **runtime-check API** lets your own agent ask DefectDojo to vet a proposed action before it runs — see [Runtime action checks](#runtime-action-checks).

## Requirements

- A **DefectDojo Pro** license that includes the **Sensei** feature, with an **agent-target quota** (`sensei_agent_target_limit`). While in beta, the capability is also gated behind the **`agent_redteam`** feature flag (**Settings > Feature Flags**).
- An **AI provider configured** for the instance (the same AI Model Settings the rest of Sensei uses) — the attacker is itself LLM-driven.
- A **reachable agent endpoint**. The attacker makes outbound HTTP calls to it, so the endpoint must be reachable from the Sensei engine.
- To **onboard** targets and **run scans**: a global **Maintainer** or **Owner** role.

## Onboard an agent target

Use **Add Target** in the hub's **AI Agents** tab, give the target a label, link it to an Asset, and configure how the attacker reaches it.

| Field | Meaning |
|-------|---------|
| **Label** | A display name for the target (e.g. "Support chatbot"). Unique within an Asset. |
| **Adapter** | How the attacker talks to the target: **OpenAI-compatible**, **OpenAI tool calling**, or **Generic JSON** (see below). |
| **Base URL** | The deployed agent endpoint to attack. |
| **Auth header** | The header the target credential is sent in. Blank sends it as `Authorization: Bearer <credential>`; set it (e.g. `x-api-key`) to send the raw credential instead. |
| **Target credential** | The bearer token or API key for the target agent (encrypted at rest). Optional — a target may be unauthenticated. This is **not** the LLM credential the attacker uses. |
| **Objective** | What the attacker should try to achieve. Leave blank for a general objective (make the agent violate its safety instructions, leak its system prompt, or invoke a restricted tool). |
| **Mode tier** | How thorough — and how expensive — the attack is: **fast**, **shallow**, **standard**, or **deep**. A deeper tier tries more techniques for more turns and spends more LLM budget. |
| **Hints** | Optional free-text notes about the target's architecture (e.g. "uses a retrieval store", "has a delete-account tool") given to the attacker to guide it. |

> **🔐 Credentials are encrypted at rest.** The target credential is stored with DefectDojo's encrypted field storage and is never returned by the API — the UI shows only whether one is set.

### Adapters

**OpenAI-compatible** — for an endpoint that accepts the OpenAI Chat Completions shape. The attacker POSTs the running conversation to `<base URL>/chat/completions` and reads the reply from `choices[0].message.content`. This is the simplest option when your agent already speaks that protocol.

**OpenAI tool calling** — the same Chat Completions shape, but the attacker also declares a set of decoy tools (destructive, data-exfiltrating, or safety-disabling operations a well-behaved agent should refuse) and watches for the agent actually **invoking** one. A returned tool call for a restricted tool is recorded as a Critical break — a real unsafe-tool-use signal rather than a match on the agent's chat text. Choose this adapter for an agent that exposes function/tool calling.

**Generic JSON** — for any JSON HTTP chat API. You provide:

- A **request template** — the JSON body to POST, with `{{message}}` and `{{session_id}}` placeholders. The attacker substitutes its probe (safely JSON-escaped) for `{{message}}` on each turn.
- A **response JSON path** — a dotted path to the reply text in the response (for example `data.reply` or `choices.0.message.content`).
- Optionally, a **session-start template** and **session-id JSON path** — for a stateful API that mints a session id the per-message calls then carry.

For example, an agent whose API takes `{"prompt": "..."}` and answers `{"result": {"text": "..."}}` uses request template `{"prompt": "{{message}}"}` and response path `result.text`.

## Scan a target

Open a target's row menu and choose **Scan now**. Sensei dispatches the attacker, which holds a multi-turn conversation with the agent per technique and adapts based on how the agent responds, until it either achieves the objective or exhausts the turn/token budget for the mode tier. Scans appear on the hub's **Scan Activity** ledger alongside repository and cloud scans.

Each imported finding is a confirmed **break**: a technique that got the agent to satisfy the objective. It is a **dynamic** finding recorded against the agent's endpoint (a URL location, when the Locations feature is on), and it carries:

- the **attack technique** as its rule and the first part of its identity,
- the full **attacker/agent transcript** in its description, so a triager can see exactly how the break was achieved,
- an **OWASP LLM** risk tag (`owasp-llm01`, `owasp-llm02`, and so on),
- a **CWE** — prompt injection, jailbreaks, goal-hijacking and retrieval injection map to **CWE-1427**; system-prompt disclosure and data exfiltration to **CWE-200**; unsafe tool use to **CWE-77/78**; improper output handling to **CWE-79**; unbounded consumption to **CWE-400**.

A scan that breaks nothing is a successful, empty scan — the same way a cloud scan that finds no misconfiguration is a success.

## Runtime action checks

AI Agent Red Teaming also exposes a runtime-defense API your own agent can call while it runs, to vet an action before performing it. This is a **public, token-authenticated** API under `/api/v2/agentsec/runtime/` — use a personal API token, exactly as with the rest of the public API. It is **best-effort advisory**: it tells your agent whether an action looks unsafe given the run's context; it does not sit inline and block the call itself.

Three endpoints, all `POST`:

| Endpoint | Body | Returns |
|----------|------|---------|
| `register_run` | `agent_id`, `system_prompt`, optional `product` | `{ "trace_id": "..." }` — the handle every later call carries. |
| `event` | `trace_id`, `type` (`user`/`model_input`/`model_output`/`tool`/`environment`/`memory`/`system`/`error`), `content` | `202 Accepted`. Append-only; builds the context a check reasons over. |
| `check` | `trace_id`, `action` | `{ "is_safe": bool, "reasoning": "...", "action_check_id": "..." }` — a synchronous verdict on the proposed action. |

A check runs a deterministic pass first (refusing known-dangerous patterns outright) and then, when an AI provider is configured, asks it to judge the action against the run's system prompt and recent events.

```bash
# 1) Register a run
TRACE=$(curl -s -X POST https://<your-dojo>/api/v2/agentsec/runtime/register_run/ \
  -H "Authorization: Token <api-token>" -H "Content-Type: application/json" \
  -d '{"agent_id": "support-bot", "system_prompt": "You are a read-only support assistant."}' | jq -r .trace_id)

# 2) Stream an event
curl -s -X POST https://<your-dojo>/api/v2/agentsec/runtime/event/ \
  -H "Authorization: Token <api-token>" -H "Content-Type: application/json" \
  -d "{\"trace_id\": \"$TRACE\", \"type\": \"tool\", \"content\": \"read_ticket(42)\"}"

# 3) Vet a proposed action before running it
curl -s -X POST https://<your-dojo>/api/v2/agentsec/runtime/check/ \
  -H "Authorization: Token <api-token>" -H "Content-Type: application/json" \
  -d "{\"trace_id\": \"$TRACE\", \"action\": \"DROP TABLE tickets\"}"
# -> {"is_safe": false, "reasoning": "...", "action_check_id": "..."}
```

## Quotas

AI Agent Red Teaming meters against the **agent-target quota** (`sensei_agent_target_limit`), shown as an **Onboarded Agent Targets** card at the top of the hub. Onboarding is blocked when the limit is reached. The attacker's LLM usage is attributed to the Sensei cost ledger like the rest of Sensei's AI spend.

## Troubleshooting

- **The AI Agents tab is not shown.** The capability is in beta and gated behind the `agent_redteam` feature flag. Enable it on **Settings > Feature Flags**.
- **"No agent-target quota is available."** Your license carries no `sensei_agent_target_limit`, or it is used up. Contact your DefectDojo administrator to raise it.
- **A scan fails to reach the target.** The Sensei engine makes outbound HTTP calls to the target's base URL; confirm the endpoint is reachable from the engine and that the credential and auth header are correct.
- **A scan errors on the LLM.** The attacker is LLM-driven, so a scan needs a working AI provider. Configure one under **AI Model Settings**.
- **A generic-JSON target returns nothing.** Check the request template is valid JSON with the `{{message}}` placeholder, and that the response JSON path points at the reply text in the target's actual response shape.
- **`check` always allows an action.** With no AI provider configured, `check` runs only the deterministic pass and allows anything that clears it. Configure an AI provider for context-aware verdicts.
