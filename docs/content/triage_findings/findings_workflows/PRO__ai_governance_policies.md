---
title: "AI Governance Policies"
description: "Decide which AI components are authorized where, and turn unauthorized ones into Findings"
audience: pro
weight: 4
---

An **AI Governance Policy** says whether an AI component is allowed: **authorized**, **unauthorized**, or **needs review**. A policy can apply to every Asset, to one Organization, or to one Asset. DefectDojo evaluates every component in the [AI Inventory](/asset_modelling/locations/pro__ai_inventory/) against the policies that apply to it. An unauthorized component becomes an ordinary Finding, so priority, SLAs, the [Triage Engine](/automation/triage_engine/about/), tickets, notifications, dashboards and reports all apply to it.

> AI Governance Policies are part of the **AI Inventory and Governance** feature (beta). Turn it on from the [Feature Flags page](/admin/feature_flags/pro__feature_flags/).

## Creating a Policy

Go to **Settings > Finding Workflow > AI Governance Policies** and choose **New Policy**. A policy has:

| Field | Meaning |
|---|---|
| **Scope** | Global, one Organization, or one Asset. |
| **Match type and value** | What the policy recognizes. An exact Package URL, such as `pkg:npm/@modelcontextprotocol/server-filesystem` (without a version it matches every version). A Package URL pattern with `*` or `?`, such as `pkg:npm/@modelcontextprotocol/*`. An AI category, such as `mcp-server`, or the `package` kind, which covers every AI package. Or a provider, such as `anthropic`. |
| **Decision** | Authorized, unauthorized, or needs review. |
| **Finding severity** | For unauthorized components only. Leave it on the default to use the kind's default: High for MCP servers and AI services, Medium for assistants, models and packages, Low for skills. |
| **Justification** | Why. Shown when you expand a component in the inventory, and in the Finding. |
| **Owner** | The person or group accountable for the policy. |

A global policy needs a superuser. An Organization or Asset policy needs edit rights on that Organization or Asset. Every change is recorded in the audit log.

DefectDojo ships four **starter** policies, all disabled. They allow the MCP SDKs, allow the major AI provider SDKs, flag every MCP server until reviewed, and flag model files checked into a repository. Enable the ones that fit, or use them as examples.

## How a Decision Is Made

When several policies match one component on one Asset:

1. **The most specific scope wins.** An Asset policy beats an Organization policy, which beats a global one.
2. **Within that scope, the most specific match wins.** An exact Package URL beats a pattern, and a longer pattern beats a shorter one. A pattern beats a provider, and a provider beats a category.
3. **A remaining tie goes to the stricter decision.** Unauthorized beats needs review, which beats authorized.

A component that no enabled policy matches **needs review**. DefectDojo never treats unknown AI as allowed.

Decisions are re-evaluated in the background after every inventory import and every policy change, for exactly the Assets the change can affect. A nightly pass catches anything else. A superuser can also choose **Re-evaluate all** on the policies page.

## Findings

An unauthorized component raises one Finding:

- It is titled **Unauthorized AI component: *name***.
- It is tagged `ai-governance`, plus `ai-<kind>` (for example `ai-mcp-server`).
- It lives in an **AI Governance** engagement and test on the Asset.
- Its description names the policy, its justification, and where in the repository the component was found.

Re-evaluation keeps it in step with the repository:

- Authorizing the component, or removing it from the repository, **mitigates** the Finding on the next evaluation.
- Unauthorizing it again reopens the same Finding. It never creates a second one.
- A Finding someone marked false positive, out of scope or risk accepted is left alone.

Components that need review raise nothing by default and are counted on the inventory page. To triage them like any other Finding, turn on **Raise Info Findings for AI components needing review** at the top of the policies page. Each undecided component then raises an Info Finding, and turning the setting off mitigates them.

## Automating the Response

Because violations are Findings, the Triage Engine handles them with no new setup. A template ships in the Triage Engine: **AI Governance: ticket and notify on an unauthorized AI component**. It triggers on new Findings tagged `ai-governance` at High or Critical, opens a ticket and sends an alert. Adopt it, point the ticket at your project, and try it in Simulate first.

A notification event, **AI component discovered**, fires the first time a kind of AI component appears on an Asset, such as its first MCP server. Removing and re-adding a component does not fire it again. Choose where it goes in your notification settings.

## Using the API

Policies and decisions are available with an API token:

```http
GET  /api/v2/ai_governance/policies/
POST /api/v2/ai_governance/policies/
GET  /api/v2/ai_governance/verdicts/?product=12&decision=unauthorized
POST /api/v2/ai_governance/policies/evaluate/   {"product": 12}
```
