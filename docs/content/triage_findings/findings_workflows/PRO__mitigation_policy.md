---
title: "Mitigation Policies"
description: "Standardize how Findings should be remediated with reusable, centrally managed Mitigation Policies"
audience: pro
weight: 3
---

A **Mitigation Policy** is a named, reusable statement of how Findings should be remediated: the steps to take, the order to take them in, and the stakeholders to inform. Instead of writing remediation guidance into each Finding by hand, you define a policy once and attach it to every Finding it applies to — directly, in bulk, or automatically through the [Triage Engine](/automation/triage_engine/about/).

Mitigation Policies are a DefectDojo Pro feature.

Mitigation Policies answer *how* a Finding should be remediated. They are the counterpart to [Service Level Agreements](/asset_modelling/pro_hierarchy/priority_sla/), which answer *when*: an SLA sets the remediation deadline, while a Mitigation Policy carries the standardized remediation guidance. The two are configured side by side under **Settings > Finding Workflow**.

## Managing Mitigation Policies

Open **Settings > Finding Workflow > Mitigation Policies** in the Pro UI. (On instances still using the previous settings menu, look for **Mitigation Policies** in the legacy settings list.) From here you can create, edit, and delete policies.

A policy has three fields:

| Field | Purpose |
| --- | --- |
| **Title** | A brief name for the policy, shown wherever the policy appears — on Findings, in list columns, and in filters. |
| **Description** | The policy itself: how to mitigate the Finding, any stakeholders to inform, and anything else the remediation owner should know. Supports Markdown. |
| **Is Default** | Whether this policy is applied to Findings where no policy is specified. Only one policy can be the default at a time — setting it on one policy clears it from any other. |

Any authenticated user can view Mitigation Policies. Creating, editing, or deleting them requires the Global Maintainer role or higher, or a [custom role](/admin/user_management/pro__custom_rbac_roles/) granting the **Mitigation Policy: Edit** permission. Changes to Mitigation Policies are recorded in the [audit log](/admin/user_management/pro__audit_log_index/).

Deleting a policy does not affect the Findings that used it: the Findings remain, with their Mitigation Policy field cleared.

### The default policy

When a policy is marked as the default, it is applied automatically to any Finding that does not have a policy of its own — including newly imported Findings.

DefectDojo ships with a built-in policy named **General Mitigation Policy**, containing generic triage and remediation guidance, which is set as the default when the feature is first installed. You can edit it, replace it with your own default, or clear the **Is Default** flag entirely so that Findings start with no policy.

## Mitigation Policies on Findings

On the Finding page, **Mitigation Policy** appears among the Finding's optional fields, where anyone with Finding Edit permission on that Finding can select a policy from the dropdown.

On Finding lists, the Mitigation Policy is available as a sortable column, and Findings can be filtered by one or more policies.

## Setting policies automatically

Both automation engines can assign a Mitigation Policy to matching Findings:

* The [Triage Engine](/automation/triage_engine/about/) has a [Set Mitigation Policy node](/automation/triage_engine/node_reference/#set-mitigation-policy).
* The classic [Rules Engine](/automation/rules_engine/about/) has a **Set a Mitigation Policy** action.

This is the intended way to keep policies applied consistently at scale: for example, a rule that matches Findings by CWE or vulnerability class and stamps each with the appropriate remediation playbook.

## API

Mitigation Policies can be managed programmatically through the `/api/v2/mitigation_policies/` endpoint. The same access rules apply: any authenticated user can read, while writes require Global Maintainer or higher (or the equivalent custom-role permission).
