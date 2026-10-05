---
title: "Finish onboarding: Assets that need attention"
description: "Find the Assets a connector left unplaced or that lack priority data, fix them in bulk, and know when onboarding is complete"
weight: 3
audience: pro
---

A connector can create thousands of Assets in its first sync. It cannot do two things for them: put each one in the right Organization, and say what each one is worth to your business. Until both are done, DefectDojo Pro ranks Findings and picks SLAs from defaults.

The **Needs Attention** page lists every Asset that still has one of those gaps. Onboarding is complete when the list is empty.

The Needs Attention page, the Asset page card and the Onboarding dashboard widget are released behind the **Onboarding Inbox** feature flag. An administrator turns it on from the [Feature Flags](/admin/feature_flags/pro__feature_flags/) page. The API endpoints described below work with the flag off.

## Why an Asset needs attention

Each Asset in the list shows one or both reasons.

### Unplaced

The Asset still sits in the Organization a connector created as its default, and that connector mapped it. When a connector does not derive an Organization from the tool it reads, it files every new Asset under an Organization named after itself, such as "Security Hub Connector". That Organization is a holding area, not a place in your hierarchy.

DefectDojo recognizes a default Organization by two facts together: its name is exactly the default name of a connector, and the Asset is mapped by a record of that same connector. An Organization you created and named yourself is never treated as a connector default, and moving an Asset out of the default Organization clears the reason.

### Missing priority data

At least one of the five fields that drive Priority is not set. Scanners never supply these, so every Asset a connector creates starts without them.

| Field | Not set when | What it does to Priority |
|---|---|---|
| Business Criticality | It is empty. "None" counts as an answer. | Raises Finding Priority by up to 25% for Very High and lowers it by up to 25% for Very Low. |
| User Records | It is empty. 0 counts as an answer. | Adds up to 20 points, in proportion to this Asset's share of all user records in its Organization. |
| Revenue | It is empty. 0 counts as an answer. | Adds up to 20 points, in proportion to this Asset's share of all revenue in its Organization. |
| External Audience | Nobody has answered it. | When yes, adds 35% of the severity score to the Priority of each Finding. |
| Internet Accessible | Nobody has answered it, and the Asset has no exposure override. | When yes, adds 65% of the severity score to the Priority of each Finding. |

Each Prioritization Engine can weight these factors up or down. See [Assign Priority, Risk and SLAs](../priority_sla/).

External Audience and Internet Accessible are checkboxes, so "no" and "never answered" look the same. DefectDojo records an answer whenever someone saves the field: through the Asset form (which always submits both checkboxes), through an `/api/v2/assets/` create or update that includes the field, or through any save that changes its value. An exposure override also answers Internet Accessible.

Answers given before this feature shipped were not recorded. An Asset that was deliberately set to "no" earlier shows the field as not set until someone saves the Asset form once.

## Work the list

Open **Assets > Needs Attention**.

* The buttons above the table switch between all Assets, only unplaced ones and only those missing priority data, with a count for each.
* Narrow the list by missing field, by Organization or by connector.
* Select Assets and use **Bulk Edit** to move them to another Organization, set Business Criticality, set the SLA configuration or Prioritization Engine, and more. A bulk edit applies to every selected Asset at once, and the list and counts refresh when it finishes.
* The pencil on a row opens the Asset form, which is where User Records, Revenue and the two checkboxes are set.

**Create a rule from this filter** opens a new Rules Engine rule. Choose the Asset trigger, add conditions that match what you filtered on, and add the action to apply, such as setting the Organization. New Assets that match are then handled as they arrive. The rule editor does not yet fill in the trigger and conditions for you.

## What drives Priority and SLA on an Asset

The **What Drives Priority and SLA** card on the Asset page lists the five fields, whether each is set, and one line on what each does. Revenue and User Records also show this Asset's share of its Organization's total, which is the number Priority actually uses. Fields that are not set link to the Asset form.

The card also names the Asset's Prioritization Engine and its SLA configuration, with where that SLA comes from:

* the default SLA configuration, because none was chosen;
* a criticality to SLA mapping, matched from the Asset's Business Criticality;
* or a configuration set on the Asset itself.

The card is part of the default Asset page layout. If you use a customized layout, add it from the layout editor.

## The onboarding complete measure

Onboarding is complete when no Asset you can see needs attention: none is unplaced, and every one has all five fields set.

* The **Onboarding** dashboard widget shows how many Assets still need placement or priority data, split by reason, with a link to the Needs Attention page. At zero it reads "Onboarding complete."
* Counts follow your permissions. A user who can see some Assets sees the measure for those Assets only.

## API

Automation uses the public `/api/v2/` API with an API token.

* `GET /api/v2/assets/needs_attention/` lists the Assets that need attention, each with `reasons` (`connector_default_org`, `missing_priority_fields`) and `missing_fields`. Filter with `reason`, `missing_field`, `organization` and `connector`, each accepting comma-separated values.
* `GET /api/v2/assets/needs_attention/summary/` returns the totals per reason, per missing field, per Organization and per connector.
* `GET /api/v2/assets/onboarding_status/` returns `onboarding_complete` and the counts behind it.
* `GET /api/v2/assets/{id}/priority_drivers/` returns what the Asset page card shows.

The same endpoints answer under `/api/v2/products/`.
