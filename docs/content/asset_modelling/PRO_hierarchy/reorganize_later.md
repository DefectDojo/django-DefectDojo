---
title: "You can reorganize later"
description: "What changes, and what stays put, when you move Assets between Organizations, change their parents, or re-map Connector Records"
draft: false
audience: pro
weight: 2
---
<!--
Links to add once the pages for these features are on dev (each is still in review):
  * Change plans (dry-run diff, CSV upload and diff export, apply and undo):
    asset_modelling/PRO_hierarchy/change_plans.md. Link it from "Moving many Assets at once"
    and from the intro, as the way to review a large reorganization before it happens.
  * Needs Attention inbox and the onboarding-complete measure:
    asset_modelling/PRO_hierarchy/finish_onboarding.md. Link it from "Before you start moving
    things" and from "Re-mapping a Connector Record", for finding Assets still in a Connector's
    default Organization or missing priority fields.
  * Rules Engine computed destinations (place Assets by tag, connector attribute or name):
    automation/triage_engine/building_rules.md and node_reference.md. Link them from
    "Moving many Assets at once", for placement that keeps happening as new Assets arrive.
  * The Security Hub re-place action for existing Assets:
    connectors/toolreference/security_hub.md. Link it from "Re-mapping a Connector Record".
-->

The safest hierarchy plan is one you can change. DefectDojo Pro lets you get scan data in on day one with a reasonable structure, then move Assets between Organizations, change their parents, or point Connector Records at different Assets as you learn more, without losing Findings, their history or their deduplication state.

This page lists, for each kind of change, what moves, what is recalculated, and what stays exactly as it was. If you are still deciding on a structure, start with [Plan your hierarchy](../plan_your_hierarchy/).

## Moving an Asset to another Organization

Change the **Organization** on the **Edit Asset** form, use **Bulk Edit** on the All Assets list, or send the change through the API. The same rules apply whichever way the move is made, including moves made by the Rules Engine.

### What happens

* **The Asset's children move with it.** Every Asset below it in the hierarchy moves to the new Organization too, so the tree stays whole.
* **A parent link left crossing Organizations is removed.** Parent and child Assets always share an Organization, so when an Asset moves away from its parent, the link to that parent is removed and the Asset becomes a top-level Asset in its new Organization.
* **Connectors do not undo the move.** A Connector that declares a parent in another Organization skips that link and logs it, rather than pulling the Asset back.
* **People are told.** The owners and contacts of each Asset that lost its parent receive a notification naming the Assets and where they went. The removed links are recorded in the audit log.
* **Priority is recalculated in both Organizations.** Revenue and User Records are weighed as a share of their Organization's totals, so a move changes the picture for every Asset in the Organization it left and the one it joined. DefectDojo recalculates Finding Priority and Risk for both Organizations, once each, however many Assets moved. Where an Asset uses a Risk-based SLA Configuration, a Finding whose Risk changes gets the deadline for its new Risk level.

### What changes and what stays

| Changes | Stays the same |
| --- | --- |
| The Organization of the Asset and of every Asset below it | The Asset itself: its ID, name and settings |
| The parent link, if the parent stays behind | Its Engagements, Tests and Findings, with their notes, files and history |
| Who can see it through an Organization role: roles on the old Organization no longer reach it, roles on the new one do | Deduplication state: duplicate links, and the hash codes reimport uses to match the next scan |
| Organization-filtered metrics, dashboards and reports pick it up under the new Organization | Roles given on the Asset itself |
| Finding Priority and Risk, recalculated for both Organizations | Its five priority fields, Prioritization Engine, SLA Configuration and tags |
| | Its Connector Record mappings, CI import targets and Jira or integrator mappings, which all point at the Asset rather than its Organization |
| | Its Dedupe Pool memberships |

Because deduplication works inside each Asset, and a moved Asset keeps its own Findings, the next import or Connector sync into it matches what is already there. Nothing is re-imported and nothing is duplicated.

### Permissions

Moving an Asset needs edit permission on it and permission to add Assets to the destination Organization. Because its children move too, you also need edit permission on every Asset that moves with it. If you lack it on any of them, the move is refused with a message naming the Asset, and nothing is changed.

## Moving many Assets at once

**Bulk Edit** on the All Assets list moves the selected Assets together and can also set a parent (or remove it), the Asset type (when Asset types are turned on), **Business Criticality**, the SLA Configuration, the Prioritization Engine and tags. When you choose an Organization, **Move Children Along** decides what happens below each selected Asset:

* **On** (the default): children move with their parent, as described above.
* **Off**: children stay in the old Organization. Their links to the moved Asset are removed, and they become top-level Assets there.

The same update is available to scripts as `POST /api/v2/assets/bulk_update/`, which also accepts the three contacts (technical contact, team manager, product manager). It takes up to 500 Assets per request and is all or nothing: if any Asset in the batch cannot be changed (no permission, a parent in another Organization, a cycle, a child that cannot move along, or Findings still being recalculated from an earlier SLA Configuration or Prioritization Engine change), the whole request is refused with a list of every problem, and nothing is written. Split larger reorganizations into batches of 500.

Tags given in a bulk update are added to each Asset's existing tags. Nothing is removed.

## Changing an Asset's parent

Use **Change Parent**, **Add Child** or **Remove From Hierarchy** on the **Asset Hierarchy** screen, the parent field on the **Edit Asset** form, or **Bulk Edit**.

* The new parent must be in the same Organization. To put an Asset under a parent in another Organization, move it to that Organization first.
* A change that would create a cycle (an Asset ending up below its own child) is refused.

Re-parenting changes how Assets roll up, and nothing else:

| Changes | Stays the same |
| --- | --- |
| The tree shown on the Asset Hierarchy screen | The Asset's Organization, Findings and history |
| The indirect Finding counts of the old and new parents, which are always calculated from the current tree | Who can see the Asset: a parent never grants or limits access |
| Metrics that include child Assets | Deduplication: Findings still deduplicate within their own Asset |
| | Priority, Risk and SLAs: they come from the Asset's own fields and its Organization |

**One exception to plan for.** If you used **Pool this asset and everything under it** to put a subtree in a [Dedupe Pool](/triage_findings/finding_deduplication/pro__dedupe_pools/), those memberships were made from the tree as it stood then, and re-parenting does not update them. After a large re-parent, run **Untoggle Subtree** and pool the subtree again to bring the pool in line with the new tree.

## Re-mapping a Connector Record

A Connector Record is what links an Asset in your scanning tool to an Asset in DefectDojo. When you point an already-mapped Record at a different Asset from **Edit Record** on the Manage Records page, DefectDojo asks what should happen to the Findings that Record has already imported. See [Change the Mapping of a Record](/connectors/upstream/manage_records/#change-the-mapping-of-a-record).

### Move (the default)

The Record's Tests move to the new Asset, under its **Global Connectors** Engagement, and keep their link to the Record. The next sync reimports into the same Tests, so it matches the Findings already there: no duplicate set, and no Findings closed and reopened.

* **Travels with the Tests, untouched:** notes, files, history, Finding Groups, import history, and the hash codes deduplication and reimport use.
* **Carried across, because they belong to an Asset:** endpoint and location statuses, Risk Acceptances, inherited tags, and SLA dates, which are recalculated for the new Asset's SLA Configuration.
* **Recalculated:** Finding Priority and Risk, and the grades of both Assets.
* **Released:** a duplicate link whose original stays behind and would no longer be in the same deduplication scope.
* **Recorded:** the moved Test gets a note naming the old and the new Asset.

The Connector Engagement left empty on the old Asset is removed, unless something a person added is attached to it.

### Start fresh

The old Tests stay on the old Asset as history. Their open and risk-accepted Findings are closed with a note saying the Record was re-mapped, and the Record starts importing into new Tests under the new Asset.

Choose this when the old Findings no longer describe anything real, for example when the Record was mapped to the wrong system entirely.

### Permissions

Re-mapping a Record needs permission to edit the Connector, and edit permission on both the old and the new Asset, so a re-map can never move Findings out of, or close Findings in, an Asset you cannot edit. A first mapping of a new Record has nothing to carry and asks no question.

## Before you start moving things

* **Check who will gain or lose access.** Organization roles decide most visibility, so a move between Organizations is also an access change. Roles given on individual Assets travel with the Asset.
* **Expect a recalculation.** After a large move, Priority and Risk update in the background for both Organizations. Lists sorted by Priority settle once it finishes.
* **Move whole trees where you can.** Moving a parent takes its children along and keeps the tree intact. Moving children out one at a time removes parent links you may want to keep.
* **Batch big reorganizations.** The bulk update takes 500 Assets per request and refuses a batch with any problem, so a refused batch never leaves a half-finished reorganization behind.

## Next steps

* [Plan your hierarchy](../plan_your_hierarchy/): patterns, a copyable LLM planning prompt, and the five priority fields.
* [Asset Hierarchy](../asset_hierarchy/): parent and child Assets and the hierarchy screen.
* [Bulk Edit Assets](/asset_modelling/engagements_tests/pro__assets/#bulk-edit-assets) and [Organizations](/asset_modelling/engagements_tests/pro__organizations/).
* [Managing Records](/connectors/upstream/manage_records/): how Connector Records map to Assets.
