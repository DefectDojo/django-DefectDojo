---
title: "Hierarchy suggestions: tidy the hierarchy after data lands"
description: "Advisor > Hierarchy finds structural problems in how Assets and Organizations ended up, proposes a fix for each, and applies it as a reviewed change plan you can undo"
weight: 4
audience: pro
---

Data usually arrives before anyone decides where it belongs. A connector that cannot place what it finds puts every new Asset in its holding Organization ("Security Hub Connector" and the like), and that Organization can hold thousands of Assets before the first findings sync ends. **Hierarchy suggestions** look at how the hierarchy ended up, describe each problem with its counts, and offer a fix you review before anything changes.

Suggestions live in **Advisor > Hierarchy** (`/ui/advisor/hierarchy`). They do not need a Sensei license and use no Advisor runs: the checks are rules, not AI, and they run on every instance where the feature is on.

## Turning it on

Hierarchy suggestions are released behind the **Hierarchy Suggestions** feature flag, which is off by default. A superuser turns it on from **Settings > Feature Flags** (see [Feature Flags](/admin/feature_flags/pro__feature_flags/)). While it is off, nothing is checked, the pages are hidden, and the API answers with a `403`.

## When the checks run

* After a connector reports the end of a discovery or a sync. Discovery is enough: placement can be reviewed before the first findings sync.
* Every night, for everything.
* When someone selects **Check Now** on the Hierarchy page (`POST /api/v2/hierarchy/health/check/`). A check names one connection or one Organization (`scope_type` with its `scope_id`, which is required), or the whole instance (no `scope_type`, or `instance`), which needs the global permission to view or edit the Asset Hierarchy. A scope is checked at most once every five minutes this way; superusers are exempt.

A burst of syncs for the same connection runs the checks once at the start and once more at the end, not once per sync. A suggestion whose problem is gone the next time the checks run is marked **Resolved**.

## Connector placement

The first check looks for Assets that a connection left in its connector's holding Organization. It offers one suggestion per connection, and the fix has three steps, because it is a connector setting and then a move:

1. **Choose how to place.** This step and the next need the permission to edit the connection. The connector's own placement options are listed with what each needs from the vendor account. For AWS Security Hub: one Organization per AWS account (named by account ID, or by account name with `organizations:ListAccounts`), one per AWS Organizations OU nested along the OU path (with `organizations:ListParents` and `organizations:DescribeOrganizationalUnit`), or one per value of an account tag (with `organizations:ListTagsForResource`). Choosing one changes the connection's placement setting. New Assets follow it at once; the Assets already in the holding Organization do not move yet. The previous value is recorded, so undo can put it back.
2. **Discover.** Discovery runs with the new setting, so each record names where its Asset belongs. If it places no account at all, the vendor account most likely lacks the permission the option needs: the page says so and offers the other options.
3. **Review the moves.** Each destination is a group: its Organization (created when it does not exist yet, nested along an OU path), its members, and a few examples. Leave a group out, rename a new Organization, open a group to leave out members or move one into another group. Every change previews again, so the review always describes the plan that applying runs.

Connectors whose records already name an Organization start at step 3. Connectors that create one Asset per host or device are listed for information only: placing those one by one would fix that grain in place.

## What the review shows

Before anything changes, the review lists every effect:

* **Organizations created and Assets moved**, including descendants that move along with their parents.
* **Who loses or gains access.** People and groups whose access comes from a role on the holding Organization lose access to the Assets that move out of it, unless they have a role on the Asset itself, a global role, or a role on the destination. A new Organization starts with no roles: only the person who applies (as its Owner) and people with global roles see its Assets until roles are added. Applying asks for an explicit acknowledgment whenever anyone loses access.
* **Left out**, with the reason for each operation you are not allowed to perform. When creating Organizations is refused, or most of the moves are left out, the review says that someone with more permissions can apply it.
* **Staying where they are**: Assets whose records name no Organization, Assets waiting for the next discovery, and existing Organizations that keep their place (a suggestion never renames or re-parents an existing Organization).
* **Recalculation**: priority is recalculated in the background for the affected Organizations. Findings, history and deduplication stay with each Asset.

Nothing is deleted.

## Applying and undoing

Applying runs the reviewed [change plan](../change_plans/) exactly as you saw it, in batches, with progress on the page. If something changed since the review, the apply is refused and the page asks you to refresh the preview. If some Assets are still recalculating an earlier SLA or prioritization engine change, the apply is refused with the list.

**Undo** builds one inverse plan that reverses every plan the suggestion applied, for its own review on the change plan page. Undo asks whether to also restore the connector's placement setting (unticked by default). When the undo is applied, the Assets return to their Organizations, the suggestion is marked **Undone** and is not offered again, and, if you asked for it, the placement setting goes back to its previous value as long as nobody changed it since.

## Dismissing and snoozing

* **Dismiss** with a reason: the structure is intentional (optionally ask again in 90 days), the grouping is wrong, or it will be fixed at the source. A dismissed suggestion stays dismissed while the problem remains, until someone restores it.
* **Snooze** hides a suggestion for 30 days.

## Who sees a suggestion

* A connection's suggestions: people with the global permission to edit connectors, or to edit the Asset Hierarchy.
* An Organization's suggestions: people who can edit that Organization, or who can edit the Asset Hierarchy globally.

Group members, examples and names are limited to the Assets you can see. Applying also needs every operation of the plan to be allowed for you, as for any change plan.

## Measures

The top of the Hierarchy page shows two measures over the Assets you can see: how many are outside connector holding Organizations, and how many carry all five priority fields (business criticality, user records, revenue, external audience and internet accessibility). Onboarding is complete when both reach 100%. The same numbers are at `GET /api/v2/hierarchy/health/`.

## API

Everything on the page is available with an API token under `/api/v2/hierarchy/`:

| Method and path | Purpose |
| --- | --- |
| `GET suggestions/?tab=open\|applied\|dismissed` | The suggestions you can act on, most Assets affected first. |
| `GET suggestions/{id}/` | One suggestion, with its placement options, its plans and your current draft. |
| `GET suggestions/{id}/groups/` and `.../groups/{gid}/members/` | The groups and members under your draft, paged (`limit`, `offset`, `search`). |
| `POST suggestions/{id}/placement/` | Step 1: `{"value": "organizational_unit"}` (and `"tag_key"` for a tag option). |
| `GET` or `POST suggestions/{id}/discovery/` | Step 2: the discovery's state, or start one. |
| `POST suggestions/{id}/preview/` | Step 3: `{"edits": {...}}` builds your draft change plan and the review. |
| `POST suggestions/{id}/apply/` | `{"draft_id": 21, "acknowledge_access_loss": true}` applies your reviewed draft. |
| `POST suggestions/{id}/dismiss/`, `snooze/`, `restore/`, `undo/` | The lifecycle. `undo/` takes `{"restore_connector_setting": true}` to also put the placement setting back. |
| `POST health/check/`, `GET health/`, `GET` or `PATCH health/settings/` | Check now (`scope_type` and `scope_id`, or the whole instance), the measures, and the thresholds (superusers). |

Titles and evidence are returned as a `kind` with counts in `params` and `facts`; `fallback_title` carries an English title for scripts.
