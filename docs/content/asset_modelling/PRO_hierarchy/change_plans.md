---
title: "Change plans: review every change before it happens"
description: "Build a plan of hierarchy changes from operations or a CSV file, review the full diff, then apply it as one change and undo it if needed"
weight: 2
audience: pro
---

Reorganizing the hierarchy touches many Assets at once: moving an Asset to another Organization takes its subtree along, removes parent links that would cross Organizations, and recalculates priority for both Organizations. A change plan lets you see every one of those effects before anything is written.

A change plan is a list of operations. Creating one writes nothing to your Assets: DefectDojo resolves every name to an ID, checks every operation against the hierarchy rules and your permissions, and records a **diff** of exactly what applying it would change. You review the diff (in the UI, through the API, or as a CSV file in a spreadsheet), then apply the whole plan, and you can undo it later with a new plan that reverses it.

## Turning change plans on

Change plans are released behind the **Change Plans** feature flag, which is off by default and requires the Asset Hierarchy. A superuser turns it on from **Settings > Feature Flags** (see [Feature Flags](/admin/feature_flags/pro__feature_flags/)). Until then the Plans page is hidden, the bulk update form on the Assets list works as before, and the change plan API answers with a `403`.

## What a plan can do

| Operation | Fields | Effect |
| --- | --- | --- |
| `create_organization` | `name`, `org_type` (default `custom`), `parent` | Create an Organization, optionally nested under another of the same type. |
| `set_organization` | `asset`, `organization`, `move_children` (default `true`) | Move an Asset to another Organization. Its subtree moves along unless `move_children` is `false`. |
| `set_parent` | `asset`, `parent` | Place an Asset under a parent. `null` removes its parent. |
| `set_fields` | `asset`, `fields` | Set any of `business_criticality`, `user_records`, `revenue`, `external_audience`, `internet_accessible`, `prioritization_engine`, `sla_configuration` (by name or ID), `asset_type` (a type code), `technical_contact`, `team_manager`, `product_manager`, and add or remove tags with `tags_add` and `tags_remove`. |
| `add_membership`, `remove_membership` | `asset`, `organization` | Add or remove a secondary Organization membership. Adding one requires non-exclusive Organization memberships to be enabled. |

Plans never delete anything and never touch Engagements.

The order of the operations in the list does not matter. A plan is always applied in the same order: Organizations are created, Assets move to their new Organization, parents are set, fields are set, and memberships change last. Because the move comes first, a new parent only has to be in the Asset's new Organization, the same rule as the [bulk update](../asset_hierarchy/#bulk-updates-through-the-api).

### Naming Assets and Organizations

Use IDs when you know them: `12` or `{"id": 12}`. When you do not, match by name: `{"match": {"name": "payments-api"}}`. Users match by username: `{"match": {"username": "kim"}}`. An Organization created by the same plan is referenced by its name.

A name is matched exactly first, and then ignoring case. If two Assets match a name only when case is ignored, the operation is reported as ambiguous and you need to use the ID. Names are always read as text, so an Asset named after a cloud account number keeps its leading zeros. You can only name Assets and Organizations you can see; anything else is reported as not found.

## Creating a plan through the API

```bash
curl -X POST "https://defectdojo.example.com/api/v2/hierarchy/plans/" \
  -H "Authorization: Token <your API token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Move payments under the new team",
    "ops": [
      {"op": "create_organization", "name": "Payments", "org_type": "team"},
      {"op": "set_organization", "asset": {"match": {"name": "payments-api"}}, "organization": {"match": {"name": "Payments"}}},
      {"op": "set_parent", "asset": 41, "parent": {"match": {"name": "payments-api"}}},
      {"op": "set_fields", "asset": 41, "fields": {"business_criticality": "high", "tags_add": ["pci"]}}
    ]
  }'
```

The response is the new plan, with status `draft`, its operations (with every name resolved to an ID), and its diff. Nothing has changed yet.

### Reading the diff

| Key | What it lists |
| --- | --- |
| `organizations_created` | The Organizations the plan creates. |
| `changes` | One entry per Asset and field: `asset_id`, `asset_name`, `field`, `from`, `to`, and readable `from_label` and `to_label`. A descendant that moves along with its ancestor carries `via_asset_id` and `via_asset_name`. |
| `parent_links_removed` | The parent links a move removes because they would cross Organizations. |
| `memberships` | Secondary memberships added or removed, and memberships that become the primary one because an Asset moves into that Organization. |
| `recalculation` | The Organizations whose Finding priority is recalculated, and how many Assets are re-scored or have their SLA recalculated. |
| `errors` | Every problem, per operation, with a `code` and a `message`. |
| `summary` | Counts of all of the above. |

An operation you are not allowed to perform is listed in `errors` with the code `forbidden`, and its effects are still shown so a reviewer can see what it would do. A plan with any error cannot be applied: fix the operations and create a new plan.

## The CSV format

A CSV file is a second way to build a plan, and the diff can be downloaded as CSV for review in a spreadsheet.

Download the current state of every Asset you can see with `GET /api/v2/hierarchy/assets.csv/` (add `?organization=<id>`, repeated, to limit it to some Organizations), or with **Download Current State as CSV** on the Plans page. The file has one row per Asset and these columns:

| Column | Content |
| --- | --- |
| `asset_id`, `asset_name` | Which Asset the row changes. The ID wins when both are filled. |
| `organization` | The Organization name to move the Asset to. |
| `parent_id`, `parent_name` | The new parent. The ID wins when both are filled. Write `null` in `parent_id` to remove the parent. |
| `asset_type` | A type code or label. |
| `business_criticality`, `user_records`, `revenue`, `external_audience`, `internet_accessible` | The five priority inputs. The last two take `true` or `false`. |
| `prioritization_engine`, `sla_configuration` | Names. |
| `technical_contact`, `team_manager`, `product_manager` | Usernames. |
| `tags_add`, `tags_remove` | Comma-separated tags to add or remove. Empty on export. |

When you upload the file:

* **An empty cell changes nothing, and a missing row changes nothing.** Delete the rows you are not changing, or leave them as they are.
* `null` clears a value: the parent, the type, a contact, the criticality, user records or revenue.
* A file exported and uploaded unchanged produces an empty plan. Only the operations that change something are kept in the plan.
* Organizations are not created from a CSV file. Create them first, or use the JSON operations.

Upload the file to the same endpoint as multipart form data, or use **Import CSV** on the Plans page:

```bash
curl -X POST "https://defectdojo.example.com/api/v2/hierarchy/plans/" \
  -H "Authorization: Token <your API token>" \
  -F "name=Quarterly re-org" \
  -F "file=@assets.csv"
```

`GET /api/v2/hierarchy/plans/{id}/export.csv/` downloads a plan's diff as CSV, one row per Organization created, field change, descendant carried along, parent link removed, membership change, recalculated Organization and error.

**Spreadsheet safety.** Asset and Organization names often come from scanners and repositories, so a name could be crafted to run as a spreadsheet formula. Every exported cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return (other than a plain number) is prefixed with an apostrophe, and the upload removes that prefix again, so a round trip does not change the value.

## Reviewing plans in the UI

**Change Plans** appears under the Asset Hierarchy in the navigation. The list shows every plan you can see with its status and counts. A plan's page shows the diff grouped by kind (Organizations created, Assets moved with their subtrees, parent links removed, fields changed, memberships, recalculation, errors), each with its count, and a filter box that narrows every group. From there **Export as CSV** downloads the diff, **Run Plan** applies a draft plan, and **Undo** reverses an applied one.

The bulk update form on the Assets list uses the same review: when change plans are on, submitting the form first shows the diff of what it would change, and nothing is written until you choose **Submit**.

## Applying a plan

`POST /api/v2/hierarchy/plans/{id}/apply/` (or **Run Plan** on the plan's page) applies a draft plan.

1. **The plan is checked again first.** DefectDojo runs the dry run again, as the person applying it. If any operation is refused now (for example, a permission was removed), the request fails with a `400` listing the errors and nothing is written. If any value recorded in the diff no longer matches the current state, the plan is marked **stale** and the request fails with a `409` (see below).
2. **The plan is then applied in the background.** The plan's status becomes `applying`, and the response is a `202`. Check the plan until its status is `applied` or `failed`. The same check runs again when the background work starts, while holding the hierarchy lock, so a change made in between is caught too.
3. **Large plans are written in batches.** Organizations are created first; then the moves, in batches of up to 500 Assets that never split one tree; then all the parent changes together, so the hierarchy is checked as a whole and never passes through an invalid state; then the fields, 500 Assets at a time; then the memberships. Every batch that touches the hierarchy takes the hierarchy lock once.
4. **The audit log groups the whole plan.** Every change a plan makes is recorded under one audit context that carries the plan's ID.
5. **Priority is recalculated once** for every affected Organization after the last batch, and owners whose Asset lost a parent link receive one notification.

**If a batch fails**, that batch is rolled back, nothing after it runs, and the plan is marked `failed`. The plan's `result` lists the operations that were applied, the ones in the failed batch, the ones that were never attempted, and the error. Priority is still recalculated for what was applied, and **Undo** reverses exactly the applied part.

A plan holds at most 10,000 operations, and a CSV upload at most 10,000 rows. That covers re-homing thousands of cloud accounts and setting their fields in one plan; split larger reorganizations into several plans.

## Stale plans

A plan records the value every field had when the diff was computed. If something changes before the plan is applied (someone edits an Asset, a new child appears under an Asset the plan moves, or an Organization with a planned name is created), applying it would no longer do what was reviewed. The plan is marked `stale` and the response lists every drifted entry with the recorded value and the current one.

A stale plan is never applied. Create the plan again (on the plan's page, **Re-run Dry Run** does this from the same operations) and review the new diff.

## Undo

`POST /api/v2/hierarchy/plans/{id}/undo/` (or **Undo** on the plan's page) works on an applied plan and on the applied part of a failed one. It does not change anything by itself: it creates a **new draft plan** that reverses the original, so the undo gets its own review before you apply it.

* Every Asset that changed Organization, including the descendants that moved along, moves back on its own.
* Every parent link the plan removed or changed is restored.
* Every field, tag and membership returns to its recorded value.
* Organizations the plan created are left in place, since plans never delete anything. The undo plan's notes list them.

## Permissions and visibility

* Anyone who can edit at least one Asset can create a plan. The diff marks the operations they are not allowed to perform.
* Applying requires every operation to be allowed for the person applying it, at the time they apply it. The permissions are the same as making each change on its own: edit permission on each Asset and on each new parent, permission to add Assets to a destination Organization, permission to create Organizations for `create_organization`, and edit permission on an Organization to change its memberships. Moving an Asset with its subtree needs edit permission on every Asset in the subtree.
* A plan is visible to the person who created it and the person who applied it, and to superusers and global owners.

## Dry runs on the bulk update

`POST /api/v2/assets/bulk_update/` accepts `"dry_run": true`. The request is checked exactly as a change plan would be, nothing is written, and the response is the same diff, including every Asset that would be refused. See [Bulk updates through the API](../asset_hierarchy/#bulk-updates-through-the-api).
