---
title: "Bulk Editing Findings"
description: "Apply metadata changes, tags, notes, and review to many Findings at once in the DefectDojo Pro UI"
audience: pro
weight: 3
---

In the DefectDojo Pro UI, Findings can be edited in bulk from any Finding List — the **All Findings** page, or the Findings list within a Test.

## Selecting Findings for Bulk Edit

In any Findings table, use the checkboxes next to Findings to select them. Selecting one or more Findings reveals a **bulk-action bar** with the following controls:

* **Bulk Edit** — opens a single form where you apply metadata changes, tags, notes, and review requests to every selected Finding. This is the main consolidated surface (detailed below).
* **Risk Acceptance** — add the selected Findings to a new or existing **Full Risk Acceptance**.
* **Finding Group** — add the selected Findings to a new or existing **Finding Group**, or remove them from their group.
* **Merge** — merge the selected Findings into a single Finding.
* **Delete** — delete the selected Findings (with confirmation).

A control is disabled when the action can't apply to your current selection — see [Availability and skipped Findings](#availability-and-skipped-findings).

## Bulk Edit

The **Bulk Edit** button opens one form containing all of the field-level bulk actions. Set only the fields you want to change and leave the rest untouched, then click **Update Selected Findings** to apply. The available actions are:

* **Severity** — set the severity (Critical, High, Medium, Low, or Info).
* **Status** — apply one of Active, Verified, False Positive, Out of Scope, Mitigated, or Under Defect Review.
* **Date** — set the discovery date.
* **Planned Remediation Date** and **Planned Remediation Version**.
* **Simple Risk Acceptance** — Accept Risk or Unaccept Risk. Applied only to Findings whose Asset has Simple Risk Acceptance enabled; others are skipped.
* **Tags** — add tags to the selected Findings, or use the **Append / Replace** toggle to overwrite each Finding's entire tag set (**Append** adds the tags; **Replace** replaces all existing tags).
* **Replace Specific Tag** — swap one named tag for another (see below).
* **Note** — add a note, with an optional note type, to every selected Finding.
* **Review** — request or clear review on the selected Findings (see below).
* **Push to Jira** — queue the selected Findings to push to Jira. Shown only when the Jira integration is enabled.
* **Push to Connector** — dispatch the selected Findings to your configured connector. Shown only when that feature is enabled.
* **Move or Copy** — move the selected Findings to another Test, or copy them there and leave the originals in place (see below).

### Replace Specific Tag

**Replace Specific Tag** performs a targeted, non-destructive tag swap. Enter the tag to replace in **Existing Tag to Replace** and the replacement in **New Tag**. For each selected Finding that actually carries the old tag, DefectDojo removes that one tag and adds the new one — every other tag is preserved, and Findings that don't have the old tag are left unchanged.

This is different from the **Tags** field above: **Tags** either *adds* tags (Append) or *overwrites the whole tag set* (Replace), whereas **Replace Specific Tag** changes only the one named tag.

### Review

The **Review** action manages peer review across all selected Findings:

* **Request Review** — choose one or more **Reviewers** and enter a **Review Note** (required). Each selected Finding is set to *Under Review* (Active, not Verified), the chosen reviewers are assigned, a review-request note is added, and the reviewers are notified.
* **Clear Review** — enter a **Review Note** (required) to take the selected Findings out of the *Under Review* state and clear their assigned reviewers.

The reviewers you can choose from are the users with edit access to the selected Findings.

### Move or Copy

The **Move or Copy** section puts the selected Findings in another Test. The Test can be in the same Engagement, another Engagement, or another Asset. Use the **Move / Copy** toggle to choose:

* **Move** reassigns the Findings to the destination Test. Use it to bring Findings recorded across several Tests together in one, or to send the Findings of a scan report that covers several domains to the Asset each belongs to.
* **Copy** creates a copy of each Finding in the destination Test and leaves the original where it is.

Choose the destination with the **Destination Asset**, **Engagement**, and **Test** dropdowns. Each narrows the next, so the Engagement list only offers Engagements in the Asset you picked, and the Test list only Tests in that Engagement. There are two ways to finish:

* **Pick an existing Test.** The Findings are moved or copied into that Test.
* **Pick only an Asset** and tick **Create a matching engagement and test if none exists.** DefectDojo mirrors each Finding's current Engagement and Test into the destination Asset, matching an Engagement by **name** and a Test by **test type and title**. An existing match is reused; only what is missing is created, and a created Engagement inherits the source Engagement's dates, lead and status.

A selection can span several source Assets — each Finding is mirrored from its own Engagement and Test.

To move or copy a single Finding, use **Move or Copy Finding** in its ⋮ menu, or in the gear menu on the Finding's own page. It offers the same toggle and destination fields, and offers **Move** only if you can edit the Finding.

#### What a move changes

Moving a Finding also updates the things that belong to its old position in the hierarchy:

* Its **Endpoints** (or **Locations**) are re-homed onto the destination Asset, so they no longer point at the Asset it came from. An Endpoint shared with a Finding that stayed behind is left in place for that Finding.
* It is removed from its **Finding Group**, because a group belongs to a single Test.
* A **Risk Acceptance** belongs to a single Engagement. A Finding moved to another Test in the same Engagement stays accepted; a Finding moved to another Engagement is removed from its Risk Acceptance and becomes active again. Re-accept the risk in the destination Engagement if it still applies.
* Its **SLA** dates are recalculated against the destination Asset's SLA configuration, which may change its due date. Its priority and the Asset grades are recalculated when it changes Asset.
* **Deduplication** runs again in the destination's scope.
* A **note** is added to each moved Finding recording where it came from and where it went.
* A linked **Jira** issue stays linked to the moved Finding; the issue itself is not moved to another Jira project.

#### What a copy carries

A copy keeps the Finding's details, its notes (with their edit history; private notes stay private), its files (duplicated, with their original titles), its Endpoints or Locations (in the destination Asset), tags, reviewers, vulnerability IDs, CWEs, request/response pairs and custom field values. A note on the copy records which Finding it was copied from.

A copy is not linked to Jira and is not added to a Finding Group. A copy of a risk-accepted Finding joins the same Risk Acceptance when it stays in the same Engagement; a copy in another Engagement is not accepted.

An attachment whose stored file is missing is not copied, and the action says which one.

A copy is deduplicated like any new Finding. With deduplication enabled, a copy in the same Asset as its original is marked a duplicate of the original, so to bring Findings together in one Test, move them rather than copy them.

#### Permissions

Moving requires edit permission on each Finding; copying requires only view permission. Both require permission to add Findings to the destination Test, or to the destination Asset when **Create a matching engagement and test** is ticked, and to add Engagements and Tests there when a matching one has to be created. The destination is checked before anything is moved or copied, so a destination you may not use changes nothing. Findings you cannot move or copy are skipped and listed when the action finishes.

Bulk Edit itself needs edit permission on every selected Finding (see [Availability and skipped Findings](#availability-and-skipped-findings)), so to copy a Finding you can only view, use **Move or Copy Finding** in its ⋮ menu.

#### Automating a move or copy

The same actions are available in the public API for scripts and integrations:

* `POST /api/v2/findings/{id}/move/` and `POST /api/v2/findings/{id}/copy/` for a single Finding.
* `POST /api/v2/findings/bulk_move/` and `POST /api/v2/findings/bulk_copy/` for several, with the Finding IDs in `findings`.

The request body names the destination, either as an existing Test or as an Asset (`destination_product`) with `create_missing`:

```json
{ "findings": [101, 102], "destination_test": 42 }
```

```json
{ "destination_product": 7, "create_missing": true }
```

The response reports how many Findings were processed, why any were skipped (`skipped_messages`), what was created, and the IDs of the moved Findings or of the new copies (`finding_ids`). Authenticate with an API token, as for the rest of `/api/v2/`. The Pro UI calls an internal mirror of these actions under `/api/vue/`; always automate against the `/api/v2/` paths.

A bulk request takes up to 1,000 Finding IDs. An ID that does not exist is skipped and listed, like one you may not act on.

## Risk Acceptance, Finding Group, Merge, and Delete

The remaining bulk-action buttons open their own dialogs:

* **Risk Acceptance** — create a new **Full Risk Acceptance** to govern the selected Findings, or add them to an existing one.
* **Finding Group** — create a new **Finding Group**, add the Findings to an existing group, or remove them from their current group. Finding Groups can only be created within a single **Test** — Findings from different Tests, Engagements, or Assets cannot share a group.
* **Merge** — merge multiple selected Findings (all from the same Asset) into one.
* **Delete** — delete the selected Findings after confirming in a popup.

## Availability and skipped Findings

Each bulk action is available only when it can apply to your whole selection:

* **Bulk Edit**, tags, and review require every selected Finding to be editable by you.
* **Risk Acceptance** is unavailable if any selected Finding is not editable, is already risk-accepted, or is a duplicate.
* **Finding Group** creation requires every Finding to be editable, ungrouped, and in the same Test.
* **Merge** requires more than one Finding, all editable and from the same Asset.
* **Delete** requires every selected Finding to be deletable by you.

When an action runs but some Findings can't be updated — for example they aren't editable by you, are already under review, or belong to an Asset without Simple Risk Acceptance enabled — DefectDojo applies the change to the rest and shows a **"One or More Findings Skipped"** warning explaining why each was skipped.
