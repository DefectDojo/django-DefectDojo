---
title: "Archive"
description: "Archive Organizations, Assets, Engagements, Tests and Findings instead of deleting them, restore them during the retention period, and remove old Findings automatically with Triage Engine rules"
audience: pro
weight: 8
---

**Archive** removes an Organization, Asset, Engagement, Test or Finding from view without deleting it. Archived data stays in the database for a fixed retention period, and you can restore it at any point during that period. When the period ends, DefectDojo deletes the archived data permanently, together with its audit history.

Archive is turned on from the **Archive** row on the **Settings > Feature Flags** page. Turning the flag off stops new archives but does not bring archived data back, and archived data is still deleted on its scheduled date.

## What archiving does

When you archive an object, DefectDojo archives it and everything under it:

- Archiving an Organization archives its Assets, their Engagements, Tests and Findings.
- Archiving an Asset archives its Engagements, Tests and Findings.
- Archiving an Engagement archives its Tests and Findings.
- Archiving a Test archives its Findings.

The records attached to those objects are archived with them, for example endpoint and location statuses, vulnerability IDs, Jira links, deduplication signatures, and memberships.

Archived data does not appear in:

- list and detail pages, search, dashboards, metrics and reports
- the API (`/api/v2/` returns 404 for an archived object)
- deduplication and reimport: a new scan never matches an archived Finding, and you cannot import into an archived Engagement or Test
- Triage Engine rules: archived Findings never enter a rule run

The only place archived data appears is the **Archived** page.

If a Finding you archive is the original of a duplicate cluster, DefectDojo promotes one of the remaining duplicates to be the new original, the same way it does when you delete a Finding. Restoring the archived Finding does not relink the cluster.

## The retention period

Archived data is kept for 6 months by default. Self-hosted installs can change this with the `DD_ARCHIVE_RETENTION_MONTHS` environment variable (minimum 1). The period cannot be shortened for data that is already archived.

Every archive has a purge date. A daily task permanently deletes archives whose purge date has passed. This removes the archived objects, everything under them, and their audit history. Nothing remains that refers to them, and they cannot be recovered.

Because of this, DefectDojo asks you to confirm the retention period every time you archive.

## Archived data and your license

Archived data counts toward your license until its purge date. Archived Findings, Endpoints and Assets are included in license usage exactly like live ones, and archived rows still take up database storage. Archiving does not free license capacity. To free it, delete the data or wait until it is purged.

## Archiving an object

You need permission to delete an object to archive it.

1. Open the gear menu on the object, either in a list or on its detail page, and choose **Archive**.
2. The dialog shows how many objects will be archived and the date they will be permanently deleted.
3. Enter a reason. It is recorded with the archive and shown on the **Archived** page and in the audit log.
4. Tick the box to confirm you understand the data is deleted after the retention period, then choose **Archive**.

The object disappears straight away. Everything under it is archived in the background, so a large Asset or Organization can take a few minutes to finish. Until it does, its archive shows **Archiving** on the **Archived** page.

To archive several Findings at once, select them in a Findings list and choose **Archive** from the bulk actions. The selected Findings form one archive and are restored together.

## Restoring archived data

The **Archived** page lists every archive you have permission to restore. For each one it shows what was archived, who archived it and why, when, how it was archived (user interface, API or Triage Engine rule) and its purge date.

Expand an archive to browse the objects it holds. Choose **Unarchive** from its menu to restore it. Restoring brings back the whole tree that was archived together. It runs in the background: the archive shows **Restoring** until everything is back, then leaves the list. An archive that is still archiving or restoring cannot be restored until that finishes.

An object archived on its own before its parent was archived keeps its own archive. Restoring the parent does not restore it, so restore it separately from the **Archived** page.

## Removing old Findings with Triage Engine rules

Triage Engine has two actions for retention, available while Archive is turned on:

- **Archive Findings** archives the Findings that reach it, with the reason you set. Each rule run makes one archive holding every Finding it archived, and restoring that archive brings them all back.
- **Delete Findings Permanently** deletes each Finding that reaches it. This cannot be undone.

Both actions require you to tick a confirmation in the node before the rule can be saved.

A typical retention rule runs on a schedule and archives Findings older than a set age:

1. **On a Schedule** trigger, for example daily.
2. **If / Filter**: `Date` **is more than N days ago**, with N set to `365`.
3. **Archive Findings**, with a reason such as "Retention: older than 365 days".

## API

Each of `/api/v2/product_types/`, `/api/v2/products/`, `/api/v2/engagements/`, `/api/v2/tests/` and `/api/v2/findings/` has two actions for a single object:

- `GET {id}/archive_preview/` returns what an archive would hide and the purge date.
- `POST {id}/archive/` archives the object. The body is `{"reason": "...", "acknowledge_retention": true}`. Without `acknowledge_retention: true` the request is refused with `400` and `"code": "acknowledge_required"`. It returns `202` with the archive record: the object is hidden already, and the record's `state` is `archiving` until everything under it is archived, then `archived`.

Archives are listed at `/api/v2/archive/records/`. `GET /api/v2/archive/records/{id}/tree/?model=finding` browses an archive's contents, and `POST /api/v2/archive/records/{id}/unarchive/` starts restoring it and returns `202` with the record in state `restoring`. The record is deleted once everything is back. Restoring an archive that is still archiving or restoring is refused with `400` and `"code": "archive_busy"`.

A new Asset or Organization cannot reuse the name of an archived one. Restore the archived one or choose another name.
