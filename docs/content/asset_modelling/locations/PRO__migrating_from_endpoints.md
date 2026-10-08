---
title: "Migrating from Endpoints"
description: "What happens when you migrate existing Endpoint data to Locations"
audience: pro
weight: 3
---

When you enable Locations on an existing DefectDojo Pro instance, the data already stored on your Findings needs to be carried forward into the new Locations model. This page describes the migration suite, what each part preserves, and how the legacy Endpoint API behaves once the migration has run.

Note that migration is **one-way**. There is no automated rollback path that re-creates Endpoints from Locations.

> **Endpoints are deprecated.** As of **3.2.201**, Endpoints are deprecated in favour of Locations. The Endpoints pages go away in **3.6.0 (December 2026)**. The read-only Endpoint API (`/api/v2/endpoints/`, `/api/v2/endpoint_status/`) stays until its own deprecation announcement. The Endpoints menu, the Endpoint list pages, and a Finding's endpoint tables carry a deprecation banner. Enable Locations and run the migration below before 3.6.0.

## Running the migration from the Feature Flags page

Enabling Locations only changes behaviour for *new* imports; your existing history is carried forward by a **data-migration suite** that appears under the Locations row on the **Settings > Feature Flags** page once the feature is on. Each item is run on demand by a superuser, shows live progress and an ETA, and is safe to re-run (every step is idempotent).

When a backfill finishes it reports how many source objects it processed and how many distinct **Locations** those objects resolved to. The two numbers differ by design: several source objects can share one Location (many Endpoints normalising to the same URL, or many Findings sharing one component), so the Location count is normally lower than the object count. If any individual object could not be migrated it is skipped rather than aborting the run, and the number skipped is shown alongside the result.

A running item shows a **Cancel** button. Cancelling stops the run at the next batch boundary, so it is not instant: the current batch finishes and commits first. A cancelled run keeps everything it had already migrated, is reported as **Canceled** with its partial counts, and because every step is idempotent, running the same item again resumes from where it stopped and converges on the same result as an uninterrupted run. Cancel is also the recovery path when a run's worker is lost: a run that stops reporting progress is marked failed on its own so the item becomes runnable again, and forcing a cancel releases a run that is otherwise wedged.

The suite has four items, because a Finding can carry three independent kinds of location:

1. **Endpoints to Locations backfill** — turns existing `Endpoint` rows into **URL Locations** (detailed below).
2. **Components to Dependencies backfill** — turns each Finding's `component_name` / `component_version` into a **Dependency Location**.
3. **Findings to Code Locations backfill** — turns each Finding's `file_path` / `line` into a **[Source Code Location](/asset_modelling/locations/pro__source_code_locations/)**.
4. **Identity rehash** — recomputes the deduplication identity for scan types whose identity digest changed when the flag flipped, so future reimports match the migrated Locations instead of closing and re-opening findings.

The three backfills are independent and can run in any order. The **Identity rehash stays locked until all three backfills have completed**, because the identity it recomputes folds in every location type; running it against a half-migrated database would bake an incomplete identity. Only one item runs at a time.

Each backfill is also available as a management command for scripted or air-gapped runs:

```bash
python manage.py migrate_endpoints_to_locations
python manage.py migrate_components_to_dependencies
python manage.py migrate_findings_to_code_locations
```

## Marking an item complete

Each suite item carries a durable **completed** marker, so the page can state that a migration does not need to be run again. It is set two ways:

- **Automatically**, when a run started here finishes successfully.
- **Manually**, with **Mark as Completed**, for a migration that finished another way: a management command from the list above, a database restore, or a fresh instance that never had Endpoints to carry forward.

A completed item shows a **Completed** badge with who marked it and when, its **Run** button becomes **Run Again** (the step stays idempotent, so re-running is always safe), and **Mark as Not Completed** clears the marker.

Marking the three backfills complete also satisfies the identity rehash's precondition, so a manual mark unlocks the rehash exactly as a real run does. Mark a backfill by hand only when its data really is migrated: the UI asks you to confirm, because unlocking the rehash before the backfill has run would let it recompute identities against a half-migrated database.

## What the Endpoints Backfill Does

For every existing Endpoint, the endpoints backfill will:

1. **Creates a URL Location** (or re-uses an existing one) using the Endpoint's `protocol`, `userinfo`, `host`, `port`, `path`, `query`, and `fragment` fields. The new URL is automatically attached to a parent `Location` object.
2. **Carries over tags.** Every tag on the Endpoint is added to the Location's tag set.
3. **Carries over metadata.** Each `DojoMeta` row attached to the Endpoint is re-pointed at the new Location.
4. **Creates a `LocationProductReference`** so the URL appears under the correct Asset.
5. **Creates a `LocationFindingReference` for every `Endpoint_Status`**:

   | Endpoint_Status flag | Resulting Location status |
   | --- | --- |
   | `risk_accepted=True` | **Risk Accepted** |
   | `false_positive=True` | **False Positive** |
   | `out_of_scope=True` | **Out of Scope** |
   | `mitigated=True` | **Mitigated** |
   | (none of the above) | **Active** |

   The mapping is order-sensitive: the *first* matching flag wins. This intentionally collapses the old multi-flag combinations down to the single canonical status that Locations use.


## What the Dependency and Code Backfills Do

The other two backfills read scalar fields that already live on your Findings, so they need no scan data you do not already have:

- **Components to Dependencies** builds a **Dependency Location** from each Finding's `component_name` and `component_version`, and links it with a `LocationFindingReference` (and a `LocationProductReference` so it also appears under the Asset). Findings with no component data are skipped. This is in addition to Dependencies created by uploading SBOMs (see [Working with SBOMs](../pro__working_with_sboms)) or re-running scans with parsers that emit dependency data.
- **Findings to Code Locations** builds a **Source Code Location** from each Finding's `file_path` and `line` (the same coordinate imports synthesize for static findings), and links it the same way. Findings with no `file_path` are skipped.

Both create Locations on their identity hash and upsert their references, so they create nothing new on a re-run.

## What the Migration Does Not Do

- It does **not** delete the original Endpoint or Endpoint_Status rows. They remain in the database to back the read-only legacy API. They are not used by the new UI or by imports after the feature is enabled, but they still count toward your license. See [Removing the Legacy Endpoint Rows](#removing-the-legacy-endpoint-rows).
- It does **not** modify your Findings. The backfills only *read* the `component_*` and `file_path`/`line` fields; they add Locations and references alongside, leaving the Finding rows untouched.
- It does **not** convert cloud resources into Cloud Resource Locations. Endpoints often recorded things that are not web addresses at all, such as container references and AWS ARNs. Every one of those migrates as a URL Location, the same as any other Endpoint. DefectDojo cannot reliably tell a resource identifier stuffed into a host field from a genuine hostname. Guessing wrong can change a Finding's identity. To model those resources properly, import the account through a cloud connector. The connector reads the provider's own resource identifier. It creates a Cloud Resource Location from that identifier.

## Removing the Legacy Endpoint Rows

The migration leaves the original `Endpoint` and `Endpoint_Status` rows in place, and your license still counts them: a **Findings + Endpoints** license counts Endpoints, and a **Total Findings** license counts Endpoint Statuses. Once their data is in Locations, these rows only take up license capacity, so you can delete them.

DefectDojo deletes a legacy row only when its data reached Locations. Everything else stays, and DefectDojo shows the reason next to it.

- An **Endpoint Status** counts as migrated when its Endpoint's URL Location exists and has a Location finding reference for the same Finding.
- An **Endpoint** counts as migrated when its URL Location exists, is linked to the Endpoint's Asset, and every one of its Endpoint Statuses is migrated.

Rows that are not migrated show one of these reasons:

| Migration Status | Meaning |
| --- | --- |
| **No Location** | No URL Location matches the Endpoint. It was probably added after the backfill ran. Run the **Endpoints to Locations backfill** again, then check it again. |
| **No Asset Reference** | The URL Location exists but is not linked to the Endpoint's Asset. |
| **No Finding Reference** | At least one Endpoint Status has no matching Location finding reference. |
| **Invalid URL** | The Endpoint's fields do not form a valid URL, so the backfill skipped it. |

Deleting legacy rows cannot be undone. It also removes the records that the Endpoint Status audit page and the read-only legacy API read from. Take a database backup first.

### From the License Page

Only superusers can delete legacy rows, and only while Locations are enabled. Other users who can see the tables get them read-only.

1. Open **Settings > License & Support > View License**.
2. In **Audit Usage**, click **View Endpoints** (on a Findings + Endpoints license) or **View Endpoint Statuses** (on a Total Findings license).
   - **View Endpoints** opens the **Legacy Endpoints** page. Each row shows its Asset, its Endpoint Status counts and its **Migration Status**.
   - **View Endpoint Statuses** opens the **Endpoint Statuses** page, which has the same **Migration Status** column.
3. To delete one row, open its menu and choose **Delete Endpoint** or **Delete Endpoint Status**. Only migrated rows have this option. Deleting an Endpoint also deletes its Endpoint Statuses.
4. To delete several rows, tick their checkboxes and click **Delete**. Migrated rows are deleted and the others are kept.
5. To delete every migrated row, click **Delete All Migrated**. The delete runs in the background, so it works on any number of rows. The button shows the run's progress, including after you leave the page and come back. If the page is open when the run finishes, DefectDojo reports how many rows it deleted and how many it kept. The table and the License page counts reflect the result either way.

   If a run stops partway, for example because Locations was disabled, the rows it already deleted stay deleted. Click **Delete All Migrated** again to finish. Each table runs one delete at a time: clicking the button while another superuser's run is going shows that run's progress instead of starting a second one.

The usage figures on the License page update as soon as the delete finishes.

### From the Command Line

Two management commands do the same cleanup for scripted or air-gapped installs. Both are a dry run by default: they print what they would delete and why each kept row stays, then roll back.

```bash
python manage.py delete_legacy_endpoints
python manage.py delete_legacy_endpoint_statuses
```

Add `--apply` to delete. The command asks you to confirm before it deletes anything; add `--force` to skip the prompt.

`delete_legacy_endpoints` removes migrated Endpoints together with their Endpoint Statuses. `delete_legacy_endpoint_statuses` removes only migrated Endpoint Statuses and leaves the Endpoints in place.

## Endpoint API After Migration

Once Locations is enabled, the legacy Endpoint API enters a **read-compatibility** mode designed to keep existing automations working without code changes — but only for read traffic.

### What still works

- `GET /api/v2/endpoints/` — Returns rows that *look like* Endpoints but are actually projected from `LocationProductReference` rows joined to URL Locations. The familiar fields (`protocol`, `host`, `port`, `path`, `query`, `fragment`, `tags`, `product`, `active_finding_count`) are all present.
- `GET /api/v2/endpoints/{id}/` — Single-Endpoint retrieval works the same way. The `id` is the original Endpoint ID and is preserved through the migration via the Asset Reference mapping.
- `GET /api/v2/endpoint_status/` and `GET /api/v2/endpoint_status/{id}/` — Returns rows projected from `LocationFindingReference`. The legacy `mitigated`, `false_positive`, `out_of_scope`, and `risk_accepted` boolean fields are reconstructed.
- Filtering by `protocol`, `host`, `port`, `path`, `query`, `fragment`, `product`, and `tag(s)` continues to work.
- The `generate_report` action on individual Endpoints continues to work.

### What returns 403

- `POST`, `PUT`, `PATCH`, and `DELETE` on `/api/v2/endpoints/` and `/api/v2/endpoint_status/` all return `HTTP 403` with the body:

  > Writes to this endpoint are deprecated when V3_FEATURE_LOCATIONS is enabled

  Clients that write Endpoint data must move to the new Reference endpoints (`POST /api/v2/location_findings/`, `POST /api/v2/location_products/`) and to the URL endpoint (`POST /api/v2/urls/`).

### Behavioural Differences to Watch For

A few things behave differently from the original Endpoint API:

- **Single status instead of flags.** Locations have one status at a time. If your code relied on a Finding being *both* `mitigated=True` *and* `false_positive=True` simultaneously on an Endpoint_Status, that is no longer representable — the migration picks the highest-priority flag (the order shown in the table above).
- **`endpoint` field on Endpoint_Status.** The legacy `endpoint` field is reconstructed by looking up the matching Asset Reference. In rare cases where a Finding's Asset no longer matches its Location's Asset references, this field may be null.
- **`mitigated` returned a date before 3.2.400.** On releases before 3.2.400 the `mitigated` field of `/api/v2/endpoint_status/` returned the record's creation date instead of a boolean. Because a date string is truthy, `mitigated_time` and `mitigated_by` answered as though every status was mitigated. From 3.2.400 the field is a boolean that is true only when the Location status is `Mitigated`. If you poll for mitigated statuses, upgrade before you trust this field.
- **Pagination and ordering.** Available ordering fields on the read-compat shim are `host`, `product`, `id`, and `active_finding_count`. If your client orders by another field, switch to one of these or move to the new Locations endpoints.

### If a Route Returns 410

Any remaining `/api/v2/` path that reaches the old Endpoint data answers `HTTP 410 Gone` rather than a server error. The body is machine-readable, so your automation can branch on `code` instead of parsing the message:

```json
{
  "code": "endpoint_api_sunset",
  "message": "The Endpoint API is not available on instances with Locations enabled. Reads are served from Locations; writes are not available.",
  "replacement": "/api/v2/location/",
  "docs": "https://docs.defectdojo.com/asset_modelling/locations/pro__migrating_from_endpoints/"
}
```

If you hit this on a read you expected to work, send us the request path. That response means we have a route left to convert, and it is a bug on our side, not on yours.

## Tags and Metadata

Tags applied to Endpoints become tags on the Location object (not on the URL subtype). Tag-based filters in the legacy API continue to match.

Endpoint metadata is re-pointed at the Location during migration, scoped to the Asset the Endpoint belonged to. It is shown in the **Custom Fields** card on the Location page (open a Location from any list), the same card the Endpoint page used, with the Asset each field belongs to shown under its value. Fields can be added, edited and deleted there. Existing automations that read metadata via `/api/v2/endpoint_meta/` should continue to work; new metadata should be written through the Location endpoints.

The Custom Fields feature flag does not change Location metadata. That feature covers Findings, Assets, Organizations, Engagements, Tests and Risk Acceptances; a Location's fields stay the migrated metadata, shown in the Custom Fields card whether the flag is on or off.
