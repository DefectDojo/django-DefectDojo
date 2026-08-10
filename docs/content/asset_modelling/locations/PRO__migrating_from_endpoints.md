---
title: "Migrating from Endpoints"
description: "What happens when you migrate existing Endpoint data to Locations"
audience: pro
weight: 3
---

When you enable Locations on an existing DefectDojo Pro instance, the data already stored as Endpoints needs to be carried forward into the new Locations model. This page describes migration, what it preserves, and how the legacy Endpoint API behaves once the migration has run.

Note that migration is **one-way**. There is no automated rollback path that re-creates Endpoints from Locations.

## What the Migration Does

For every existing Endpoint, migration will:

1. **Creates a URL Location** (or re-uses an existing one) using the Endpoint's `protocol`, `userinfo`, `host`, `port`, `path`, `query`, and `fragment` fields. The new URL is automatically attached to a parent `Location` object.
2. **Carries over tags.** Every tag on the Endpoint is added to the Location's tag set.
3. **Carries over metadata.** Each `DojoMeta` row attached to the Endpoint is re-pointed at the new Location.
4. **Creates a `LocationProductReference`** so the URL appears under the correct Asset (Product).
5. **Creates a `LocationFindingReference` for every `Endpoint_Status`**:

   | Endpoint_Status flag | Resulting Location status |
   | --- | --- |
   | `risk_accepted=True` | **Risk Accepted** |
   | `false_positive=True` | **False Positive** |
   | `out_of_scope=True` | **Out of Scope** |
   | `mitigated=True` | **Mitigated** |
   | (none of the above) | **Active** |

   The mapping is order-sensitive: the *first* matching flag wins. This intentionally collapses the old multi-flag combinations down to the single canonical status that Locations use.


## What the Migration Does Not Do

- It does **not** create Dependency Locations. SBOM and library data has never existed as Endpoints, so there is nothing for the migration to convert. To populate Dependencies, upload SBOMs (see [Working with SBOMs](../pro__working_with_sboms)) or re-run scans with parsers that emit dependency data.
- It does **not** delete the original Endpoint or Endpoint_Status rows. They remain in the database to back the read-only legacy API. They are not used by the new UI or by imports after the feature is enabled.

## Endpoint API After Migration

Once Locations is enabled, the legacy Endpoint API enters a **read-compatibility** mode designed to keep existing automations working without code changes — but only for read traffic.

### What still works

- `GET /api/v2/endpoints/` — Returns rows that *look like* Endpoints but are actually projected from Location Product Reference rows joined to URL Locations. The familiar fields (`protocol`, `host`, `port`, `path`, `query`, `fragment`, `tags`, `product`, `active_finding_count`) are all present.
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
- **Pagination and ordering.** Available ordering fields on the read-compat shim are `host`, `product`, `id`, and `active_finding_count`. If your client orders by another field, switch to one of these or move to the new Locations endpoints.

## Tags and Metadata

Tags applied to Endpoints become tags on the Location object (not on the URL subtype). Tag-based filters in the legacy API continue to match.

Endpoint metadata is re-pointed at the Location during migration. Existing automations that read metadata via `/api/v2/endpoint_meta/` should continue to work; new metadata should be written through the Location endpoints.
