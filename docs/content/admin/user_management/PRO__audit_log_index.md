---
title: "Audit Logging"
description: "Every create, update, and delete action DefectDojo records in its audit log, plus what is captured and how to configure retention."
draft: false
weight: 4
---

DefectDojo records an audit trail of changes to its data.  Every tracked object automatically
records **create**, **update**, and **delete** events, and relationship
(many-to-many) tables record **add** and **remove** events.

## How it works

Audit tracking is driven by database triggers registered per model. For each
tracked object, three event types can fire:

| Event type    | When it fires                                                                 | Action     |
| ------------- | ----------------------------------------------------------------------------- | ---------- |
| `InsertEvent` | A new record is created                                                        | **Create** |
| `UpdateEvent` | A record changes — only when a real field value actually changes               | **Update** |
| `DeleteEvent` | A record is deleted                                                            | **Delete** |

Many-to-many relationship tables (tags, reviewers, firewall IP ranges) track
only **add** (`InsertEvent`) and **remove** (`DeleteEvent`) — there is no
"update" for a relationship row.

### What is captured with every event

- **Who** — the acting user, taken from the request context.
- **When** — a timestamp.
- **Source IP** — the remote address, honoring `X-Forwarded-For` proxy chains.
- **Before/after snapshot** — the full field values of the record.
- **Context / label** — groups events originating from the same request. The
  label `initial_backfill` marks historical records imported when tracking was
  first enabled.

Events produced by background jobs are stitched back to the
originating request's context, so an action completed asynchronously is still
attributed to the user who triggered it.

## Core (Open Source) — tracked actions

| Object                         | Create | Update | Delete | Notes                                          |
| ------------------------------ | :----: | :----: | :----: | ---------------------------------------------- |
| User                           |   ✅   |   ✅   |   ✅   | `password` excluded from snapshots             |
| Organization                   |   ✅   |   ✅   |   ✅   |                                                |
| Asset                        |   ✅   |   ✅   |   ✅   |                                                |
| Engagement                     |   ✅   |   ✅   |   ✅   |                                                |
| Test                           |   ✅   |   ✅   |   ✅   |                                                |
| Finding                        |   ✅   |   ✅   |   ✅   |                                                |
| Finding Group                  |   ✅   |   ✅   |   ✅   |                                                |
| Finding Template               |   ✅   |   ✅   |   ✅   |                                                |
| Risk Acceptance                |   ✅   |   ✅   |   ✅   |                                                |
| Endpoint                       |   ✅   |   ✅   |   ✅   |                                                |
| Location                       |   ✅   |   ✅   |   ✅   |                                                |
| URL                            |   ✅   |   ✅   |   ✅   |                                                |
| Notification Webhook           |   ✅   |   ✅   |   ✅   | `header_name` / `header_value` excluded (secrets) |

### Core — relationship (add / remove) events

| Relationship                       | Add | Remove |
| ---------------------------------- | :-: | :----: |
| Finding → Reviewers                | ✅  |   ✅   |
| Finding → Tags                     | ✅  |   ✅   |
| Finding → Inherited Tags           | ✅  |   ✅   |
| Asset → Tags                     | ✅  |   ✅   |
| Engagement → Tags                  | ✅  |   ✅   |
| Engagement → Inherited Tags        | ✅  |   ✅   |
| Test → Tags                        | ✅  |   ✅   |
| Test → Inherited Tags              | ✅  |   ✅   |
| Endpoint → Tags                    | ✅  |   ✅   |
| Endpoint → Inherited Tags          | ✅  |   ✅   |
| Finding Template → Tags            | ✅  |   ✅   |
| App Analysis (Technology) → Tags   | ✅  |   ✅   |
| Objects/Asset → Tags             | ✅  |   ✅   |

## Pro — tracked actions

| Object                            | Create | Update | Delete | Notes                          |
| --------------------------------- | :----: | :----: | :----: | ------------------------------ |
| Enhanced Finding                  |   ✅   |   ✅   |   ✅   | Pro companion to Finding       |
| Enhanced Risk Acceptance          |   ✅   |   ✅   |   ✅   | Pro companion to Risk Acceptance |
| Risk Acceptance Finding Record    |   ✅   |   ✅   |   ✅   | Findings attached to a Risk Acceptance |
| Rule                              |   ✅   |   ✅   |   ✅   | Rules engine                   |
| Rule Action                       |   ✅   |   ✅   |   ✅   |                                |
| Rule Action Condition             |   ✅   |   ✅   |   ✅   |                                |
| Rule Filter Entry                 |   ✅   |   ✅   |   ✅   |                                |
| Rules Engine Operation            |   ✅   |   ✅   |   ✅   |                                |
| Rules Engine Operation Message    |   ✅   |   ✅   |   ✅   |                                |
| Rules Engine 2.0 Rule             |   ✅   |   ✅   |   ✅   | Node based rules               |
| Rules Engine 2.0 Delivery         |   ✅   |   ✅   |   ✅   | Entries in the Deliveries ledger |
| Scheduled Task                    |   ✅   |   ✅   |   ✅   |                                |
| Scheduled Task Run                |   ✅   |   ✅   |   ✅   |                                |
| Mitigation Policy                 |   ✅   |   ✅   |   ✅   |                                |
| Work Assignment                   |   ✅   |   ✅   |   ✅   | Findings and Risk Acceptances assigned to a person |
| CMMC Assessment                   |   ✅   |   ✅   |   ✅   |                                |
| Tunable Setting                   |   ✅   |   ✅   |   ✅   | System configuration changes   |
| Custom Field Definition           |   ✅   |   ✅   |   ✅   | The custom field itself        |
| Custom Field Value                |   ✅   |   ✅   |   ✅   | Values filled in on a record   |
| Form Configuration                |   ✅   |   ✅   |   ✅   | Create and edit form settings  |
| Feature Flag State                |   ✅   |   ✅   |   ✅   | Flag toggles + system pins     |
| Feature Flag Definition           |   ✅   |   ✅   |   ✅   | Metadata / registry sync       |
| Cloud Firewall                    |   ✅   |   ✅   |   ✅   | `locked` field excluded        |
| Firewall IP Mask                  |   ✅   |   ✅   |   ✅   |                                |

### Pro — RBAC / permissions

| Object                        | Create | Update | Delete |
| ----------------------------- | :----: | :----: | :----: |
| Group                         |   ✅   |   ✅   |   ✅   |
| Role                          |   ✅   |   ✅   |   ✅   |
| Role permissions              |   ✅   |   ✅   |   ✅   |
| Group Membership              |   ✅   |   ✅   |   ✅   |
| Global Role                   |   ✅   |   ✅   |   ✅   |
| Asset Group Assignment      |   ✅   |   ✅   |   ✅   |
| Organization Group Assignment |   ✅   |   ✅   |   ✅   |
| Asset Member                |   ✅   |   ✅   |   ✅   |
| Organization Member           |   ✅   |   ✅   |   ✅   |

### Pro — relationship (add / remove) events

| Relationship                | Add | Remove |
| --------------------------- | :-: | :----: |
| Cloud Firewall → IP Ranges  | ✅  |   ✅   |

## Configuration & retention (On-Premise Controls)

| Setting              | Environment variable                  | Default            | Effect                                                              |
| -------------------- | ------------------------------------- | ------------------ | ------------------------------------------------------------------ |
| Enable audit logging | `DD_ENABLE_AUDITLOG`                  | `True`             | When `False`, all history triggers are disabled and no events are recorded |
| Retention period     | `DD_AUDITLOG_FLUSH_RETENTION_PERIOD`  | `-1` (never flush) | Months of history to keep; older events are batch-deleted by the flush job  |
| Flush batch size     | `DD_AUDITLOG_FLUSH_BATCH_SIZE`        | `1000`             | Rows deleted per batch during cleanup                              |
| Flush max batches    | `DD_AUDITLOG_FLUSH_MAX_BATCHES`       | `100`              | Cap on the number of batches per flush run                        |

## Notes and limitations

- **Secrets are never captured.** User passwords and notification-webhook header
  values are explicitly excluded from event snapshots.
- **Updates record only on a genuine change.** A save that does not alter any
  field value produces no update event; auto-managed fields such as
  `last_updated` alone do not trigger one.
- **Authentication events are not captured here.** data
  changes only. Login, logout, and failed-login activity are handled separately and are not part of this audit log.
