---
title: "Backstage"
description: "How to set up the Backstage Upstream Connector for DefectDojo"
weight: 22
audience: pro
---
The Backstage connector is an **asset connector**: instead of importing Findings, it pulls your [Backstage](https://backstage.io) Software Catalog into DefectDojo and keeps your Asset hierarchy and team ownership in sync with it. It is designed for organizations that maintain their service inventory and org structure in Backstage and want DefectDojo to mirror that structure instead of maintaining it by hand.

#### What gets mapped

| Backstage | DefectDojo |
|---|---|
| **System** | Organization (Components with no System are grouped under a configurable "Backstage / Uncategorized" Organization) |
| **Component** | Asset — named from the entity `title` (falling back to `name`), with the catalog description |
| **Owning Group** (`ownedBy` relation) | A DefectDojo Group linked to the Asset (default role: Maintainer, configurable) |
| **Owner email** (Group profile email, or a User owner's email) | An Asset Member, when a DefectDojo user with that email already exists (users are never created) |
| `metadata.tags`, `spec.type`, `spec.lifecycle`, namespace, domain | Asset tags under a `backstage:` prefix |
| `metadata.annotations` | Stored on the Record (bounded); selected annotations can be promoted to first-class attributes or tags via **Annotation Mappings** |

Records are keyed by the entity's server\-assigned `metadata.uid`, so renames in Backstage update the mapped Asset **in place** on the next sync — no duplicates. The Asset name always tracks the catalog: to rename an Asset managed by this connector, rename the Component in Backstage (a DefectDojo\-side rename, or a custom name given during manual mapping, is reconciled back to the catalog name on the next sync unless it would collide with another Asset). Ownership changes move the Asset's group assignment. Components that disappear from the catalog (or are flagged with the `backstage.io/orphan` annotation) are marked **MISSING** — DefectDojo never deletes an Asset on its own. Domain and Group hierarchy (parent teams) are recorded as tags/metadata only; they do not create extra hierarchy levels.

#### Prerequisites

The connector authenticates with a **static external access token** against the Backstage backend. In your Backstage app config, define a token and (recommended) restrict it to the catalog plugin:

```yaml
backend:
  auth:
    externalAccess:
      - type: static
        options:
          token: ${DEFECTDOJO_BACKSTAGE_TOKEN}
          subject: defectdojo-connector
        accessRestrictions:
          - plugin: catalog
```

Generate a strong random token (for example `openssl rand -hex 32`) and store it in your Backstage deployment's environment. See the [Backstage service-to-service auth documentation](https://backstage.io/docs/auth/service-to-service-auth) for details.

#### Connector Mappings

1. Enter your **Backstage backend root URL** in the **Location** field: for example `https://backstage.example.com` (the connector appends `/api/catalog`). This must be the **backend** URL, not the frontend web UI.
2. Enter the static external access token in the **Secret** field.

Optional fields (leave blank for the defaults):

* **Namespaces** — comma\-separated catalog namespaces to import; blank imports every namespace.
* **Component Types** — comma\-separated `spec.type` values (e.g. `service,website`); blank imports every type.
* **Page Size** — catalog query page size (1\-500, default 250).
* **TLS Verification** — set to `false` only if Backstage serves a certificate DefectDojo cannot verify (internal CA); not recommended.
* **Uncategorized Organization** — the Organization used for Components with no System (default `Backstage / Uncategorized`).
* **Owner Group Role** — the role granted to the owning team on mapped Assets (default `Maintainer`).
* **Annotation Mappings** — a JSON object mapping annotation keys to Record attribute names, or to `"tag"` to import an annotation as an Asset tag, e.g. `{"github.com/project-slug": "GITHUB_PROJECT", "example.com/tier": "tag"}`.

With **Auto\-Map** enabled, a single Discover \+ Sync builds the complete Organization / Asset / ownership structure with no manual steps. With Auto\-Map disabled, discovered Components appear as Records awaiting your mapping decision.

#### Limitations (v1)

* Backstage **Group membership is not synchronized**: the connector creates/links the owning team as a DefectDojo Group, but populating that group's users is left to your identity provider or admins.
* Only Components become Assets; APIs, Resources, and Domains are not imported as assets (domains surface as tags).
* Tags and annotations are normalized and bounded to fit DefectDojo field limits (oversized values are truncated).

**A note on the reverse direction:** displaying DefectDojo findings and grades *inside* Backstage (on entity pages) is a natural follow\-on that would be built as a Backstage frontend plugin consuming the DefectDojo REST API — it is deliberately out of scope for this connector, which only pulls catalog data into DefectDojo.
