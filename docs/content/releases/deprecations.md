---
title: "Deprecations"
description: "Features removed from DefectDojo and DefectDojo Pro, features scheduled for removal, and features planned for removal without a release yet"
weight: 3
---

This page lists what has been removed from DefectDojo and DefectDojo Pro, what is deprecated and scheduled for removal, and what is planned for removal without a release yet. It covers open source and Pro.

A deprecated feature keeps working until the release that removes it. Where it can, DefectDojo warns you in the product: deprecated pages show a warning banner, deprecated API endpoints send an `X-Deprecated` header, and the Pro sidebar marks deprecated pages with a `DEPRECATED` or `LEGACY` badge (see [Menu Badges](/navigation/pro__menu_badges/)).

DefectDojo Pro is built on the open source release with the same version number, so when open source deprecates or removes a feature, Pro deprecates or removes it in the same release. The exceptions are features that Pro keeps or replaces with its own version, and those rows say so. The **Affects** column shows who each row applies to: **Open Source and Pro**, **Open Source only** (Pro keeps its own version), or **Pro only**. Where a version was never published, the table says **Not recorded**.

For each release's details, see the [Pro Changelog](/releases/pro/changelog/) and the [Open Source upgrade notes](/releases/os_upgrading/upgrading_guide/).

## Deprecated (scheduled)

These features still work. Plan to move off them before the release named in **Removal**.

| Feature | Affects | Deprecated in | Removal | Replacement | Notice |
|---|---|---|---|---|---|
| API-based (pull) parsers: BlackDuck API, Bugcrowd API Import, Cobalt.io API Import, Edgescan Scan, SonarQube API Import, Vulners | Open Source and Pro | 3.2.0 | 3.6.0 (December 7, 2026) | Pro [Connectors](/connectors/upstream/about/) for Black Duck, Bugcrowd, Cobalt.io, Edgescan and SonarQube, or import the tool's report as a file. Vulners has no replacement. In Pro, `manage.py migrate_api_parsers_to_connectors` moves existing Bugcrowd API Import setups to a Connector. | [3.2 upgrade notes](/releases/os_upgrading/3.2/#deprecation-api-based-pull-parsers), [API Pull parsers](/supported_tools/parsers/api/) |
| Tool Types: the Tool Type pages, `/api/v2/tool_types/`, and **Settings > Configuration > Tool Types** in Pro | Open Source and Pro | 3.2.0 | 3.6.0 (December 7, 2026) | Pro [Connectors](/connectors/upstream/about/) | [3.2 upgrade notes](/releases/os_upgrading/3.2/#deprecation-tool-type-and-tool-configuration) |
| Tool Configurations: the Tool Configuration pages, `/api/v2/tool_configurations/`, and **Settings > Configuration > Tool Configurations** in Pro | Open Source and Pro | 3.2.0 | 3.6.0 (December 7, 2026) | Pro [Connectors](/connectors/upstream/about/) | [3.2 upgrade notes](/releases/os_upgrading/3.2/#deprecation-tool-type-and-tool-configuration) |
| API Scan Configurations: the per-Asset pages, `/api/v2/product_api_scan_configurations/`, `/api/v2/asset_api_scan_configurations/`, and the `api_scan_configuration` parameter on `import-scan` and `reimport-scan` | Open Source and Pro | 3.2.0 | 3.6.0 (December 7, 2026) | Pro [Connectors](/connectors/upstream/about/) | [3.2 upgrade notes](/releases/os_upgrading/3.2/#deprecation-tool-type-and-tool-configuration), [3.4.100 upgrade notes](/releases/os_upgrading/3.4.100/) |
| Configuration Permissions API: the `configuration_permissions` endpoint, and the field of that name on users and groups, which is now read-only | Pro only | 3.5.0 | 3.6.0 (December 7, 2026) | Grant Configuration Permissions on a role and assign the role as a Global Role. Read the effective set from the user or group. | [Custom RBAC Roles](/admin/user_management/pro__custom_rbac_roles/#configuration-permissions), [v3.5.0 changelog](/releases/pro/changelog/#november-2-2026-v350) |
| Endpoints: the Endpoints menu, the Endpoint and Host list pages, and a Finding's endpoint tables | Pro only | 3.2.201 | 3.7.0 (January 4, 2027) | Locations. Turn on Locations on the Feature Flags page and run the migration. | [Migrating from Endpoints](/asset_modelling/locations/pro__migrating_from_endpoints/) |
| `manage.py dbbackup` and `dbrestore` (django-dbbackup) | Open Source and Pro | 3.2.0 | To be confirmed | Your database's own tooling, such as `pg_dump` and `pg_restore` matched to your PostgreSQL server version, or your provider's managed backups. Self-hosted Pro: see [Backing Up a Self-Hosted Deployment](/get_started/pro/onprem/backing_up/). | [3.2 upgrade notes](/releases/os_upgrading/3.2/#deprecation-managepy-dbbackup) |

## Planned, no timeline yet

These features are on the way out, but no removal release has been chosen. Where a replacement exists, new work should use it.

| Feature | Affects | Status | Replacement | Notice |
|---|---|---|---|---|
| Open source GitHub issue integration: GitHub Configurations, the per-Asset repository setting, and **Push to GitHub** | Open Source and Pro | Planned | Open source: none. Pro: the [downstream Connector for GitHub](/connectors/toolreference/github/#downstream-connector), which works through GitHub Projects and is set up differently. | |
| Asset Grades (the A to F grade on an Asset) | Open Source and Pro | Planned | To be announced | |
| Classic Jira integration (per-Asset Jira instances and projects, **Connect > Jira** in Pro) | Open Source and Pro | `LEGACY` badge in Pro | Open source: none. Pro: the [downstream Connector for Jira](/connectors/toolreference/jira/). | [Menu Badges](/navigation/pro__menu_badges/) |
| Classic Rules Engine (**Act > Triage Engine > Classic Rules**) | Pro only | `LEGACY` badge | Triage Engine, which can convert classic rules | [Converting from Rules Engine](/automation/triage_engine/converting_from_rules_engine/) |
| Tag-based Organization membership rules | Pro only | Deprecated. Existing rules keep working. | The Triage Engine **Add Organization Membership** node | [Node Reference](/automation/triage_engine/node_reference/#add-organization-membership) |
| `push_to_integrator` on import, reimport, Finding and Finding Group API requests | Pro only | Deprecated | `push_to_connector` | |
| `/api/integrators/v1/` routes | Pro only | Marked deprecated in the API schema | `/api/connectors/v1/downstream/` routes | |
| API list requests with `limit` above 250 | Pro only | A request above 250 gets a warning in the response's `meta`. Later, such requests will be cut to 250 results. | Page through results with `limit` of 250 or less | |
| License status fields `measured_usage`, `measured_capacity`, `measured_percentage` and `usage_breakdown_total` | Pro only | Deprecated | `enforcements`, which breaks usage down per signal | |
| The single `Risk_Acceptance` role permission | Pro only | Deprecated | `Risk_Acceptance_View`, `Risk_Acceptance_Add`, `Risk_Acceptance_Edit` and `Risk_Acceptance_Delete` | |
| Read-only Endpoint API: `/api/v2/endpoints/` and `/api/v2/endpoint_status/` | Open Source and Pro | Writes already fail when Locations is on. Reads stay until their own announcement. | `/api/v2/location/`, `/api/v2/location_findings/` and `/api/v2/location_products/` | [Migrating from Endpoints](/asset_modelling/locations/pro__migrating_from_endpoints/) |
| Running with Locations turned off (`DD_V3_FEATURE_LOCATIONS=False`, or the **Locations** feature flag in Pro) | Open Source and Pro | Planned | Locations | [3.0 upgrade notes](/releases/os_upgrading/3.0/#locations-enabled-by-default) |
| Remaining Endpoint code, after Locations is mandatory: the Classic UI Endpoint pages, the Metrics **Measure Affected Endpoints** view, and the `endpoint` parent on `/api/v2/metadata/` | Open Source and Pro | Planned | Locations | [Migrating from Endpoints](/asset_modelling/locations/pro__migrating_from_endpoints/) |
| Turning the Asset and Organization labels off (`DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL=False`, or the **Organization / Asset Relabeling** feature flag in Pro) | Open Source and Pro | Planned | Asset and Organization labels, always on | [3.0 upgrade notes](/releases/os_upgrading/3.0/#asset--organization-labels-enabled-by-default) |
| Redirects from the old `/product` and `/product/type` URLs | Open Source and Pro | Planned | `/asset` and `/organization` URLs | [3.0 upgrade notes](/releases/os_upgrading/3.0/#asset--organization-labels-enabled-by-default) |
| `DD_FEATURE_FINDING_GROUPS` environment variable | Open Source and Pro | Deprecated | The Finding Groups setting in System Settings | |
| `Coverity API` scan type | Open Source and Pro | Deprecated in Pro | Open source: none. Pro: the [Coverity Connector](/connectors/toolreference/coverity/), and `manage.py migrate_api_parsers_to_connectors` moves existing setups to it. | |
| `dojo-pro-helm`, the first Pro Helm chart | Pro only | Deprecated | `dojo-pro-helm-v2` | [Upgrade on Kubernetes](/get_started/pro/onprem/kubernetes/upgrading_on_kubernetes/) |
| Helm value `secrets.createMainSecret` | Pro only | Deprecated. It has no effect. | `dojo.existingSecret` | |
| Helm value `config.cloud_bucket_name` | Pro only | Deprecated | `storage.gcsfuse.bucketName` | |
| Open source Helm values `securityContext.djangoSecurityContext` and `securityContext.nginxSecurityContext` | Open Source only | Deprecated in 2.52 | The per-container `containerSecurityContext` values. Pro installs use their own chart and are not affected. | [2.52 upgrade notes](/releases/os_upgrading/2.52/) |
| `dojo-compose-cli` and `dojo-helm-cli` installer command names | Pro only | The old names print a notice | `dojo-deploy` | |
| `DD_CONNECTORS_SEMGREP_URL` environment variable (self-hosted) | Pro only | Planned | The **Location** field on the [Semgrep Connector](/connectors/toolreference/semgrep/) | |

## Removed

### 3.x releases

| Feature | Affects | Deprecated in | Removed in | Replacement | Notice |
|---|---|---|---|---|---|
| ddorch private key copy in the `<fullname>-orch-certs-configmap` ConfigMap | Pro only | Helm chart 3.4.100 | The Helm chart release after 3.4.101 | The `<fullname>-orch-certs` Secret, or `ddorch.tls.existingSecret` | [Upgrade on Kubernetes](/get_started/pro/onprem/kubernetes/upgrading_on_kubernetes/) |
| Classic sidebar, the **Menu 2.0** toggle, and the **Enable Calendar** system setting | Pro only | Not recorded | 3.4.200 | The current sidebar, and the **Calendar** feature flag | [3.4.200 upgrade notes](/releases/os_upgrading/3.4.200/) |
| Contact Support menu entries and pages | Pro only | Not recorded | 3.4.0 | The Support section in Settings. Old bookmarks redirect. | [v3.4.0 changelog](/releases/pro/changelog/#october-5-2026-v340) |
| PSIRT 1.0 Advisory Engine | Pro only | Not recorded | 3.3.0. Its sidecar left the deployment in 3.3.200. | The current PSIRT. Move leftover data with `psirt_import_legacy`. | [v3.3.200 changelog](/releases/pro/changelog/#september-22-2026-v33200) |
| Classic Report Engine: classic Report Builder, Report Templates and Generated Reports | Pro only | 3.2.100 | 3.3.0 | [Report Builder](/metrics_reports/reports/report-builder/) in the Pro UI | [v3.3.0 changelog](/releases/pro/changelog/#september-9-2026-v330) |
| Classic UI as the Pro UI | Pro only | 3.1.100 | No longer the default Pro UI (3.3.0) | The Pro UI and its sidebar | [v3.3.0 changelog](/releases/pro/changelog/#september-9-2026-v330) |
| Maintenance window feature | Pro only | Not recorded | 3.3.0 | None | [v3.3.0 changelog](/releases/pro/changelog/#september-9-2026-v330) |
| Legacy Watson search backend | Pro only | Not recorded | 3.1.200 | Postgres global search. `DD_WATSON_SEARCH_ENABLED` turns Watson indexing on or off. | [v3.1.200 changelog](/releases/pro/changelog/#july-20-2026-v31200) |
| Questionnaire API endpoints (`/api/v2/questionnaire_*`) | Open Source and Pro | 2.56.0 | 3.0.0 (announced as 2.59.0) | None. The endpoints return 404. | [3.0 upgrade notes](/releases/os_upgrading/3.0/#removal-questionnaire-api-endpoints) |
| Credential Manager: the pages, `/api/v2/credentials/` and `/api/v2/credential_mappings/` | Open Source and Pro | 2.57.0 | 3.0.0 (announced as 2.59.0) | None. The endpoints return 404. | [3.0 upgrade notes](/releases/os_upgrading/3.0/#removal-credential-manager) |
| Stub Findings: the pages and `/api/v2/stub_findings/` | Open Source and Pro | 2.57.0 | 3.0.0 (announced as 2.59.0) | None. The endpoint returns 404. | [3.0 upgrade notes](/releases/os_upgrading/3.0/#removal-stub-findings) |
| Single sign-on in open source: SAML, OIDC, Google, Okta, Azure AD, GitLab, Auth0, Keycloak, GitHub Enterprise and remote-user headers | Open Source only | Not recorded | 3.0.0 | DefectDojo Pro, which keeps single sign-on. Open source keeps local login. | [3.0 upgrade notes](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only) |
| Members and Groups (role-based access) in open source | Open Source only | Not recorded | 3.0.0 | The **Authorized Users** panel on Assets and Organizations. Pro keeps role-based access. | [3.0 upgrade notes](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) |

The 2.56 and 2.57 notices named 2.59.0 as the removal release. The removals shipped in 3.0.0.

### Removal release not recorded

| Feature | Affects | Deprecated in | Removed in | Replacement | Notice |
|---|---|---|---|---|---|
| SSE (Server-Sent Events) transport for the MCP Server | Pro only | Not recorded | Not recorded | Streamable HTTP | [MCP Server](/metrics_reports/ai/mcp_server_pro/) |
| DefectDojo Burp plugin | Open Source and Pro | Not recorded | Not recorded | Import Burp XML reports | [Burp plugin](/archived_docs/burp-plugin/) |
| Open source Helm values `tag` and `repositoryPrefix` | Open Source only | 2.52 | Not recorded | `images.django.image.tag` and `images.nginx.image.tag` for the tag, `global.imageRegistry` for a private registry, and the per-container `image` values. Pro installs use their own chart and are not affected. | [2.52 upgrade notes](/releases/os_upgrading/2.52/) |

### 2.x and earlier

Removals in 2.x and earlier releases, such as MySQL and RabbitMQ support, asynchronous import, django-auditlog and the Finding `cve` field, are listed in the [Open Source upgrade notes](/releases/os_upgrading/upgrading_guide/) for each release. The same rule applies to them. One exception: open source removed asynchronous import in 2.47, and Pro import and reimport have their own `background_import` option.
