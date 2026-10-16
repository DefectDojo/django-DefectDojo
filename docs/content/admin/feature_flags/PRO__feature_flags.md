---
title: "Feature Flags"
description: "Turn optional DefectDojo Pro features on and off from the DefectDojo UI"
weight: 1
audience: pro
---

Feature Flags let you turn optional DefectDojo Pro capabilities on and off for your own instance — features that previously could only be enabled by contacting DefectDojo Support can now be self-served from the UI.

The Feature Flags page is visible to **superusers** only. Other users, including Global Owners, do not see it.

## Opening the Feature Flags page

Go to **Settings > Feature Flags** in the left sidebar.

The page lists every optional feature with:

* **Name** — the feature, with a **BETA** tag when it is still in beta
* **Description** — what the feature does
* **Documentation link**: a link to that feature's documentation. Every feature on the page has one, and the [Feature reference](#feature-reference) below lists them all.
* **Toggle** — whether the feature is currently on

Use the search box to filter the list by feature name or description.

### Features that are not listed

The page lists the features you can choose to adopt. Two kinds of feature are absent from it.

**Always on.** Once a feature reaches general availability it is on for every instance and stops being listed, because there is no longer a decision to make:

* **Downstream Connectors** — see [Downstream Connectors](/connectors/downstream/about/)
* **Universal Parser** — see [Universal Parser](/import_data/pro/specialized_import/universal_parser/)
* **Asset Hierarchy** — see [Asset Hierarchy](/asset_modelling/pro_hierarchy/asset_hierarchy/)
* **Appearance** and **Feature Flags** — the two Settings pages of the same name

Nothing changes for your instance if you had one of these turned on. If you had one turned off, it is now on: these features are part of DefectDojo Pro rather than opt-in. Contact [DefectDojo Support](mailto:support@defectdojo.com) if that is a problem for your instance.

**Enabled by DefectDojo on request.** A few capabilities depend on infrastructure that is provisioned per instance, so they are switched on by DefectDojo rather than from this page:

* **Scheduling Service** — see [Scheduling Rules](/automation/rules_engine/scheduling/)

Contact [DefectDojo Support](mailto:support@defectdojo.com) to have one of these enabled. If it is already on for your instance, it stays on.

## Turning a feature on or off

1. Find the feature in the list.
2. Click its toggle.
3. The change takes effect immediately. Other users pick the change up on their next page load.

Some features show a confirmation dialog before the change is applied. This happens when enabling a feature that carries a warning (for example one that requires a restart or may affect existing data), or one that cannot be turned back off.

Turning a feature off is normally just the reverse of turning it on. The exceptions are called out in [When a toggle is locked](#when-a-toggle-is-locked).

### Restart Recommended

A few features carry a **Restart Recommended** tag next to their name (a stronger **Restart Required** variant also exists). The tag means that part of the feature is decided when DefectDojo starts: server-side URL routing, generated reports, and some `/api/v2` route wiring read their configuration once at boot. A toggle reaches the Pro UI right away, but those start-time surfaces only pick it up after the serving process restarts. A **Restart Recommended** feature still works in the Pro UI without a restart; the restart only reconciles the remaining surfaces.

The tag is shown only while a restart is actually outstanding. Once the running server already reflects the flag's current value (because it has been restarted since you changed the flag), the tag disappears on your next page load. Turn a flag on and then back off without restarting and the tag clears too, because nothing is left to reconcile. There is nothing to dismiss: the tag tracks the real state of the running server, so a lingering tag means a restart is still pending, and its absence means the running server is already in sync.

### Organization / Asset Relabeling

**Organization / Asset Relabeling** renames "Product Type" to "Organization" and "Product" to "Asset". It is on by default and toggles from this page like any other feature, but it is worth knowing which parts of DefectDojo it governs:

* The **Pro UI** follows this toggle. The new labels appear on your next page load.
* Server-side URLs and generated reports take their naming when DefectDojo starts. They follow this toggle after the next restart, in either direction. You do not need to change a deployment setting: DefectDojo reads the stored toggle at start-up and applies it to those surfaces itself.

Until you restart, those URLs and reports keep the naming the process started with, so they can disagree with the Pro UI for a while. On [DefectDojo Pro (Cloud)](/get_started/pro/cloud/), contact [DefectDojo Support](mailto:support@defectdojo.com) if you need a restart scheduled.

The feature carries a **Restart Recommended** tag on the Feature Flags page for this reason: the naming used outside the Pro UI is fixed when the process starts. The tag shows only while a restart is still outstanding, and clears once you have restarted or toggled the flag back (see [Restart Recommended](#restart-recommended)). Relabeling is cosmetic either way. Database models, field names, and API endpoints are unchanged, so existing automation keeps working. See [Asset Hierarchy](/asset_modelling/pro_hierarchy/asset_hierarchy/).

The `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL` deployment setting still exists, but only as the value the stored toggle was seeded from on upgrade and as a fallback when the database cannot be reached at start-up. Once the toggle has a stored value, the database owns it.

### Locations

**Locations** replaces the legacy Endpoints model: with it on, imports create Location records and the UI and API surface Locations; with it off, imports create Endpoints. It is off by default and is enabled from this page like any other feature, but a few things are worth knowing:

* The **Pro UI** and the **import pipeline** follow this toggle. After you enable Locations, new imports create Locations and the Locations pages appear on your next page load, without a restart.
* The `/api/v2` endpoint/location route wiring is decided when DefectDojo starts. It follows this toggle after the next restart: the `/api/v2/location/` routes (and the `/api/v3/` API) are mounted and listed in the API documentation, and `/api/v2/endpoints/` is served read-compatibly from Locations. You do not need to change a deployment setting. Until you restart, those routes stay as they were when the process started, so `/api/v2/location/` answers 404 in the meantime. The stored toggle is seeded from the `DD_V3_FEATURE_LOCATIONS` deployment setting on upgrade, so an instance that already ran with `DD_V3_FEATURE_LOCATIONS=True` comes up with the toggle already on (and locked); from then on the database owns the value and the setting is only a fallback for when the database cannot be reached at start-up.
* Enabling existing history is not automatic. Your existing data stays as it is until you run the **data-migration suite** that appears under this row once Locations is on: three backfills (endpoints, dependencies, and source-code locations) followed by an identity rehash that unlocks once all three finish. Each is superuser-run, shows progress, is safe to re-run, and can be cancelled while running (it stops at the next batch boundary and can be resumed). Each item can also be **marked complete**, automatically when a run here finishes or by hand for a migration you ran another way, so the page stops prompting you to run it. See [Migrating from Endpoints](/asset_modelling/locations/pro__migrating_from_endpoints/).

Enabling Locations is **self-service and one-way**: once it is on, the toggle locks (shown as **Cannot Be Disabled**), because turning it back off would require reversing the endpoint-to-location data migration, which is not yet supported. The feature carries a **Restart Recommended** tag for the API reason above; as with any such feature, the tag clears once the server has been restarted (see [Restart Recommended](#restart-recommended)).

## When a toggle is locked

A feature you cannot change is shown with a lock badge explaining why:

| Badge | What it means | What to do |
| --- | --- | --- |
| **Managed by DefectDojo** | DefectDojo has set this feature centrally for your instance. Your setting cannot override it. | Contact [DefectDojo Support](mailto:support@defectdojo.com) if you need it changed. |
| **Unavailable on This Deployment** | The feature is not offered on your installation type. See [Feature availability](#feature-availability) below. | Nothing. The feature is not applicable to your instance. |
| **Cannot Be Disabled** | The feature is already on and is one way. There is no mechanism to reverse it. | Nothing. This is expected. |
| **Managed by deployment** | The feature is controlled by your deployment configuration rather than by this page. | See [DefectDojo Pro (On-Premise)](#defectdojo-pro-on-premise) below. |

## DefectDojo Pro (Cloud)

On [DefectDojo Pro (Cloud)](/get_started/pro/cloud/), **Settings > Feature Flags** is the only place you need. Toggle a feature on and it is live.

Two things are handled by DefectDojo rather than by you:

* **Managed by DefectDojo** — the feature is pinned centrally. Contact [DefectDojo Support](mailto:support@defectdojo.com) to have it changed.
* **Managed by deployment** — the feature is part of how your instance is provisioned. Contact Support for these as well, since Cloud instances do not expose deployment configuration to customers.

Cloud instances also have access to features that are not offered on-premise. See [Feature availability](#feature-availability).

## DefectDojo Pro (On-Premise)

On [DefectDojo Pro (On-Premise)](/get_started/pro/onprem/), most features work exactly as they do on Cloud: open **Settings > Feature Flags** and toggle them.

A small number of features are read from your deployment configuration instead. They change how the application starts, so they cannot be flipped at runtime. These appear on the page as read-only, labeled **Managed by deployment**, and name the environment variable that controls them.

Because these features require a restart, and some of them cannot be reversed once enabled, check the feature's own documentation before changing one. Several are best enabled with help from [DefectDojo Support](mailto:support@defectdojo.com).

To change one of those features:

1. Set the environment variable on your DefectDojo deployment. The page tells you which variable to set.
2. Restart DefectDojo so the new value is read at startup.
3. Reload the Feature Flags page to confirm the new state.

Because these values are read at startup, changing them in the UI is not possible, and toggling them in your environment without a restart has no effect.

Features that are offered only on Cloud appear as **Unavailable on This Deployment** on an on-premise instance. This is expected and is not a licensing problem.

## Feature reference

Every feature on the Feature Flags page, with its default on a new instance and a link to its documentation. A feature marked BETA is still in beta. "Requires" names another flag that must also be on; while it is off, this feature stays off.

Features under **MCP** appear on the Feature Flags page beneath the MCP server switch. Some features are also limited by your license or installation type; see [Feature availability](#feature-availability).

| Feature | What it does | Default | Documentation |
| --- | --- | --- | --- |
| **Administrator MFA Reset** | Let superusers reset multi-factor authentication for another user from the Users page. The reset removes that user's authenticator and recovery codes and notifies them; they set MFA up again at their next sign-in if it is required. Turning this off removes the action. Users can still remove their own MFA from their profile. | On | [Docs](/admin/user_management/pro__mfa/#recovering-a-user-who-has-lost-their-mfa-device) |
| **AI Inventory and Governance** (BETA) | Inventory the AI in every scanned repository: coding assistants and their rules files, MCP servers, models, AI packages, AI service endpoints, agent skills and AI provider keys. Policies mark each component authorized, unauthorized or needs review, unauthorized components become Findings, and each Asset can export an AI bill of materials. Inventories that arrive while this is off are still stored and appear when it is turned on. Requires **Locations**. | Off | [Docs](/asset_modelling/locations/pro__ai_inventory/) |
| **AI Threat Modeling** | Generate a STRIDE threat model, attacker profiles, attack paths and security requirements from a feature design with Sensei. | On | [Docs](/sensei/threat_modeling/) |
| **Airgapped instance** | This instance has no route off its network, so it never contacts DefectDojo. The version check, external tools, announcements, threat intel downloads and error and performance diagnostics stop, and both support pages show the DefectDojo support address instead. Load threat intel bundles from a file. The DD_AIRGAPPED environment variable turns this on for the whole deployment. | Off | [Docs](/get_started/pro/onprem/airgapped/) |
| **Asset Exposure** (BETA) | Compute whether an asset is reachable from outside, and whether a finding's code is actually deployed in production, from the evidence connectors already collect. Both feed prioritization; exposure can also drive the FedRAMP VDR SLA tiers. | Off | [Docs](/triage_findings/finding_scoring/asset_exposure/) |
| **Calendar** | Show the Calendar in the sidebar. The calendar plots engagements and tests on a month view. Turning this off removes the entry; it does not change any engagement or test dates. | On | [Docs](/navigation/pro__sidebar/) |
| **Celery Status** | Expose background-task queue health in the UI. | Off | [Docs](/admin/pro__celery_status/) |
| **Certification Control Catalogs** (BETA) | Assess a product against ISO/IEC 27001:2022 Annex A, the SOC 2 Trust Services Criteria and the NIS2 technical requirements, and see one body of evidence answer all three in the cross-framework view. Running the assessments also needs **EU Evidence Packs** and **Compliance**. | Off | [Docs](/federal_compliance/certification_catalogs/) |
| **Change Plans** (BETA) | Review every hierarchy change before it happens: build a change plan from operations or a CSV file, see a diff of every Asset and Organization it changes, and apply or undo the whole plan. The Asset bulk update form shows the same review before it writes. | Off | [Docs](/asset_modelling/pro_hierarchy/change_plans/) |
| **Compliance** (BETA) | The federal compliance pack: FedRAMP POA&M ledger and ConMon deliverables, CMMC Level 2 assessments, and control coverage. | On | [Docs](/federal_compliance/) |
| **Component Support Metadata** (BETA) | Record who supplies each component, how long it is supported and when support ends, read from bills of materials or entered by hand, and carry those facts through the SBOM exporters. | Off | [Docs](/asset_modelling/locations/pro__working_with_sboms/#supplier-and-support-metadata) |
| **Connector Location Inventory** (BETA) | Let asset connectors populate Location inventory directly on their mapped asset, so cloud resources appear as Locations without waiting for a finding to reference them. Locations that disappear vendor-side are mitigated, never deleted. Requires **Locations**. | Off | [Docs](/connectors/upstream/location_inventory/) |
| **Container Image Locations** (BETA) | Model container images as Locations: registry, repository, tag and digest, grouped on the location map and listed as All Images, with the assets that run each image. Images that arrive while this is off are still stored and appear when it is turned on. Requires **Locations**. | Off | [Docs](/asset_modelling/locations/pro__container_image_locations/) |
| **Custom Fields** (BETA) | Replaces the legacy Metadata feature with typed, admin-defined Custom Fields. Once enabled, Pro uses Custom Fields everywhere Metadata was used and the old metadata endpoints and UI are disabled, so existing metadata values are no longer shown until you convert them. Converting your current metadata into Custom Fields is optional and runs on demand from the Convert button that appears under this feature once it is on. This setting cannot be turned off. | Off | [Docs](/asset_modelling/pro__custom_fields/) |
| **Customizable Page Layouts** | Customizable widget-grid layouts for the Organization, Asset, Engagement, Test, Finding, and Risk Acceptance view pages. | On | [Docs](/pro/page_layouts/) |
| **Dashboards 2.0** | The redesigned customizable widget dashboard. | Off | [Docs](/metrics_reports/dashboards/custom-dashboards/) |
| **EU Evidence Packs** (BETA) | Assess product evidence against authored CRA and DORA obligation catalogs, preserve assessor overrides, and generate dated evidence packs. Requires **Compliance**. | Off | [Docs](/federal_compliance/eu_evidence_packs/) |
| **FDA Cyber Device Pack** (BETA) | Assess a cyber device against an authored catalog for section 524B of the Federal Food, Drug, and Cosmetic Act, and generate an evidence pack carrying the component inventory, the lifecycle metrics and the exported bill of materials. Requires **Compliance**. | Off | [Docs](/federal_compliance/fda_cyber_device_pack/) |
| **Framework Presets** (BETA) | Apply a published framework's patch windows and scan cadence as one preset: preview the plan, apply it, revert it, and see when the applied settings drift. Ships with UK Cyber Essentials and the Australian Essential Eight. | Off | [Docs](/asset_modelling/pro_hierarchy/framework_presets/) |
| **Global Component Deduplication** | Deduplicate Components globally across the instance instead of per Asset. | Off | [Docs](/triage_findings/finding_deduplication/pro__global_component_deduplication/) |
| **Global Locations Deduplication** | Deduplicate Findings globally across the instance based exclusively on shared locations (a URL or a dependency), like Global Component Deduplication. Requires **Locations**. | Off | [Docs](/triage_findings/finding_deduplication/pro__global_locations_deduplication/) |
| **Global Vulnerability ID Deduplication** | Deduplicate Findings by vulnerability ID globally across the instance. | Off | [Docs](/triage_findings/finding_deduplication/pro__deduplication_tuning/#global-vulnerability-id) |
| **Hierarchy Menu 2.0** | The map-first hierarchy page: land on the full map of every hierarchy you can see, with Organization boundaries drawn around each one, finding counts on the nodes, per-node direct and inherited finding breakdowns by severity, and Asset creation from the page header. Turning this off restores the previous table-first page, where the canvas draws only the Assets picked from the list. | On | [Docs](/asset_modelling/pro_hierarchy/assets_organizations/) |
| **In-App Walkthroughs** (BETA) | Guided, step-by-step tours of the Pro UI. Includes the App Tour, offered once on a user's first visit to Home. Each user can turn the automatic offers off from their profile. | On | [Docs](/navigation/pro__walkthroughs/) |
| **Inbound Webhooks** | Accept webhook deliveries for Triage Engine webhook receivers and keep the webhook gateway in step with them. Turning this off refuses every delivery and stops DefectDojo talking to the gateway; the gateway keeps what it has captured and retries it for a few hours. | On | [Docs](/automation/triage_engine/webhook_receivers/) |
| **Location Map** | Land the Asset Locations page on a map: every URL, source file, dependency and cloud resource the Asset has, drawn as trees inside a dashed region per location type, with active finding counts rolled up onto every node. Turning this off restores the table-only Locations page. Requires **Locations**. | On | [Docs](/asset_modelling/locations/pro__location_map/) |
| **Locations** | Location-based Finding tracking (3.0), the successor to Endpoints. With it on, imports create Locations and the Pro UI shows them; with it off, imports create Endpoints. Enabling is self-service and one-way -- once on, it cannot be turned back off. After enabling, run the endpoints-to-locations migration to carry existing history forward. The Classic UI and /api/v2 route wiring are decided when DefectDojo starts, so restart DefectDojo for them to follow this toggle. | Off | [Docs](/asset_modelling/locations/pro__locations_overview/) |
| **MCP: Asset Hierarchy** | Let MCP clients work with the Asset hierarchy: read trees, structure summaries and node statistics, and create, re-parent or detach Assets and Organizations. Every call runs as the connecting user, with the same permissions that user has in the REST API. Requires the MCP server to be enabled. | Off | [Docs](/metrics_reports/ai/mcp_server_pro/) |
| **MCP: Dashboards 2.0** | Let MCP clients discover the Dashboards 2.0 widget catalog, read dashboards and render their widget data, and create, update, clone, share and delete dashboard layouts, as the connecting user and with that user's REST API permissions. Requires the MCP server and Dashboards 2.0 to be enabled. | Off | [Docs](/metrics_reports/ai/mcp_server_pro/) |
| **MCP: PSIRT** | Let MCP clients read the PSIRT feed, matches, rules, cases and authored advisories, and triage feed items, tune rules, update matches, manage cases and drive advisory drafts through review and publication, as the connecting user and with that user's PSIRT permissions. Requires the MCP server, Locations, PSIRT and a PSIRT licence. | Off | [Docs](/metrics_reports/ai/mcp_server_pro/) |
| **MCP: Reporting** | Let MCP clients read and build report themes, blocks and templates, generate reports and fetch their download links, as the connecting user and with that user's REST API permissions. Requires the MCP server and Reporting to be enabled. | Off | [Docs](/metrics_reports/ai/mcp_server_pro/) |
| **Menu 2.0** | Reorganizes the whole sidebar. Settings becomes seven task-based groups -- System, Users & Permissions, Finding Workflow, Configuration, Notifications, Operations, and License & Support -- behind a searchable All Settings directory page. The AI capabilities gather into a Sensei + AI section; Dashboards becomes Overview; Import folds into Connect; and Manage groups its catalogs, so create pages are reached from their list's Add button rather than from a menu row of their own. Every page keeps its existing URL, and turning this off restores the previous menu layout. New installations start with this enabled. | On | [Docs](/navigation/pro__sidebar/) |
| **Messaging Connectors** (BETA) | Send alerts to messaging services such as Slack from the Downstream Connectors catalog. Delivery is routed by Rules Engine 2.0, which must also be enabled. | On | [Docs](/issue_tracking/pro_integration/messaging_connectors/) |
| **Multilingual UI** (BETA) | Let each user pick the language the interface is shown in, from the languages that are fully translated. The choice is stored on the user's profile and follows them to any browser they sign in from. Translations other than English are machine generated. | Off | [Docs](/navigation/language_and_localization/) |
| **Onboarding Inbox** (BETA) | List the Assets that still sit in a connector's default Organization or lack the priority data scanners never supply, fix them in bulk, and see on each Asset what drives its priority and SLA. Onboarding is complete when the list is empty. | Off | [Docs](/asset_modelling/pro_hierarchy/finish_onboarding/) |
| **Organization / Asset Relabeling** | Relabels Product Types and Products as Organizations and Assets (3.0 naming). The Pro UI picks up the new labels on your next page load. Classic UI pages, their URLs, and generated reports take their naming when DefectDojo starts, so restart DefectDojo for them to follow this toggle. | Off | [Docs](/asset_modelling/pro_hierarchy/asset_hierarchy/#label-changes-optional) |
| **PCI DSS** (BETA) | PCI DSS v4.0.1 support: per-product cardholder-data-environment scope and component inventory, the Requirement 6.3.3 patch-clock SLA, and a scope inventory export. | Off | [Docs](/asset_modelling/engagements_tests/pro__pci_dss_scope/) |
| **PSIRT** | The platform-native PSIRT Advisory Engine: advisory feed ingestion, SBOM matching, case management with SLA clocks, and advisory publishing. Feeds ship disabled; enabling a source presents its publisher's terms and records your acceptance. Use additionally requires the psirt_engine licensed feature. Requires **Locations**. | Off | [Docs](/psirt/) |
| **Regulatory Profile** (BETA) | Record the regulatory facts EU regimes such as CRA, DORA and NIS2 ask about first: whether an asset supports a critical or important function, its CRA product class and support period, and where vulnerability reports go. | Off | [Docs](/federal_compliance/regulatory_profile/) |
| **Remediation Center** (BETA) | Groups open Findings by the change that resolves them, one remediation action per change per location, with the earliest SLA as the action's due date, owners, workflow status and campaign rollups. Findings stay the evidence underneath, and each keeps its own SLA and history. | Off | [Docs](/triage_findings/remediation_center/pro__remediation_center/) |
| **Risk Acceptances 2.0** (BETA) | Give Risk Acceptances a reviewable lifecycle: propose one, have it approved or rejected, and keep a record of who decided what and why. | Off | [Docs](/triage_findings/findings_workflows/pro__risk_acceptance/) |
| **Root Cause Correlation** | Groups Findings that share a root cause -- the same vulnerable component or the same CVE -- into ranked Root Causes, so one fix can be traced to every Finding it resolves. Correlation is additive: every Finding stays independently visible, and the links carry the evidence that produced them. | Off | [Docs](/triage_findings/finding_correlation/pro__root_cause_correlation/) |
| **Rules Engine** (BETA) | Automate Finding workflows with user-defined rules that react to imports and Finding changes. | Off | [Docs](/automation/rules_engine/about/) |
| **Rules Engine 2.0 (Graph Editor)** (BETA) | Build automation rules as visual node graphs that react to Finding events, with per-run traces and a delivery outbox. | Off | [Docs](/automation/rules_engine_2/about/) |
| **Scan Cadence Assurance** (BETA) | Schedule hosted repository scans, monitor scan cadence, and export dated attestations. | Off | [Docs](/sensei/scan_cadence_policies/) |
| **Smart Upload** | Upload scan results without naming the asset or engagement first, and triage what could not be matched from the Unassigned Findings queue. Turning this off removes Smart Upload and Unassigned Findings from the Connect menu. It does not delete anything, and any findings already imported through Smart Upload are unaffected. | On | [Docs](/import_data/pro/specialized_import/smart_upload/) |
| **Support** | Open a support request, track its status, and vote on what other customers ask for. When off, the Support pages are hidden and this instance sends no support requests to DefectDojo. | On | [Docs](/navigation/pro__support/) |
| **Vulnerability Response Policies** (BETA) | Read the response-policy matrix, the unevaluated queue and the escalation queue, and export machine-readable response evidence. | Off | [Docs](/asset_modelling/pro_hierarchy/priority_sla/#vulnerability-response-policies) |

## Feature availability

Most features are available on both installation types. The exceptions are:

| Feature | Availability | How it is controlled |
| --- | --- | --- |
| Request a New Connector | [DefectDojo Pro (Cloud)](/get_started/pro/cloud/) only | Always on for Cloud instances, and not offered on-premise. No longer listed on the Feature Flags page. |
| Locations | Both | Feature Flags page. The Pro UI and import pipeline follow it right away; the `/api/v2` route wiring follows it after a restart. Enabling is self-service and one-way: once on, it cannot be turned back off. See [above](#locations) and [Locations Overview](/asset_modelling/locations/pro__locations_overview/). |
| Organization / Asset Relabeling | Both | Feature Flags page. The Pro UI follows it right away; server-side URLs and generated reports follow it after a restart. See [above](#organization--asset-relabeling). |

Every other optional feature is toggled directly on the Feature Flags page on both Cloud and On-Premise instances.

## Reading feature flags outside the UI

You do not have to open the Feature Flags page to find out which features are enabled — flag state can also be read programmatically, which is useful when automation needs to check that a capability is available before depending on it.

```
GET /api/v2/defectdojo_information/feature_flags/
```

This returns a JSON array with one object per feature flag. Alongside the flag's `key`, `title` and `description`, each object reports the values automation usually wants: `effective` (whether the feature is actually on for this instance), `default`, `application_value` (the instance's own setting, or `null` if unset), `editable`, and `locked_reason` where a flag cannot be changed. Flags retired from the product are omitted.

Any **authenticated** user can read it — no superuser role is required. For the exact response schema on your version, see your instance's interactive API documentation at `/api/v2/oa3/swagger-ui/`, which is generated from the running build. See also the [API v2 documentation](/automation/api/api-v2-docs/).

The same read-only listing is also published on the instance's `/api/mcp/` surface, at `/api/mcp/defectdojo_information/feature_flags/`.

This endpoint is **read-only**. Turning a feature on or off is still done from the Feature Flags page, or — for the deployment-configured features noted above — in your deployment settings.

## Frequently asked questions

**A feature I want is not in the list.**
The list shows optional features only. Capabilities that are always on do not appear. A feature also leaves the list once it becomes standard — it is then on for every instance and there is nothing to switch. If you expected a feature that is missing, confirm your license includes it, then contact [DefectDojo Support](mailto:support@defectdojo.com).

**A feature I had turned off is on again after an upgrade.**
A feature that becomes standard is turned on everywhere, and the setting you had chosen for it while it was optional is cleared as part of that release — otherwise an instance that had opted out would stay off with no toggle left to change it back. This only happens to features that leave the list; everything still shown keeps your setting. If a standard feature causes you a problem, contact [DefectDojo Support](mailto:support@defectdojo.com), who can turn it off for your instance.

**I turned a feature on but I do not see it.**
Reload the page — menu entries and routes are evaluated when the page loads, so a newly enabled feature appears on the next load rather than instantly in the current view.

**Will upgrading change my settings?**
For every feature on this page, yes — upgrading preserves the ones you have turned on and the ones you have turned off. The exception is a feature that becomes standard in that release and leaves the page; see the question above.
