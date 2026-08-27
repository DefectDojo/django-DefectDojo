---
title: "DefectDojo Pro Changelog"
description: "DefectDojo Pro Changelog"
exclude_search: true
outputs:
  - "html"
  - "rss"
aliases:
  - "/en/changelog/changelog/"
  - "/changelog/pro_changelog/"
---

Here are the release notes for **DefectDojo Pro (Cloud Version)**. These release notes are focused on UX, so will not include all code changes.

You can subscribe to these release notes with the [RSS feed](/releases/pro/changelog/index.xml).

For Open Source release notes, please see the [Releases page on GitHub](https://github.com/DefectDojo/django-DefectDojo/releases), or alternatively consult the Open Source [upgrade notes](/releases/os_upgrading/upgrading_guide/).

## August 2026: v3.2

### August 24, 2026: v3.2.300

New features:
* **(Custom Fields)** Added typed Custom Fields: define your own fields across seven datatypes and attach them to six entity types. Custom field values are tracked in the audit log, and Rules Engine 2.0 rules can read and write them.
* **(Rules Engine 2.0)** Rules can now work with Assets end to end, and a new asset provenance widget on the asset page layout shows which rule produced an asset.
* **(Asset Hierarchy)** Rebuilt the Asset Hierarchy page on the Rules Engine 2.0 editor shell.
* **(Connectors)** The GitHub Advanced Security connector can now import repository issues as a fourth finding family, under the new **GitHub: Issues** scan type. Pre-existing mappings are backfilled with the new subtype automatically.
* **(Connectors)** The OpenVAS / Greenbone connector now supports GMP over SSH as a transport.

Enhancements:
* **(Deduplication)** The deduplication identity ledger is now enabled by default.
* **(Connectors)** The Action1 connector now consolidates findings per organization, with machines recorded as endpoints, and each connector tile now counts only actively syncing records as mapped and surfaces unmapped records directly on the tile.
* **(Locations)** The component and code backfills now run in batches, and stale-run reaping was moved off the poll, making the data-migration suite faster and lighter.
* **(Operations)** DefectDojo now reports when a Celery task is routed to a queue that no worker consumes.
* **(Sensei)** The scan-and-fix release image is smaller, with scanner installs split into per-ecosystem layers.
* **(MCP)** The Pro MCP server now reports its version (with commit hash) via a CLI option.
* **(Compliance)** The POA&M scheduled completion date is now derived from the finding's SLA.
* **(Reporting)** The Risk Acceptance name is now offered as a finding report column.
* **(Jira)** The custom fields JSON limit was raised from 200 to 1000.

### August 18, 2026: v3.2.201

New features:
* **(Page Layouts)** The Risk Acceptance view page now uses a customizable widget grid, like the other View pages.
* **(Sensei)** Added Amazon Bedrock as an on-prem LLM connection.
* **(Locations)** The data-migration suite on the Feature Flags page can now be cancelled while a backfill is running. Cancelling stops the run at the next batch boundary and keeps everything migrated so far, so re-running the item resumes and converges on the same result. A run whose worker is lost is now detected and marked failed on its own, so a stuck suite becomes runnable again instead of blocking every item.
* **(Endpoints)** Endpoints are now deprecated in favour of Locations.
* **(Menu)** Classic-menu users are now warned that Menu 2.0 becomes the standard in 3.3.0.

Enhancements:
* **(CSPM)** Cloud Security Posture Management is now gated on the Sensei license rather than a separate feature flag.
* **(Sensei)** Scan-and-fix scanner parallelism is now configurable, via `--max-parallel` / `MAX_PARALLEL` (and `sensei.maxParallel` in Helm).

Bug fixes:
* **(Authorization)** Import and reimport preview targets are now scoped to the caller's permissions, POA&M item findings are validated against the record's own product, and questionnaire expiration and question-set editing are checked against the response route and the questionnaire change permission.
* **(Risk Acceptance)** A companion-less risk acceptance is now counted correctly, as active and as non-global, when filtering.
* **(Reporting)** Report graph blocks that no browser captured are now drawn instead of failing silently, and the BETA badge that Menu 2.0 re-added after GA is gone.
* **(Licensing)** License enforcement no longer blocks authentication.
* **(Connectors)** The Action1 connector derives severity from the CVSS score when no severity bucket is usable, and a chunked sync now records one Import History row per sync.
* **(Locations)** The endpoints-to-locations backfill now reports distinct locations and per-endpoint failures.
* **(Dedupe)** Finding post-processing now retries on a transient DB deadlock.
* **(UI)** The Advisor now renders with PrimeVue, and PSIRT and Field Mappings are nested correctly in the legacy sidebar.
* **(Threat Model)** The schema-repair loop no longer deletes the prompt it is repairing.

### August 17, 2026: v3.2.200

New features:
* **(CSPM)** Added Cloud Security Posture Management: connect AWS, Azure, and GCP cloud accounts, run posture scans against them, and apply reversible direct remediation to the misconfigurations that are found.
* **(Asset Exposure)** Added asset exposure reporting from Wiz, Shodan, and Censys, and from CrowdStrike Spotlight (which reports only the exposure it can prove).
* **(Connectors)** Registered the Aikido Security, Jit, and Cycode connectors.
* **(Finding Templates)** You can now apply a finding template to a Finding, and turn a Finding into a template, directly from the Vue UI.
* **(Form Configuration)** Added admin-controlled Form Configuration for the Vue create and edit forms, so an administrator can decide which fields appear.
* **(Locations)** Added a DB-backed Locations toggle, with a data-migration suite to move existing data over.
* **(Assets)** You can now export the asset and organization inventory as CSV.
* **(Reporting)** Quick Export now names its output from the current context, and you can apply a report template to an export.
* **(Findings)** Added a filterable Review Claimant column to the findings list.
* **(Rules Engine)** Rules Engine permissions now split into View / Add / Edit / Delete for finer RBAC.
* **(Feature Flags)** Promoted nine feature flags off the menu, turned five more on by default, and moved Feature Flags out of System into its own settings location.
* **(Layouts)** Layout customization can now be restricted to admin-designated defaults.

Enhancements:
* **(Qualys)** The Qualys connector now accepts a **Host Tags** filter that scopes discovery to hosts carrying the Qualys asset tags you name. The filter is sent to Qualys, so out-of-scope hosts are never downloaded. It applies to the detection download as well as the host listing, so a narrowed scope also shortens each Sync. Tag names are matched exactly, because Qualys supports no wildcards on tag names. Leave the field blank to keep discovering every host.
* **(JFrog)** The JFrog connector now surfaces a pending status.
* **(Jira)** The Jira connector now accepts service accounts.
* **(Findings)** The count of Findings a tool submitted is now recorded before deduplication runs.
* **(API)** The finding serializer now exposes a flat `test_type_name` field.
* **(MCP)** Finding and asset Location retrieval is now consolidated into single REST calls.

Bug fixes:
* **(Authorization)** Location data, DojoMeta visibility, and the `/api/v2/location/` endpoint are now scoped to the requesting user's products and RBAC rather than superusers only; every routed connector endpoint is named in the permission allow-list; the user edit form authorization was hardened; Tool Configuration credentials are kept out of the edit form; and the private-note visibility rule is now applied in the note UI views.
* **(Export)** Spreadsheet formulas can no longer execute out of an exported file (CSV/formula injection).
* **(SSO)** SAML2 routes now answer 404 when SAML is disabled.
* **(Findings)** The Priority filter and override inputs now accept decimal values.
* **(Assets)** A PATCH without a `parent` field no longer orphans the asset, and auto-creating the same asset name concurrently no longer returns a 500.
* **(Importers)** Bulk finding deletes, tag-count updates, and async cascade deletes now retry on transient DB conflicts and are ordered so concurrent imports and deletes cannot deadlock.
* **(Connectors)** The Action1 connector tolerates non-numeric sentinels in quoted numeric fields, and the Microsoft Defender connector retries a transient 5xx/429 on a single export page instead of failing the whole export.
* **(Parsers)** Fixed a Trivy Scan crash from an uninitialized `resource_name`, and reset Scout Suite parser state so a report parses to the same findings twice.
* **(Notes)** A partial note PATCH now keeps the note body and no longer writes a null NoteHistory entry.
* **(Reporting)** Reports no longer fetch unrenderable columns, report cells are now bounded, and a block's Order By is applied through the filterset.
* **(Tables & UI)** Clipped table cell text now wraps, the empty band below short pages is gone, the viewport row cap no longer oscillates and stalls a table, and the severity bar chart is positioned correctly in the open findings chart.
* **(Page Grid)** A widget's Title and Icon now follow its Records choice.
* **(Jira)** Fixed the Jira migration.

### August 10, 2026: v3.2.100

**NOTE: The classic report engine (Report Builder, Report Templates and Generated Reports) will be removed in 3.3.0 on September 8, 2026.**

New features:
* **(VEX)** Added CycloneDX SBOM / VEX / VDR export and import, as a round trip: a document exported from DefectDojo can be imported back into DefectDojo. The raw CycloneDX VEX analysis is now preserved on parsed Findings.
* **(SCIM)** Added SCIM 2.0 provisioning. Your identity provider can now create, update and deactivate DefectDojo users and manage groups directly, rather than DefectDojo only learning about a user when that user first signs in. Deactivating a user over SCIM also deletes that user's API tokens. SCIM is configured under **Connect > Authorization**, alongside your login providers, and is tagged **Provisioning** to distinguish it from the providers that put a button on the login page.
* **(Downstream Connectors)** Added Messaging Connectors (beta), which send alerts to Slack, Microsoft Teams, email, or an Amazon SNS topic. Alerts are routed by Rules Engine 2.0: a rule decides when to send, which Findings qualify, and which connection and destination the message goes to. Requires the **Messaging Connectors** and **Rules Engine 2.0** feature flags.
* **(Reporting)** Reporting is now generally available, and no longer carries the BETA label.
* **(Reports)** Both the classic Report Builder and the new Report Builder now offer a one-click migration of your existing report templates. The migration works with the Reporting feature flag off, so you can move on your own schedule. Reports you have already generated are finished files and stay downloadable until removal.
* **(Page Layouts)** The five View pages now use customizable widget grids, so you can arrange each page's widgets.
* **(Tables)** Table columns can now be resized, and the widths you set are saved to your table preferences. List tables also render a per-column loading skeleton while data is loading.
* **(Connectors)** Registered the Tenable Web App Scanning and Rapid7 InsightVM connectors, along with six connectors that had shipped without a registration.
* **(Sensei)** A provider can now hold several connections rather than one, and setup is scoped to the connection you are working in. Add Repositories now opens on the repository step. Semgrep scans run under a memory cap and recover across a hard kill (OOM).
* **(Risk Acceptance)** Added Expire and Reinstate to the risk acceptance menu, and as API actions.
* **(Rules Engine 2.0)** A Rules Engine 2.0 rule can now be given its own schedule. Enabling the feature flag now warns that a worker restart is required before it takes effect.
* **(Locations)** Added `migrate_locations_to_endpoints`, the reverse of the endpoint-to-location conversion.

Enhancements:
* **(Connectors)** A connector request now requires a usable credential and a base URL, so a request cannot be submitted with details that will not connect.
* **(Snyk)** Snyk reachability is now rendered as the raw values Snyk reports, rather than a derived yes/no.
* **(Performance)** Notes are now serialized a page at a time without re-filtering the page, and deduplication no longer lowercases the hash input on every Finding purely to log it.
* **(Dashboards)** The two Group By selects now focus their filter automatically when opened.

### August 4, 2026: v3.2.0

**NOTE: We have deprecated API-based pull parsers, Tool Type/Tool Configuration, and dbbackup, with end-of-life scheduled for 3.5.0.**

This release added many entries to the Feature Flags list: features that can be opted into.
* **(Review Claiming)** Let a requested reviewer claim a Finding review so the other eligible reviewers can see it is being handled. Once claimed, only the claimer or the requester can clear the review.
* **(Work Assignment)** Assign Findings and Risk Acceptances to individual people, alongside the existing group Owners, and give each person a My Work queue of what they are responsible for.
* **(Priority)** Added a threat-intel risk floor, which is based on whether a Finding has EPSS, KEV or other exploitability.  Only takes effect if Threat Intelligence Enrichment is enabled.
* **(Rules Engine 2.0)** Build automation rules as visual node graphs that react to Finding events, with per-run traces and a delivery outbox.
* **(Threat Intelligence Enrichment)** Threat Intelligence reached general availability, with signed threat-intel bundles, downgrade hysteresis, and new list and dashboard surfaces.
* **(Menu 2.0)** Reorganized the Settings menu behind Menu 2.0, with a new All Settings hub.
* **(Compliance)** The federal compliance pack: FedRAMP POA&M ledger and ConMon deliverables, CMMC Level 2 assessments, and control coverage.

Additional features:
* **(API)** DefectDojo REST API can now produce reports as HTML, CSV, and Excel, not just JSON.  Use the `/generate_report/` endpoint path, e.g. `api/v2/findings/generate_report/`
* **(Performance)** Improved the performance of Celery/Async tasks.
* **(Deduplication)** Added set-based deduplication that matches Findings on their full set of vulnerability IDs and CWEs, including partial/subset matches, alongside a new global vulnerability-ID deduplication algorithm and `global_locations` cross-product deduplication on shared locations. False-positive history now honors the same vulnerability-ID/CWE set-match tokens, false-positive-history candidate filtering is now pluggable, and deduplication now produces a stable "original" finding regardless of scan-import order.
* **(Findings)** Findings can now carry multiple CWEs across the API, the Vue UI, and the universal parser. Vulnerability IDs are normalized into a first-class Vulnerability entity with ordered references, per-vulnerability KEV/EPSS enrichment columns, and vulnerability aliases. Added a copy-finding action with an auto-detected vulnerability-ID type.
* **(Locations)** Location drift matching keeps a finding tracked as its locations change across reimports.
* **(Enrichment)** Added a two-stage KEV/EPSS pipeline that projects the worst score per vulnerability onto Findings, plus bulk cloud-enrichment reads and import-time enrichment.
* **(Connectors)** Added one-button migration from classic Jira to Downstream Connectors. Connector syncs now keep branch tags current on the Findings they report, and the public `/assign_product` endpoint can map Findings-type records again.
* **(Connectors)** JFrog now scopes artifact-mode Findings to each artifact's latest build.
* **(Notes)** Notes now support Markdown.
* **(Tools)** Added SPDX, CSAF 2.0, and OpenVEX interchange-format parsers and a Promptfoo (LLM eval and red-teaming) parser.

## July 2026: v3.1

### July 31, 2026: v3.1.303

* **(Connector)** For Checkmarx Connector, A branch value containing * now selects across every matching branch

### July 29, 2026: v3.1.302

* **(Connectors)** Added another large batch of Connectors to the Pro UI. New Findings connectors: AppCheck, CyCognito, Picus, Red Hat Satellite, ImmuniWeb, Trustwave Fusion, Scantist, Black Duck Continuous Dynamic, Finite State, SOOS, Ostorlab, Automox, Qwiet AI, HiddenLayer, Nozomi Networks, NetRise, Uptycs, Klocwork, Parasoft DTP, CI Fuzz, Akto, BigID, Action1, ManageEngine Vulnerability Manager Plus, Zimperium, Dragos, CyberArk Certificate Manager, Calico Cloud, Rapid7 InsightCloudSec, Holm Security, Wazuh SCA, Fleet, and Elastic Security.
* **(Connectors)** Checkmarx One branch tracking now accepts wildcard branch patterns, and JFrog Xray gained a `repository_filter` that scopes discovery before any per-repository work is done. The all-records view can now be filtered by record state.
* **(Connectors)** Fixed a Microsoft Defender export page whose body arrives truncated being dropped instead of refetched, Microsoft Defender for Cloud now tolerates Azure Resource Graph shape drift on `additionalData.cve`, and a Checkmarx One wildcard that matches no branch in the scan window now skips the sync instead of closing every finding.
* **(Performance)** Connector syncs now fetch only the records they need rather than the full record set.
* **(Security)** Hardened SAML assertion handling, and the login rate limiter now also applies to the API token authentication endpoint.
* **(Import)** Failure-path cleanup no longer masks the real import error, and import/reimport failures keep their intended status codes.
* **(Search)** The search language facet is now seeded from the authorized queryset.
* **(Bug Fixes)** The affected-engagements recompute no longer deadlocks concurrent risk acceptance updates, and stored JFrog api-summary deduplication settings are refreshed to match the current algorithm.

### July 28, 2026: v3.1.301

* **(Connectors)** Added nine parser-backed Findings connectors: Google Artifact Analysis, Zora, PingCastle, Promptfoo, Alert Logic, Cyberwatch, WebInspect Enterprise, TruffleHog, and Chef Automate. Each mirrors its existing DefectDojo parser's mapping and scan type, so connector imports and file imports land in the same parser and the same deduplication configuration. Also wired up the credential forms for the Coverity, Cobalt.io, and Nuclei connectors, and gave five connectors their own logo.
* **(Connectors)** Connector syncs can now stream Findings in chunks, so very large syncs no longer exhaust memory. Checkmarx One per-branch tracking now defaults on for new installations only, leaving existing installations on their current behavior.
* **(FIPS)** Added optional FIPS 140-3 image variants (CMVP #5247) for the connectors service, MCP server, integrators, and PSIRT advisory engine, deployable via `fips.enabled` in the Helm chart.
* **(Integrations)** Added Opsgenie and ServiceNow SecOps / Vulnerability Response outbound integrators.
* **(SSO)** Added structured attribute-mapping editors for SAML, LDAP, and OIDC in the Tuner, along with OIDC group mapping.
* **(Pro UI)** Feature Flags and Appearance are now flagged as new in the menu, and dropdown menu triggers are hidden when they have no visible items.
* **(Authorization)** Risk acceptances are now scoped by their accepted Findings, the Jira finding-mapping project field and the bulk-update target finding group are restricted to authorized objects, the member-management check is applied on every serializer exposing the field, metadata API object authorization was hardened, and finding and engagement UI actions now require POST.
* **(Bug Fixes)** Locations are now carried across a finding merge; the risk acceptance expiration job no longer aborts on an unattached risk acceptance; chained duplicates are re-pointed before excess duplicates are deleted; the deduplication hash-recompute task no longer prefetches deprecated endpoints; and the API returns a validation error instead of a 500 when `environment` is omitted.
* **(Docs)** Documented the SSO attribute-mapping editors and OIDC group mapping, and enabling the Jira integration in System Settings. Clarified that the Jira webhook secret authenticates incoming requests.

### July 27, 2026: v3.1.300

* **(RBAC)** Added user-defined Custom Roles. You can now create your own roles with a granular permission set per object type, instead of being limited to the built-in roles.
* **(Connectors)** Added another large batch of Connectors. New Findings connectors: Fortify (SSC and FoD), HCL AppScan (ASoC and AppScan 360°), Datadog Cloud Security, MobSF, Deepfence ThreatMapper, NeuVector, Lacework / FortiCNAPP, Socket.dev, Bright Security, Aqua Security, Escape, Detectify, Fairwinds Insights, Wallarm, Vanta, NowSecure, FOSSA, Codacy, DeepSource, Beagle Security, Orca, AccuKnox, Halo Security, and Nightfall AI. Connector nomenclature is now unified as Upstream and Downstream Connectors, and you can request either type from the cloud UI.
* **(Connectors)** JFrog Xray gained an artifact-level record mode, with connector-declared parents materialized as asset hierarchy edges. The new mode is on by default for new installations only, so existing installations keep their current record layout. Checkmarx One added opt-in per-branch sync via a `track_branches` toggle, which creates a separate engagement per tracked branch. Connector engagement names now include the asset name.
* **(Connectors)** Connector syncs are more resilient on large data sets.
* **(Sensei)** Added Bitbucket, Azure DevOps, and GitHub Enterprise connections, along with a Revert action and GitLab remediation support.
* **(Authentication)** Login, logout, MFA, SSO, and password reset now run natively in the Pro UI rather than falling back to the classic UI. Added a generic LDAP authentication integration, configurable from the Tuner.
* **(SSO)** Added self-serve SSO diagnostics and logs so you can troubleshoot a misconfigured provider without opening a support ticket.
* **(Feature Flags)** Organization / Asset relabeling is now a database-driven feature flag. Feature flags are also readable through the v2 API and MCP, and the legacy feature flag table was retired.
* **(Integrations)** The ServiceNow integrator now supports transition-time custom fields and `client_credentials` authentication, and surfaces integration errors in the UI.
* **(Filters)** Date filters now resolve day boundaries in the viewing user's timezone, and the SLA filter options were reworked.
* **(API)** Tightened validation and authorization across the user, product type, test, location, and endpoint reference endpoints. Configuration permission assignment is now restricted to superusers.
* **(Performance)** Reimport matching now builds a run-scoped candidate index, global search splits matching into per-lane index-served queries, and vulnerability IDs gained a case-insensitive index.
* **(Tools)** Added a Fortify parser V2 that prefers the true line number reported by the scanner. Fixed KICS severity mapping.
* **(Bug Fixes)** Report summary charts now render after the table of contents is rebuilt; connector records are marked STALE when their owner is deleted through an async cascade; non-superusers can view the MCP page while MCP is enabled; a background sub-fetch failure no longer ejects you to the error page on secondary navigation; dropdown filters keep every character you type; an explicit scalar `cwe` stays primary when a `cwes` list is also supplied; API schema generation no longer scopes serializer querysets by `AnonymousUser`.

### July 22, 2026: v3.1.202

* **(Connectors)** Registered the Intigriti bug bounty connector and the runZero asset connector in the Pro UI. The Qualys connector now sizes its request timeout for large detection exports.
* **(Integrations)** Integrator assignments now support per-assignment push filters, so you can limit what gets pushed by minimum severity and active-only status. 
* **(Sensei)** Added a cloud dispatch guard, retroactive re-staging of auto-fixes, and a per-row actions menu. Fixed the "Configure Product" button clipping in the Findings list.
* **(Findings)** Request Review is now gated on `Finding_View` instead of `Finding_Edit`.
* **(Pro UI)** Export options now prefill from the active table preference, the AI menu was flattened into top-level Sensei, Model Settings, and MCP links, and the PSIRT menu link now opens in a new tab.
* **(Import)** Scan-import cleanup now streams files and fails loudly on error.
* **(Performance)** Dashboard count tiles no longer time out on large finding buckets.
* **(Bug Fixes)** Cleared default ordering in count subqueries

### July 20, 2026: v3.1.200

* **(Connectors)** Added another large batch of Connectors. New Findings connectors: Rapid7 InsightAppSec, Cobalt.io PtaaS, Sonatype IQ (Nexus Lifecycle), Acunetix 360, Mend (WhiteSource), Bugcrowd, Black Duck, Edgescan, Sysdig Secure, Coverity Connect, Harbor, OpenVAS / Greenbone, Nuclei / ProjectDiscovery Cloud, Endor Labs, Prowler, Kubescape / ARMO, Quay + Clair, Intruder.io, and YesWeHack. Added a ServiceNow CMDB asset connector. You can now request a new connector directly from the cloud UI, and CrowdStrike Spotlight now derives its severity floor from structured sync filters.
* **(Integrations)** Added a Linear integrator for pushing Findings to Linear.
* **(Feature Flags)** Redesigned feature flags into a two-tier, metadata-driven system with a dedicated Feature Flags admin page.
* **(Findings)** Similar Findings now only surfaces genuinely similar Findings, the CVSS and EPSS columns now expose numeric filter operators, and several broken Findings-table column filters were fixed.
* **(UI)** Metric colors in the Vue UI are now configurable per instance.
* **(SSO)** Added a configurable OIDC username claim and hardened SSO user creation.
* **(Performance)** Authorized-finding queries now filter by a literal product-id list, and the paginated count-cache refill is now single-flighted to avoid redundant recounts on busy instances.
* **(Import)** The generic parser no longer produces a nested list when a finding has both a CVE and vulnerability IDs, and the Import/ReImport forms no longer touch the database at import time.
* **(Settings)** Added `DD_EDITABLE_MITIGATED_DATA` to control whether mitigation data is editable, and ignored close-finding fields are now hidden.
* **(Bug Fixes)** Connector backend config refresh now encodes datetimes correctly

### July 15, 2026: v3.1.101

* **(Findings)** Consolidated the bulk-edit actions in the Findings table into a single surface, and added bulk "replace tag" and bulk review actions.
* **(Search)** Retired the legacy Watson search backend in Pro in favor of the native Postgres global search introduced in v3.1.100. Watson indexing can now be toggled with `DD_WATSON_SEARCH_ENABLED`.
* **(Performance)** Full-table pagination counts on large API list endpoints can now be cached behind an opt-in flag, speeding up paginated list requests on big instances.
* **(SSO)** Groups created through SSO now default to the Reader role.
* **(Jira)** Fixed the "Connect with Jira" OAuth flow being blocked by hidden-field validation.
* **(Reports)** Chart blocks in report PDFs no longer capture mid-animation, so exported charts render fully drawn.

### July 13, 2026: v3.1.100

* **(Connectors)** Added a large batch of new Connectors. New Findings connectors: CrowdStrike Falcon, Microsoft Defender Vulnerability Management, Microsoft Defender for Cloud, Veracode, Qualys, Rapid7 InsightVM, GitHub Advanced Security, HackerOne, Contrast, Google Cloud Security Command Center, Shodan, Wazuh, Cloudflare, Censys, Docker Scout, and Have I Been Pwned. New asset connectors: GitLab, Atlassian JSM Assets, Bitbucket Cloud, Azure DevOps, Backstage, and Group-IB ASM. Added a GitGuardian secrets connector.
* **(Integrations)** Added new outbound integrators for Jira (Cloud and Data Center, with per-transition custom fields, ticket templates, and a test-render path), PagerDuty, Shortcut, and Bitbucket Cloud. Jira integrations now support setting fields on close/reopen transitions and Jira Cloud OAuth.
* **(Search)** Added cross-model global search backed by native Postgres full-text search and trigram indexes, so you can search across Findings and related objects from one place.
* **(Findings)** Added a public API endpoint for merging Findings, and "Not X" negation options on the finding status filter.
* **(Notes)** You can now @mention users in notes with autocomplete; mentioned users receive a notification.
* **(Users)** Added bulk API-token and password resets from the users list.
* **(Sensei)** Added candidate triage directly in the Findings table
* **(Pro UI)** Reworked the big-table toolbar menu. Long unbroken names now wrap instead of being clipped, table scrollbars stay visible on hover, and in-page navigation refreshes data in place instead of triggering a full-page reload. Added a classic-UI deprecation banner with one-click opt-in to the Pro UI. The test page now shows the effective deduplication matching policy.
* **(Authorization)** Tightened authorization on product reassignment, V3 location routes, location-reference writes, and questionnaire relink routes.
* **(Performance)** `close_old_Findings` now fetches only the columns it needs, and uWSGI workers and Celery prefork children are recycled by memory to keep long-running instances healthy.
* **(Import)** Fixed reimport so it dispatches post-processing with the correct per-finding `push_to_jira` value, stopped dynamic Test Type names from doubling the `(scan_type)` suffix, and made risk-acceptance Findings reinstate correctly when the expiration date is updated via the API.
* **(Tools)** Checkmarx One parser now handles explicit null scanner sections in filtered reports, and the CSV universal parser no longer strips backticks from imported values.
* **(Bug Fixes)** After deleting the object you were viewing, the Pro UI now lands on its parent context instead of erroring; a background sub-fetch 404 no longer ejects authorized users to the 404 page; the global loader no longer gets stuck open in bulk menus; and audit-log history context is now JSON-safe before Celery dispatch.

### July 7, 2026: v3.1.0

* **(Insights)** Added export functionality and per-metric descriptions to Insights charts.
* **(Connectors)** Added Connectors filtering\
* **(Prioritization)** Added a per-user Products/Assets count column to the prioritization engine.
* **(Import)** Import and reimport can now wait for deduplication to finish before returning. Reimport title hashing now applies the full titlecase transform for multi-line titles.
* **(Jira)** Project settings now support multiple components. Issue status is now read from `statusCategory` instead of the resolution field.
* **(Reports)** PDF reports now show vulnerability IDs.
* **(Security)** Tool Configuration credentials are now encrypted with AES-256-GCM.
* **(Pro UI)** Breadcrumbs are now deterministic and derived from the object hierarchy.
* **(Locations)** Legacy endpoint access in Make Template and Merge Findings is now guarded behind the Locations feature flag, and the finding Asset-tag (AND) filter uses the v3 Asset vocabulary.
* **(UI)** Finding Groups now fold under Findings in the sidebar; filter category accordions and collapse panels animate smoothly; right-aligned dropdown menus no longer overflow off the page edge; new-UI styling uses brand/design tokens instead of hardcoded colors; and a global required-fields notice was added for WCAG H90 compliance. The open source message banner can now be disabled and dismissed.
* **(Tools)** Added an Alert Logic CSV parser and a Garak (NVIDIA LLM vulnerability scanner) parser. The GitHub Vulnerability parser now sets `fix_available`; Dependency-Track FPF Findings now include `analysis.detail` in the description; the Trivy parser no longer crashes on legacy reports missing the `Class` field; govulncheck now rejects SARIF reports with a clear error pointing to the SARIF scan type; and JFrog Xray impact paths are now deterministic.
* **(Performance)** Faster imports and deduplication: batched `Vulnerability_Id` and `BurpRawRequestResponse` inserts, skip-unchanged-row and `VALUES` fast-write dedup paths, batched prefetching of Pro relations, Watson search index prefetch with async indexing, a new `sla_expiration_date` index for the global finding list, a case-insensitive product-name index, and a fix for finding-group Jira push N+1 queries.

### June 29, 2026: v3.0.200

* **(Reports)** Added a Graph block type to the Pro Report Builder, letting you embed Insights chart-catalog visualizations directly in reports.
* **(Pro UI)** Dashboard V2 can now be exported as a branded, paginated PDF.
* **(Pro UI)** Number columns now support multi-value "In List" / "Not In List" filtering.
* **(Findings)** KEV and EPSS data is now aggregated across all CVEs on a Finding.
* **(Custom Enrichment)** Added a dedicated error page for EPSS/KEV connectivity failures, and default KEV/EPSS URLs now persist in tuner settings across upgrades.
* **(Import)** Reimport no longer closes and recreates Findings whose titles exceed 511 characters.
* **(SSO)** The SAML configuration form now clarifies which fields are conditionally required.
* **(Permissions)** The Engagement Testing Lead selector now resolves product-scoped users, and authorized-users handling has been improved.
* **(Performance)** Heavy dashboard metric aggregations can now be cached behind `DD_METRICS_CACHE_ENABLED`.
* **(Tools)** Xygeni parser no longer deduplicates distinct SAST/Secrets Findings in the same file (now keyed on `uniqueHash`). SARIF parser now unwraps BlackDuck nested fingerprint values.
* **(Tags)** User-set tags are now preserved when creating a Finding under product tag inheritance.

### June 22, 2026: v3.0.100

* **(Pro UI)** Added native Excel (`.xlsx`) export for Findings, Engagements, and Users.
* **(Pro UI)** Bulk "Add to Existing Finding Group" no longer fails with an "Invalid pk 'None'" error.
* **(Classic UI)** Fixed the disclaimer border rendering in the new UI.
* **(Findings)** Blank component values are now normalized to NULL for consistent matching and filtering.
* **(Reports)** Added DefectDojo Pro Report Builder guides (UI, API, and LLM).
* **(Tools)** Added a PICUS Breach and Attack Simulation CSV parser.
* **(Tools)** Added a Govulncheck Scanner V2 parser.
* **(Tools)** cargo-audit parser now parses CVSS vectors and derives severity from them.

### June 18, 2026: v3.0.2

* **(SSO)** SAML now keeps the Pro group-mapping backend as the active authentication backend.
* **(API)** Restored `members` and `authorization_groups` fields on the Asset and Organization serializers.
* **(API)** Registered the `asset_*` / `organization_*` RBAC alias routes.
* **(API)** Restored RBAC fields on `/api/v2/user_profile/`.

### June 17, 2026: v3.0.1

* **(Pro UI)** Calendar sidebar now honors the "Enable Calendar" system setting.
* **(Pro UI)** Keyword search no longer blanks the Components table.
* **(Reports)** Added a Finding quick report via the reporting engine.
* **(SSO)** Azure AD configuration now requires and defaults the Application ID URI.
* **(Locations)** Single-location filter now resolves correctly against the Location model.
* **(API)** Fixed a 500 error when deleting an Organization/Asset that still has deprecated endpoints; the new-UI banner now points at 3.3.0.
* **(API)** Refactored and enhanced API permissions.

### June 15, 2026: v3.0.0

* **(Locations)** Locations are now enabled by default, superseding the legacy Endpoint model. The legacy Endpoint API stays read-compatible and your data is preserved. See [Locations enabled by default](/releases/os_upgrading/3.0/#locations-enabled-by-default).
* **(Assets & Organizations)** "Product Type" → "Organization" and "Product" → "Asset" relabeling (UI labels + URL routing) is now on by default. The change is cosmetic — API endpoints and field names are unchanged. See [Asset / Organization labels enabled by default](/releases/os_upgrading/3.0/#asset--organization-labels-enabled-by-default).
* **(Authorization)** Open Source restores the **Authorized Users** panel on Product/Product Type detail under the legacy authorization model; Pro deployments retain full RBAC and are not impacted. See [Authorized Users panel replaces Members/Groups under legacy authorization](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization).
* **(SSO)** SSO providers (SAML, OIDC, Google, Okta, Azure AD, GitLab, Auth0, Keycloak, GitHub Enterprise, remote-user header auth) are now DefectDojo Pro-only. See [SSO providers are available in DefectDojo Pro only](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only).
* **(API)** Removed the Questionnaire API endpoints. See [Removal: Questionnaire API Endpoints](/releases/os_upgrading/3.0/#removal-questionnaire-api-endpoints).
* **(API)** Removed the Credential Manager feature and its API endpoints. See [Removal: Credential Manager](/releases/os_upgrading/3.0/#removal-credential-manager).
* **(API)** Removed the Stub Findings feature and its API endpoint. See [Removal: Stub Findings](/releases/os_upgrading/3.0/#removal-stub-findings).
* **(Search)** Watson search index updates during import/reimport are now batched, tunable via `DD_WATSON_ASYNC_INDEX_UPDATE_BATCH_SIZE`. See [Configuration change in Watson Search Indexing](/releases/os_upgrading/3.0/#configuration-change-in-watson-search-indexing).

## May 2026: v2.58

### May 26, 2026: v2.58.4

* **(Pro UI)** Migrated the Pro UI select buttons to the new shared component for consistent behavior across forms.
* **(Reports)** Lowered the minimum permission required to access reporting, so more roles can reach reports without elevated privileges.
* **(Tools)** CycloneDX parser no longer drops the `vector` field on import.

### May 18, 2026: v2.58.3

* **(Licensing)** Pro features are now blocked at 130% license usage, with weekly finding-usage enforcement backed by a new auditable multi-enforcement License Policy. The capacity alert threshold was raised from 80% to 90%.
* **(Pro UI)** Added UI support for relative location relationships.
* **(Permissions)** Finding duplicate API actions now enforce object-level permission checks, report views are scoped to the requesting user's authorized products, and location finding references are anchored to the finding's own product.

### May 11, 2026: v2.58.2

* **(Connectors)** Connectors now support subtypes, so a single connector type can be configured against multiple flavors of the same upstream tool.
* **(Pro UI)** Jira push success/error messages are now displayed correctly in the Pro UI, so it's clear whether the push actually reached Jira.
* **(MCP)** MCP acknowledgement settings are now consistent across superusers, so toggling acknowledgement no longer drifts between admin accounts.
* **(Classic UI)** The Celery Status page is now gated behind the `celery_status` feature flag, off by default.

### May 6, 2026: v2.58.1

* **(Pro UI)** You can now activate or deactivate Test Types and Users directly from their list menus, so retiring or restoring entries no longer requires opening the edit form.
* **(Pro UI)** Anchor links now open in a new tab as expected, so following a reference no longer pulls you away from the page you were working on.
* **(Pro UI)** Adding Findings to an existing Risk Acceptance works reliably again. A recent performance improvement caused the form to fail for some users; you can now resume managing accepted Findings without errors.
* **(Pro UI)** Your customized table column order is now preserved across page refreshes. Previously only column visibility carried over, so any rearranging you did would silently revert to the default — forcing you to reorder columns every session.
* **(API)** Fixed a 500 error when fetching vulnerable endpoints (`GET /api/vue/endpoints/{id}/vulnerable/`), restoring reliable access to vulnerability data for an endpoint.

### May 4, 2026: v2.58.0

* **(Pro UI)** Added shared table preferences so saved column/filter configurations on list views can be shared across users.
* **(Pro UI)** Markdown content now wraps text correctly, preventing horizontal overflow on long lines.
* **(Performance)** Pro UI List Virtualization
* **(Performance)** Improved import performance by optimizing import queries and bulk-applying parser-supplied per-finding tags.
* **(Performance)** Locations endpoints optimized for faster retrieval on large datasets.
* **(SBOM)** SBOM imports now support replace mode for re-importing the full inventory of a component set.
* **(Reports)** Beat Reporting feature is now available for Cloud subscribers
* **(API)** Added `created` and `updated` date filters to the Risk Acceptance API.
* **(Jira)** Webhook handler no longer mis-mitigates Findings on non-"done" Jira issue transitions.
* **(Deployment)** Default Celery task serializer is now JSON, removing pickle from the task dispatch path.
* **(Tools)** Added Qualys VMDR CSV parser.
* **(Tools)** Coverity API parser now supports `RESOURCE_LEAK` quality Findings.
* **(Tools)** SonarQube parser now falls back to `mdDesc` when populating finding descriptions.
* **(Settings)** `MAX_ZIP_*` limits are now configurable via settings.

## Apr 2026: v2.57

### Apr 27, 2026: v2.57.3

* **(Pro UI)** Asset menu now shows the Permissions tab for users with an inherited Organization role.
* **(Pro UI)** Added an Environment column to the Test list and Findings list.
* **(Pro UI)** Asset hierarchy refreshes immediately after editing an asset, so changes are reflected without a manual reload.
* **(Pro UI)** Standardized the "Test Type" label and split Test and Test Type into separate columns on the test list.
* **(Pro UI)** Corrected the Product column label on the Group page under the V3 relabeling.
* **(Pro UI)** Removed the duplicate greeting message shown after login.
* **(Performance)** Create-path notifications are now dispatched asynchronously, removing a source of slow POST latency.
* **(Deployment)** On premise deployments now include the Orchestrator services. Please see [additional instructions](/releases/pro/ddorch-database) for more details
* **(Notifications)** Improved the format and display of SLA breach notifications.
* **(Engineer Metrics)** Fixed a KeyError that could be raised when loading the Engineer Metrics page.
* **(Tools)** Contrast parser no longer collapses distinct Findings that share a rule name.
* **(Tools)** Dependency Track parser no longer drops vulnerability IDs when `aliases` is empty.
* **(Tools)** Added WatchGuard security advisories as a supported Vulnerability ID source.

### Apr 20, 2026: v2.57.2

* **(Pro UI)** Search and filter state is now preserved when closing a Finding from a Finding list, so you don't lose your place after editing.
* **(Risk Acceptance)** Bulk Edit no longer leaves Simple Risk Acceptance Findings in an inconsistent "Active + Risk Accepted" state. Reactivating a previously risk-accepted Finding now behaves correctly.
* **(Risk SLA)** Creating a Risk SLA no longer silently coerces unchecked `enforce_*_risk` options to `True`.
* **(Surveys)** Fixed survey access for both authenticated users and anonymous links.
* **(Universal Parser)** Non-ASCII scan names no longer cause a `UnicodeEncodeError` on import. CSV files with `""`-escaped quotes in multiline fields now parse correctly.
* **(API)** Import/Reimport now validates consistency between ID-based and name-based identifiers, catching mismatched payloads earlier.
* **(Permissions)** Moving an Engagement between Products now requires appropriate permission on both the source and target Product.
* **(Reports)** Fixed a CSS overflow issue in rendered reports. Cleaned up endpoint template rendering for user fields.
* **(Tools)** `govulncheck` parser now records `fix_available` and `fix_version`. Risk Recon parser now validates URLs via a shared SSRF utility. Added Mozilla Foundation security advisories as a supported Vulnerability ID source.

### Apr 13, 2026: v2.57.1

* **(Pro UI)** Object-level history views no longer default to a 31-day date filter, so the full history is visible on load.
* **(Pro UI)** Audit Log "changes" filter now searches only the names of changed fields, reducing false matches.
* **(Pro UI)** Predefined Finding filters now sync UI state correctly, so the active filter indicator reflects the applied filter.
* **(Deduplication)** Added a UI for global component deduplication settings, behind a feature flag.
* **(Rules Engine)** Fixed a preview timeout that occurred when rules were previewed against large Finding sets.
* **(Universal Parser)** CSV/XML query path now displays correctly in the Universal Parser UI.
* **(Import)** Additional parameters are now stored in import settings, making them available for reuse on reimport.
* **(Tools)** Wazuh 4.8 parser now correctly attaches endpoints and locations to Findings.
* **(Tools)** Invicti parser now uses `FirstSeenDate` when populating Finding dates when `DD_USE_FIRST_SEEN` is enabled.
* **(Tools)** `govulncheck` parser fixed for NDJSON output.
* **(Tools)** Added CNNVD as a supported Vulnerability ID source.

### Apr 7, 2026: v2.57.0

* **(Custom Enrichment)** On-prem administrators can now configure custom URLs for EPSS and KEV enrichment data sources under **Settings → Finding Enrichment Settings**. Each source (EPSS scores and CISA Known Exploited Vulnerabilities) can be independently enabled and pointed to an internal mirror or proxy. A **Test Configuration** button validates connectivity before saving. Findings with CVE IDs are automatically enriched with EPSS score/percentile and KEV status during enrichment runs.
* **(Performance)** Optimized API response times across all endpoints with selective field loading and conditional prefetches.
* **(Performance)** Improved Dashboard load times by eliminating redundant authorization queries and caching license lookups.
* **(Performance)** Improved deduplication performance by batching duplicate marking and deferring large text fields.
* **(Performance)** Improved false-positive history processing performance during async imports by using batch operations.
* **(Pro UI)** Asset hierarchy filter dropdowns now only show relevant options (e.g., Parent filter shows only assets that have children).
* **(Security)** Hardened container configurations for improved runtime security.
* **(Universal Parser)** Added a list view and field mappings modal to the Pro UI for managing Universal Parser configurations.
* **(Universal Parser)** Added support for 7 new fields: `file_path`, `component_name`, `component_version`, `line`, `steps_to_reproduce`, `severity_justification`, and CVSSv4 vectors.

## Mar 2026: v2.56

### Mar 30, 2026: v2.56.4

* **(Deduplication)** Fixed an issue where cross-tool deduplication could silently fail to match duplicates when Findings were imported across different scan tools.
* **(Pro UI)** Audit Log table now supports global search and query parameter–based filtering.
* **(Pro UI)** Improved page load performance for large listing tables (Findings, Endpoints, etc.) by reducing unnecessary computation during pagination.

### Mar 23, 2026: v2.56.3

* **(MFA)** All authenticated users can now access their own MFA settings page, regardless of role.
* **(Pro UI)** Alerts table now uses server-side filtering, sorting, and pagination for improved performance.
* **(Pro UI)** Removed the deprecated Credentials section from System Settings.
* **(Pro UI)** Fixed boolean filters on the Product Types table for the Critical and Key Asset columns.
* **(Pro UI)** Fixed a filter alignment issue on the Engagements table.
* **(Pro UI)** Standardized the Test field label to "Title" across all screens.
* **(Rules Engine)** Fixed a timeout (502 error) that could occur when previewing rules against a large number of Findings.

### Mar 16, 2026: v2.56.2

* **(API)** Added pagination limit enforcement and deprecation warnings for unpaginated API requests.
* **(Jira)** Custom field values are now properly encoded and decoded as JSON, with validation errors shown for invalid input.
* **(Pro UI)** The New Risk Acceptance form now pre-fills the expiration date using the system default number of days.
* **(Pro UI)** Improved handling of Group membership and permissions in the UI.
* **(SBOM)** SBOM imports are now processed asynchronously, improving upload responsiveness for large files.

### Mar 12, 2026: v2.56.1

* **(Pro UI)** Finding Groups can now be filtered by computed status: resolved, active, or risk-accepted.
* **(Users)** Filters selected on the Users List are now included when exporting to CSV, so your export reflects the current view.
* **(Jira)** Basic auth failures with Jira are now surfaced as warnings, making it easier to diagnose connection issues.

### Mar 5, 2026: v2.56.0

* **(API)** Restricted Note Types are now accessible via the API.
* **(Connectors)** Added **IriusRisk** connector: see [tools reference](/connectors/toolreference/upstream/) for configuration instructions.
* **(SAML)** SAML settings now support optional group attributes, allowing configurations that don't provide group mappings to work without errors.
* **(SMTP)** Fixed an issue where DefectDojo would attempt SMTP authentication even when no credentials were configured, which could cause email delivery failures.
* **(Universal Parser)** The Universal Parser now falls back to `clevercsv` for non-standard or malformed CSV files, improving compatibility with edge-case scanner outputs.


## Feb 2026: v2.55

### Feb 26, 2026: v2.55.5

* **(Rules Engine)** Rules Engine now automatically retries when encountering database lock contention or serialization conflicts, reducing the likelihood of a rule run failing due to temporary load on the system.

### Feb 24, 2026: v2.55.4

* **(Connectors)** Added Akamai API Security, JFrog Xray to Connectors.
* **(Surveys)** Anonymous surveys: users can now access surveys without logging in when anonymous surveys are enabled.
* **(Pro UI)** The Pro UI editor now uses Markdown-based editing for text fields.  This resolves issues with HTML-string encoding, especially when Findings were manually entered or edited.
* **(Rules Engine)** Added **Set Mitigation Policy** action type: Rules can now assign a pre-configured Mitigation Policy to matching Findings.
* **(Rules Engine)** Added **Add to Risk Acceptance** action type: Rules can now add matching Findings to an existing Risk Acceptance record, automatically setting them as risk-accepted and inactive, and handling Jira integration and endpoint statuses.

### Feb 17, 2026: v2.55.3

* **(Pro UI)** Added “Scheduled” status to Engagements to enhances the tracking and management of Engagements.

### Feb 10, 2026: v2.55.2

* **(Pro UI)** Enhanced Organization addition permissions with configuration checks.

### Feb 4, 2026: v2.55.1

* **(Pro UI)** Findings: Added support for Custom Fields; key-value pairs that can be added to Findings.
* **(Pro UI)** Fixed an issue where a date filter could throw a 500 error.

### Feb 2, 2026: v2.55.0

* **(Pro UI)** Risk Acceptances can now have Notes added.
* **(Pro UI)** Note Types are now available in the Pro UI.

## Jan 2026: v2.54

### Jan 27, 2026: v2.54.3

* **(Connectors)** Added a "Pending" status to Connectors when Sync or Discovery operations are in progress.
* **(Pro UI)** Findings Under Review can now be Mitigated when clearing Review.
* **(Pro UI)** An Asset's Parent and Child Assets can now be quickly added to a Pro Metrics query.


### Jan 20, 2026: v2.54.2

* **(Pro UI)** corrected a bug where unordered lists would display as ordered lists in editor forms.
* **(Smart Upload)** introduced severity filtering to the Smart Importer to skip Findings below a specified severity level. Added detailed logging throughout the Findings processing to improve traceability and debugging.

### Jan 12, 2026: v2.54.1

* **(AI Tools)** added Risk Scores to schema for MCP processing.

### Jan 5, 2026: v2.54.0

No significant UX changes.

## Dec 2025: v2.53

#### Dec 29, 2025: v2.53.5

* **(Pro UI)** Added Finding count columns to Engagement table.
* **(Pro UI)** Enter/Return no longer automatically submits forms.

#### Dec 22, 2025: v2.53.4

* **(Pro UI)** Asset Hierarchy now uses separate tabs for Asset selection and for the rendered Asset tree:
![image](images/asset-hierarchy-2.53.4.png)

#### Dec 15, 2025: v2.53.3

*DefectDojo v2.53.2 does not have a corresponding Pro release.*

* **(Connectors)** Support for private CA certificates has been added to Connectors to assist with connectivity.

#### Dec 8, 2025: v2.53.1

* **(Assets/Organizations)** Introduced overhaul to Products/Product Types, added the ability to create and diagram relationships between Assets.  See [Assets/Organizations documentation](/asset_modelling/pro_hierarchy/asset_hierarchy/) for details, and information on opting in to the Beta.
* **(Findings)** Added new KEV fields for ransomware, exploits, and date handling.
* **(Pro UI)** Added Table Preferences menu, allowing you to store preset lists of columns for each table.

![image](images/pro_tablepreferences.png)

#### Dec 1, 2025: v2.53.0

* **(Pro UI)** Added Asset Hierarchy.
* **(Priority)** Priority and Risk can now be overridden manually, or through Rules Engine.

## Nov 2025: v2.52

#### Nov 24, 2025: v2.52.3

* **(Pro UI)** Improved error messaging for failed Imports.
* **(Pro UI)** Added Engagement Tags column to Finding lists


#### Nov 17, 2025: v2.52.2

* No significant feature changes.

#### Nov 10, 2025: v2.52.1

* **(Pro UI)** Finding view now shows all associated Endpoints, not just Active Endpoints


#### Nov 3, 2025: v2.52.0

* **(Pro UI)** In-app Contact Support form now requires a valid email address in your user profile.
* **(Pro UI)** You can now Add Files to Findings through the Pro UI directly from Finding Lists.
* **(Pro UI)** Unicode letters are now allowed in Tags.

## Oct 2025: v2.51

#### Oct 27, 2025: v2.51.3

* **(Tools)** Added Nuclei scan support for Smart Upload.
* **(Priority)** Added Prioritization Engine to allow for configurable Priority and Risk calculations for individual Findings under a given Product.
* **(Metrics)** Updated Metrics table to include Products with zero Findings (as a result of filter parameters, or otherwise).
* **(Pro UI)** Added Surveys to Pro UI.



#### Oct 20, 2025: v2.51.2

* **(Connectors)** Added Anchore Enterprise Connector.
* **(Rules Engine)** Rules can now be scheduled to run automatically on a recurring or one-time basis.  From the Rules list, use the **⋮** menu on any rule to open the **Schedule Rule** form.


#### Oct 14, 2025: v2.51.1

* **(Pro UI)** Added Finding Quick Report feature.  Quick report allows users to quickly render an HTML report with the currently displayed Findings on a Finding table.

![image](images/quick_report.png)

* **(Pro UI)** Added vector builder and calculator to the Edit Finding form, for CVSSv3 and CVSSv4.  You can build vector strings using the 🛠️ button next to the CVSSv3 / CVSSv4 string entry on the Edit Finding form.

Click the calculator button to render a score based on the vector string.

![image](images/pro_cvss_vector_and_score.png)
![image](images/cvssv4_vector_builder.png)

* **(Pro UI)** Added Similar Findings view on Findings when enabled in System Settings.  
* **(Pro UI)** File names (for attached artifacts) can now be edited directly in the UI.
* **(Pro UI)** Redirect user to Home after a successful Support Inquiry submission.  

#### Oct 6, 2025: v2.51.0

No significant Pro changes are present in this release.

## Sept 2025: v2.50

#### Sept 29, 2025: v2.50.4

* **(MCP)** Added MCP toggle for Superusers only.
* **(Pro UI)** Bypassed endpoint validation on Edit Finding form when Endpoints have not changed.
* **(Pro UI)** Collapsed additional fields in the Universal Parser preview for cleaner display.
* **(Pro UI)** Updated Engagement Deduplication form label and help text for clarity.

#### Sept 22, 2025: v2.50.3

* **(Pro UI)** Added support for [CVSSv4.0](https://www.first.org/cvss/v4-0/) vector strings.

#### Sept 15, 2025: v2.50.2

* **(Pro UI)** Added Any/All status filtering.  Filtering by status allows you to apply either AND (inner join) logic, or OR (outer join) logic to the filter.
* **(Pro UI)** Added Contact Support form for On-Premise installs.

#### Sept 9, 2025: v2.50.1

* **(Tools)** Removed CSV limit for Qualys HackerGuardian
* **(SSO)** Removed Force Password Reset for users created via SSO

#### Sept 2, 2025: v2.50.0

* **(Pro UI)** "Date During" filter has been added to the UI, allowing users to filter by a range of dates
* **(Pro UI)** Vulnerability ID column can now be sorted, however the sorting only considers the **first** vulnerability ID.
* **(Pro UI)** Request/Response pairs can now be added / updated / deleted via the Edit Finding form.

## August 2025: v2.49

The Pro UI has been significantly reorganized, with changes to page organization.
![image](images/pro_ui_249.png)

#### August 25: 2.49.3

[Integrations](/connectors/issue_tracking/) has been added to DefectDojo Pro, adding an Jira-style integrations for Azure DevOps, GitHub and GitLab boards.

* **(API)** Basic Auth Login has been removed from the swagger form.  Only cookieAuth and tokenAuth are accepted.
* **(API)** When MFA is enabled, an MFA code will be required to use the `/api-token-auth` endpoint.
* **(Connectors)** "Location" has been renamed to "Location URL" in Connectors setup form.
* **(Universal Parser)** Fixed an issue where a False value in an Active key still created an Active Finding.
* **(Pro UI)** Unique ID from Tool has been added to the Findings list and Finding view
* **(Pro UI)** Test Status added to Test View.
* **(Pro UI)** Added additional Import/Reimport success messages to confirm successful test creation.


## July 2025: v2.48

### July 21/22/28, 2025: v2.48.3 / v2.48.4 / v2.48.5

- No significant UI/UX changes.

### July 14, 2025: v2.48.2

- **(Findings)** KEV ([Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)) related data can now be added as metadata to Findings. 
![image](images/findings_kev.png)

### July 8, 2025: v2.48.1

- **(Permissions)** Users with "Edit Users" configuration permission can now force password resets for other users.
- **(Pro UI)** The Users listing now includes pre-filtered views for All, Active, Inactive, Superuser, and Global Owner users. The default view has been set to Active.
- **(Pro UI)** Request/Response pairs are now displayed on Finding View.
- **(Pro UI)** Product Technologies are now visible and can be created, edited and deleted from the View Product page, within the Product Overview’s “Technologies” section.
- **(Pro UI)** Finding peer-review now supports the assignment of both Users and Groups, as well as an “Allow All Eligible Reviewers” (all users with access to the Finding) option.

### July 1, 2025: v2.48

- **(Pro UI)** Helptext has been added to the Private Note checkbox to better explain this feature.  Private Notes are Notes that will not appear in Generated Reports - only in the DefectDojo UI.  This feature can be used for internal communication that you don't want to include in a Report.

- **(Pro UI)** Pro UI is now set as the default user interface. All new and existing users/instances will be directed to the Pro UI by default. Users can still opt-out of this UI by unchecking this checkbox:

![image](images/pro_ui_default.png)

## June 2025: v2.47

#### July 1, 2025: v2.47.4

- **(Pro UI)** Products, Engagements, Tests, Findings and Endpoints can be edited directly from their respective tables via a modal.
- **(Pro UI)** Calendar view now supports additional query parameters for filtering Tests or Engagements.
- **(Pro UI)** Engagements, Tests and the entire Calendar can be exported as .ics files.

![image](images/pro_ics_export.png)

#### June 23, 2025: v2.47.3

- **(Pro UI)** Finding Templates can now be added in the Pro UI, from **Findings > Finding Templates** on the sidebar.
- **(Pro UI)** A better error message is displayed when Jira Instance deletion is unsuccessful.
- **(Pro UI)** Product Types can now be edited through a modal: **"⋮" > Edit Product Type** will open a pop-up modal window instead of taking a user to a new page.

![image](images/pro_product_type_modal.png)

#### June 16, 2025: v2.47.2

- **(Pro UI)** Endpoint Metadata can now be uploaded to Products.  You can now import a .csv list of all endpoints associated with a Product, from **View Product > Endpoints > Import Endpoint Metadata**

![image](images/pro_endpoint_metadata.png)

- **(Pro UI)** Pie Charts for Metrics now dynamically update based on selected categories.
- **(Pro UI)** Finding metadata (specifically notes, endpoints, and file path/line number) are now visible from the Findings table if present.
- **(Pro UI)** Findings table now uses icons to identify linked Endpoints, Notes or Files.  Clicking the Endpoints or Notes icon opens a window which lists all Endpoints or Notes.

![image](images/pro_finding_icons.png)

- **(Pro UI)** Login page has been redesigned.

![image](images/pro_login.png)

#### June 9, 2025: v2.47.1

- **(Pro UI)** Vulnerable Endpoints table has now been added to Finding pages.

![image](images/pro_vulnerable_endpoints.png)

- **(Pro UI)** "Original Finding" link has been added to Finding Metadata table for Duplicate Findings.
- **(Pro UI)** CI/CD Metadata has been added to Engagement view.

#### June 2, 2025: v2.47.0

- **(Pro UI)** Finding review can now be set through the Pro UI.  You can now Request Review or clear a Finding review from Finding tables, or from the Finding View.

![image](images/pro_request_review.png)

- **(Pro UI)** Artifact files can now be uploaded through the Pro UI to Findings.  These files can be viewed or deleted on the **Finding Overview > Files** tab of a Finding page.

![image](images/pro_upload_file.png)


## May 2025: v2.46

### ⚠️ Tag Format Change 

As of version 2.46.0, Tags can no longer contain the following characters:
- Commas (,)
- Quotations (both single ' and double ")
- Spaces

To ensure a smooth transition, an automatic migration will be applied to existing tags as follows:
- Commas → Replaced with hyphens (-)
- Quotations (single and double) → Removed
- Spaces → Replaced with underscores (_)
Examples
- example,tag → example-tag
- 'SingleQuoted' → SingleQuoted
- "DoubleQuoted" → DoubleQuoted
- space separated tag → space_separated_tag

This update improves consistency, enhances DefectDojo's search capabilities, and aligns with best practices for tag formatting.

We recommend reviewing your current tags to ensure they align with the new format.  Following the deployment of these new behaviors, requests sent to the API or through the UI with any of the violations listed above will result in an error, with the details of the error raised in the response.

#### May 26, 2025: v2.46.4

- **(Pro Metrics)** Rework of filter menu within insights dashboards to remove cross Product Type and Product filtering capabilities.
- **(Pro UI)** Clickable links within insights dashboards.
- **(Pro UI)** You can now differentiate between **AppSec** and **SOC** Test Types, to specify whether Findings in DefectDojo were created by an AppSec or SOC process.  You can assign the SOC label by editing a Test Type in the Pro UI:

![image](images/pro_test_types.png)

Whether a Finding is "AppSec" or "SOC" depends on the parent Test Type.  If a Test Type does not have SOC set, all of the Findings associated with this Test Type will be considered "AppSec".

The Priority Insights dashboard can quickly render a list of all SOC or AppSec Findings, ordered by Priority.

![image](images/pro_soc_filter.png)

- **(Pro UI)** More detailed messages in Bulk Edit provide a better explanation of why some Findings may have been skipped.

#### May 19, 2025: v2.46.3

- **(Calendar)** New filters have been added to Calendar view: Unassigned Lead, and Engagement/Test Type.
- **(Dashboard)** Added Finding Status filter for Dashboard tiles.
- **(Engagements)** A repository URI can be added to an Engagement via **Edit Engagement > Optional Fields > Repo**.  If this field is set, Findings under that Engagement will automatically generate clickable links to the source code if File Path is set on the Finding.  See [docs](/asset_modelling/os_hierarchy/os__source-code-repositories/) for more details.
- **(Findings)** Added "Jira Issue URL" column to the CSV export of Finding tables.
- **(Metrics)** Priority Dashboard has been added to Metrics, to display your organization's risk profile at a glance.
![image](images/pro_dashboard_priority.png)
- **(Universal Parser)** Added a 'SOC Alerts' flag to Universal Parser, to indicate whether the Findings from the parser originate from a Security Operations Center.

#### May 12, 2025: v2.46.2

- **(Findings)** Component Name and Version have been added to the metadata table on a Finding View.
- **(Metrics)** Pro Insights Dashboards can now be filtered by Tag.
- **(Users)** The Users table can now be exported as a .csv file.

#### May 7, 2025: v2.46.1

Hotfix release - no significant feature changes.

#### May 5, 2025: v2.46.0


- **(Import)** Mitigated timestamp in reports are no longer ignored/overwritten on Reimport.
- **(Tools)** Fortify Webinspect has been added as a supported tool.
- **(Tools)** Added JSON as a supported tool for Immuniweb.
- **(Tools)** Nessus (Tenable) parser now handles additional fields.
- **(Tools)** Wiz parser now handles additional fields and unique_id_from_tool.


## Apr 2025: v2.45

#### Apr 28, 2025: v2.45.3

- **(Import)** Reimporting a scan can now handle special statuses assigned by a tool.  Now, if a Finding was initially imported as Active, but the status was changed to False Positive, Out Of Scope or Risk Accepted by a subsequent report, that status will now be respected and applied to the Finding by Reimport.
- **(Tools)** Fortify parser can now assign False Positive status to Findings according to the audit.xml file.

#### Apr 22, 2025: v2.45.2

![image](images/risk_table.png)

- **(Pro UI)** Added a link to Universal Importer to the sidebar, which provides access to the [Universal Importer and DefectDojo CLI](/import_data/pro/specialized_import/external_tools/) tools.
- **(Pro UI)** Added smart Prioritization and Risk fields to DefectDojo Pro, which can be used to more easily triage Findings based on the impact of the Product they affect.  See [Priority](/asset_modelling/pro_hierarchy/priority_sla/) documentation for more information.
- **(Tools)** Updated Fortify Webinspect parser to handle Fortify's new XML report format.

#### Apr 14, 2025: v2.45.1

- **(Connectors)** Added a Connector for Wiz: see [tools reference](/connectors/toolreference/upstream/) for configuration instructions.

#### Apr 7, 2025: v2.45.0

- **(Pro UI)** Added Calendar view to Pro UI: Calendar view now displays Tests and Engagements, and can be filtered.  Clicking on a Calendar entry now displays a more detailed description of the object.
![image](images/pro_calendar_view.png)
- **(Universal Parser)** Added the ability to map an EPSS score from a file.  Note that this field **will** be updated by EPSS database sync, but this gives a user the ability to capture that field from initial import.

## Mar 2025: v2.44

#### Mar 31, 2025: v2.44.4

- **(Pro UI)** Group and Configuration permissions can now be assigned quickly from a User page.  For more information, see [DefectDojo Pro Permissions](/admin/user_management/pro_permissions_overhaul/).

#### Mar 24, 2025: v2.44.3

- **(Import)** Generic Findings Import will now parse tags in the JSON payload when Async Import is enabled.

#### Mar 17, 2025: v2.44.2

- **(Pro UI)** Added a new method to quickly assign permissions to Products or Product Types.  See our [Pro Permissions](/admin/user_management/pro_permissions_overhaul/) for more details.

![image](images/pro_permissions_2.png)

#### Mar 10, 2025: v2.44.1

- **(Pro UI)** Added a field in the View Engagement page which allows a user to navigate to the linked Jira Epic, if one exists.
- **(Universal Parser)** XML is now a supported file type for Universal Parser.
- **(SSO)** SSO can now be set up with any kind of [OIDC Configuration](https://auth0.com/docs/authenticate/protocols/openid-connect-protocol).  See OIDC Settings in the Pro UI:

![image](images/oidc.png)

#### Mar 3, 2025: v2.44.0

- **(Pro UI)** Breadcrumbs have been overhauled to better represent the context each page exists in.  Breadcrumbs will now include filtering and query parameters.  The titles of tables now better represent their context, for example when looking at the Engagements list for a particular Product, the view will be titled {Product Name} Engagements, rather than All Engagements as before.

## Feb 2025: v2.43

#### Feb 24, 2025: v2.43.4

- **(API)** API can now filter Findings by tag using AND, in addition to OR.  This can be done with the `tags__and` API filter.
- **(Connectors)** Users of AWS Security Hub, Snyk can now set a minimum Severity level for Findings to limit the amount of data imported via Connector.  Findings below the minimum Severity level will not be imported.  If Minimum Severity is changed, existing Findings below the new Minimum Severity will be Closed (not deleted).
- **(Pro Metrics)** Tool Insights can now be filtered with specific Date values, rather than simply 'past 30 days', etc.

#### Feb 19, 2025: v2.43.3

- **(API)** `/audit_log` has been added as an API endpoint for DefectDojo Pro, which can return a JSON report of all user activity, or filter by object ID. <span style="background-color:rgba(242, 86, 29, 0.5)">(Pro)</span>
- **(Pro UI)** Vulnerability ID can now be edited for a given Finding, using the Edit Finding page.  This allows users to manually identify duplicates by assigning a matching Vulnerability ID to an additional Finding.

#### Feb 12, 2025: v2.43.2

- **(Pro UI)** Tests and Risk Acceptances can now be added directly from the All Tests / All Risk Acceptances lists.
- **(CLI Tools)** Added a `background-import` flag to allow for asynchronous imports or reimports.
- **(Connectors)** Users of Burp, SonarQube and Dependency-Track Connectors can now set a minimum Severity level for Findings to limit the amount of data imported via Connector.  Findings below the minimum Severity level will not be imported.  If Minimum Severity is changed, existing Findings below the new Minimum Severity will be Closed (not deleted).
- **(API)** Fixed issue where Findings created by API with methods other than `/import` / `/reimport` were not being identified as duplicates.
- **(Findings)** 'Close Old Findings' will now apply 'Unique ID From Tool' deduplication, if this algorithm is in use for a set of Findings.

#### Feb 10, 2025: v2.43.1

- **(Pro UI)** Added 'Has Jira' (True/False) as a filter, to filter Findings, Products or Engagements that have associated Jira data.
- **(Pro UI)** Notes can now be added to Engagement / Findings / Tests from All Engagements / Findings / Tests lists as well as View Engagement / Findings / Tests pages.
- **(Pro UI)** Added ability to Close Finding from a Finding List, without needing to first open the Edit Finding form.
- **(CLI Tools)** Improved help text for Universal Importer / DefectDojo CLI. Many guides and examples are now in our [docs](/import_data/pro/specialized_import/external_tools/) instead of being displayed in the CLI itself.
- **(Tools)** Updated Burp scan to use Hashcode Deduplication.  Default hashcode forms are `title`, `file_path`, `severity`, and `vuln_id_from_tool`.
- **(Tools)** Corrected issue with AWS Inspector2 OSS parser related to `mitigated date` being handled incorrectly.

#### Feb 3, 2025: v2.43.0

- **(Pro UI)** Users can now upload local SAML metadata when configuring SAML.
- **(Pro UI)** Added new section on Risk Acceptance Form to allow users to upload 'Proof'; any relevant files that can be used to support a Risk Acceptance (emails, screenshots of communication, policies, etc).
- **(Connectors)** Users of Semgrep and Tenable Connectors can now set a minimum Severity level for Findings to limit the amount of data imported via Connector.  Findings below the minimum Severity level will not be imported.  If Minimum Severity is changed, existing Findings below the new Minimum Severity will be Closed (not deleted).
- **(Reimport)** Clarified 'no change' state in Import History with message 'There were no Findings created, closed, or modified'.
- **(Jira)** Next-Gen Epic creation from an Engagement no longer requires an Epic Name to be set, and will instead use an Epic ID value if Epic Name fails.
- **(Jira)** Removed HTML encoding from strings that are sent to Jira, to prevent escape characters from being added to issue descriptions unnecessarily.
- **(System Settings)** Split up the 'Disclaimer' function, allowing boilerplate 'Disclaimer' text to be displayed in Notifications, Reports, or Notes.

## Jan 2025: v2.42

#### Jan 27, 2025: v2.42.3

- **(Connectors)** Added 'minimum severity' filter for Semgrep and Tenable Connectors.  If you want to only upload Findings of a certain severity and up, you can set a filter for this under 'Minimum Severity' in your Connector options.

![image](images/connectors_min_severity.png)

Previously synced Findings that are no longer within the filter parameters will be set to Closed upon the following Sync operation.
- **(API)** Prefetching multiple parameters now returns all prefetched objects in an array.

#### Jan 21, 2025: v2.42.2

- **(Classic UI)** Corrected link to Smart Upload form.
- **(CLI Tools)** Fixed issue with .exe extensions not getting added to Windows binaries
- **(Findings)** `Mitigated` filter now uses datetime instead of date for filtering.
- **(OAuth)** Clarified Azure AD labels to better align with Azure's language.  Default value for Azure Resource is now set. <span style="background-color:rgba(242, 86, 29, 0.5)">(Pro)</span>
- **(RBAC)** Request Review now applies RBAC properly with regard to User Groups.

#### Jan 13, 2025: v2.42.1

- **(API)** Pro users can now specify the fields they want to return in a given API payload.  For example, this request will only return the title, severity and description fields for each Finding.  <span style="background-color:rgba(242, 86, 29, 0.5)">(Pro)</span>
```
curl -X 'GET' \
  'https://localhost/api/v2/findings/?response_fields=title,severity,description' \
  -H 'accept: application/json'
```
- **(Findings)** Excel and CSV exports now include tags.
- **(Reports)** Reports now exclude unenforced SLAs from Executive Summary to avoid confusion.
- **(Risk Acceptance)** Simple Risk Acceptances now have a 'paper trail' created - when they are added or removed, a note will be added to the Finding to log the action.
- **(Tools)** ImageTags are now included with AWS SecurityHub and AWS inspector parsers.

#### Jan 6, 2025: v2.42.0

- **(API)** `/test_reimport` results can now be ordered via id, created, modified, version, branch_tag, build_id, and commit_hash.
- **(Jira)** When a Risk Acceptance expires, linked Jira Group issues will now be updated to reflect the status change.

## Dec 2024: v2.41

#### Dec 31, 2024: v2.41.4

- **(API)** 'Force To Active / Verified' flag is no longer required when calling `/import-scan`, `/reimport-scan` endponts: a value of True now forces to Active, False now forces to Inactive, while setting a value of none (or not using the flag) will use the tool's status.
- **(Pro UI)** Added ability to regenerate / copy your API token.
- **(Pro UI)** Fixed bug preventing date / planned remediation dates from being added via Bulk Edit.
- **(Import)** Added fields for EPSS score and percentile to Generic Findings Import parser.

#### Dec 24, 2024: v2.41.3

- **(API)** Added `/request_response_pairs` endpoint.
- **(Pro UI)** When sorting by Severity, Findings will now be ordered by **severity level** rather than alphabetically.
- **(Pro UI)** On the Findings table, the Endpoint Hosts column has been replaced with a numerical count of affected Endpoints.
- **(Pro UI)** On the Findings table, the Vulnerability ID field can now be filtered with "starts_with", "ends_with" filters.
- **(Pro UI)** Added Edit Test Type form: you can now edit the properties of a custom Test Type to determine if it is Active or Inactive, or a Static Scan or Dynamic Scan Test.
- **(Pro UI)** Same Tool Deduplication Settings / Test Type field is now searchable.
- **(Tools)** Qualys HackerGuardian now uses hashcode against "title", "severity", "description" for deduplication.
- **(Tools)** Horusec scan now uses hashcode against "title", "description", "file_path", and "line" for deduplication.

#### Dec 16, 2024: v2.41.2

- **(Connectors)** Remove the 'Beta' logo from Connectors

#### Dec 9, 2024: v2.41.1

- **(API)** When using the jira_finding_mappings API endpoint, trying to update a finding's Jira mapping with a Jira issue that is already assigned to another finding will now raise a validation error.
- **(Pro UI)** A Test's Import History is now paginated by default.
- **(Findings)** New Filter: 'Has Any JIRA' which accounts for Findings with single Issues or Findings that were pushed to Jira as part of a Group.
- **(Classic UI)** Filters have been added to the Product Type view.  This is useful for when a single Product Type contains many Products which need to be filtered down.
- **(Classic UI)** Reported Finding Severity by Month graph now tracks the X axis by month correctly.

#### Dec 2, 2024: v2.41.0

- **(API)** `engagements/{id}/update_jira_epic` endpoint path added so that users can now push an updated Engagement to Jira, without creating a new Jira Epic.
- **(Pro UI)** Columns can now be reordered in tables, by clicking and dragging the column header.

![image](images/reorder-columns.png)

- **(Pro UI)** Notes can now be added to a Test directly from the Test page.
- **(Classic UI)** Reviewers are now displayed on Finding pages.
- **(Docs)** New integrated docs site: https://docs.defectdojo.com/

## Nov 2024: v2.40

#### Nov 25, 2024: v2.40.4

- **(Pro UI)**  Improved Metadata tables with Parent object relationships for Products, Engagements, Tests, Findings, Endpoints/Hosts
- **(Pro UI)**  Deleting an object now returns you to a page which makes more sense.
- **(Endpoints)**  Endpoints can now be sorted by ID.
- **(Review Request)**  When a user requests a review, both the requester and the requestee are now captured in audit logs.
- **(Tools)**  Trivy Operator now parses the ‘cluster compliance report’ from scans.
- **(Tools)**  CheckMarx One parser can now handle cases where a result has no description.
- **(Tools)**  AnchorCTL Policies tool has been fortified to handle new severity values.


#### Nov 17, 2024: v2.40.2

- **(API)** Added an API endpoint to get the DefectDojo version number: `/api/v2/version` <span style="background-color:rgba(242, 86, 29, 0.5)">(Pro)</span>
- **(API)**  Multiple Metadata objects can now be added to a single Endpoint, Finding or Product via POST or PATCH to `/api/v2/metadata/` .  Previously, only one Metadata key/value pair could be updated per call.
- **(Pro UI)**  You can now Clear Alerts in the Pro UI.
- **(Pro UI)**  Corrected an issue with Pro UI’s form validation when trying to connect a Jira Project with an Engagement.  
- **(Pro UI)**  Fixed an issue in the Pro UI where new Product Tiles could not be created.
- **(Reports)**  Changes have been made to the Report Generator's description text to clarify how new reports are created from existing reports.
- **(Findings)**  “Verified” is now an optional status for many Finding workflows.  This can be changed from the System Settings page in the Legacy UI (not yet implemented in Pro UI).
- **(Tools)**  Update to AWS Prowler parser - can now handle the ‘event_time’ parameter


#### Nov 14, 2024: v2.40.1

- **(API)** Added a method to validate for file extensions, when 'artifact' files are added to a test (images, for example)
- **(Cloud Portal)** Fixed an issue where QR codes were not being generated correctly for MFA setup.  <span style="background-color:rgba(242, 86, 29, 0.5)">(Pro)</span>
- **(Dashboards)** Insights dashboards can now filter by Product Tag  <span style="background-color:rgba(242, 86, 29, 0.5)">(Pro)</span>
- **(Notifications)** Added a new notification template for ‘Engagement Closed’ - Email, Alerts, Teams, Slack
- **(Tools)** Fixed an issue with the Burp Entreprise HTML parser not correctly handling certain reports
- **(Tags)** Tags are now forced to lowercase when created



#### Nov 4, 2024: v2.40.0

- **(API)** Engagement_End_Date is now honored when submitted via /import /reimport endpoint.
- **(API)** Corrected an issue with the /import endpoint where old Findings were not being mitigated correctly.
- **(Pro UI)**  Certain Error 400 notifications will now be displayed as ‘toasts’ in the Pro UI with a better error description, rather than redirecting to a generic 400 page.
- **(Pro UI)**  Dojo-CLI and Universal Importer are now available for download in-app.  See External Tools menu in the top-right hand menu of the Pro UI.
- **(Connectors)**  Multiple connectors of the same type can now be added.  Each Connector will create a unique Engagement which will be populated with Findings.  <span style="background-color:rgba(242, 86, 29, 0.5)">(Pro)</span>
- **(Connectors)**  AWS Security Hub connector can now find any AWS delegated accounts associated with a centralized account.  All Security Hub Findings from a connector will be tagged with the appropriate AwsAccountId field, and additional Products can be added for each.  <span style="background-color:rgba(242, 86, 29, 0.5)">(Pro)</span>
- **(CLI Tools)**  Dojo-CLI tool now available: a command-line tool which you can use to manage imports and exports to your Cloud instance.  To get started, download the app from the External Tools menu.
- **(Deduplication)**  There’s no longer a brief service interruption when changes are applied to Deduplication Settings.  Those changes can be applied without restarting the service.
- **(Tools)**  Added a new parser for AWS Inspector2 Findings.

#### Setting up multiple AWS Hub accounts with a Connector

If you manage Security Hub Findings for multiple accounts from a centralized administrator account, you will need to
create the IAM user under that account and configure the Connector with it in order to retrieve Findings from those
sub-accounts with a single connector configuration. 

"Member" accounts (either invited manually or automatically associated when using AWS Organizations) will be detected by the Discover operation, and Products will be created for each of your account + region pairs based on the administrator account's cross-region aggregation settings. 

See [this
section of the AWS Docs](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html#finding-aggregation-admin-member) about cross-region aggregation with multiple accounts for more information.
* Once you have created your IAM user and assigned it the necessary permissions using an appropriate policy/role, you will
need to generate an access key and provide the "Access Key" and "Secret Key" components in the relevant connector
configuration fields.
* The "Location" field should be populated with the appropriate API endpoint for your region. For example, to retrieve results from the us-east-1 region, you would supply https://securityhub.us-east-1.amazonaws.com.
* Note that we rely on Security Hub's cross-region aggregation to pull Findings from more than one region. If cross-region aggregation is enabled, you should supply the API endpoint for your "Aggregation Region". Additional linked regions will have ProductRecords created for them in DefectDojo based on your AWS account IDs and the region names.

## Oct 2024: v2.39

#### Oct 29, 2024: v2.39.4

- **(API)**  Corrected 'multiple positional arguments' issue with `/import` endpoint
- **(Metrics)**  Dashboards can now handle multiple Products or Product Types simultaneously: this includes the Executive, Program, Remediation and Tool insights dashboards.  <span style="background-color:rgba(242, 86, 29, 0.5)">(Pro)</span>
- **(Tools)**  OSV, Tenable parsers have been made more robust


#### Oct 21, 2024: v2.39.1

- **(Pro UI)**  Parent Object links have been added to the Metadata table to help contextualize the page you're on
- **(Pro UI)**  Improved "Toggle Columns" menu on tables
- **(Pro UI)**  Added additional helptext for Simple Risk Acceptance, SLA Enforcement
- **(Pro UI)**  Improved Test View with better Import History and Active Finding Severity Breakdown elements
- **(Import)**  Development Environments which do not already exist can now be created via 'auto create context'
- **(Metrics)**  All Metrics dashboards can now be exported as a PDF (Remediation Insights, Program Insights, Tool Insights)  <span style="background-color:rgba(242, 86, 29, 0.5)">(Pro)</span>


#### Oct 7, 2024: v2.39.0

- **(Pro UI)**  Dropdown menus for Import Scan / Reimport Scan no longer block the active element of a form.
- **(Pro UI)**  Finding counts by Severity now disregard Out Of Scope / False Positive Findings.
- **(Dashboard)**  Tile filters with a Boolean filter of False are now saving correctly.  E.G. If you tried to create a Tile with a filter condition of “Has Jira = No” previously this would not be applied correctly.  
- **(Jira)**  Added help text for 'Push All Issues'.
- **(Tools)**  AWS Security Hub EPSS score now parses correctly.

## Sept 2024: v2.38

#### Sept 30, 2024: v2.38.4

- **(API)**  Object History can now be accessed via the API.
- **(API Docs)**  Generating the response schema for certain API endpoints no longer breaks the Swagger interface.
- **(Metrics)**  Added Executive Insights dashboard, Select a Product or Product type, and you can view an executive summary of that Product/Product Type’s security posture with relevant stats.  <span style="background-color:rgba(242, 86, 29, 0.5)">(Pro)</span>
- **(Passwords)**  Password creation for new users can now be made optional upon request.  This feature is toggled via the back-end.


#### Sept 23, 2024: v2.38.3

- **(API)**  `/global_role` endpoint now supports prefetching.
- **(API)**  It is now possible to prefetch a Finding with attached files via API.
- **(Login)**  A new "Forgot Username" link has been added to the login form.  The link will navigate to a page which requests the user's email address. The username will be sent to that address if it exists.
- **Risk Acceptances**  Notes are now added to Findings when they are removed from Risk Acceptances.
- **(Risk Acceptance)**  Risk Acceptance overhaul. Feature has been extended with new functions.  See [Risk Acceptance documentation](/triage_findings/findings_workflows/pro__risk_acceptance/) for more details.
- **Tools**  Qualys HackerGuardian parser added.
- **Tools**  Semgrep Parser updated with new severity mappings. HackerOne parser updated and now supports bug bounty reports.
- **Tools**  fixed an issue where certain tools would not process asyncronously: Whitehat_Sentinel, SSLyze, SSLscan, Qualys_Webapp, Mend, Intsights, H1, and Blackduck.


#### Sept 16, 2024: v2.38.2

- **(Pro UI)**  Jira integration in Pro UI now has parity with Legacy UI.  Ability to Push To Jira has been added, and the Jira ticket view has been added to Findings, Engagements, and all other related objects in DefectDojo.
- **(Finding SLAs)**  Added “Mitigated Within SLA” Finding filter, so that users can now count how many Findings were mitigated on time, and how many were not.  Previously, we were only able to filter Findings that were currently violating SLA or not, rather than ones that had historically violated SLA or not.
- **(Metrics)**  “Mitigated Within SLA” simple metric added to Remediation Insights page.
- **(Reports)**  Custom Content text box no longer renders as HTML.
- **(Tools)**  Wiz Parser now supports SCA format.
- **(Tools)**  Fortify now supports a wider range of .fpr files.
- **(Tools)**  Changed name of Netsparker Scan to Invicti Scan following their acquisition.  Integrations that use the ‘Netsparker’ terminology will still work as expected, but now ‘Invicti’ appears in our tools list.
- **(Universal Importer)** Tag Inheritance has been added to Universal Importer.  Tags can now be added to Findings from that tool.  <span style="background-color:rgba(242, 86, 29, 0.5)">(Pro)</span>



#### Sept 9, 2024: v2.38.1

- **(Pro UI)**  Clearing a date filter and re-applying it no longer throws a 400 error.
- **(Dashboard)**  Dashboard Tag Filters now work correctly in both legacy and Pro UIs.  
- **(MFA)**  When an admin enforced Global MFA on a DefectDojo instance, there was a loop state that could occur with new users attempting to set up their accounts.  This issue has been corrected, and new users can set a password before enabling MFA.
- **(Permissions)**  When a user had permission to edit a Product, but not a Product Type, there was a bug where they were unable to submit an ‘Edit Product’ form (due to interaction with the Product Type). This has been corrected.
- **(Reimport)**  Reimport now correctly records additional vulnerability IDs beyond 1.  In the past, Findings that had more than one Vulnerability ID (a CVE, for example) would have those additional Vulnerability IDs discarded on reimport, so users were potentially losing those additional Vulnerability IDs.
- **(Tools)**  Threat Composer parser added
- **(Tools)**  Legitify parser added
- **(Tools)**  EPSS score / percentile will now be imported from Aquasec files


#### Sept 3, 2024: v2.38.0

- **(API)**  Better naming conventions on Mitigated and Discovered date filters: these are now labeled Mitigated/Discovered On, Mitigated/Discovered Before, Mitigated/Discovered After.
- **(Pro UI)**  Pre-filtered Finding Routes added to Sidebar: you can now quickly filter for Active Findings, Mitigated Findings, All Risk Acceptances, All Finding Groups.
- **(Pro UI)**  Pro UI Findings datatable can now apply every filter that the legacy UI could: filter Findings by (Last Reviewed, Mitigated Date, Endpoint Host, Reviewers… etc).
- **(Pro UI)**  Pro UI OAuth settings leading to a 404 loop - bug fixed and menu now works as expected.
- **(Pro UI)**  Vulnerable Hosts page no longer returns 404.
- **(Pro UI)**  Sorting the Findings data table by Reporter now functions correctly.
- **(Connectors)**  Dependency-Track Connector now available.   <span style="background-color:rgba(242, 86, 29, 0.5)">(Pro)</span>
- **(Deduplication Tuner)**  Deduplication Tuner now available in Pro UI under Enterprise Settings > Deduplication Tuner.
- **(Filters)**  Filtering Findings by Date now applies the filter as expected.
- **(Filters)**  Sorting by Severity now orders by lowest-highest severity instead of alphabetically
- **(Reimport)**  Reimporting Findings that have been Risk-Accepted no longer changes their status to ‘Mitigated’.
- **(Risk Acceptance)**  Updating the Simple Risk Acceptance or the Full Risk Acceptance flag on a Product now updates the Product as expected.

## Aug 2024: v2.37

#### Aug 28, 2024: v2.37.3

- **(API)**  New Endpoint: /finding_groups allows you to GET, add Findings to, delete, or otherwise interact with Finding Groups.  <span style="background-color:rgba(242, 86, 29, 0.5)">(Pro)</span>
- **(Pro UI)**  Relative date ranges for Findings have been added to Finding Filters (last 30 days, last 90 days, etc)
- **(Pro UI)**  Bulk Edit / Risk Acceptance / Finding Group actions are now available in Pro UI.	
- **(Pro UI)**  Finding Groups are now available in the Pro UI.  Selecting multiple Findings allows you to create a Finding Group, provided those Findings are in the same Test.
- **(Pro UI)**  Enhanced Endpoint View now available in Pro UI.
- **(Pro UI)**  Jira Instances can now be added and edited via Pro UI.
- **(Connectors)**  SonarQube / SonarCloud Connector added.  <span style="background-color:rgba(242, 86, 29, 0.5)">(Pro)</span>
- **(Questionnaires)**  Anonymous Questionnaires can now be added to an Engagement after they are completed.  This solves an issue where users wanted to have their team complete questionnaires related to a Product without giving the user access to the complete Product on DefectDojo.
- **(Reports)**  Report issue where images would disappear from reports has been corrected
- **(SLAs)**  “SLA Violation in _ Days” notifications are no longer being sent for unenforced SLAs.
- **(Tools)**  New Parser: AppCheck Web Application Scanning
- **(Tools)**  Nmap Parser now handles script output

#### Aug 7, 2024: v2.37.0

- **(API)**  Created a method to handle simultaneous async reimports to the same Test via API
- **(API)**  Minimum Severity flag now works as expected on /import, /reimport endpoints (Clearsale)
- **(API)**  API errors now default to "Expose error details"
- **(Pro UI)**  New Filter: by calculated SLA date (you can now filter for SLA due dates between a particular date range, for example)
- **(Pro UI)**  New Filter: age of Finding
- **(Pro UI)**  Improvements to pagination / loading behavior for large amounts of Findings
- **(Pro UI)**  Added ability to Reimport Findings in new UI:
- **(Connectors)**  Tenable Connector Released
- **(Dashboard)**  Risk Acceptance tile now correctly filters Findings
- **(Jira)**  Manually syncing multiple Findings with Jira (via Bulk Edit) now pushes notes correctly
- **(Reports)**  Adding the WYSIWYG Heading to a Custom Report now applies a custom Header, instead of a generic ‘WYSIWYG Heading’
- **(SAML)**  Fixed issue where reconfiguring SAML could cause lockout
- **(Tools)**  Wizcli Parser released
- **(Tools)**  Rapplex Parser released
- **(Tools)**  Kiuwan SCA Parser released
- **(Tools)**  Test Types can now be set to Inactive so that they won’t appear in menus.  This ‘inactive’ setting can only be applied in the legacy UI, via Engagements > Test Types (or defectdojo.com/test_type)

## Jul 2024: v2.36.0

- **(Notifications)**  Improved email notifications with collapsible Finding lists for greater readability
- **(SLAs)**  SLAs can now be optionally enforced.  For each SLA associated with a Product you can set or unset the Enforce __ Finding Days box in the relevant SLA Configuration screen.  When this box is unchecked, SLAs for Findings that match that Severity level will not be tracked or displayed in the UI.
