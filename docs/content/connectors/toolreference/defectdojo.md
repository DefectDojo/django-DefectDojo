---
title: "Source DefectDojo"
description: "How to set up the Source DefectDojo Upstream Connector, which pulls another DefectDojo instance into DefectDojo Pro"
weight: 48
audience: pro
---
The Source DefectDojo connector pulls the data of another DefectDojo instance into DefectDojo Pro. The source is usually an open source DefectDojo instance. The source can also be a DefectDojo Pro instance on a release that serves the export API. The connector reads the source over its [export API](/automation/api/product_export/). It changes nothing on the source.

Use it to move an open source estate into DefectDojo Pro, or to consolidate two instances. You set it up in the Connectors UI, like every other Upstream Connector. On **Connect > Upstream**, its tile is **Source DefectDojo**. You can run it again and again until you cut over. For the full migration procedure, and for the database dump path, see [Migrating from Open Source to Self-Hosted DefectDojo Pro](/get_started/pro/onprem/migrating_from_open_source/).

This page uses the open source names Product Type and Product. In DefectDojo Pro, they can show as Organization and Asset.

This connector ships in a coming DefectDojo Pro release.

#### Prerequisites

The source must meet three requirements:

* **Version.** The source runs DefectDojo 3.4.300 or later. That release added the export API. If the source is older, the connector refuses it when you save the configuration.
* **HTTPS.** The source URL starts with `https://`. The connector refuses a plain `http://` URL, so the token never travels in clear text.
* **A superuser API token.** Create an API v2 key for a superuser on the source. The connector sends it with every request.

##### Why a superuser token

The export API answers only a superuser. The export does not filter by permissions, and private notes cross. Its manifest lists every Product Type, every Product and every user of the instance. Only a superuser can read all of that in one place. A token of any other user gets a 403. The connector reports that when you save the configuration.

Create a user on the source for the connector alone, for example `defectdojo-migration`. Make it a superuser and create an API key for it. The connector only reads with that key. If the key expires within 30 days, the [preflight report](#the-preflight-report) warns you. Revoke the key after the cutover.

#### Connector Mappings

1. Open **Connect > Upstream**, and click **Add Configuration** on the **Source DefectDojo** tile.
2. Enter the URL of the source in **Location URL**, for example `https://dojo.example.com`. The URL must start with `https://`.
3. Enter the superuser API key in **API Token**.
4. Keep the defaults of the fields in the table below, or change them.
5. Turn on **Enable Auto-Mapping**. See [Records](#records) for the reason.
6. Click **Submit**.

| Field | Default | What it does |
|---|---|---|
| **Verify TLS Certificate** | On | Checks the certificate of the source. Turn it off only for a source with a self-signed certificate. |
| **Include Inactive Findings** | On | Imports findings that are not active. |
| **Include Duplicate Findings** | Off | Imports findings that the source marked as duplicates. |
| **Include Files** | On | Imports the files of findings, engagements and tests, and the proof of each risk acceptance. |
| **Provenance** | References | **References** adds a `Migrated from <source>/finding/<id>` line to the references of each finding. **None** leaves it out. |
| **Minimum Severity** | Info | Skips findings below this severity. **Info** imports every finding. |
| **Maximum File Size (Bytes)** | `10485760` (10 MiB) | The largest file the connector imports, in bytes. The highest value is `25165824` (24 MiB). A larger file stays on the source. |

When you submit, DefectDojo Pro checks the token and the version of the source. If either check fails, it tells you why.

#### Records

Discover creates one Record per Product on the source. The Record carries the Product's name and Product Type. It also carries the tags, the business criticality, the SLA configuration and the owner emails. Mapping applies them to the Product. The Records list does not show them.

Use **Auto-Mapping**. With it on, each Record gets a Product of the same name, under a Product Type of the same name. If DefectDojo Pro already has a Product of that name, the Record maps to it. The [Managing Records](/connectors/upstream/manage_records/#how-auto-mapping-chooses-the-product) page explains the order.

Without Auto-Mapping, you can map a Record by hand only to a Product that already exists. Mapping by hand cannot create a Product. If you started without Auto-Mapping, turn it on and run Discover again. Ignore a Record to leave that Product behind.

A Record is keyed on the install id of the source and the id of the Product. If the source moves to a new hostname, update the **Location URL** field. The Records stay the same.

#### The preflight report

Each Discover also stores a preflight report. It shows what a Sync brings before you run one. The report is in the **Migration Preflight** card. The card is on the connector's tile on **Connect > Upstream**, and on its **Manage Records and Operations** page. Before the first Discover, the card says "Run a discovery to see the preflight report."

The card opens folded. It shows the warnings, the totals and the estimated duration. Click **View Details** to see the rest. The button then reads **Hide Details**. The rows of the table below that need **View Details** say so.

| Section | What it shows |
|---|---|
| **Source** | Needs **View Details**. The URL and the version of the source. **Mode** is **Verbatim**: the connector copies each record as it is on the source. **Locations** shows if the source has the Locations feature on. |
| **Token** | Needs **View Details**. The user of the API token, if that user is a superuser, and when the token expires. |
| **Warnings** | **Unknown Scan Types** lists the source scan types that DefectDojo Pro has no parser for. Their findings go to a test of type `DefectDojo - Connectors Import`. Other warnings say that the token expires soon, or how many files are over the size limit. |
| **Counts** | The totals of the source. **View Details** adds the counts of each Product: engagements, tests, findings, endpoints, notes, files, risk acceptances and finding groups. |
| **To Be Created** | Needs **View Details**. The users and the reference data that DefectDojo Pro does not have yet: SLA configurations, environments, regulations and note types. A source user whose username already exists in DefectDojo Pro is reused. The card counts those users. |
| **Not Migrated** | Needs **View Details**. The settings that never cross: Single Sign-On, Jira, tool configurations, notifications, API tokens, passwords and system settings. |
| **Estimated Duration** | How long a Sync of every finding takes. Before the first Sync, the estimate uses a default rate. Then it uses the rate of the last successful Sync. |

The counts cover every Product on the source, also the Products you ignore.

#### What crosses

Each Sync imports every mapped Record. For each Product the connector sends:

* **The Product and its Product Type.** Description, tags, business criticality, SLA configuration, lifecycle, platform, origin, regulations and metadata.
* **The owners of the Product, as members.** The source Product's product manager, technical contact and team manager become members of the Product. They get the Maintainer role. DefectDojo Pro finds each of them by email address.
* **Every engagement and every test**, with their fields, notes and files. A test with no findings still crosses. An engagement with no tests crosses too.
* **Every finding**, with every column. A finding also brings its tags, vulnerability ids, CWEs and endpoints with their status. Its notes, files, request and response pairs and metadata come too. It lands in the engagement and the test it came from.
* **Risk acceptances**, with their notes and their proof file, linked to the same findings.
* **Finding groups**, with the same member findings.
* **Users.** Every user of the source crosses, also the users of a Product you ignore. A finding field that names a user, for example the reporter, points at these accounts.
* **Reference data**: SLA configurations, development environments, regulations and note types.

A new user arrives inactive, with no usable password. It is never a superuser, also when it was one on the source. It does not use a license seat until it is activated or it logs in. If DefectDojo Pro already has a user with that username, the connector uses it and changes nothing on it. Users join no group, except the default group when their email matches its pattern.

Each test keeps its scan type. If DefectDojo Pro has no parser for that scan type, the test gets the scan type `DefectDojo - Connectors Import`. A custom scan type is the usual case. A test with no scan type on the source gets it too. The deduplication hash of each finding stays equal to the hash on the source. Deduplication in DefectDojo Pro gives the same result as on the source.

#### What does not cross

* **Secrets and settings.** Single Sign-On, JIRA instances and credentials, tool configurations and credentials, notification preferences, API tokens, passwords and system settings. Configure them in DefectDojo Pro yourself.
* **History.** The audit trail of the source stays on the source.
* **JIRA issue links.**
* **Groups, roles and memberships.** Only the owners of each Product become members. Activate the user accounts you need and give them roles.
* **The product manager, technical contact and team manager fields.** The owners become members instead, and the three fields stay empty.
* **The creator of a finding group.**
* **Files over Maximum File Size (Bytes).** They stay on the source. The preflight report counts them. The connector also skips a file that does not fit its transfer limits, and logs a warning.
* **Duplicates**, unless you turn on **Include Duplicate Findings**.
* **The Pro data of a DefectDojo Pro source.** Only the open source data crosses. The priority and risk scores, asset types, custom fields, groups and roles, and history stay on the source.

The [export API page](/automation/api/product_export/#what-does-not-cross) lists everything the source leaves out of its export.

#### Re-runs

Run Sync as often as you need until you cut over. Each run updates what an earlier run created. It makes no copies:

* A finding keeps its identity through its source id and its hash. A run with no change on the source changes nothing in DefectDojo Pro.
* A finding that changed on the source updates in DefectDojo Pro.
* A finding that the source deleted from a test closes in DefectDojo Pro. It is marked mitigated, not deleted. The test must still exist on the source.
* A note or a file keeps its identity too. A run updates it instead of adding a copy.
* A test that the source deleted stops syncing. Its findings in DefectDojo Pro stay as they are.

If a Sync stops in the middle of a Product, the next Sync imports that Product again. The source ids and the hash keep it free of duplicates.

#### Check the finding count after a Sync

A Sync operation shows **Success** when the connector has sent the data. DefectDojo Pro then imports the findings in the background. For a large Product, the import goes on for some minutes after **Success**.

Before you trust a Sync, open each Product and check its finding count. Compare it with the findings count of that Product in the preflight report. The count in DefectDojo Pro is lower by the findings that your fields skip. Duplicates, findings below **Minimum Severity** and, with **Include Inactive Findings** off, inactive findings are not imported.
