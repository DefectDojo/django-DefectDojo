---
title: "DefectDojo"
description: "How to set up the DefectDojo Upstream Connector, which pulls another DefectDojo instance into DefectDojo Pro"
weight: 48
audience: pro
---
The DefectDojo connector pulls the data of another DefectDojo instance into DefectDojo Pro. The source is usually an open source DefectDojo instance. The connector reads the source over its [export API](/automation/api/product_export/). It changes nothing on the source.

Use it to move an open source estate into DefectDojo Pro, or to consolidate two instances. You set it up in the Connectors UI, like every other Upstream Connector. You can run it again and again until you cut over. For the full migration procedure, and for the database dump path, see [Migrating from Open Source to Self-Hosted DefectDojo Pro](/get_started/pro/onprem/migrating_from_open_source/).

This connector ships in a coming DefectDojo Pro release.

#### Prerequisites

The source must meet three requirements:

* **Version.** The source runs DefectDojo 3.4.300 or later. That release added the export API. If the source is older, the connector refuses it when you save the configuration.
* **HTTPS.** The source URL starts with `https://`. The connector refuses a plain `http://` URL, so the token never travels in clear text.
* **A superuser API token.** Create an API v2 key for a superuser on the source. The connector sends it with every request.

##### Why a superuser token

The export API answers only a superuser. The export does not filter by permissions, and private notes cross. Its manifest lists every Product Type, every Product and every user of the instance. Only a superuser can read all of that in one place. A token of any other user gets a 403. The connector reports that when you save the configuration.

Create a user on the source for the connector alone, for example `defectdojo-migration`. Make it a superuser and create an API key for it. The connector only reads with that key. If the key expires within 30 days, the connector warns at the start of each Sync. Revoke the key after the cutover.

#### Connector Mappings

1. Enter the URL of the source in the **Location** field, for example `https://dojo.example.com`. The URL must start with `https://`.
2. Enter the superuser API key in the **Secret** field.
3. Keep the defaults of the fields below, or change them.

| Field | Default | What it does |
|---|---|---|
| `tls_verify` | `true` | Checks the certificate of the source. Set it to `false` for a source with a self-signed certificate. |
| `include_inactive` | `true` | Imports findings that are not active. |
| `include_duplicates` | `false` | Imports findings that the source marked as duplicates. |
| `include_files` | `true` | Imports the files of findings, engagements and tests, and the proof of each risk acceptance. |
| `provenance` | `references` | `references` adds a `Migrated from <source>/finding/<id>` line to the references of each finding. `none` leaves it out. |
| `minimum_severity` | none | Skips findings below this severity: `Low`, `Medium`, `High` or `Critical`. `Info` sets no floor. |
| `max_file_bytes` | `10485760` (10 MiB) | The largest file the connector imports, in bytes. The upper bound is 24 MiB (`25165824`). A larger file stays on the source. |

When you submit, DefectDojo Pro checks the token and the version of the source. If either check fails, it tells you why.

#### Records

Discover creates one Record per Product on the source. The Record carries the Product's name and Product Type. It also carries the tags, the business criticality, the SLA configuration and the owner emails. With **Auto-Mapping** on, each Record gets a Product of the same name under a Product Type of the same name. Without it, map each Record yourself. Ignore a Record to leave that Product behind.

A Record is keyed on the install id of the source and the id of the Product. If the source moves to a new hostname, update the **Location** field. The Records stay the same.

#### What crosses

Each Sync imports every mapped Record. For each Product the connector sends:

* **The Product and its Product Type.** Description, tags, business criticality, SLA configuration, lifecycle, platform, origin, regulations and metadata. Also the three owners: product manager, technical contact and team manager.
* **Every engagement and every test**, with their fields, notes and files. A test with no findings still crosses. An engagement with no tests crosses too.
* **Every finding**, with every column. A finding also brings its tags, vulnerability ids, CWEs and endpoints with their status. Its notes, files, request and response pairs and metadata come too. It lands in the engagement and the test it came from.
* **Risk acceptances**, with their notes and their proof file, linked to the same findings.
* **Finding groups**, with the same member findings.
* **Users**, as inactive accounts without passwords. A finding field that names a user, for example the reporter, points at these accounts.
* **Reference data**: SLA configurations, development environments, regulations and note types.

Each test keeps its scan type. A test with no scan type on the source gets the scan type `DefectDojo - Connectors Import`. The deduplication hash of each finding stays equal to the hash on the source. Deduplication in DefectDojo Pro gives the same result as on the source.

#### What does not cross

* **Secrets and instance settings.** SSO, JIRA and tool credentials, notifications, API keys and passwords. Configure them in DefectDojo Pro yourself.
* **History.** The audit trail of the source stays on the source.
* **JIRA issue links.**
* **Groups, roles and memberships.** Users arrive inactive, with no password. Activate the accounts you need and give them roles.
* **Files over `max_file_bytes`.** They stay on the source. The export counts them in `files_over_cap`.
* **Duplicates**, unless you set `include_duplicates` to `true`.

The [export API page](/automation/api/product_export/#what-does-not-cross) lists everything the source leaves out of its export.

#### Re-runs

Run Sync as often as you need until you cut over. Each run updates what an earlier run created. It makes no copies:

* A finding keeps its identity through its source id and its hash. A run with no change on the source creates, closes and reactivates nothing.
* A finding that changed on the source updates in DefectDojo Pro.
* A finding that the source deleted from a test closes in DefectDojo Pro. The test must still exist on the source.
* A note or a file keeps its identity too. A run updates it instead of adding a copy.
* A test that the source deleted stops syncing. Its findings in DefectDojo Pro stay as they are.

If a Sync stops in the middle of a Product, the next Sync imports that Product again. The source ids and the hash keep it free of duplicates.
