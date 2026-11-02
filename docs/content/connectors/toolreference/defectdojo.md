---
title: "DefectDojo Migration"
description: "How to set up the DefectDojo Migration Upstream Connector, which pulls another DefectDojo instance into DefectDojo Pro"
weight: 48
audience: pro
---
The DefectDojo Migration connector pulls the data of another DefectDojo instance into DefectDojo Pro. The source is usually an open source DefectDojo instance. The source can also be a DefectDojo Pro instance on a release that serves the export API. The connector reads the source over its [export API](/automation/api/product_export/). It changes nothing on the source.

Use it to move an open source estate into DefectDojo Pro, or to consolidate two instances. You set it up in the Connectors UI, like every other Upstream Connector. On **Connect > Upstream**, its tile is **DefectDojo Migration**. You can run it again and again until you cut over. For the full migration procedure, and for the database dump path, see [Migrating from Open Source to Self-Hosted DefectDojo Pro](/get_started/pro/onprem/migrating_from_open_source/).

This page uses the open source names Product Type and Product. In DefectDojo Pro, they can show as Organization and Asset.

This connector ships in a coming DefectDojo Pro release.

#### Prerequisites

The source must meet three requirements:

* **Version.** The source runs DefectDojo 3.4.300 or later. That release added the export API. If the source is older, the connector refuses it when you save the configuration.
* **HTTPS.** The source URL starts with `https://`. The connector refuses a plain `http://` URL, so the token never travels in clear text.
* **A superuser API token.** Create an API v2 key for a superuser on the source. The connector sends it with every request.

##### Why a superuser token

The export API answers only a superuser. The export does not filter by permissions, and private notes cross. Its manifest lists every Product Type, every Product and every user of the instance. Only a superuser can read all of that in one place. A token of any other user gets a 403. The connector reports that when you save the configuration.

Create a user on the source for the connector alone, for example `defectdojo-migration`. Make it a superuser and create an API key for it. The connector reads the source with that key, and it turns read-only mode on and off with it. See [Read-only mode during a Sync](#read-only-mode-during-a-sync). If the key expires within 30 days, the [preflight report](#the-preflight-report) warns you. Revoke the key after the cutover.

#### Connector Mappings

1. Open **Connect > Upstream**, and click **Add Configuration** on the **DefectDojo Migration** tile.
2. Enter the URL of the source in **Location URL**, for example `https://dojo.example.com`. The URL must start with `https://`.
3. Enter the superuser API key in **API Token**.
4. Keep the defaults of the fields in the table below, or change them. Auto-Mapping is always on for this connector, so the form does not offer it. See [Records](#records).
5. For a migration you run once, keep **One-Time** in both **Frequency** fields. To delete the connection when the migration is done, turn on **Delete the Connection After the Migration**.
6. Click **Submit**. With **One-Time** in **Frequency**, Discover starts at once and the connection's migration page opens. The preflight report appears on it when Discover ends.

| Field | Default | What it does |
|---|---|---|
| **Verify TLS Certificate** | On | Checks the certificate of the source. Turn it off only for a source with a self-signed certificate. |
| **Include Inactive Findings** | On | Imports findings that are not active. |
| **Include Duplicate Findings** | Off | Imports findings that the source marked as duplicates. |
| **Include Files** | On | Imports the files of findings, engagements and tests, and the proof of each risk acceptance. |
| **Provenance** | References | **References** adds a `Migrated from <source>/finding/<id>` line to the references of each finding. **None** leaves it out. |
| **Minimum Severity** | Info | Skips findings below this severity. **Info** imports every finding. |
| **Maximum File Size (MB)** | `10` | The largest file the connector imports, in megabytes. The highest value is `24`. A larger file stays on the source. |
| **Frequency** (Discovery and Synchronization) | One-Time | **One-Time** runs Discover or Sync only when you click its button. **Daily**, **Weekly** (on the weekday you pick) and **Monthly** (on the first day of each month) run it on a schedule instead, at the time you pick. |
| **Delete the Connection After the Migration** | Off | Shown when the Synchronization frequency is **One-Time**. When the migration ends without errors and DefectDojo Pro has imported its findings, the connection is deleted. The Products, findings and everything else the Sync brought stay. |

When a One-Time Sync ends and DefectDojo Pro has imported its findings, one notification sums up the migration: the findings it brought, the users it created inactive, the users that were superusers on the source but are not superusers in DefectDojo Pro, and the settings to set up again. It uses the **Connector health warning** notification, so it follows your settings for that notification, and it stays in the alerts after the connection is deleted.

When you submit, DefectDojo Pro checks the token and the version of the source. If either check fails, it tells you why.

If you delete the connection, or the Sync deletes it, and you add a new one for the same source later, the new connection continues where the old one stopped. It updates the objects the old one imported and makes no copies.

#### Read-only mode during a Sync

DefectDojo 3.5.0 and later have a read-only mode. On such a source, the connector turns read-only mode on when a Sync starts, and turns it off when the Sync ends, also when the Sync fails. While it is on, nobody can change the source, so the Sync reads one consistent state. Discover does not change the mode.

* If read-only mode was already on when the Sync started, the Sync still turns it off at the end. To keep the source frozen after the last Sync, turn read-only mode on again in **Configuration > System Settings**.
* If the connector stops in the middle of a Sync, for example on a restart, the source stays read-only until the next Sync ends, or until a superuser turns it off in **System Settings**.
* A task that started on the source before the lock still writes until it ends.

A source on 3.4.300 has no read-only mode. The preflight report warns about it, and people can still change the source while a Sync reads it.

#### Records

Discover creates one Record per Product on the source. The Record carries the Product's name and Product Type. It also carries the tags, the business criticality, the SLA configuration and the owner emails. Mapping applies them to the Product.

**Auto-Mapping** is always on for this connector. Each Record gets a Product of the same name, under a Product Type of the same name. If DefectDojo Pro already has a Product of that name, the Record maps to it. The [Managing Records](/connectors/upstream/manage_records/#how-auto-mapping-chooses-the-product) page explains the order.

To leave a source Product behind, clear its **Include** box on the migration page. This connector has no records page: the migration page replaces it.

A Record is keyed on the install id of the source and the id of the Product. If the source moves to a new hostname, update the **Location URL** field. The Records stay the same.

#### The preflight report

Each Discover also stores a preflight report. It shows what a Sync brings before you run one. The report is on the connection's migration page. To open the page, click **Open Migration** on the connector's tile on **Connect > Upstream**, above **Manage Configuration**. After a save on **Edit Configuration**, the page opens too. Before the first Discover, the page says "Run a discovery to see the preflight report."

The top of the page shows a short summary: the number of findings in the Products you include, the estimated duration and the number of warnings. **Begin Migration** is beside it and runs a Sync, and the gear menu holds **Discover** and **Edit Configuration**. During a migration a progress bar counts the imported findings against the expected ones. Then the summary shows **Migration Complete** once DefectDojo Pro has imported every finding, or **Migration Failed**. If the connection deletes itself after the migration, it also shows **Connection Deleted**.

If an import stops before every finding arrives (for example, when a worker process is killed), the page shows **Migration Stalled** once no import has worked on it for 45 minutes. Click **Begin Migration** again to finish it: findings that already arrived are matched, not duplicated. A stalled migration sends no summary and never deletes its connection. Below the summary, the page shows the report in sections, and **History** lists every Discover and Sync. The table below lists the report sections.

In the **Products** section, each source Product has an **Include** box. Clear it before the Sync to leave that Product on the source. If Auto-Mapping created an empty Product for it, that Product is deleted. Select the box again to bring the Product back. The boxes are locked while a Sync runs.

| Section | What it shows |
|---|---|
| **Source** | The URL and the version of the source. The user of the API token, if that user is a superuser, and when the token expires. |
| **Warnings** | **Unknown Scan Types** lists the source scan types that DefectDojo Pro has no parser for. Their findings go to a test of type `DefectDojo - Connectors Import`. Other warnings say that the token expires soon, how many files are over the size limit, or that the source has no read-only mode. A warning also names each SLA configuration, regulation and note type that DefectDojo Pro already has under the same name, with other values. DefectDojo Pro keeps its own values for them. |
| **Products** | The totals of the source, and one row for each source Product with its **Include** box and its counts: engagements, tests, findings, endpoints, notes, files, risk acceptances and finding groups. |
| **To Be Created** | The users and the reference data that DefectDojo Pro does not have yet: SLA configurations, environments, regulations and note types. A source user whose username already exists in DefectDojo Pro is reused. The card counts those users. **Notification Settings** names the new users whose notification settings cross. **System Settings** names the settings that the first Sync changes. |
| **Not Migrated** | What does not cross, with one sentence on what to do about each item. The help icon beside an item gives the reason. The items are passwords, API tokens, tool credentials and Jira. Jira issue links, notification channels and the audit trail follow. |
| **Estimated Duration** | In the summary at the top: how long a Sync of the findings in the included Products takes. Before the first Sync, the estimate uses a default rate. Then it uses the rate of the last successful Sync. |

The counts cover every Product on the source, also the Products you ignore.

#### What crosses

Each Sync imports every mapped Record. For each Product the connector sends:

* **The Product and its Product Type.** Description, tags, business criticality, SLA configuration, lifecycle, platform, origin, regulations, user records and metadata. If DefectDojo Pro has no lifecycle, platform or origin with the source value, the connector creates it with the source name, icon and order.
* **The owners of the Product, as members.** The source Product's product manager, technical contact and team manager become members of the Product. They get the Maintainer role. DefectDojo Pro finds each of them by email address. On each Sync, an owner gets that role again, also when an administrator changed it.
* **The access of each Product and Product Type, as members.** The users in the **Authorized Users** list of a source Product become members of the Product. The users in the **Authorized Users** list of its Product Type become members of the Product Type. The connector does this only when the connection maps every Product in that Product Type. Otherwise these users get no Product Type membership, so they get no access to the other Products in it. A user that was staff on the source gets the Maintainer role. Every other user gets the Writer role. A user that is already a member keeps the membership as it is. The connector gives each membership once. If an administrator removes a membership, a later Sync does not add it again. Only an owner of the Product differs, as described above. The connector skips an entry that names no user it migrated. The connector sets no global role.
* **Every engagement and every test**, with their fields, notes and files. The engagement fields include the first contact date, the reason, the tracker and test strategy links, the threat model, API test, pen test and check list boxes, the progress, the threat model path and whether the engagement is active. A test brings its percent complete. A test with no findings still crosses. An engagement with no tests crosses too.
* **Every finding**, with every column. A finding also brings its tags, vulnerability ids, CWEs and endpoints with their status and tags. Its notes, files, request and response pairs and metadata come too. It lands in the engagement and the test it came from.
* **The edit history of each note.** Each earlier text of a note crosses with its time and editor.
* **Risk acceptances**, with their notes and their proof file, linked to the same findings.
* **Finding groups**, with the same member findings.
* **Users.** Every user of the source crosses, also the users of a Product you ignore. A finding field that names a user, for example the reporter, points at these accounts.
* **Reference data**: SLA configurations, development environments, regulations and note types. If DefectDojo Pro already has one with the same name, it keeps its own values. The preflight report warns when those values differ from the source.
* **Finding templates**, with their tags and vulnerability ids. A template belongs to the instance, not to a Product. If DefectDojo Pro already has a template with the same title, it keeps its own. The connector adds no copy.
* **Tool types and tool configurations, without passwords and keys.** A tool type brings its name and description. A tool configuration brings its name, description, URL, authentication type, username and **Title for SSH/API Key**. It never brings its password, SSH key, API key or extras. The connector creates it with those fields empty. Tool types match by name, and a tool configuration matches by name within its tool type. If DefectDojo Pro already has one with the same name, it keeps its own values, passwords and keys included. For a configuration that the connector created, enter the password, SSH key, API key or extras in DefectDojo Pro yourself.
* **Engagement presets.** Each preset brings its title, notes, scope, test types and network locations. A preset matches by Product and title. A test type matches by name. If DefectDojo Pro has no test type with that name, the connector skips it and creates none. A network location matches by its location text. If none matches, DefectDojo Pro creates it. A preset that DefectDojo Pro already has keeps its own values.
* **Notification settings, once.** The notification settings of each user cross, with their settings for each Product. The system notification settings and the template for new users cross too. The first Sync copies them, and a later Sync changes nothing, so a change in DefectDojo Pro stays. The system settings and the template cross once for each DefectDojo Pro instance. A second source does not change them. A user that the connector creates gets the source settings. A user that already exists in DefectDojo Pro, or that signed in before the copy, keeps its own settings. It only gets the Product settings that it does not have yet. A Slack, Microsoft Teams, email or webhook channel sends nothing until you set it up in DefectDojo Pro.
* **System settings, once.** The first Sync copies the behavior settings of the source. These include deduplication, false positive history and the verified status rules. They also include product grading, SLA notifications, engagement auto-close and the risk acceptance defaults. Disclaimers, password rules and feature switches such as finding groups cross too. A later Sync changes nothing. The settings cross once for each DefectDojo Pro instance, so a second source changes none of them. The preflight report names the settings that the first Sync changes.
* **API scan configurations.** Each one brings its three service keys and points at the tool configuration it used on the source. A scan configuration matches by Product, tool configuration and first service key. The credentials are in the tool configuration. If the connector created it, enter them there.

A new user arrives inactive, with no usable password. It is never a superuser, also when it was one on the source. It does not use a license seat until it is activated. An administrator activates it with **Activate and Invite**, and the user sets a new password. [How Migrated Users Sign In](/get_started/pro/onprem/migrating_from_open_source/#how-migrated-users-sign-in) explains the steps. If DefectDojo Pro already has a user with that username, the connector uses it and changes none of its fields. That user can still get the memberships above. The connector adds no user to a group. The default group rule of DefectDojo Pro still applies to a new user. That group can carry a global role. The memberships of a new user are in place before you activate it. The migration summary names the users that were superusers on the source, so you can decide who gets that role.

Each test keeps its scan type. If DefectDojo Pro has no parser for that scan type, the test gets the scan type `DefectDojo - Connectors Import`. A custom scan type is the usual case. A test with no scan type on the source gets it too. The deduplication hash of each finding stays equal to the hash on the source. Deduplication in DefectDojo Pro gives the same result as on the source.

#### What does not cross

* **Secrets and instance settings.** JIRA instances and credentials, API tokens and passwords. The Slack, Microsoft Teams, email and webhook setup. The system settings that hold a secret or describe the source instance also stay. These are the JIRA settings, the sender address, the URL prefix and the team name. Read-only mode, API error details and the GitHub switch stay too. So do the calendar, CVSS display and table search switches, which DefectDojo Pro manages another way. A tool configuration also keeps its password, SSH key, API key and extras on the source. Configure them in DefectDojo Pro yourself.
* **History.** The audit trail of the source stays on the source. Only the edit history of notes crosses.
* **JIRA issue links.**
* **The link from an engagement to its preset, and from a test to its API scan configuration.** The presets and the scan configurations cross as their own objects.
* **The product manager, technical contact and team manager fields.** The owners become members instead, and the three fields stay empty.
* **The creator of a finding group.**
* **Files over Maximum File Size (MB).** They stay on the source. The preflight report counts them. The connector also skips a file that does not fit its transfer limits, and logs a warning.
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

A Sync operation shows **Success** when the connector has sent the data. DefectDojo Pro then imports the findings in the background. For a large Product, the import goes on for some minutes after **Success**. The migration page shows **Migration Complete** when the import ends.

Before you trust a Sync, open each Product and check its finding count. Compare it with the findings count of that Product in the preflight report. The count in DefectDojo Pro is lower by the findings that your fields skip. Duplicates, findings below **Minimum Severity** and, with **Include Inactive Findings** off, inactive findings are not imported.
