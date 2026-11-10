---
title: "DefectDojo Migration"
description: "How to set up the DefectDojo Migration Upstream Connector, which pulls another DefectDojo instance into DefectDojo Pro"
weight: 48
audience: pro
---
The DefectDojo Migration connector pulls the data of another DefectDojo instance into DefectDojo Pro. The source is usually an open source DefectDojo instance. The source can also be a DefectDojo Pro instance on a release that serves the export API. The connector reads the source over its [export API](/automation/api/product_export/). It changes nothing on the source.

> The DefectDojo Migration is a **beta** feature and is **off by default**. A superuser turns on **DefectDojo Migration** on the [Feature Flags page](/admin/feature_flags/pro__feature_flags/). While it is off, the connector's tile, its connections, the migration page and **Activate and Invite** do not show.

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
| **Migrate Import History** | On | Copies each test's imports and reimports with the findings they touched. See [What crosses](#what-crosses). |
| **Migrate Audit History** | On | Copies the change history of each Product, engagement, test, finding, finding group and risk acceptance. This includes the older legacy audit entries. See [What crosses](#what-crosses). |
| **Provenance** | References | **References** adds a `Migrated from <source>/finding/<id>` line to the references of each finding. **None** leaves it out. |
| **Minimum Severity** | Info | Skips findings below this severity. **Info** imports every finding. |
| **Maximum File Size (MiB)** | `10` | The largest file the connector imports, in mebibytes (1 MiB is 1,048,576 bytes). The highest value is `24`. A larger file stays on the source. A stored size that is not a whole MiB shows rounded up, with the exact byte count under the field. |
| **Frequency** (Discovery and Synchronization) | One-Time | **One-Time** runs Discover or Sync only when you click its button. **Daily**, **Weekly** (on the weekday you pick) and **Monthly** (on the first day of each month) run it on a schedule instead, at the time you pick. |
| **Delete the Connection After the Migration** | Off | Shown when the Synchronization frequency is **One-Time**. When the migration ends without errors and DefectDojo Pro has imported its findings, the connection is deleted. The Products, findings and everything else the Sync brought stay. |

When a One-Time Sync ends and DefectDojo Pro has imported its findings, one notification sums up the migration: the findings it brought, the users it created inactive, the users that were superusers on the source but are not superusers in DefectDojo Pro, and the settings to set up again. It uses the **Connector health warning** notification, so it follows your settings for that notification, and it stays in the alerts after the connection is deleted.

When you submit, DefectDojo Pro checks the token and the version of the source. If either check fails, it tells you why.

If you delete the connection, or the Sync deletes it, and you add a new one for the same source later, the new connection continues where the old one stopped. It updates the objects the old one imported and makes no copies.

#### Read-only mode during a Sync

DefectDojo 3.5.100 and later have a read-only mode. On such a source, the connector turns read-only mode on when a Sync starts, and turns it off when the Sync ends, also when the Sync fails. While it is on, nobody can change the source, so the Sync reads one consistent state. Discover does not change the mode.

* If read-only mode was already on when the Sync started, it stays on at the end. The Sync puts the mode back to what it was. To keep the source frozen after the last Sync, turn read-only mode on before that Sync.
* If the connector stops in the middle of a Sync, for example on a restart, the source stays read-only. The next Sync finds the mode on and keeps it on. The preflight report warns when the source is read-only. If you did not lock the source yourself, turn read-only mode off in **System Settings** before the next Sync.
* A task that started on the source before the lock still writes until it ends.

A source on 3.4.300 has no read-only mode. The preflight report warns about it, and people can still change the source while a Sync reads it.

#### Records

Discover creates one Record per Product on the source. The Record carries the Product's name and Product Type. It also carries the tags, the business criticality, the SLA configuration and the owner emails. Mapping applies them to the Product.

**Auto-Mapping** is always on for this connector. Each Record gets a Product of the same name, under a Product Type of the same name. If DefectDojo Pro already has a Product of that name, the Record maps to it. The [Managing Records](/connectors/upstream/manage_records/#how-auto-mapping-chooses-the-product) page explains the order.

To leave a source Product behind, clear its **Include** box on the migration page. This connector has no records page: the migration page replaces it.

A Record is keyed on the install id of the source and the id of the Product. If the source moves to a new hostname, update the **Location URL** field. The Records stay the same.

#### The preflight report

Each Discover also stores a preflight report. It shows what a Sync brings before you run one. The report is on the connection's migration page. To open the page, click **Open Migration** on the connector's tile on **Connect > Upstream**, above **Manage Configuration**. After a save on **Edit Configuration**, the page opens too. Before the first Discover, the page says "No preflight report yet."

The top of the page shows a short summary. **Findings to Migrate** counts the findings in the Products you include. The summary also shows the estimated duration and the number of warnings. **Begin Migration** is beside it. It asks you to confirm, then runs a Sync. The gear menu holds **Discover** and **Edit Configuration**. The button is off while a run is active and before a report exists. It is also off while users would migrate and DefectDojo Pro cannot send them email. Discover tests the mail server once, without sending a mail. The gate does not apply when DefectDojo Pro signs users in with SSO or LDAP, or on DefectDojo Pro cloud. Set up SMTP under **Settings > System > Email**, then run **Discover** again. The page links there for a user who can open it. The warnings also name each new user without an email address. Such a user still needs its link passed on by hand, or SSO. During a migration a progress bar counts the imported findings against the findings the connector sent. Under it the page says how many duplicates stayed on the source and how many files were not sent. It also counts the findings whose hash differs from the source at the last import. Then the summary shows **Migration Complete** with the imported count, or **Migration Failed** with the reason. If the connection deletes itself after the migration, it also shows **Connection Deleted**.

If an import stops before every finding arrives (for example, when a worker process is killed), the page shows **Migration Stalled** once no import has worked on it for 45 minutes. Click **Begin Migration** again to finish it: findings that already arrived are matched, not duplicated. A stalled migration sends no summary and never deletes its connection. Below the summary, the page shows the report in sections, and **History** lists every Discover and Sync. The table below lists the report sections.

Discover creates an empty Product in DefectDojo Pro for each source Product. In the **Products** section, each source Product has an **Include** box. Clear it before the Sync to leave that Product on the source. If Auto-Mapping created an empty Product for it, that Product is deleted. Select the box again to bring the Product back. The boxes are locked while a Sync runs.

| Section | What it shows |
|---|---|
| **Source** | The URL and the version of the source. The user of the API token, if that user is a superuser, and when the token expires. |
| **Warnings** | A warning names each test type that DefectDojo Pro already has with other settings. DefectDojo Pro keeps its own settings for it. Other warnings say that the token expires soon, how many files are over the size limit, or that the source has no read-only mode. A warning also says that the source is already in read-only mode, or that another connection already migrates this source. A source on an older release gets a warning. It sends no finding templates, tool types, tool configurations, engagement presets or API scan configurations. A warning also names each SLA configuration, regulation and note type that DefectDojo Pro already has under the same name, with other values. DefectDojo Pro keeps its own values for them. When audit retention is on in DefectDojo Pro and audit events cross, a warning follows. It says that the next flush deletes migrated audit events older than the retention period. |
| **Products** | The totals of the source, and one row for each source Product with its **Include** box and its counts: engagements, tests, findings, endpoints, notes, files, risk acceptances and finding groups. The totals also show **Imports**, **Import Actions**, **Audit Events** and **Legacy Audit Entries**. They show only when the source sends that history and its field is on. **Target** shows where the Product lands: **New**, or the existing Product in DefectDojo Pro that it merges into. The summary counts the Products that merge into existing ones. After a run, **Imported** shows how many findings arrived for each Product. A search box filters the rows by name, and **Include All** and **Include None** set every visible row. |
| **To Be Created** | The users and the reference data that DefectDojo Pro does not have yet: SLA configurations, environments, regulations, note types and test types. A source user whose username already exists in DefectDojo Pro is reused. So is a source user whose email address matches exactly one user in DefectDojo Pro, under that user's username. **Reused Users** lists them, and says which were matched by email. A warning icon marks a user whose email address differs from the source. Check that it is the same person before the Sync. The **Users** row says how many of the new users were inactive on the source. **Notification Settings** names the new users whose notification settings cross. **System Settings** names the settings that the first Sync changes. |
| **Not Migrated** | A short list of what stays on the source. It names passwords and API tokens, tool and notification credentials, and Jira. It also names questionnaires, benchmarks and tracking files, and endpoint metadata and endpoints without findings. **Audit History** and **Import History** show here when the source sends no such history. They also show here when you turned the matching field off. |
| **Estimated Duration** | In the summary at the top: how long a Sync of the findings in the included Products takes. Before the first Sync, the estimate uses a default rate. Then it uses the rate of the last successful Sync. |
| **License** | A warning above the summary when the license has too few free seats for the users to create. The same when it has too few free assets for the included Products. |

The counts cover every Product on the source, also the Products you ignore.

#### What crosses

Each Sync imports every mapped Record. For each Product the connector sends:

* **The Product and its Product Type.** Description, tags, business criticality, SLA configuration, lifecycle, platform, origin, regulations, user records and metadata. If DefectDojo Pro has no lifecycle, platform or origin with the source value, the connector creates it with the source name, icon and order.
* **The owners of the Product, as members.** The source Product's product manager, technical contact and team manager become members of the Product. They get the Maintainer role. DefectDojo Pro finds each of them by email address. The three fields of the Product point at the migrated users too. A person's value in one of those fields stays. On each Sync, an owner gets that role again, also when an administrator changed it.
* **The access of each Product and Product Type, as members.** The users in the **Authorized Users** list of a source Product become members of the Product. The users in the **Authorized Users** list of its Product Type become members of the Product Type. The connector does this only when the connection maps every Product in that Product Type. Otherwise these users get no Product Type membership, so they get no access to the other Products in it. A user that was staff on the source gets the Maintainer role. Every other user gets the Writer role. A user that is already a member keeps the membership as it is. The connector gives each membership once. If an administrator removes a membership, a later Sync does not add it again. Only an owner of the Product differs, as described above. The connector skips an entry that names no user it migrated. The connector sets no global role.
* **Every engagement and every test**, with their fields, notes and files. The engagement fields include the first contact date, the reason, the tracker and test strategy links, the threat model, API test, pen test and check list boxes, the progress, the threat model path and whether the engagement is active. An engagement keeps its SCM server, build server and orchestration engine: the CI/CD infrastructure rows cross, and a row with the same name and type in DefectDojo Pro keeps its own values. A test brings its percent complete. A test with no findings still crosses. An engagement with no tests crosses too.
* **Every finding**, with every column. With **Include Duplicate Findings** on, a duplicate keeps the link to its original once both have arrived. A finding also brings its tags, vulnerability ids, CWEs and endpoints with their status and tags. Its notes, files, request and response pairs and metadata come too. It lands in the engagement and the test it came from.
* **The edit history of each note.** Each earlier text of a note crosses with its time and editor.
* **Risk acceptances**, with their notes and their proof file, linked to the same findings.
* **Finding groups**, with the same member findings.
* **Import history.** With **Migrate Import History** on, each import and reimport of a migrated test crosses once. It keeps its type, version, build id, commit hash, branch or tag, import settings, and its created and modified times. Each action of an import crosses on the finding it touched, with its time. An action whose finding did not migrate is dropped, and the warnings of the Sync count it. The import that the Sync itself writes for each test stays as it is.
* **Audit history.** With **Migrate Audit History** on, the change history crosses for each object that the migration created. These objects are findings, tests, engagements, finding groups and risk acceptances. A Product counts only when this connection created it. Each event keeps its time and its type: insert, update, delete or initial backfill. A field that names another object holds the object it became in DefectDojo Pro. It stays empty when that object did not cross. The context of an event keeps its source values and gains `migrated_from`, which names the source install and the connection. A source user maps to the DefectDojo Pro user that it became. The older legacy audit entries of these objects cross too. They keep their time, action, changes text and object name, and they show under **Legacy Audit Logs**. Ids inside the changes text stay as the source wrote them. DefectDojo Pro also writes its own events when the migration creates the objects. Their context has `source` set to `defectdojo_migration`.

The history fields need a source whose export offers history. An older source sends none, and the migration page names **Audit History** and **Import History** under **Not Migrated**.

* **Users.** Every user of the source crosses, also the users of a Product you ignore. A finding field that names a user, for example the reporter, points at these accounts. A user that was inactive on the source arrives inactive too, and **Activate and Invite** skips it. The preflight report counts these users. If you delete a migrated user in DefectDojo Pro, a later Sync does not create it again.
* **Source staff users.** A user that was staff on the source had access to every Product there. It gets the Maintainer role on every Product this connection migrates. It also gets that role on every Product Type that the connection maps fully. The preflight report and the migration summary name these users.
* **Reference data**: SLA configurations, development environments, regulations, note types and test types. If DefectDojo Pro already has one with the same name, it keeps its own values. The preflight report warns when those values differ from the source.
* **Finding templates**, with their tags and vulnerability ids. A template belongs to the instance, not to a Product. If DefectDojo Pro already has a template with the same title, it keeps its own. The connector adds no copy.
* **Tool types and tool configurations, without passwords and keys.** A tool type brings its name and description. A tool configuration brings its name, description, URL, authentication type, username and **Title for SSH/API Key**. It never brings its password, SSH key, API key or extras. The connector creates it with those fields empty. Tool types match by name, and a tool configuration matches by name within its tool type. If DefectDojo Pro already has one with the same name, it keeps its own values, passwords and keys included. For a configuration that the connector created, enter the password, SSH key, API key or extras in DefectDojo Pro yourself.
* **Engagement presets.** Each preset brings its title, notes, scope, test types and network locations. An engagement keeps the link to its preset, and a test keeps the link to its API scan configuration. A preset matches by Product and title. A test type matches by name. The connector creates the test types that DefectDojo Pro lacks before it applies the presets. If a name still matches no test type, the connector skips it. A network location matches by its location text. If none matches, DefectDojo Pro creates it. A preset that DefectDojo Pro already has keeps its own values.
* **Notification settings, once.** The notification settings of each user cross, with their settings for each Product. The system notification settings and the template for new users cross too. The first Sync copies them, and a later Sync changes nothing, so a change in DefectDojo Pro stays. The system settings and the template cross once for each DefectDojo Pro instance. A second source does not change them. A user that the connector creates gets the source settings. A user that already exists in DefectDojo Pro, or that signed in before the copy, keeps its own settings. It only gets the Product settings that it does not have yet. A Slack, Microsoft Teams, email or webhook channel sends nothing until you set it up in DefectDojo Pro.
* **Deduplication rules.** The rules set on the source for a scan type cross. A rule is the deduplication algorithm and the fields of the hash. A scan type that nobody changed on the source keeps the rule of DefectDojo Pro. A test type that the migration creates is the exception: it takes the rule of its first source test. A copied rule applies to deduplication and to reimport in DefectDojo Pro, before the first finding imports. The rule of a created test type arrives with its tests, after their findings import. If the rule changes the hash fields, DefectDojo Pro computes the hash of those findings again. A rule that a person edited in DefectDojo Pro stays, and the preflight report names its scan type. When two sources migrate into one DefectDojo Pro, the first one to copy a rule keeps it. The rule that lets a hash ignore a missing CWE is a deployment setting on both sides. The preflight report names each scan type where it differs, so an administrator can set it in DefectDojo Pro.
* **System settings, once.** The first Sync copies the behavior settings of the source. These include deduplication, false positive history and the verified status rules. They also include product grading, SLA notifications and the risk acceptance defaults. Disclaimers, password rules and feature switches such as finding groups cross too. A setting crosses only when DefectDojo Pro still has its default value, so a value that an administrator set stays. A password rule crosses only when the source rule is stricter. Duplicate deletion with its maximum and retroactive false positive history cross only into a DefectDojo Pro with no findings yet. Engagement auto-close and product tag inheritance never cross. A later Sync changes nothing. The settings cross once for each DefectDojo Pro instance. A second source changes none of them. The preflight report names the settings that the first Sync changes.
* **API scan configurations.** Each one brings its three service keys and points at the tool configuration it used on the source. A scan configuration matches by Product, tool configuration and first service key. The credentials are in the tool configuration. If the connector created it, enter them there.
* **Technologies and languages.** The technologies of each Product cross with their version, confidence, links and tags. Its languages cross with their file and line counts, and a language type that DefectDojo Pro does not have yet arrives with the source color.
* **Tool settings per Product.** Each setting crosses with its name, URL and project id, and points at the tool configuration it used on the source.
* **The requester and the report type of an engagement, its check list, the announcement and the login banner.** These need a source whose product export sends them. On an older source they stay behind, and the migration page names them under **Not Migrated**. The requester crosses as a contact, matched by email address. The check list keeps the findings it names. The announcement copies once, only when DefectDojo Pro has none. The login banner copies once, only onto the default banner.

A new user arrives inactive, with no usable password. It is never a superuser, also when it was one on the source. It does not use a license seat until it is activated. An administrator activates it with **Activate and Invite**. The user then sets a new password. If SSO or LDAP sign-in is on, the user signs in with SSO or LDAP instead. [How Migrated Users Sign In](/get_started/pro/onprem/migrating_from_open_source/#how-migrated-users-sign-in) explains the steps. If DefectDojo Pro already has a user with that username, the connector uses it and changes none of its fields. That user can still get the memberships above. The connector adds no user to a group. The default group rule of DefectDojo Pro still applies to a new user. That group can carry a global role. The memberships of a new user are in place before you activate it. The migration summary names the users that were superusers on the source, so you can decide who gets that role.

Each test keeps the test type and the scan type of the source test, exactly as written. A custom test type keeps its own name. A test with no scan type on the source has none in DefectDojo Pro either. Only a test with no test type on the source gets the test type `DefectDojo - Connectors Import`. Each Sync sets both again, so a test follows its source when its test type changes.

A test type that DefectDojo Pro lacks is created with the name and the settings of the source type. These settings are static tool, dynamic tool, active and dynamically generated. It also takes the deduplication rule of its first source test: the algorithm and the hash fields. When the rule of that test changes on the source, the next Sync changes the rule of the type too. Other tests of the type can use another rule on the source. Then the type keeps the rule of its first test, and the Sync adds a warning that names the type. A person's edit of that rule, or **Reset to Default**, stays on later Syncs, like a copied deduplication rule. A test type that DefectDojo Pro already has keeps its own settings. **Warnings** names it when its static tool, dynamic tool or active setting differs from the source. Its rule stays as it is, unless the deduplication rules above change it.

Each finding keeps its `found_by` list of test types. When both instances use the same rule, the deduplication hash of each finding stays equal to the source hash. The hash can differ for a test type that keeps its own rule in DefectDojo Pro. It can also differ for a test with another source rule than the first test of its type. The migration page counts the findings whose hash differs from the source at the last import.

**All Audit Logs** shows the last 31 days by default. A migrated event older than that shows on the history page of its object. It also shows when you change the date filter. See [Audit Logs Timeline](/admin/user_management/pro__audit_logging/#audit-logs-timeline).

Audit retention can delete migrated events. The flush runs when `DD_AUDITLOG_FLUSH_RETENTION_PERIOD` is 0 or above. It deletes audit events older than that many months, migrated events included. A period of 0 deletes every event. The flush keeps legacy audit entries. The preflight report warns about this when audit events cross. To keep older migrated events, raise the retention period before the Sync. You can also set `DD_AUDITLOG_FLUSH_RETENTION_PERIOD` to `-1` to turn the flush off. See [Configuration and retention](/admin/user_management/pro__audit_log_index/#configuration--retention-on-premise-controls).

#### What does not cross

* **Secrets and instance settings.** JIRA instances and credentials, API tokens and passwords. The Slack, Microsoft Teams, email and webhook setup. The system settings that hold a secret or describe the source instance also stay. These are the JIRA settings, the sender address, the URL prefix and the team name. Read-only mode, API error details and the GitHub switch stay too. So do the calendar, CVSS display and table search switches, which DefectDojo Pro manages another way. A tool configuration also keeps its password, SSH key, API key and extras on the source. Configure them in DefectDojo Pro yourself.
* **History of other data.** Users, finding templates, Product Types, endpoints, locations, tags and other reference data keep no source history. A Product that you mapped to an existing Product keeps only the history of DefectDojo Pro. The history of an object that the source deleted does not cross, because the object does not cross.
* **History you turn off, or that the source cannot send.** With **Migrate Import History** or **Migrate Audit History** off, that history stays on the source. A source on an older export sends no history. Findings then arrive with their current status.
* **JIRA issue links.**
* **The creator of a finding group.**
* **Files over Maximum File Size (MiB).** They stay on the source. The preflight report counts them. The export also keeps a file on the source when the files of one finding, engagement or test pass 48 MiB together. The connector also skips a file that does not fit its transfer budget for the Product. The summary notification after the migration counts every file that stayed. This covers engagement files, test files and risk acceptance proofs. The migration page and the migration summary say how many files it skipped.
* **Endpoints with no finding, and endpoint metadata.** Only endpoints on findings cross. Endpoint and location metadata stays on the source.
* **Questionnaires, benchmarks and tracking files.** They stay on the source. The migration page lists them under **Not Migrated**. The feature switches for questionnaires, benchmarks, checklists, tracking files and endpoint metadata import do not cross either.
* **Small fields.** The `mitigated_by` user of an endpoint status, the creator of a finding group, the creation dates of engagements and tests, the `done_testing` box of an engagement, and the join and last sign-in dates of a user. A risk acceptance on two engagements keeps one. A Product Type with no Product does not cross, with its Authorized Users.
* **Duplicates**, unless you turn on **Include Duplicate Findings**.
* **The Pro data of a DefectDojo Pro source.** Only the open source data crosses. The priority and risk scores, asset types, custom fields, groups and roles stay on the source. So does the history of that Pro data.

The [export API page](/automation/api/product_export/#what-does-not-cross) lists everything the source leaves out of its export.

#### Re-runs

Run Sync as often as you need until you cut over. Each run updates what an earlier run created. It makes no copies:

* A finding keeps its identity through its source id and its hash. A run with no change on the source changes nothing in DefectDojo Pro.
* A finding that changed on the source updates in DefectDojo Pro.
* A finding that the source deleted from a test closes in DefectDojo Pro. It is marked mitigated, not deleted. The test must still exist on the source.
* A note or a file keeps its identity too. A run updates it instead of adding a copy.
* A run adds only the imports, import actions, audit events and legacy audit entries made since the last run. It never adds one a second time.
* A test that the source deleted closes its findings in DefectDojo Pro, as above. The test itself stays.
* A re-run deletes nothing else. An engagement, a test, a note, a file, a finding group or a risk acceptance that the source deleted stays in DefectDojo Pro. A deleted risk acceptance stays linked to its findings, and the next run marks those findings as not accepted. A member that an administrator removed from a migrated Product comes back on the next run while the user is in the source's Authorized Users list or is an owner of the Product.

A Product that was deleted on the source after Discover is skipped with a message in the operation's history. Run Discover again to drop its Record. If a Sync stops in the middle of a Product, the next Sync imports that Product again. The source ids and the hash keep it free of duplicates.

A Sync overwrites changes made in DefectDojo Pro to migrated engagements, tests and findings. When a team starts to work on a Product in DefectDojo Pro, clear its **Include** box. Do this before the next Sync. A Product name or description that a person changed in DefectDojo Pro stays as changed.

One connection serves one source. If a second connection points at the same source, its preflight report warns, and its Sync writes nothing. Delete the second connection. Or delete the first one before you set up the second. The second then takes over what the first migrated.

#### Check the finding count after a Sync

A Sync operation shows **Success** when the connector has sent the data. DefectDojo Pro then imports the findings in the background. For a large Product, the import goes on for some minutes after **Success**. The migration page shows **Migration Complete** when the import ends.

Before you trust a Sync, open each Product and check its finding count. Compare it with the findings count of that Product in the preflight report. The count in DefectDojo Pro is lower by the findings that your fields skip. Duplicates, findings below **Minimum Severity** and, with **Include Inactive Findings** off, inactive findings are not imported.
