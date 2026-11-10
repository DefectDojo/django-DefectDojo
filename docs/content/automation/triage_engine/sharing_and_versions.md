---
title: "Sharing and Versions"
description: "Give a rule to a group, share it with other groups, export it to a file, import it on another instance, restore an earlier version, and drive rules from the API"
weight: 7
audience: pro
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Triage Engine is a DefectDojo Pro-only feature.</span>

A rule can leave the instance it was built on. You can export it to a JSON file, import that file on another instance, and go back to any earlier version of it. The usual reason is promotion: you build and run a rule on a test instance until it behaves, then carry it to production. The export file is also plain enough to keep in version control.

Within one instance, a rule can also belong to a group instead of to one person, and be shared with other groups. That is covered first.

## Group ownership

A rule is owned either by a group or by the instance. A group's rule belongs to the group rather than to whoever wrote it: its members manage it, it runs with the group's access, and it keeps running when the person who built it leaves.

Group Ownership is a beta feature and is off by default. A superuser turns it on under **Settings > Feature Flags**. While it is off, the controls on this page are hidden and every rule behaves as an Instance rule. Turning it on makes Group membership roles count for the content a Group owns: see [Group membership roles](/admin/user_management/pro__custom_rbac_roles/) for what that grants.

### Ownership tiers

| Tier | Owner | Who can see the rule | Who the rule runs as |
|---|---|---|---|
| **Group** | A group | Members of the group whose membership role carries **Rule View**, and anyone holding **Rule View** as a global role | The group's automation identity |
| **Shared** | A group | Everyone above, plus members of the chosen groups whose membership role carries **Rule View**. A shared group can read the rule but never change it. | The group's automation identity |
| **Everyone** | A group | Anyone who holds **Rule View** through any role | The group's automation identity |
| **Instance** | No group | Anyone holding **Rule View** as a global role | The person who owns the rule |

Every rule that existed before Group Ownership is an Instance rule, and stays one until someone transfers it. Instance rules work exactly as they always have: each runs as its human owner, and only that owner (or a superuser) can change it.

The permissions involved (**Rule View**, **Rule Add**, **Rule Edit**, **Rule Delete** and the node family permissions) sit in the **Group Content** table of a role. Held as a global role, they apply to every rule. Held as a group membership role, they apply to that group's rules. No built-in role carries them: see [Group Content permissions](/admin/user_management/pro__custom_rbac_roles/#group-content-permissions) for how to set up a role that does.

### Who can change a group's rule

Changing what a group's rule does (editing it, enabling or disabling it, running it, setting its schedule, restoring a version, sharing or transferring it) needs both of these:

* **Rule Edit** through your membership role in the owning group, or through a global role.
* Membership of the owning group.

Membership is required because the rule acts with the group's access. Someone outside the group cannot change what a group's rule does, even with **Rule Edit** as a global role, because that would let them act with access they do not have. A superuser can always change it.

Deleting a group's rule needs only **Rule Delete**, through your membership role in the owning group or through a global role. Deleting stops the rule rather than acting with the group's access, so it does not need membership.

**Preview** in the rule editor runs with your own access, not the group's, so for a group's rule it can show items the group itself cannot see. The rule's runs use the group's access, as its **Runs As** panel says.

### Creating a rule in a group

**New Rule**, **From Template** and **Import** each offer an **Owned By** choice:

* The groups where your membership role carries **Rule Add** (every group, if you hold **Rule Add** as a global role, though you must still be a member of the group you choose).
* **Instance**, if you hold **Rule Add** as a global role.

When there is only one choice it is already selected. With more than one, pick one before saving, adopting a template or importing: nothing is created until you do. Starting a rule from **New Rule** in the **Rules** row of a group's **Owned Content** tab selects that group. The owner is fixed when the rule is created: to move it later, use **Transfer**.

The rule lists on **Act > Triage Engine > Rules** have an **Owner** column (the group, or **Instance**) and an **Owner** filter:

| Owner filter | Shows |
|---|---|
| **My Groups** | Rules owned by a group you are a member of |
| **Shared With Me** | Rules another group has shared with one of your groups |
| **Everyone** | Rules shared with everyone |
| **Instance** | Rules with no owning group |
| A group, by name | Rules that group owns. The **Rules** row of the group's **Owned Content** tab opens the list this way. |

The filter only narrows the list. It never shows a rule you could not otherwise see.

Rule names do not have to be unique. Two groups can each have a rule called `Escalate KEV`, and the **Owner** column tells them apart.

### Runs As

Every rule runs as someone, and that identity decides what the rule can see and change. A group's rule runs as the group's **automation identity**, a service user the group gets the first time it owns a rule or a report schedule. The identity has exactly the group's access: the group's Organization and Asset roles and its global roles, and nothing else. When the group's access changes, so does what its rules can reach. See [the group's automation identity](/admin/user_management/create_user_group/#the-groups-automation-identity).

The **Runs As** panel in the rule editor says who the rule runs as:

* For a group's rule, the group's automation identity and what it can see (how many Organizations and Assets), with a link to the group. When the group holds a global role, the panel warns that the group has instance-wide access, so the rule can act on every Finding.
* For an Instance rule, the person who owns it, with a suggestion to move the rule into a group so that it runs as automation instead.

### Sharing a rule

Open a rule's menu and choose **Share**. **Visible To** offers:

* **Group**: only the owning group's members (the default).
* **Specific Groups**: the owning group plus the groups you choose. You can only choose groups you can see. Their members read the rule but cannot change it.
* **Everyone**: anyone who holds **Rule View** through any role. Only someone holding **Rule Edit** as a global role can share with everyone, so a group cannot broadcast its rules without an instance-level grant.

Sharing changes who can read a rule. It never changes who the rule runs as or who can edit it.

### Transferring a rule

Open a rule's menu and choose **Transfer** to move it to another group or to the instance. You need **Rule Edit** on the rule and permission to create rules where it is going: **Rule Add** in the destination group (and membership of it), or **Rule Add** as a global role to move it to **Instance**. You must also be allowed to use every node family the rule contains in its new home (see [Node family permissions](../building_rules/#node-family-permissions)).

A transfer changes who the rule runs as, so it also:

* turns the rule off,
* clears its credentials (signing secrets, tokens, passwords and API keys in node settings), and
* clears any reference its new identity is not allowed to use.

Review the rule, fill in what was cleared, and enable it again. A rule moved to **Instance** is owned by, and runs as, the person who moved it. Sharing starts over after a transfer: the rule is visible to its new owning group only.

A rule managed by a webhook receiver cannot be transferred until it is detached from the receiver.

**Take Ownership** still works for Instance rules, whether or not group ownership is turned on. It is a transfer of someone else's Instance rule to **Instance**, with you as its owner, so it needs what that transfer needs (**Rule Edit**, **Rule Add** as a global role, and every node family the rule contains) and has the same effect: the rule is turned off, its credentials are cleared, and sharing starts over. A group's rule cannot be taken over this way: move it with **Transfer**.

### Unowned rules

A rule is left without an owner when its group is deleted, or when the person an Instance rule runs as is deleted or deactivated. Deleting a group turns off every rule it owned. These rules appear under **Settings > Groups > Unowned Content**, together with report templates, blocks, themes and schedules in the same state.

The page is open to anyone holding **Rule Edit** as a global role (for rules) or **Report Template Edit** as a global role (for the Report Builder types). Each person sees the types their permissions cover. Select one or more rows and choose **Transfer** to move them to a group or to the instance in one step. Each move follows the same rules as a single transfer: the destination has to be somewhere you could have created the rule. Rules arrive turned off, so review each one before enabling it.

### What a rule may act on

These limits apply to every rule, whoever owns it:

* **A rule only changes Findings its identity may edit.** Nodes that change Findings act only on Findings the rule's run-as identity (or, for an Instance rule, its owner) has permission to edit. A Finding it can view but not edit is left alone, and the node's entry in the run trace counts it, for example "12 findings not edited: no edit permission". An Instance rule whose owner can only read some Assets now leaves those Assets' Findings unchanged instead of editing them.
* **A group's rule only names groups and users its identity can see.** **Set Owners**, **Set Reviewers** and the recipients of **Raise an In-App Alert** must be groups and users the group's automation identity can see. A run that meets one it cannot see fails with an error naming it.

## Exporting rules

Open a rule's menu on **Act > Triage Engine > Rules** and choose **Export**. To export several rules as one file, tick them in the list and choose **Export** in the bar that appears. One file holds up to 100 rules.

The file contains each rule's name, description, mode, graph and schedule, and a stable identifier for the rule that importing uses to recognise it again. The file does not record which group owns the rule: the importer chooses the owner. A few things are handled differently from the rule as you see it in the editor:

- **Secrets are never exported.** Signing secrets, tokens, passwords and API keys in node settings are left out, so the file is safe to store and pass around. Whoever imports the rule enters them again.
- **Webhook URLs typed into a node are left out too.** An incoming-webhook URL (Slack, Teams and many others) often carries its token in the address, so a **Call a Webhook** node's **URL** setting is exported empty. A node that uses a configured webhook endpoint is exported by the endpoint's name instead. After importing, enter the URL again, or overwrite the rule and its stored URL is kept.
- **References are written by name.** A rule refers to Assets, Organizations, connections, SLA configurations, report templates and so on by internal ID, and the same object has a different ID on another instance. The export therefore writes a portable key beside each ID: a name, a username, or a connection's label and vendor. A reference you cannot see yourself is exported empty and noted in the file's `warnings`, so an export never reveals the name of an object you could not have picked in the editor.

Exporting needs only permission to view rules.

## Importing rules

Choose **Import** on the Rules page and pick an export file. DefectDojo runs a dry run straight away and shows what the import would do, one row per rule:

- the rule's name, and whether it will be created, skipped or overwrite a rule already here
- every reference it could not match here
- any problem that stops it from being imported

Nothing is created until you press **Import**. If any rule in the file has a problem, nothing is imported at all. In the rare case that saving a rule fails after the checks passed (the database or the scheduling service refuses it), the rules before it stay imported, and the report marks which ones were written.

Every imported rule arrives **disabled** and in **Simulate** mode. Choose its owner in **Owned By** before importing: a group you can create rules in, or **Instance**, in which case the rule is owned by whoever imported it. A rule imported into a group runs as that group's automation identity, and only node families you may use in that group are accepted. Review it, fill in anything left empty, then enable it, as described in [Testing a rule safely](../building_rules/#testing-a-rule-safely).

Importing needs **Rule Add** where the rules will be owned: in the chosen group (as a member of it), or as a global role for **Instance**.

### How references are matched

Each reference in the file is looked up on this instance by its portable key:

| The rule refers to | Matched by |
|---|---|
| Users | Username |
| Groups, Assets, Organizations, SLA configurations, Prioritization Engines, dedupe pools, report templates, notification webhooks | Name |
| Mitigation policies | Title |
| Engagements | Asset name and Engagement name |
| Downstream Connector connections | Label and vendor |
| Issue tracker mappings | Label, plus the connection's label and vendor |
| Webhook receivers | Label, preferring one you own |
| IDs inside a trigger's scope filters | The same keys as above, filter by filter |

A reference is filled in only when exactly one object matches **and** you are allowed to use it. Otherwise it is left empty and the report says why: nothing matched, more than one object matched, or the match is one you cannot see. A rule saved with an empty required setting cannot be enabled, or run with **Run Now**, until someone fills it in.

A few things are never carried across, because they only exist on the source instance:

- **Risk acceptances** named in a node, and **Shogun case IDs**, are always left empty.
- **Scope filters on individual records** (a Finding ID, a Test, an endpoint) are removed. If a scope filter loses all of its values this way, it is removed entirely, which makes the rule's scope **wider** than it was. The report says so for each filter affected. Read the scope before enabling the rule.
- **Custom fields** are matched by their slug. A rule that sets or clears a custom field that does not exist here is not imported. Create the custom field first.
- **Nodes for a feature that is turned off here** (a Shogun node, Dynamic Scanning) stop the rule from being imported.

Message destinations such as a Slack channel are copied as they are. They only work when the matching connection on this instance points at the same workspace.

### When a rule is already here

Each rule in an export file carries a stable identifier, and import uses it to recognise a rule that is already on this instance (one imported from the same file earlier, for example). A file exported before rules had identifiers is matched by name instead, among the rules of the owner you are importing into. Rule names do not have to be unique, so a name alone never stops an import.

Choose what happens when an imported rule matches one already here:

- **Create** imports the rule as a new rule beside the existing one, keeping the name it has in the file. This is the default.
- **Skip** leaves the existing rule alone and does not import that one.
- **Overwrite** replaces the existing rule's graph and description with the imported ones, as a new version of that rule, and disables it. You need permission to change the existing rule (for a group's rule, **Rule Edit** in the group and membership of it; for an Instance rule, being its owner) as well as **Rule Add**, and a rule managed by a webhook receiver cannot be overwritten. The rule keeps its own secrets for any node that is unchanged, and keeps its owner.

If two rules in one file match the same rule here, only the first can overwrite it, and the second is imported as a new rule.

## Versions and restoring

Every saved change to a rule is kept as a version. Open a rule's menu and choose **Versions** to see them, newest first, with who saved each one, when, which settings changed, and how many nodes were added, removed or changed.

From a version's menu:

- **View** shows that version's nodes.
- **Export** downloads that version as an export file. This is how you carry a rollback to another instance.
- **Restore** puts that version's graph and description back.

A restore is itself saved as a new version, so it can be undone the same way. Restoring brings back only the graph and description. The rule's name, mode, enabled state, owner, sharing and schedule stay as they are now.

Secrets are never taken from history. Each node keeps the secret it has now, and a node that no longer exists comes back with its secret empty. This matters after a rule changes owner or is transferred: a version saved under the previous owner cannot bring back their webhook secret. Any reference in the old version that no longer exists, or that you are not allowed to use, is left empty, and the rule is disabled until you fill it in.

Restoring a version needs the same permission as any edit: for an Instance rule, being its owner (or a superuser); for a group's rule, **Rule Edit** in the group and membership of it. Viewing versions needs permission to view rules.

Versions are read from the audit log. If the audit log is turned off, no versions are kept, and audit log retention removes old versions along with the rest of the audit history.

## Using the API

The rules API is available on the public, token-authenticated API at `/api/v2/rules_engine_v2/rules/`, with the same permissions as the UI. It covers listing, creating, updating and deleting rules, validating and previewing a graph, running a rule, and everything on this page. Authenticate with your API token:

```bash
curl -H "Authorization: Token <your API key>" \
  https://defectdojo.example.com/api/v2/rules_engine_v2/rules/
```

The Pro UI calls an internal mirror of these endpoints under `/api/vue/`. Always automate against the `/api/v2/` paths documented here.

| Method and path | What it does |
|---|---|
| `GET /api/v2/rules_engine_v2/rules/{id}/export/` | Export one rule. Add `?event_id=<id>` to export one of its versions. |
| `GET /api/v2/rules_engine_v2/rules/export/?id=1,2,3` | Export several rules as one file. Takes the same filters as the rule list, up to 100 rules. |
| `POST /api/v2/rules_engine_v2/rules/import/` | Import a file. Body: `bundle` (the file's contents), `dry_run` (default `true`), `conflict` (`create`, `skip` or `overwrite`; default `create`), and `owner_group` (the id of the group the new rules will belong to; leave it out for **Instance**). |
| `GET /api/v2/rules_engine_v2/rules/{id}/versions/` | List a rule's versions, newest first. Paged with `limit` and `offset`. |
| `GET /api/v2/rules_engine_v2/rules/{id}/versions/{event_id}/` | One version, with its graph. Secrets are masked. |
| `POST /api/v2/rules_engine_v2/rules/{id}/restore/` | Restore a version. Body: `event_id`, and optionally `expected_version`. |
| `GET /api/v2/rules_engine_v2/rules/?scope=mine` | List rules by ownership. `scope` is `mine` (owned by a group you are a member of), `shared` (shared with one of your groups), `everyone` or `instance`. `owner_group=<id>` lists one group's rules, and `owner_group=instance` the rules with no group. |
| `POST /api/v2/rules_engine_v2/rules/{id}/share/` | Change who can read a rule. Body: `visibility` (`group`, `shared` or `everyone`) and, for `shared`, `shared_groups` (a list of group ids). |
| `POST /api/v2/rules_engine_v2/rules/{id}/transfer/` | Move a rule. Body: `owner_group` (a group id, or `null` for the instance). The rule is turned off and its credentials are cleared. |

Every rule in a response carries its ownership: `owner_group` (the group's id, or `null` for an Instance rule), `owner_group_name`, `visibility` (`group`, `shared`, `everyone`, or `orphaned` for a rule whose group was deleted), `shared_groups` (each with `id` and `name`, when `visibility` is `shared`), and `uuid`, the stable identifier export and import use. To create a rule in a group, send `owner_group` with the create request. It can only be set when the rule is created: a different value on an update answers `400` and points to `transfer/`. `share/` and `transfer/` answer `403` with a `detail` sentence when you may not make the change (for example, sharing with everyone without **Rule Edit** as a global role), and `400` for invalid input. `take_ownership/` on a group's rule answers `409`: move it with `transfer/` instead.

An import answers `200` with one report row per rule, or `400` with the same report when any rule has a problem. A problem found while checking the file means nothing was written. If saving a rule fails after the checks passed, the rules before it stay written and the response's `imported` count says how many. Each row gives the rule's `name`, its `action` (`create`, `skip` or `overwrite`), its `warnings` and `problems`, `written`, and, once written, its `rule_id`. The older `conflict` value `rename` is still accepted and means `create`.

A restore with `expected_version` answers `409` if the rule has been saved since you read it, so a restore cannot quietly undo a change someone else just made.

### Promoting a rule from staging to production

1. Export the rule from the staging instance:

   ```bash
   curl -s -H "Authorization: Token $STAGING_TOKEN" \
     https://staging.example.com/api/v2/rules_engine_v2/rules/42/export/ > rule.json
   ```

2. Dry-run the import on production and read the report:

   ```bash
   curl -s -X POST -H "Authorization: Token $PROD_TOKEN" -H "Content-Type: application/json" \
     -d "{\"bundle\": $(cat rule.json), \"dry_run\": true}" \
     https://defectdojo.example.com/api/v2/rules_engine_v2/rules/import/
   ```

3. When every row is free of problems and the warnings are ones you expect, run it again with `"dry_run": false`.
4. Open the imported rule on production, fill in anything left empty, enter its secrets, and enable it in **Simulate** mode. Switch it to **Live** once its deliveries look right.

To roll back on production later, list the rule's versions and restore the one you want:

```bash
curl -s -H "Authorization: Token $PROD_TOKEN" \
  https://defectdojo.example.com/api/v2/rules_engine_v2/rules/57/versions/

curl -s -X POST -H "Authorization: Token $PROD_TOKEN" -H "Content-Type: application/json" \
  -d '{"event_id": 1234}' \
  https://defectdojo.example.com/api/v2/rules_engine_v2/rules/57/restore/
```
