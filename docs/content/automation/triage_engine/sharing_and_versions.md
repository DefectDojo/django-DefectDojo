---
title: "Sharing and Versions"
description: "Export rules to a file, import them on another instance, restore an earlier version, and drive rules from the API"
weight: 7
audience: pro
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Triage Engine is a DefectDojo Pro-only feature.</span>

A rule can leave the instance it was built on. You can export it to a JSON file, import that file on another instance, and go back to any earlier version of it. The usual reason is promotion: you build and run a rule on a test instance until it behaves, then carry it to production. The export file is also plain enough to keep in version control.

## Exporting rules

Open a rule's menu on **Act > Triage Engine > Rules** and choose **Export**. To export several rules as one file, tick them in the list and choose **Export** in the bar that appears. One file holds up to 100 rules.

The file contains each rule's name, description, mode, graph and schedule. Two things are handled differently from the rule as you see it in the editor:

- **Secrets are never exported.** Signing secrets, tokens, passwords and API keys in node settings are left out, so the file is safe to store and pass around. Whoever imports the rule enters them again.
- **References are written by name.** A rule refers to Assets, Organizations, connections, SLA configurations, report templates and so on by internal ID, and the same object has a different ID on another instance. The export therefore writes a portable key beside each ID: a name, a username, or a connection's label and vendor. A reference you cannot see yourself is exported empty and noted in the file's `warnings`, so an export never reveals the name of an object you could not have picked in the editor.

Exporting needs only permission to view rules.

## Importing rules

Choose **Import** on the Rules page and pick an export file. DefectDojo runs a dry run straight away and shows what the import would do, one row per rule:

- the name the rule will get on this instance
- every reference it could not match here
- any problem that stops it from being imported

Nothing is created until you press **Import**. If any rule in the file has a problem, nothing is imported at all. In the rare case that saving a rule fails after the checks passed (the database or the scheduling service refuses it), the rules before it stay imported, and the report marks which ones were written.

Every imported rule arrives **disabled**, in **Simulate** mode, and owned by whoever imported it. Review it, fill in anything left empty, then enable it, as described in [Testing a rule safely](../building_rules/#testing-a-rule-safely).

Importing needs permission to add rules.

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

### When a rule name is already taken

Rule names are unique. Choose what happens when an imported rule's name is already in use:

- **Import as New** adds the rule under a numbered name, such as `Escalate KEV (2)`. This is the default.
- **Skip** leaves the existing rule alone and does not import that one.
- **Overwrite** replaces the existing rule's graph and description with the imported ones, as a new version of that rule, and disables it. You can only overwrite a rule you own, you need permission to edit rules (Rule Edit) as well as to add them, and a rule managed by a webhook receiver cannot be overwritten. The rule keeps its own secrets for any node that is unchanged.

## Versions and restoring

Every saved change to a rule is kept as a version. Open a rule's menu and choose **Versions** to see them, newest first, with who saved each one, when, which settings changed, and how many nodes were added, removed or changed.

From a version's menu:

- **View** shows that version's nodes.
- **Export** downloads that version as an export file. This is how you carry a rollback to another instance.
- **Restore** puts that version's graph and description back.

A restore is itself saved as a new version, so it can be undone the same way. Restoring brings back only the graph and description. The rule's name, mode, enabled state, owner and schedule stay as they are now.

Secrets are never taken from history. Each node keeps the secret it has now, and a node that no longer exists comes back with its secret empty. This matters after a rule changes owner: a version saved by the previous owner cannot bring back their webhook secret. Any reference in the old version that no longer exists, or that you are not allowed to use, is left empty, and the rule is disabled until you fill it in.

Only the rule's owner (or a superuser) can restore a version, the same as any edit. Viewing versions needs permission to view rules.

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
| `POST /api/v2/rules_engine_v2/rules/import/` | Import a file. Body: `bundle` (the file's contents), `dry_run` (default `true`), `conflict` (`rename`, `skip` or `overwrite`; default `rename`). |
| `GET /api/v2/rules_engine_v2/rules/{id}/versions/` | List a rule's versions, newest first. Paged with `limit` and `offset`. |
| `GET /api/v2/rules_engine_v2/rules/{id}/versions/{event_id}/` | One version, with its graph. Secrets are masked. |
| `POST /api/v2/rules_engine_v2/rules/{id}/restore/` | Restore a version. Body: `event_id`, and optionally `expected_version`. |

An import answers `200` with one report row per rule, or `400` with the same report when any rule has a problem. A problem found while checking the file means nothing was written. If saving a rule fails after the checks passed, the rules before it stay written and the response's `imported` count says how many. Each row gives the rule's `name`, its `action` (`create`, `rename`, `skip` or `overwrite`), its `warnings` and `problems`, `written`, and, once written, its `rule_id`.

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
