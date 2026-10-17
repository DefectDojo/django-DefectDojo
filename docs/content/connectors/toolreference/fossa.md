---
title: "FOSSA"
description: "How to set up the FOSSA Upstream Connector for DefectDojo"
weight: 60
audience: pro
---
The FOSSA connector imports both **security vulnerabilities** and **license-policy violations** from FOSSA. DefectDojo creates a Record for each FOSSA **project**.

#### Prerequisites

A FOSSA **Full** API token.

> **A Push-Only token will not work.** FOSSA's Push-Only tokens cannot read the APIs this connector uses, so the Sync fails to retrieve anything. This is the most common misconfiguration for this connector — make sure the token is a **Full** token.

#### Connector Mappings

1. Enter `https://app.fossa.com/api` in the **Location** field.
2. Enter your FOSSA Full API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.
4. Optionally, narrow what the connector imports with **Issue Categories**, **Project Labels**, **Project Title Filter** and **Tags** (see below).

Each FOSSA project becomes a Record. Only your organization's **active** issues are imported, covering both vulnerability and license-policy findings — so this connector can drive licence compliance work as well as security remediation.

#### Scoping the import (optional)

By default the connector discovers **every** project the token can see and imports **both** issue categories. In a large FOSSA organization that can mean hundreds of Records and a lot of licensing findings a security team may not want, or the reverse. The fields below, under **Import Filters** on the connector form, control the finding volume and which FOSSA projects become assets. All of them can be changed after the connection is created.

##### Issue Categories

Choose which FOSSA issue categories to import: **Vulnerabilities**, **Licensing**, or both (the default). At least one must stay selected.

An unselected category is not downloaded at all, so a vulnerabilities-only connection also syncs faster. Use this when licence compliance is handled elsewhere, or when you want a separate connection per team.

##### Project Labels

Import only FOSSA projects that carry **any** of the labels you list, as a comma-separated list of FOSSA project label names:

```
prod, payments
```

* Labels are matched as **whole names**, exactly but **case-insensitively**, so `prod` matches a label `Prod` but not `production`.
* A project with **no labels** is excluded whenever this field is set. If your FOSSA projects are not labelled, setting this field excludes every project.
* Leave it blank to import every project.

##### Project Title Filter

Import only FOSSA projects whose **title** matches **any** of the patterns you list. A project with no title is matched on its FOSSA locator instead.

```
github.com/example/*, *-service
```

The example above imports every project under `github.com/example/` plus every project whose title ends in `-service`.

* Matching is **case-insensitive**.
* `*` matches any run of characters, **including `/`**, so `*web` matches `github.com/example/web`.
* `?` matches exactly one character, and `[...]` matches one character from a set or range, for example `api-v[12]`.
* Commas separate patterns, so a pattern cannot contain one. To match a literal comma, use `?` in its place.
* A malformed pattern (for example an unclosed `[`) makes the connector fail with a configuration error, rather than silently matching nothing on every Sync.
* Leave it blank to import every project.

When **Project Labels** and **Project Title Filter** are both set, a project must pass **both**: it needs one of the labels **and** a matching title.

##### Tags

The **Tags** field imports only findings that carry at least one of the tags you list. Every FOSSA finding is tagged with its category, so `category:vulnerability` or `category:licensing` works here, as does the FOSSA issue type (for example `fossa:policy_conflict`) and the dependency's package manager (for example `package-manager:npm`). Prefer **Issue Categories** to split by category: it skips the download entirely instead of filtering after it.

##### Changing the scope later

* A project that a newly narrowed project filter excludes is no longer discovered. Its existing Record follows the normal lifecycle for assets the tool stops reporting: a **mapped** Record is flagged `MISSING`, and an unmapped `NEW` Record is removed. A Sync that runs before discovery catches up skips the Record rather than importing an empty result, so its findings are not closed by accident.
* **Turning off an issue category closes its findings** in projects that still have findings in the other category. Both categories are imported into the same test, so the next Sync's reimport closes the findings it no longer sees. A project whose findings were **all** in the category you turned off syncs empty, and its findings stay open; close or delete them in DefectDojo if you no longer want them.
* Findings already imported from a project that a project filter later excludes are **not closed automatically**, because its Record is skipped rather than synced. Close or delete them in DefectDojo if you no longer want them.
