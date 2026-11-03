---
title: "Supply Chain Security"
description: "Flag components named by the OSSF malicious-packages feed, enforce license policies, analyze npm and PyPI packages for risky behavior, and check packages before they land"
weight: 9
audience: pro
---

**Supply Chain Security** checks every component in your Assets' inventory against the [OSSF malicious-packages](https://github.com/ossf/malicious-packages) feed of known-malicious open-source packages and the license policy you set. With **Package Analysis** on, it also reads the code of each npm and PyPI version and raises alerts for risky behavior, such as install scripts or obfuscated code. Matches become Findings on the Asset, and the same checks are available through the API for a list of packages you have not imported yet.

> Supply Chain Security requires the Locations feature and is enabled separately as the **Supply Chain Security** flag (beta) on the [Feature Flags page](/admin/feature_flags/pro__feature_flags/).

## What It Checks

The checks run against the Dependency locations on each Asset. Those come from SBOM imports (see [Working with SBOMs](/asset_modelling/locations/pro__working_with_sboms/)) and from SCA scanners and connectors that report components.

### Known-malicious packages

Every night DefectDojo syncs the OSSF malicious-packages records for npm, PyPI, Go, Maven, crates.io, RubyGems, NuGet and Packagist from OSV's public data. A component that a record names gets a **Critical** Finding naming the package and version, with the record's analysis, its aliases and a link to the record on osv.dev.

Package names are compared the way each registry compares them. For example, PyPI treats `Django_REST.framework` and `django-rest-framework` as the same package, and so does this check. A record usually names a whole package; when it names specific versions, only those versions match. When a component's version cannot be compared to a record's version range, the component is treated as affected, so an unusual version string never hides a malware match.

Only public data is downloaded. Your inventory is matched on your instance and never sent anywhere.

### License policy

A license policy lists licenses by their [SPDX identifier](https://spdx.org/licenses/):

- **Denied licenses**: a component under one of these gets a Finding at the policy's denied severity (High by default).
- **Review licenses**: a component under one of these gets a Finding at the review severity (Low by default).
- **Allowed licenses**: optional. When the list is not empty, any license that is not on it needs a review.
- **Flag unknown**: a component with no declared license needs a review.

Entries are case-insensitive and may use `*` as a wildcard, so `AGPL-*` covers every AGPL version. Deprecated identifiers match their current form (`GPL-3.0` and `GPL-3.0-only` are the same license).

License expressions are evaluated the way SPDX defines them. `MIT OR GPL-3.0-only` is acceptable when MIT is, because you may use the component under either license. `MIT AND GPL-3.0-only` is only as acceptable as its stricter part.

There is one default policy for the instance, and each Asset can have its own policy that replaces the default. An Asset policy that is turned off opts that Asset out of license checks.

### Package analysis

Package analysis looks at what a package does, so it can catch a malicious or risky version before any feed names it. It is enabled separately as the **Package Analysis** flag (beta), which requires **Supply Chain Security** and a Sensei license.

For each npm and PyPI version in your inventory, the Sensei engine downloads the version's metadata and artifact from the public registry (or the mirror you configure), checks the artifact's digest, and reads its code without running it. Each version is analyzed once, and the result is shared by every Asset that carries it. Only package names and versions are sent to the registries; your inventory is not.

Each analysis can raise these alerts:

| Alert | Default action | What it means |
|---|---|---|
| Install script added | Warn | This version runs an install script and the previous version did not. |
| Install scripts | Monitor | The package runs code when it is installed. |
| Executable .pth file | Warn | A Python `.pth` file runs code every time the interpreter starts. |
| Obfuscated code | Warn | Code that hides what it does, such as decoded and evaluated strings. |
| Unstable ownership | Warn | The package's maintainers or publisher changed recently. |
| Manifest confusion | Warn | The registry's metadata disagrees with the package's own manifest. |
| Git dependency | Warn | A dependency is fetched from a Git repository instead of the registry. |
| HTTP dependency | Warn | A dependency is fetched from a plain URL. |
| Recently published | Warn | The version is younger than the policy's cool-down (off by default). |
| Yanked | Warn | The version was withdrawn by its publisher. |
| npm shrinkwrap | Monitor | The package pins its own dependency tree. |
| Network access | Monitor | The code opens network connections. |
| Shell access | Monitor | The code runs shell commands or child processes. |
| Uses eval | Monitor | The code evaluates strings as code. |
| Native code | Monitor | The package ships or builds native binaries. |
| Dynamic require | Monitor | The code loads modules whose names it computes at run time. |
| Environment variable access | Monitor | The code reads environment variables. |
| High-entropy strings | Monitor | The code holds long random-looking strings, such as encoded payloads. |
| Trivial package | Monitor | The package holds very little code. |
| Partially analyzed | Monitor | Part of the package's code was not read, because it was past the analysis's size, file-count or time limits. |
| Deprecated | Monitor | The publisher marked the version deprecated. |
| Filesystem access | Ignore | The code reads or writes files. |

A version the engine could not read (for example, a registry error) is marked failed and tried again after seven days. Each version is read as npm or pip would install it: for PyPI, every wheel and the sdist, up to eight files per version. Ecosystems other than npm and PyPI are not analyzed.

Analysis runs in the background: every ten minutes, a few jobs at a time and within a daily limit, so it never crowds out your other Sensei scans. A first pass over a large inventory spreads over several days. Versions you check through the evaluate API are also queued as they are met (see [Using the API](#using-the-api)).

### Alert policies

An alert policy sets what each alert type does:

- **Block**: the alert raises a Finding, and the evaluate API answers `block`.
- **Warn**: the alert raises a Finding, and the evaluate API answers `warn`.
- **Monitor**: the alert is recorded and shown in the API, but raises no Finding.
- **Ignore**: the alert is dropped.

A policy only lists the alert types it changes; every other type keeps its default action from the table above. A policy can also set a **cool-down** in hours, which raises a Recently published alert for any version younger than that.

As with license policies, there is one default policy for the instance, and an Asset's own policy replaces it. An Asset policy that is turned off opts that Asset out of alert Findings.

## Where the Findings Appear

Each Asset with a match gets an engagement and test named **Supply Chain Policy**. The evaluation runs every night after the feed syncs and reimports its results, so:

- A component that is removed from the Asset, or upgraded past a malicious version, has its Finding closed automatically.
- A license policy change takes effect on the next nightly run.
- Supply chain Findings get the same SLAs, notifications, Jira sync and risk acceptance as any other Finding.

Each Finding is linked to its component, so it also shows on the Dependency's page. A package analysis Finding lists where in the package each alert was found, with the file, the line and a short excerpt of the code.

## Using the API

Manage license policies with `/api/v2/supply_chain_license_policies/`. A policy with no `product` is the default.

```json
POST /api/v2/supply_chain_license_policies/
{
  "name": "Default",
  "denied_licenses": ["AGPL-*", "SSPL-1.0"],
  "review_licenses": ["GPL-*", "LGPL-*"],
  "denied_severity": "High",
  "review_severity": "Low"
}
```

Managing policies requires the license policy configuration permissions (view, add, change and delete), which superusers have.

Alert policies work the same way at `/api/v2/supply_chain_alert_policies/`, with the alert policy configuration permissions. `actions` maps alert types to `block`, `warn`, `monitor` or `ignore`, and `/api/v2/supply_chain_alert_policies/alert_types/` lists every alert type with its severity and default action:

```json
POST /api/v2/supply_chain_alert_policies/
{
  "name": "Default",
  "actions": {"obfuscated_code": "block", "network_access": "warn"},
  "cooldown_hours": 48
}
```

To check packages before they are added, for example in a CI pipeline, send them to the evaluate endpoint. It writes nothing and returns `allow`, `warn` or `block` for each package:

```json
POST /api/v2/supply_chain_evaluate/
{
  "product": 12,
  "components": [
    {"purl": "pkg:npm/left-pad@1.3.0", "license_expression": "MIT"},
    {"purl": "pkg:pypi/example-package@2.0.0", "license_expression": "GPL-3.0-only"}
  ]
}
```

`block` means the package is known malicious, its license is denied, or it has an alert whose action is block. `warn` means its license needs a review or it has an alert whose action is warn. `product` is optional; with it, that Asset's license and alert policies apply instead of the defaults. You must be able to view the Asset.

With Package Analysis on, each result also has an `analysis` state and the package's `alerts`, each with its type, action, severity and where it was found. The `analysis` state is one of:

- `complete`: the version has been read.
- `pending`: it has not been read yet.
- `failed`: the engine could not read it.
- `unsupported`: the ecosystem is not analyzed.
- `off`: package analysis is not enabled.

A `pending` version is queued for analysis when you can import scan results into at least one Asset, up to 100 versions per user per hour, so a CI pipeline that checks the same packages again a little later gets their alerts.

Analysis results are listed at `/api/v2/supply_chain_package_analyses/` (filter by `purl_type`, `package`, `version`, `status` and `alert_type`). Users without global view permission see only the versions in Assets they can view.

The synced records are listed at `/api/v2/supply_chain_malicious_packages/` (filter by `purl_type` and `package`), and `/api/v2/supply_chain_malware_feed/` shows when each ecosystem last synced.

## Air-Gapped Instances

An instance with no route to OSV can load the feed from files. On a connected machine, download `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip` for each ecosystem you use, copy the files across, and load each one:

```bash
python manage.py load_malware_feed --file npm-all.zip --ecosystem npm --evaluate
```

`--evaluate` runs the Asset evaluation straight after loading. To sync through a mirror of OSV's bucket instead, set `DD_SUPPLY_CHAIN_OSV_BASE_URL` to the mirror's address.

Package analysis needs to reach the npm and PyPI registries, so it does not run on an air-gapped instance. To read packages through your own registry mirror (for example Artifactory, Nexus or Verdaccio), set `DD_SUPPLY_CHAIN_NPM_REGISTRY_URL` and `DD_SUPPLY_CHAIN_PYPI_URL`. A mirror URL may carry `user:token@` credentials, which are sent only to that mirror.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `DD_SUPPLY_CHAIN_ANALYSIS_DAILY_LIMIT` | 2000 | Versions the background run analyzes per 24 hours. |
| `DD_SUPPLY_CHAIN_ANALYSIS_MAX_JOBS_IN_FLIGHT` | 2 | Package analysis jobs running at once. |
| `DD_SUPPLY_CHAIN_ANALYSIS_QUEUE_PER_USER_HOUR` | 100 | Versions one user may queue through the evaluate API per hour. |
| `DD_SUPPLY_CHAIN_NPM_REGISTRY_URL` | `https://registry.npmjs.org` | The npm registry or mirror to read packages from. |
| `DD_SUPPLY_CHAIN_PYPI_URL` | `https://pypi.org` | The PyPI index or mirror to read packages from. |
