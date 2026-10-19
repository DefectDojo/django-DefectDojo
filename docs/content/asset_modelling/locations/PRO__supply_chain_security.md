---
title: "Supply Chain Security"
description: "Flag components named by the OSSF malicious-packages feed, enforce license policies on component licenses, and check packages before they land"
weight: 9
audience: pro
---

**Supply Chain Security** checks every component in your Assets' inventory against two things: the [OSSF malicious-packages](https://github.com/ossf/malicious-packages) feed of known-malicious open-source packages, and the license policy you set. Matches become Findings on the Asset, and the same checks are available through the API for a list of packages you have not imported yet.

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

## Where the Findings Appear

Each Asset with a match gets an engagement and test named **Supply Chain Policy**. The evaluation runs every night after the feed syncs and reimports its results, so:

- A component that is removed from the Asset, or upgraded past a malicious version, has its Finding closed automatically.
- A license policy change takes effect on the next nightly run.
- Supply chain Findings get the same SLAs, notifications, Jira sync and risk acceptance as any other Finding.

Each Finding is linked to its component, so it also shows on the Dependency's page.

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

`block` means the package is known malicious or its license is denied, and `warn` means its license needs a review. `product` is optional; with it, that Asset's license policy applies instead of the default. You must be able to view the Asset.

The synced records are listed at `/api/v2/supply_chain_malicious_packages/` (filter by `purl_type` and `package`), and `/api/v2/supply_chain_malware_feed/` shows when each ecosystem last synced.

## Air-Gapped Instances

An instance with no route to OSV can load the feed from files. On a connected machine, download `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip` for each ecosystem you use, copy the files across, and load each one:

```bash
python manage.py load_malware_feed --file npm-all.zip --ecosystem npm --evaluate
```

`--evaluate` runs the Asset evaluation straight after loading. To sync through a mirror of OSV's bucket instead, set `DD_SUPPLY_CHAIN_OSV_BASE_URL` to the mirror's address.
