---
title: "JFrog XRay"
description: "How to set up the JFrog XRay Upstream Connector for DefectDojo"
weight: 81
audience: pro
---
The JFrog Xray connector uses the JFrog Xray REST API to fetch vulnerability data from your Artifactory repositories. DefectDojo will discover all repositories in your JFrog instance and generate vulnerability reports via Xray, importing findings on a scheduled basis.

#### Prerequisites

You will need an API token with access to both Artifactory and Xray APIs. We recommend creating a dedicated service account for DefectDojo. The account requires:

* Read access to Artifactory repositories
* Permission to generate and view Xray vulnerability reports (`Apply on Watches` permission in Xray, or equivalent)

#### Connector Mappings

1. Enter your JFrog instance base URL in the **Location** field. This should be the root URL of your JFrog instance, for example `https://your-instance.jfrog.io`. Do not include a trailing path — DefectDojo will construct the appropriate API paths automatically.
2. Enter a valid **Reference Token** in the **Secret** field. Tokens can be generated under **User Management \> Access Tokens** in the JFrog Platform UI.
You'll need to generate a **Reference Token** and use that value.

Required token scopes for JFrog Xray:

- **All Services**, as DefectDojo needs access to both access to both XRay and Artifactory services
- **Manage Reports + Manage Resources** at a minimum.

By default, DefectDojo maps each Artifactory **repository** as a separate Record. Each Sync generates a complete vulnerability report per repository via Xray, so finding statuses in DefectDojo always reflect the current state of the repository.

#### Repository Filter (optional)

By default the connector discovers **every** repository in your JFrog instance. On instances with a large number of repositories — many of which may not be relevant to security review — discovery can be narrowed with the optional **Repository Filter** field, under **Import Filters** on the connector form.

The filter is applied during discovery, **before any per\-repository work is done**. A repository outside the filter costs nothing: no Xray report is generated for it and, in artifact mode, none of its first\-level artifacts are enumerated. This makes it the most effective way to cut both Sync time and the load DefectDojo places on your JFrog instance — more so than any setting applied later in the Sync. It is especially recommended alongside **Artifact\-Level Records** on large instances.

**Syntax:** a comma\-separated list of repository keys. Each entry may use `*` wildcards:

* An entry containing `*` is matched as a pattern — `releases-*` matches every repository key beginning `releases-`, and `*docker-pr-local*` matches any key containing `docker-pr-local`. A `*` matches any run of characters, including `/`.
* An entry with no `*` must match a repository key **exactly**.
* A repository is discovered if it matches **any** entry in the list. Spaces around commas are ignored.

```
releases-*, snapshots
```

The example above discovers every repository whose key starts with `releases-`, plus the single repository named exactly `snapshots`.

Notes:

* The filter is an **allow\-list** — a match selects a repository. There is no exclusion or negation syntax, so you cannot express "everything except X" directly.
* Matching is **case\-sensitive**, for both exact entries and wildcards. `*` is the only wildcard character; `?` and character ranges are not supported.
* **Leave it blank to discover every repository.** A value that is only spaces or commas is treated as blank.
* A filter that matches nothing simply discovers nothing — there is no error. If a Sync unexpectedly finds no repositories, check the connector log for the `repository filter scoped discovery` entry, which reports how many of the total repositories matched.
* The field can be changed after the connection is created.

**Changing the filter later:** repositories that a newly narrowed filter now excludes are no longer discovered, and their existing Records follow the normal lifecycle for Assets the tool no longer reports — **mapped** Records are flagged `MISSING` on the next Sync, and unmapped `NEW` Records are removed. Findings already imported into DefectDojo are not deleted; the filter governs discovery only.

#### Artifact-Level Records

The **Artifact-Level Records** toggle changes discovery to one level below the repository: every first-level entry under a repository root (for Docker repositories, each image; for generic repositories, each top-level file or folder) becomes its own Record. Each Sync still generates a single Xray report per repository — DefectDojo attributes each vulnerability to the artifacts it impacts, so the load on your JFrog instance does not increase.

> **Check which mode you are in before your first Sync.** Artifact\-Level Records is **on by default for new installations**. Installations that predate the feature keep their existing repository\-level layout, so the toggle is off for them until someone turns it on. In both cases the toggle can be changed at any time — see *Switching an existing connection* below.

With Artifact-Level Records enabled:

* Repositories remain as Records and become **parent assets**: they carry no findings themselves, but when the Asset Hierarchy feature is enabled, DefectDojo automatically relates each artifact asset to its repository asset with a `parent` relationship. Assets can then be filtered by parent/child, and findings roll up the hierarchy.
* A vulnerability that impacts several artifacts is imported into each affected artifact's asset, so every asset shows the complete set of findings that affect it.
* Findings are scoped to each artifact's **latest build**, so an artifact's findings describe its current build rather than accumulating results from every build Xray has ever scanned.
* Hierarchy relationships created by the connector never overwrite relationships you created by hand. If an asset already has a parent you assigned, the connector leaves it alone.
* The token additionally needs read access to the Artifactory storage API (included in the scopes above).

**Switching an existing connection to Artifact-Level Records:** the toggle can be changed at any time. On the first Sync afterward, new artifact Records appear for mapping — enable **Auto Map** on the connection when flipping the toggle so findings move without a gap. The repository-level assets stop receiving findings and their previously imported findings are closed on their next Sync (the same findings are re-imported under the new artifact assets, with fresh status); notes and history on the old repository-level findings stay on the repository asset. Switching back reverses this: repository Records resume carrying findings (previously closed findings re-open as they re-match), and artifact Records are marked MISSING — their assets and findings are kept but stop updating, so you can archive them at your convenience.

See the [JFrog Xray REST API documentation](https://jfrog.com/help/r/jfrog-rest-apis/xray-rest-apis) for more information.
