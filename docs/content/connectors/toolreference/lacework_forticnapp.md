---
title: "Lacework / FortiCNAPP"
description: "How to set up the Lacework / FortiCNAPP Upstream Connector for DefectDojo"
weight: 86
audience: pro
---
The Lacework / FortiCNAPP connector uses the Lacework v2 API to import **host and container vulnerabilities** for your whole Lacework account.

#### Prerequisites

You will need a Lacework **API key** — an API key id and secret, created in the Lacework console under **Settings → API keys**. The connector exchanges these for a short-lived access token on each sync; the key id, secret and token are never logged.

#### Connector Mappings

1. Enter your Lacework account URL in the **Location** field — for example `https://YOUR-ACCOUNT.lacework.net` (a bare account name is also accepted).
2. Enter the **API Key ID** and **API Secret**.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps the Lacework **account** to a Record (the whole-account scope). Each **container** and **host** vulnerability becomes a finding: the severity comes from Lacework's own rating, the affected package and version become the component, the fix version becomes the mitigation, and the affected image/host is recorded as tags. Container vulnerabilities are recorded as static findings (image scans) and host vulnerabilities as dynamic findings (running-host scans).

See the [Lacework API documentation](https://docs.lacework.net/api/v2/docs) for more information.

#### Asset Grouping (optional)

By default the connector creates a single Record, and so a single asset, for the whole Lacework account. The **Asset Grouping** field, under **Import Filters** on the connector form, can split findings more finely:

| Asset Grouping | Records | Findings are imported on |
|---|---|---|
| **Account** (default) | one for the account | the account Record |
| **Resource type** | additionally, **Container images** and **Hosts** under the account | the two resource type Records |
| **Resource** | additionally, one per container image repository and one per host, under their resource type | the repository and host Records |

With **Resource**, image tags and digests are grouped under their repository, because they are versions of the repository. Repository Records are named `<repository> (container image, <registry>, <account>)` and host Records `<hostname> (host, <account>)`, with the machine ID added when two hosts share a hostname.

With a finer grouping:

* The account Record keeps the same identity and becomes a **parent asset** with no findings of its own. When the Asset Hierarchy feature is enabled, DefectDojo relates the resource type assets to the account asset, and each repository or host asset to its resource type asset, with a `parent` relationship. Relationships created by the connector never overwrite relationships you created by hand.
* Each vulnerability is imported once, on the asset of its repository or host.
* Only repositories and hosts with at least one active vulnerability at or above the minimum severity become Records. A repository or host whose vulnerabilities are all fixed keeps its Record for 14 days, during which the fixed vulnerabilities close, after which the Record is marked MISSING.
* Lacework machine tags reach host assets as asset tags, prefixed `lacework:` (for example `lacework:env:prod`). Tags you add yourself are never touched.
* Repository Records carry the repository's registry address, so the same repository reported by another connector can be recognized as the same asset.
* The connector still runs the same two Lacework searches per Sync as the default grouping, whatever the number of repositories and hosts, so it stays within Lacework's API rate limits.

**Switching an existing connection to a finer grouping:** the field can be changed at any time. On the next discovery, the new Records appear for mapping; enable **Auto Map** on the connection when you change the grouping so findings move without a gap. On the next Sync, the account asset stops receiving findings and its previously imported findings are closed (the same findings are imported again on the new assets). Switching back reverses this, and the finer Records close their findings and are then marked MISSING. Closing the findings of the parent assets needs DefectDojo and the connectors service from the same release or later.

A Lacework connection covers a single Lacework account, so this connector has no **Organization Placement** option.
