---
title: "Qualys"
description: "How to set up the Qualys Upstream Connector for DefectDojo"
weight: 109
audience: pro
---
The Qualys connector imports **VMDR host vulnerability detections** — each joined with its Qualys KnowledgeBase (QID) metadata — from the Qualys Cloud Platform. DefectDojo creates a Record for each Qualys **host** in your subscription.

#### Prerequisites

A Qualys user account with **VMDR API access**, and your subscription's **API server (platform) URL** — this differs per subscription. Find it in the Qualys UI under **Help \> About**, or on the Qualys [Platform Identification](https://www.qualys.com/platform-identification/) page (for example `https://qualysapi.qualys.com` for US Platform 1, or `https://qualysapi.qg2.apps.qualys.com` for US Platform 2).

The connector only sees the hosts the Qualys user can see, so the user's **scope** (its asset groups or tags) must cover every host you expect to import, and the **VM module** must be enabled on the subscription. A user scoped to a single asset group silently limits the import to that group. The connector is read-only: it calls the Qualys **host list**, **host detection list** and **KnowledgeBase** APIs and nothing else.

#### Connector Mappings

1. Enter your Qualys API server URL in the **Location** field (for example `https://qualysapi.qualys.com`).
2. Enter the Qualys API username in the **Username** field.
3. Enter the Qualys API password in the **Secret** field.
4. Optionally, restrict discovery to part of your subscription with **Host Tags** (see below).
5. Optionally, choose an **Asset Grouping**: one asset per host (the default) or one asset per tag (see below).
6. Optionally, enable **Create Endpoints From Hosts** to attach each finding to its host as an endpoint (see below).
7. Optionally, set a **Minimum Severity** to limit which findings are imported.

By default each Qualys host becomes a Record. Detections Qualys has marked **Fixed** are excluded, so reimport closes remediated findings.

Each host Record carries the host's Qualys details as attributes, including a **TAGS** attribute listing the host's Qualys asset tag names (sorted, comma-separated), which helps when deciding how to map Records to assets. Attributes are captured at discovery: once a Record is mapped, its attributes are not refreshed, so a Record mapped before the TAGS attribute existed does not gain it.

#### Host Tags (optional)

By default the connector discovers **every** host in your Qualys subscription. On a large estate that produces a Record list far bigger than most teams want. It also makes every Sync download the detections of every host.

The optional **Host Tags** field, under **Import Filters** on the connector form, restricts the connector to hosts carrying the Qualys asset tags you name. The restriction travels to Qualys as part of the request, so out-of-scope hosts are never returned. It applies to **both** the host listing and the detection download. Narrowing the scope therefore cuts Sync time and transfer volume, not just the length of the Record list.

**Syntax:** a comma-separated list of Qualys asset tag **names**, exactly as they appear in the Qualys UI under **Asset Management \> Tags**.

```
Prod, Business Unit: Finance
```

The example above discovers every host tagged `Prod` plus every host tagged `Business Unit: Finance`.

Notes:

* Tag names are matched **exactly**, and **wildcards are not supported**. Qualys offers no pattern matching on tag names, so `Prod-*` matches a tag literally named `Prod-*` and nothing else. This differs from the JFrog Xray **Repository Filter** described above, which does accept `*`.
* A host is discovered if it carries **any** tag in the list, not all of them.
* Spaces **around** the commas are ignored. Spaces **inside** a tag name are kept, so `Business Unit: Finance` works as written.
* A tag name that itself contains a comma cannot be used here, because the comma separates entries.
* The filter is an **allow-list**. There is no exclusion or negation syntax, so you cannot express "everything except X".
* **Leave it blank to discover every host.** A value that is only spaces or commas is treated as blank.
* If the tag names match no host, nothing is discovered. Check the spelling against the Qualys UI, and check the visible-host count reported on the connection.
* The field can be changed after the connection is created.
* With **Asset Grouping** set to **Tag**, this field is required and also decides which assets are created (see below).

**Testing the connection** ignores this field on purpose, so it still confirms your username and password even when the tag names are wrong.

#### Asset Grouping (optional)

By default the connector creates one Record, and so one asset, per Qualys host. When an application or business unit runs on many hosts, that spreads its findings over many assets, and you have to map each one. The **Asset Grouping** field, under **Import Filters** on the connector form, can group hosts by Qualys tag instead:

| Asset Grouping | Records | Findings on each Record |
|---|---|---|
| **Host** (default) | one per Qualys host | that host's detections |
| **Tag** | one per tag listed in **Host Tags** that at least one host carries | the detections of every in-scope host carrying that tag |

With **Tag**, **Host Tags** is required and does two jobs: it is the scope (which hosts are imported) and the list of tags to group by. For example, with Host Tags set to

```
Product: Web Portal, Product: Billing API
```

the connector creates two Records, `Product: Web Portal` and `Product: Billing API`, each holding the findings of every host carrying that tag.

* **Type each tag exactly as it appears in Qualys.** Hosts carrying none of the listed tags are not imported.
* A host carrying several listed tags contributes its findings to each of those Records.
* A listed tag that no host carries creates no Record.
* Each Record is named with the tag **as Qualys spells it**. If an asset already exists with exactly that name, auto-mapping routes the tag's findings to it, so you can create or rename assets to match your Qualys tags ahead of time.
* Every finding carries its **host as an endpoint**, whatever **Create Endpoints From Hosts** is set to. Without it, the same QID on two hosts would look like two identical findings on one asset.
* Tag Records carry a **TAG_NAME** attribute (the tag) and a **HOST_COUNT** attribute (how many in-scope hosts carried the tag at discovery). Like other attributes, they are not refreshed once the Record is mapped.
* **Asset Grouping cannot be changed after the connection is created**, because switching would change the identity of every Record. To move from host to tag grouping, create a new connection.

**Removing a tag from Host Tags later:** its Record is no longer discovered and follows the normal lifecycle (flagged `MISSING` if mapped, removed if `NEW`). Until then, Syncs skip it rather than importing an empty result. Findings already imported for that tag are **not closed automatically**; close or delete them in DefectDojo if you no longer want them.

#### Create endpoints from hosts (optional)

By default, findings imported by this connector are linked only to the mapped asset, with no per-host endpoint. On an asset that aggregates several Qualys hosts, that makes it hard to see which systems a finding affects.

The optional **Create Endpoints From Hosts** toggle attaches each finding's Qualys host as an endpoint:

* The endpoint host is the Qualys host's **DNS name**, or its **NetBIOS name** when there is no DNS name, or its **IP address** when there is neither — the same preference order the connector uses to name the Record.
* When the detection reports a **port**, it is included, so `web01.example.com:443` and `web01.example.com:8443` remain distinct endpoints.
* If the asset already has a matching endpoint, the finding is attached to it; otherwise the endpoint is created. No duplicate endpoints are created either way.

The toggle is **off by default**, which keeps the connector's historical behavior: findings stay asset-only. With **Asset Grouping** set to **Tag**, findings always carry their host as an endpoint and this toggle has no effect. It can be changed after the connection is created, and takes effect on the next Sync — existing open findings gain their endpoints then too, since a Sync reimports them.

**Changing the filter later:** hosts that a newly narrowed filter excludes are no longer discovered. Their existing Records then follow the normal lifecycle for assets the tool stops reporting: **mapped** Records are flagged `MISSING` on the next Sync, and unmapped `NEW` Records are removed. Findings already imported into DefectDojo are not deleted. The filter governs discovery only.
