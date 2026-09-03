---
title: "Qualys"
description: "How to set up the Qualys Upstream Connector for DefectDojo"
weight: 109
audience: pro
---
The Qualys connector imports **VMDR host vulnerability detections** — each joined with its Qualys KnowledgeBase (QID) metadata — from the Qualys Cloud Platform. DefectDojo creates a Record for each Qualys **host** in your subscription.

#### Prerequisites

A Qualys user account with **VMDR API access**, and your subscription's **API server (platform) URL** — this differs per subscription. Find it in the Qualys UI under **Help \> About**, or on the Qualys [Platform Identification](https://www.qualys.com/platform-identification/) page (for example `https://qualysapi.qualys.com` for US Platform 1, or `https://qualysapi.qg2.apps.qualys.com` for US Platform 2).

#### Connector Mappings

1. Enter your Qualys API server URL in the **Location** field (for example `https://qualysapi.qualys.com`).
2. Enter the Qualys API username in the **Username** field.
3. Enter the Qualys API password in the **Secret** field.
4. Optionally, restrict discovery to part of your subscription with **Host Tags** (see below).
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Qualys host becomes a Record. Detections Qualys has marked **Fixed** are excluded, so reimport closes remediated findings.

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

**Testing the connection** ignores this field on purpose, so it still confirms your username and password even when the tag names are wrong.

**Changing the filter later:** hosts that a newly narrowed filter excludes are no longer discovered. Their existing Records then follow the normal lifecycle for assets the tool stops reporting: **mapped** Records are flagged `MISSING` on the next Sync, and unmapped `NEW` Records are removed. Findings already imported into DefectDojo are not deleted. The filter governs discovery only.
