---
title: "Aqua Supply Chain"
description: "How to set up the Aqua Supply Chain Upstream Connector for DefectDojo"
weight: 18
audience: pro
---
The Aqua Supply Chain connector imports **code-security findings from Aqua Supply Chain Security**. It covers five categories: vulnerabilities, secrets, infrastructure-as-code misconfigurations, SAST findings and pipeline misconfigurations. It imports these findings across every repository in your Aqua tenant. This is a different product from the [Aqua Security](/connectors/toolreference/aqua_security/) connector, which imports container image and workload vulnerabilities. The two connectors call different hosts, so do not point one at the other's URL. DefectDojo creates a Record for each repository.

#### Prerequisites

An **admin-generated** Aqua **API key and secret**, created under **Account Management \> API Keys** in the Aqua console. This is the same key and secret the Aqua Security connector uses. The secret is shown only once when the key is generated, so capture it at that point. Neither value is ever logged.

#### Connector Mappings

1. Enter your Aqua Supply Chain **edge** host in the **Location** field, for example `https://eu-central-1.edge.cloud.aquasec.com`. This is not the tenant URL the Aqua Security connector uses. Aqua Supply Chain Security answers on the region's **edge** host, not `<tenant>.cloud.aquasec.com`.
2. Enter the API key in the **API Key** field.
3. Enter the API secret in the **API Secret** field.
4. If your tenant is in the EU, set the **Auth Host** field to `https://eu-1.api.cloudsploit.com`. Leave it blank for the US host, `https://api.cloudsploit.com`. Aqua caps the issued authentication token at two hours, regardless of the validity the connector requests. The connector re-authenticates on its own when the token expires.
5. Optionally, set **Scan Categories** to a comma-separated list of the categories to import. The five values are `vulnerabilities` (SCA), `secrets`, `iacMisconfigurations` (IaC), `sast` and `pipelineMisconfigurations` (Pipeline). Leave it blank to import all five. Each finding carries a `category:<value>` tag naming the category it came from.
6. Optionally, set a **Minimum Severity** to limit which findings are imported. Aqua reports severity as a 0-4 value, which DefectDojo maps to Info, Low, Medium, High and Critical.

Each repository in the tenant becomes a Record. A repository that disappears from Aqua stops being returned by the API. DefectDojo reconciles it like any other connector's missing record. Enable **Skip Repositories With No Findings** to only create a Record for a repository that has at least one finding.

#### Branch handling

A repository's default branch is always imported. Two optional fields extend this:

- **Branch**: an exact branch name, or a `*` wildcard family such as `release/*`. It adds matching branches on top of the default branch.
- **Track Scanned Branches**: when enabled, each imported branch gets its own engagement on the mapped Record. A fix on one branch then cannot close another branch's findings. The default branch is imported first. A finding that also appears on another branch is marked a duplicate of the default branch's finding. When this is off, all selected branches import into the Record's default engagement.

This setting also affects which branches are selected when **Branch** is blank. If **Track Scanned Branches** is off, only the default branch is imported. If it is on, every branch Aqua has scanned is imported.

Aqua only stores results for a branch it has actually scanned. A Branch value that matches no scanned branch contributes no findings for that branch.

#### Filing

Set **Filing Prefixes** to a comma-separated list of repository-name prefixes, for example `PAY,WEB,INFRA`. Each repository is filed under the prefix its name starts with. A repository that matches none of the configured prefixes is filed under **Fallback Filing Name**, which defaults to `Aqua Unmapped`. Leave **Filing Prefixes** blank to file each repository under the first hyphen- or underscore-delimited part of its name instead.

#### Duplicate findings

Aqua can return several byte-identical rows for the same finding. One example is a row per instantiation of a shared Terraform module. The connector keeps one copy and records how many rows it collapsed in the finding description.

#### Sync cost

A full sync pulls the whole tenant in a handful of requests. It sends roughly one request per 10,000 findings, plus the repository list, which takes two or three requests. The connector groups the results locally.
