---
title: "DeepSource"
description: "How to set up the DeepSource Upstream Connector for DefectDojo"
weight: 47
audience: pro
---
The DeepSource connector imports **static analysis findings** from DeepSource. DefectDojo enumerates every account your token can see and creates a Record for each **activated** repository.

#### Prerequisites

A DeepSource **personal access token**, sent as a bearer token.

#### Connector Mappings

1. Enter your DeepSource GraphQL API URL in the **Location** field — `https://api.deepsource.com/graphql/` for the cloud platform, or your own host's GraphQL path if self\-hosted.
2. Enter the personal access token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each activated repository becomes a Record. DeepSource reports the currently-open set of issue occurrences rather than a per\-finding status, so each Sync reflects what is open at that moment.
