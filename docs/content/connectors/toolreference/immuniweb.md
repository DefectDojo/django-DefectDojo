---
title: "ImmuniWeb"
description: "How to set up the ImmuniWeb Upstream Connector for DefectDojo"
weight: 76
audience: pro
---
The ImmuniWeb connector imports **web application security findings** from ImmuniWeb. DefectDojo creates a Record for each **tested asset** (website) on the account.

#### Prerequisites

An ImmuniWeb **premium API key**.

> **A premium key is required, even though ImmuniWeb treats its API key as optional.** Without one, ImmuniWeb **truncates the vulnerability list** it returns. DefectDojo requires the key rather than importing a silently incomplete set of findings — an import that under\-reports is worse than one that will not start.

#### Connector Mappings

1. Enter your ImmuniWeb API URL in the **Location** field.
2. Enter your premium API key in the **API Key** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each tested asset becomes a Record, carrying that asset's detected vulnerabilities.
