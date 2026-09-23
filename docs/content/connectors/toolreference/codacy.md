---
title: "Codacy"
description: "How to set up the Codacy Upstream Connector for DefectDojo"
weight: 38
audience: pro
---
The Codacy connector imports **code quality and security findings** from Codacy. DefectDojo enumerates every organization your token can see and creates a Record for each **repository that carries security issues** — repositories with none are not mapped.

#### Prerequisites

You need a Codacy **account** API token.

> **A repository ("project") token will not work.** Codacy's repository tokens are valid only against its older API version, and this connector uses the current one. Pasting a project token produces authentication failures that look like an invalid key. Make sure you generate an **account** token.

#### Connector Mappings

1. Enter `https://app.codacy.com/api/v3` in the **Location** field.
2. Enter your Codacy **account** API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each repository with security issues becomes a Record. Only **open** Security and Risk Management items are imported, so items you resolve in Codacy are reflected on the next Sync.
