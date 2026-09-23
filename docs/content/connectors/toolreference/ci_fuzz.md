---
title: "CI Fuzz"
description: "How to set up the CI Fuzz Upstream Connector for DefectDojo"
weight: 35
audience: pro
---
The CI Fuzz connector imports **fuzzing findings** from Code Intelligence CI Fuzz. DefectDojo creates a Record for each CI Fuzz **project**.

#### Prerequisites

A CI Fuzz **API token**, sent as a bearer token and never logged.

#### Connector Mappings

1. Enter `https://app.code-intelligence.com` in the **Location** field.
2. Enter the API token in the **API Token** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each CI Fuzz project becomes a Record, carrying that project's fuzzing findings.
