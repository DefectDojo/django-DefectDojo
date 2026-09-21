---
title: "HackerOne"
description: "How to set up the HackerOne Upstream Connector for DefectDojo"
weight: 69
audience: pro
---
The HackerOne connector uses the HackerOne REST API to import reports from your bug bounty or vulnerability disclosure program. DefectDojo creates a Record for each program the token can access and imports its reports as findings.

#### Prerequisites

The connector uses HackerOne's **customer** API, which requires an **organization API token** — a personal token from your user settings only works against the hacker API and will not authenticate here.

1. In HackerOne, go to **Organization Settings > API Tokens**.
2. Create a token and note both the **identifier** and the **token** value. Read access to the program is sufficient.

#### Connector Mappings

1. Enter `https://api.hackerone.com` in the **Location** field.
2. Enter the token **identifier** in the **API Token Identifier** field.
3. Enter the token value in the **API Token** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each program becomes a Record, and its reports are imported as findings with the HackerOne severity rating preserved.
