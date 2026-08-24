---
title: "YesWeHack"
description: "How to set up the YesWeHack Upstream Connector for DefectDojo"
weight: 143
audience: pro
---
The YesWeHack connector uses the YesWeHack REST API to import reports from your bug bounty and vulnerability disclosure programs. DefectDojo creates a Record for each program your token can access and imports its reports as findings.

#### Prerequisites

You will need a YesWeHack **Personal Access Token (PAT)**. Read access to your programs is sufficient. Some accounts require TOTP/MFA when creating a token; once created, the token value itself is what the connector uses.

1. In YesWeHack, open your account settings and go to **API / Personal Access Tokens**.
2. Create a token and copy its value. It is only shown once.

#### Connector Mappings

1. Enter `https://api.yeswehack.com/` in the **Location** field.
2. Enter your Personal Access Token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported. Findings below the selected severity will not be imported.

DefectDojo creates a separate Record for each program your token can access, and imports each report as a finding. The finding's severity is taken from the report's CVSS rating (falling back to the triage priority), and its status reflects the report's workflow state — for example, resolved reports are imported as mitigated, and reports marked invalid or out of scope are imported as inactive.
