---
title: "Bugcrowd"
description: "How to set up the Bugcrowd Upstream Connector for DefectDojo"
weight: 29
audience: pro
---
The Bugcrowd connector uses the Bugcrowd REST API to import submissions from your bug bounty and vulnerability disclosure programs. DefectDojo discovers the programs your API token can access and creates a Record for each one, importing that program's submissions as findings.

#### Prerequisites

You will need a Bugcrowd **API token** with access to the programs you want to import. We recommend creating a dedicated service account for DefectDojo so automated activity is easy to distinguish from manual team actions. Generate the token in Bugcrowd under **Organization settings \> API credentials**; read access to submissions, programs, and targets is sufficient.

#### Connector Mappings

1. Enter `https://api.bugcrowd.com` in the **Location** field.
2. Enter your Bugcrowd API token in the **Secret** field. It is sent as an `Authorization: Token` header.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Bugcrowd **program** becomes a Record, and its submissions are imported as findings with the Bugcrowd severity preserved. Duplicate submissions are excluded, so reimport does not create repeated findings for the same issue.
