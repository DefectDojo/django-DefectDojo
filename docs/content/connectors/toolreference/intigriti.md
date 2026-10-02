---
title: "Intigriti"
description: "How to set up the Intigriti Upstream Connector for DefectDojo"
weight: 78
audience: pro
---
The Intigriti connector uses the Intigriti external company API to pull bug-bounty / pentest **submissions** into DefectDojo. It syncs the whole company account: DefectDojo discovers every program the token can access and creates a Record for each, then imports that program's submissions as findings.

#### Prerequisites

You will need an Intigriti **company API token**. In the Intigriti company portal, under **Company Settings > API** (the `company_external_api` scope), generate an access token with read access to your programs and submissions. A dedicated token for DefectDojo is recommended. The token is sent as a Bearer token and is never logged.

#### Connector Mappings

1. Enter the Intigriti external company API base URL in the **Location** field: `https://api.intigriti.com/external/company`. The URL must be HTTPS.
2. Enter the company API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each Intigriti **program** to a Record and each **submission** to a finding, keyed by the submission code. The finding severity follows Intigriti's rating (Exceptional/Critical → Critical, then High/Medium/Low, otherwise Informational), and the submission's lifecycle state maps to the finding's status: open/triage submissions are active, accepted submissions are verified, and closed submissions become mitigated, a duplicate, out-of-scope, false-positive or risk-accepted according to their close reason. The finding description carries the report's vulnerability type, affected asset, proof of concept and the researcher's answers.

See the [Intigriti API documentation](https://kb.intigriti.com/en/articles/6117846-intigriti-api) for more information.
