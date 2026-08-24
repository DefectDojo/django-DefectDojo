---
title: "Prowler"
description: "How to set up the Prowler Upstream Connector for DefectDojo"
weight: 108
audience: pro
---
The Prowler connector uses the **Prowler App** REST API to import cloud security posture (CSPM) findings from a self-hosted Prowler App instance. DefectDojo discovers each Prowler **provider** (cloud account) as a Record and imports the **FAIL** findings of that provider's latest completed scan.

#### Prerequisites

You will need a running, self-hosted **Prowler App** instance and either a user email + password (for JWT authentication) or a Prowler App **API key**. Findings only appear once you have connected a cloud account (AWS, GCP, Azure, Kubernetes, ...) in Prowler App and run a scan.

#### Connector Mappings

1. Enter your Prowler App URL in the **Location** field (for example `https://prowler.your-company.com`).
2. For JWT authentication, enter the Prowler App user **Email** and **Password**. Alternatively, leave those blank and enter a Prowler App **API Key**. If both are provided, the email/password (JWT) is used.
3. Optionally set a **Minimum Severity** to limit which findings are imported. Findings below the selected severity are not imported.

DefectDojo creates a Record for each Prowler provider and imports the FAIL findings of its latest completed scan, mapping Prowler severities to DefectDojo severities, the affected cloud resource (ARN/resource id) as the component, and the check's remediation and risk into the finding. Muted findings are skipped. Cloud account, region, and service are attached as tags.

For more information, see the **[Prowler App API documentation](https://api.prowler.com/api/v1/docs)**.
