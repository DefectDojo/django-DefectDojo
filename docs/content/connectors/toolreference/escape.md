---
title: "Escape"
description: "How to set up the Escape Upstream Connector for DefectDojo"
weight: 55
audience: pro
---
The Escape connector uses the [Escape](https://escape.tech) API to import **API\-security (DAST) findings**. DefectDojo enumerates every organization the token can access and every application within each, creates a Record for each application that has a scan, and imports that application's latest scan issues as findings — there is no per\-application configuration.

#### Prerequisites

You will need an Escape **API key**, created in the Escape app under **Settings → API keys**. The key is sent in the `Authorization: Key` header and is never logged.

#### Connector Mappings

1. Keep the pre-filled **Location**, `https://public.escape.tech/v2`, or enter your Escape API host explicitly.
2. Enter the Escape API key in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each **application** to a Record and each scan **issue** to a finding: the severity comes from Escape's rating (Critical/High/Medium/Low), the CWE is carried over, the OWASP category and HTTP method become tags, the affected URL becomes the endpoint, and the remediation guidance is included. Findings are recorded as dynamic findings and de\-duplicated on Escape's issue id.

See the [Escape API documentation](https://docs.escape.tech/) for more information.
